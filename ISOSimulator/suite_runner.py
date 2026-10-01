"""
suite_runner.py - Executes end-to-end test cases (Switch -> CBS)
================================================================
* Builds each step's ISO message from the channel config + profile + overrides
* Links steps: reversal / repeat reversal (0421) / identical duplicate / same RRN
* Tampers with the wire message for format & security tests
* Sends over TCP and evaluates: RC, response MTI, mandatory DEs, echoed DEs,
  DE presence / absence / regex, DE 54 balance movement, expected timeouts
"""

import random
import re
import socket
import time
from datetime import datetime

from iso_engine import (
    get_field_def, format_iso_layout, parse_iso_ex, set_bitmap_bit,
    pack_payload, frame_bytes, parse_tpdu, unpack_response, tcp_transact,
    expected_response_mti, describe_rc, amount_to_n12, rupees_to_paise,
    available_balance, paise_to_str,
)

ENQUIRY_PREFIXES = ("31", "38", "41")
TOKEN_RE = re.compile(r"\{step(\d+)(\.resp)?\.(\d+)\}")


# ============================================================================
# Field generation (shared with the Single Request screen)
# ============================================================================
def fit_fixed(de, val, field_defs):
    """Pad / trim GENERATED default values to the fixed DE length."""
    fdef = get_field_def(de, field_defs)
    val = str(val)
    if not fdef or fdef[0] != "fixed" or fdef[1] <= 0 or len(val) == fdef[1]:
        return val
    length = fdef[1]
    if val.isdigit():
        return val.zfill(length)[-length:]
    return val.ljust(length)[:length]


def build_de90(orig_mti, orig_fields):
    """DE 90 = Orig MTI(4) + Orig STAN(6) + Orig DE7(10) + Acq ID(11) + Fwd ID(11)."""
    stan = str(orig_fields.get(11, "000000")).zfill(6)[-6:]
    de7 = str(orig_fields.get(7, datetime.now().strftime("%m%d%H%M%S"))).zfill(10)[-10:]
    acq = str(orig_fields.get(32, "0")).zfill(11)[-11:]
    fwd = str(orig_fields.get(33, "0")).zfill(11)[-11:]
    return f"{str(orig_mti)[:4]}{stan}{de7}{acq}{fwd}"


def new_rrn():
    return f"61{random.randint(1000000000, 9999999999)}"


def generate_fields(mti, proc_code, des_present, custom=None, channel="ATM", field_defs=None):
    """Return {de: value} for every DE in des_present using defaults + custom overrides."""
    custom = custom or {}
    now = datetime.now()
    is_atm = (channel == "ATM")

    pan = custom.get("pan") or ("6072930130054479" if is_atm else "8180073930053234")
    rrn = custom.get("rrn") or new_rrn()
    stan = custom.get("stan") or str(rrn)[-6:]
    account = custom.get("account") or ("101303130001356" if is_atm else "0020001010000069")
    acq_id = custom.get("acq_id") or ("800024" if is_atm else "622018")
    expiry = custom.get("expiry") or "2907"
    proc = str(proc_code)
    if custom.get("amount"):
        amount = custom["amount"]
    elif proc[:2] in ENQUIRY_PREFIXES:
        amount = "000000000000"
    else:
        amount = "000000050000" if proc.startswith("01") else "000000297800"

    generators = {
        2: str(pan),
        3: proc,
        4: str(amount),
        7: now.strftime("%m%d%H%M%S"),
        11: str(stan).zfill(6),
        12: now.strftime("%H%M%S"),
        13: now.strftime("%m%d"),
        14: str(expiry),
        15: now.strftime("%m%d"),
        17: now.strftime("%m%d"),
        18: custom.get("mcc") or ("6011" if is_atm else "6012"),
        22: custom.get("pos_entry") or ("810" if 14 in des_present else "051"),
        25: custom.get("pos_cond") or ("59" if 14 in des_present else "00"),
        32: str(acq_id),
        33: "000000",
        35: f"{pan}={expiry}6204850000000000",
        37: str(rrn).zfill(12),
        38: "244729",
        39: custom.get("de39") or ("E2" if mti in ("0420", "0421", "0220") else "00"),
        41: custom.get("terminal_id") or ("BECN1053" if is_atm else f"{channel}0001"),
        42: "BECN105305     " if is_atm else f"{channel}PAYMENTSW01",
        43: "OT SECTION ULHASNAGAR  THANE        MHIN" if is_atm else f"{channel} SWITCH SWITCHING NETWORK IN",
        46: custom.get("de46") or "ICH356D000000001000",
        48: "CASHNET                 40000035600000000000",
        49: "356",
        50: "356",
        54: "1001356C0000000500001002356C000000050000",
        60: "EUROPRO1+000",
        63: "00100207002003GDN",
        70: "301",
        90: custom.get("de90") or build_de90("0200", {11: stan, 7: now.strftime("%m%d%H%M%S"), 32: acq_id}),
        102: str(account),
        104: "919850698696",
        120: "00100207002003GDN",
        123: "UPI",
        124: "UPI|000000|DEBIT|9024655944-2@ybl|9024655944-2@ybl|UPI",
        127: "UPI|CR|663921617265|PRAVIN TEK|KKBK|8446165338|UPI",
    }

    fields = {}
    for de in sorted(set(int(d) for d in des_present)):
        if de in custom:
            fields[de] = str(custom[de])
        elif str(de) in custom:
            fields[de] = str(custom[str(de)])
        elif de in generators:
            fields[de] = fit_fixed(de, generators[de], field_defs)
    return fields


def assemble_iso_from_numericals(mti, proc_code, des_present, custom_params=None, channel="ATM", field_defs=None):
    fields = generate_fields(mti, proc_code, des_present, custom_params, channel, field_defs)
    iso, _ = format_iso_layout(mti, fields, field_defs)
    return iso, fields


# ============================================================================
# Step execution
# ============================================================================
class StepError(Exception):
    pass


def resolve_tx(key, channel_cfg, default_cfg):
    if not key:
        return None
    tx = (channel_cfg.get("sample_requests") or {}).get(key)
    if tx is None:
        tx = (default_cfg.get("sample_requests") or {}).get(key)
    return tx


def resolve_tokens(value, ctx):
    def repl(m):
        n = int(m.group(1))
        is_resp = bool(m.group(2))
        de = int(m.group(3))
        if not (1 <= n <= len(ctx)):
            raise StepError(f"token {m.group(0)} refers to a step that has not run")
        src = ctx[n - 1]["resp_fields" if is_resp else "req_fields"] or {}
        return str(src.get(de, ""))
    return TOKEN_RE.sub(repl, str(value))


def apply_tamper(iso, layout, ops):
    for op in ops or []:
        kind = op.get("op")
        if kind == "llvar_len":
            de = int(op["de"])
            lay = layout.get(de)
            if not lay or not lay["prefix_len"]:
                raise StepError(f"tamper llvar_len: DE {de} is not a variable-length field in this message")
            val = str(op.get("value", "99")).zfill(lay["prefix_len"])[-lay["prefix_len"]:]
            ps = lay["prefix_start"]
            iso = iso[:ps] + val + iso[ps + lay["prefix_len"]:]
        elif kind == "truncate":
            n = int(op.get("chars", 10))
            iso = iso[:-n] if n > 0 else iso
        elif kind == "append":
            iso = iso + str(op.get("value", "X"))
        elif kind == "bitmap_set":
            iso = set_bitmap_bit(iso, int(op["de"]), True)
        elif kind == "bitmap_clear":
            iso = set_bitmap_bit(iso, int(op["de"]), False)
        elif kind == "replace":
            iso = str(op.get("value", ""))
        else:
            raise StepError(f"unknown tamper op '{kind}'")
    return iso


def build_step(step, idx, tc, ctx, channel, catalog, channel_cfg, default_cfg, field_defs):
    """Returns (mti, fields, iso_str, tx_info)."""
    settings = catalog.get("settings", {})
    profiles = catalog.get("profiles", {})
    prof_key = step.get("profile") or tc.get("profile") or "standard"
    if prof_key not in profiles:
        raise StepError(f"profile '{prof_key}' not found in {channel} catalog")
    prof = profiles[prof_key]
    link = step.get("link") or {}
    ltype = link.get("type")
    base = None
    if ltype:
        n = int(link.get("step", 0))
        if not (1 <= n < idx):
            raise StepError(f"link.step {n} must point to an earlier step")
        base = ctx[n - 1]
        if not base.get("req_fields"):
            raise StepError(f"step {n} has no request to link to")

    tx = resolve_tx(step.get("tx"), channel_cfg, default_cfg)
    if step.get("tx") and tx is None:
        raise StepError(f"transaction '{step['tx']}' not found in {channel} config")

    overrides = {}
    for k, v in (step.get("set") or {}).items():
        overrides[int(k)] = resolve_tokens(v, ctx)

    rule = settings.get("direction_rule") or {}
    dir_de, dir_val = None, None
    if step.get("direction") and rule.get("enabled") and rule.get("de"):
        dir_de = int(rule["de"])
        dir_val = rule.get("credit_value") if step["direction"].upper() == "CR" else rule.get("debit_value")

    # ---- identical duplicate ----
    if ltype == "duplicate":
        return base["mti"], dict(base["req_fields"]), base["req_iso"], base.get("tx")

    # ---- reversal / repeat reversal ----
    if ltype in ("reversal", "repeat_reversal"):
        f = dict(base["req_fields"])
        for d in (14, 35, 52, 55, 39, 95):
            f.pop(d, None)
        f[39] = str(link.get("reason", "68")).zfill(2)[-2:]
        f[38] = (base.get("resp_fields") or {}).get(38) or base["req_fields"].get(38) or "000000"
        f[90] = build_de90(base["mti"], base["req_fields"])
        f[7] = datetime.now().strftime("%m%d%H%M%S")
        if link.get("amount"):
            f[4] = amount_to_n12(link["amount"])
        if link.get("partial_amount"):
            actual = amount_to_n12(link["partial_amount"])
            f[95] = f"{actual}{actual}C00000000C00000000"
        f.update(overrides)
        for d in step.get("remove") or []:
            f.pop(int(d), None)
        mti = "0421" if ltype == "repeat_reversal" else "0420"
        iso, layout = format_iso_layout(mti, f, field_defs)
        return mti, f, apply_tamper(iso, layout, step.get("tamper")), base.get("tx")

    # ---- fresh message (optionally same RRN as an earlier step) ----
    mti = step.get("mti") or (tx or {}).get("mti") or "0200"
    proc = step.get("proc_code") or (tx or {}).get("proc_code") or "000000"
    des = list(step.get("des") or (tx or {}).get("req_des_present") or (tx or {}).get("des_present") or [])
    des += [int(d) for d in step.get("add") or []]
    des += list(overrides.keys())
    if dir_de:
        des.append(dir_de)
    remove = {int(d) for d in step.get("remove") or []}
    des = sorted({int(d) for d in des} - remove)

    custom = {"pan": prof.get("card"), "account": prof.get("account"), "expiry": prof.get("expiry") or "2907"}
    if step.get("amount") is not None:
        custom["amount"] = amount_to_n12(step["amount"])
    if ltype == "same_rrn":
        custom["rrn"] = base["req_fields"].get(37)
        custom["stan"] = base["req_fields"].get(11)
    if dir_de:
        custom[dir_de] = dir_val
    custom.update(overrides)

    f = generate_fields(mti, proc, des, custom, channel, field_defs)
    iso, layout = format_iso_layout(mti, f, field_defs)
    return mti, f, apply_tamper(iso, layout, step.get("tamper")), tx


def send(iso, target, timeout):
    """Returns (outcome, resp_iso, latency_ms, error)."""
    try:
        payload = pack_payload(iso, framing=target["framing"], bitmap_fmt=target["bitmap_fmt"],
                               charset=target["charset"], tpdu=target["tpdu"])
    except (ValueError, IndexError):
        codec = "cp500" if target["charset"] == "ebcdic" else "latin-1"
        payload = frame_bytes(parse_tpdu(target["tpdu"]) + iso.encode(codec, errors="replace"), target["framing"])
    t0 = time.time()
    try:
        raw = tcp_transact(target["ip"], target["port"], payload, timeout=timeout, framing=target["framing"])
        return "RESPONSE", unpack_response(raw), int((time.time() - t0) * 1000), None
    except socket.timeout:
        return "TIMEOUT", "", int((time.time() - t0) * 1000), None
    except (ConnectionResetError, BrokenPipeError):
        return "NO_RESPONSE", "", int((time.time() - t0) * 1000), None
    except OSError as e:
        return "CONN_ERR", "", int((time.time() - t0) * 1000), f"{type(e).__name__}: {e}"


def evaluate(step, idx, sent_mti, req_fields, outcome, resp, ctx, tx, settings, is_link, tampered, latency):
    """Returns (checks_failed, notes, actual_label, resp_fields, balance)."""
    exp = step.get("expect") or {}
    checks, notes = [], []
    resp_fields, balance = {}, None

    if outcome == "CONN_ERR":
        return ["Could not connect to target"], notes, "CONN_ERR", resp_fields, balance

    if outcome in ("TIMEOUT", "NO_RESPONSE"):
        label = "TIMEOUT" if outcome == "TIMEOUT" else "NO_RESP"
        if exp.get("timeout") or exp.get("allow_no_response"):
            notes.append("No response, as expected" if exp.get("timeout") else "No response (allowed)")
        else:
            checks.append(f"No response from CBS ({outcome.lower().replace('_', ' ')})")
        return checks, notes, label, resp_fields, balance

    r = parse_iso_ex(resp)
    if exp.get("timeout"):
        rc = r["fields"].get(39, "--") if r["mti"] else "--"
        checks.append(f"Expected no response (timeout) but CBS answered RC {rc}")
        return checks, notes, rc, r["fields"], available_balance(r["fields"].get(54))

    if not r["mti"]:
        return [f"Response unparseable: {r['error']}"], notes, "PARSE_ERR", resp_fields, balance

    resp_fields = r["fields"]
    if not r["complete"]:
        checks.append(f"Response partially parsed: {r['error']}")

    rc = resp_fields.get(39)
    actual = rc or "NO_DE39"
    if not rc:
        checks.append("DE 39 missing in response")
    elif exp.get("rc") and rc not in exp["rc"]:
        checks.append(f"RC {rc} ({describe_rc(rc)['label']}) not in expected {'/'.join(exp['rc'])}")

    exp_mti = exp["mti"] if "mti" in exp else expected_response_mti(sent_mti)
    if exp_mti and r["mti"] != exp_mti:
        checks.append(f"Response MTI {r['mti']} != expected {exp_mti}")

    # mandatory DEs
    if exp.get("des"):
        missing = sorted(set(int(d) for d in exp["des"]) - set(resp_fields))
        if missing:
            checks.append(f"Missing response DEs: {missing}")
    elif tx and not is_link and rc == "00" and not tampered:
        baseline = tx.get("resp_des_present") or []
        missing = sorted(set(int(d) for d in baseline) - set(resp_fields))
        if missing:
            msg = f"Missing response DEs vs schema: {missing}"
            (checks if settings.get("des_check", "strict") == "strict" else notes).append(msg)

    for d in exp.get("present") or []:
        if int(d) not in resp_fields:
            checks.append(f"DE {d} expected but absent")
    for d in exp.get("absent") or []:
        if int(d) in resp_fields:
            checks.append(f"DE {d} must not be present")

    echo = exp.get("echo")
    if echo is None and not tampered:
        echo = settings.get("default_echo_des") or []
    for d in echo or []:
        d = int(d)
        if d in req_fields and d in resp_fields and str(req_fields[d]) != str(resp_fields[d]):
            checks.append(f"DE {d} echo mismatch: sent '{req_fields[d]}' got '{resp_fields[d]}'")

    for d, pattern in (exp.get("regex") or {}).items():
        val = resp_fields.get(int(d))
        if val is None or not re.search(pattern, str(val)):
            checks.append(f"DE {d} value '{val}' does not match /{pattern}/")

    balance = available_balance(resp_fields.get(54))
    bexp = exp.get("balance")
    if bexp:
        ref = int(bexp.get("from_step", 0))
        base_bal = ctx[ref - 1].get("balance") if 1 <= ref <= len(ctx) else None
        want = rupees_to_paise(bexp.get("delta", "0"))
        if balance is None or base_bal is None:
            checks.append(f"Balance check impossible: DE 54 missing (step {ref} or this step)")
        else:
            got = balance - base_bal
            if got != want:
                checks.append(f"Balance moved {paise_to_str(got)} vs step {ref}, expected {paise_to_str(want)}")
            else:
                notes.append(f"Balance moved {paise_to_str(got)} vs step {ref} as expected")

    return checks, notes, actual, resp_fields, balance


def run_testcase(tc, channel, target, catalog, channel_cfg, default_cfg, field_defs, log_fn=None):
    settings = catalog.get("settings", {})
    delay_ms = int(settings.get("step_delay_ms") or 0)
    ctx, steps_out = [], []
    t_start = time.time()

    for idx, step in enumerate(tc.get("steps") or [], start=1):
        if idx > 1 and delay_ms:
            time.sleep(delay_ms / 1000.0)
        if step.get("wait_ms"):
            time.sleep(int(step["wait_ms"]) / 1000.0)

        label = step.get("label") or step.get("tx") or (step.get("link") or {}).get("type") or f"Step {idx}"
        exp = step.get("expect") or {}
        exp_txt = "NO RESPONSE" if exp.get("timeout") else "/".join(exp.get("rc") or [])
        entry = {"n": idx, "label": label, "mti": "", "resp_mti": "", "expected": exp_txt, "actual": "",
                 "latency_ms": 0, "verdict": "FAIL", "checks": [], "notes": [], "req_iso": "", "resp_iso": "",
                 "balance": None}
        state = {"mti": None, "req_fields": {}, "req_iso": "", "resp_fields": {}, "balance": None, "tx": None}

        try:
            mti, req_fields, iso, tx = build_step(step, idx, tc, ctx, channel, catalog, channel_cfg, default_cfg, field_defs)
        except (StepError, ValueError, KeyError, TypeError) as e:
            entry.update(actual="BUILD_ERR", checks=[f"Cannot build message: {e}"])
            steps_out.append(entry)
            ctx.append(state)
            continue

        state.update(mti=mti, req_fields=req_fields, req_iso=iso, tx=tx)
        entry.update(mti=mti, req_iso=iso)
        if log_fn:
            log_fn(f"SUITE {tc.get('id')} S{idx} REQUEST: {iso}")

        timeout = float(step.get("timeout_sec") or target["timeout_sec"])
        outcome, resp, latency, err = send(iso, target, timeout)
        if log_fn:
            log_fn(f"SUITE {tc.get('id')} S{idx} {outcome} ({latency}ms): {resp}")

        is_link = bool(step.get("link"))
        tampered = bool(step.get("tamper"))
        checks, notes, actual, resp_fields, balance = evaluate(
            step, idx, mti, req_fields, outcome, resp, ctx, tx, settings, is_link, tampered, latency)
        if err:
            checks.append(err)

        state.update(resp_fields=resp_fields, balance=balance)
        parsed_mti = parse_iso_ex(resp)["mti"] if resp else None
        entry.update(resp_mti=parsed_mti or "", resp_iso=resp, actual=actual, latency_ms=latency,
                     checks=checks, notes=notes, balance=paise_to_str(balance) if balance is not None else None,
                     verdict="PASS" if not checks else "FAIL")
        steps_out.append(entry)
        ctx.append(state)

    passed = sum(1 for s in steps_out if s["verdict"] == "PASS")
    total = len(steps_out)
    return {
        "id": tc.get("id"), "name": tc.get("name"), "category": tc.get("category"),
        "priority": tc.get("priority", ""), "profile": tc.get("profile", "standard"),
        "expected_result": tc.get("expected_result", ""), "description": tc.get("description", ""),
        "verdict": "PASS" if total and passed == total else "FAIL",
        "pass_steps": passed, "total_steps": total,
        "duration_ms": int((time.time() - t_start) * 1000),
        "final_rc": steps_out[-1]["actual"] if steps_out else "",
        "steps": steps_out,
    }
