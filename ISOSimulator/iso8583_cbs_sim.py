"""
iso8583_cbs_sim.py - Stateful Mock CBS (ISO 8583 responder)
============================================================
Behaves like a Core Banking host for Switch -> CBS end-to-end testing.

What it does
  * Account & card master loaded from cbs_accounts.json (auto-created on first run):
    balances, minimum balance, status (ACTIVE / CLOSED / DORMANT / TOTAL_FREEZE /
    DEBIT_FREEZE / CREDIT_FREEZE), card status (ACTIVE / LOST / STOLEN / HOTLISTED),
    valid BINs, per-channel per-transaction limits and daily frequency limits.
  * Real debits / credits with DE 54 ledger + available balances and a DE 63
    mini-statement built from posted transactions.
  * Duplicate detection (same RRN) -> 94.
  * Reversals (0420 / 0421) matched by DE 90, falling back to RRN:
      full reversal, partial reversal (DE 95), duplicate 0420 -> 94,
      repeat 0421 -> 00 (idempotent), amount mismatch -> 13,
      reversal of a declined txn -> 21, no original -> 25.
  * Network management 0800 -> 0810 (001 sign-on, 002 sign-off, 101 key exchange,
    201 cut-over, 301 echo). DE 70 = 999 resets the mock state (test helper).
  * Format validation: malformed / truncated / trailing data / missing mandatory
    DEs -> 30, bad amount -> 13, unsupported processing code / currency -> 12.
  * Fault injection by amount (debits only, configurable):
      68.00 -> posts, then answers late (switch times out)
      91.00 -> posts, then drops the connection without answering
      96.00 -> answers RC 96 without posting
  * Credit vs debit for DE 3 = 00xxxx is decided by a configurable tag
    (default: DE 124 containing "CREDIT"); DE 3 = 20/21/26 is always credit.
  * One listener per channel (default 9019 = ATM, 9020 = UPI, 9021 = IMPS) so
    channel-specific limits apply.

Usage
  python iso8583_cbs_sim.py                     -> ports from cbs_accounts.json
  python iso8583_cbs_sim.py 9000                -> single port, channel auto-detected
  python iso8583_cbs_sim.py 9019:ATM 9020:UPI   -> explicit port:channel pairs
"""

import copy
import json
import os
import random
import socket
import sys
import threading
import time
from datetime import datetime

from iso_engine import (
    parse_iso_ex, format_iso, encode_iso_str, decode_iso_bytes,
    frame_bytes, extract_frame, expected_response_mti, describe_rc,
    n12_to_paise, rupees_to_paise, build_de54, paise_to_str,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "cbs_accounts.json")

DEFAULT_CBS_DATA = {
    "settings": {
        "ports": {"9019": "ATM", "9020": "UPI", "9021": "IMPS"},
        "currency": "356",
        "valid_bins": ["607293", "607607", "508557"],
        "direction_rule": {"de": 124, "credit_token": "CREDIT"},
        "credit_proc_prefixes": ["20", "21", "26"],
        "debit_proc_prefixes": ["00", "01", "40"],
        "network_codes": ["001", "002", "101", "201", "301"],
        "limits": {
            "ATM": {"per_txn": "25000.00", "daily_count": 1000},
            "POS": {"per_txn": "200000.00", "daily_count": 1000},
            "ECOM": {"per_txn": "200000.00", "daily_count": 1000},
            "UPI": {"per_txn": "100000.00", "daily_count": 1000},
            "IMPS": {"per_txn": "500000.00", "daily_count": 1000}
        },
        "faults": {
            "delay": {"68.00": 5},
            "drop": ["91.00"],
            "rc": {"96.00": "96"}
        }
    },
    "accounts": {
        "101303130001356": {"name": "ATM STANDARD SAVINGS", "status": "ACTIVE", "balance": "1000000.00", "min_balance": "0.00"},
        "0020001010000069": {"name": "UPI/IMPS STANDARD SAVINGS", "status": "ACTIVE", "balance": "10000000.00", "min_balance": "0.00"},
        "0020001010011800": {"name": "CLOSED ACCOUNT", "status": "CLOSED", "balance": "0.00", "min_balance": "0.00"},
        "0020001010011663": {"name": "TOTAL FREEZE", "status": "TOTAL_FREEZE", "balance": "50000.00", "min_balance": "0.00"},
        "0020001010011664": {"name": "DEBIT FREEZE", "status": "DEBIT_FREEZE", "balance": "50000.00", "min_balance": "0.00"},
        "0020001010011665": {"name": "CREDIT FREEZE", "status": "CREDIT_FREEZE", "balance": "50000.00", "min_balance": "0.00"},
        "0020001010011700": {"name": "DORMANT / INOPERATIVE", "status": "DORMANT", "balance": "50000.00", "min_balance": "0.00"},
        "0020001010010463": {"name": "MIN BALANCE 1000", "status": "ACTIVE", "balance": "1500.00", "min_balance": "1000.00"},
        "0020001010010999": {"name": "LOW FUNDS", "status": "ACTIVE", "balance": "100.00", "min_balance": "0.00"},
        "0020001010012000": {"name": "FREQUENCY LIMIT 3/DAY", "status": "ACTIVE", "balance": "100000.00", "min_balance": "0.00",
                             "limits": {"ATM": {"daily_count": 3}, "UPI": {"daily_count": 3}, "IMPS": {"daily_count": 3}}}
    },
    "cards": {
        "6072930130054479": {"account": "101303130001356", "status": "ACTIVE"},
        "6072930130011800": {"account": "0020001010011800", "status": "ACTIVE"},
        "6072930130011663": {"account": "0020001010011663", "status": "ACTIVE"},
        "6072930130011664": {"account": "0020001010011664", "status": "ACTIVE"},
        "6072930130011700": {"account": "0020001010011700", "status": "ACTIVE"},
        "6072930130010463": {"account": "0020001010010463", "status": "ACTIVE"},
        "6072930130010999": {"account": "0020001010010999", "status": "ACTIVE"},
        "6072930130012000": {"account": "0020001010012000", "status": "ACTIVE"},
        "6072930130099990": {"account": "101303130001356", "status": "ACTIVE"},
        "6072930130041000": {"account": "101303130001356", "status": "LOST"},
        "6072930130043000": {"account": "101303130001356", "status": "STOLEN"},
        "6072930130062000": {"account": "101303130001356", "status": "HOTLISTED"},
        "6072930130000000": {"account": "0020009999999999", "status": "ACTIVE"}
    }
}

MANDATORY_FIN = [2, 3, 7, 11, 37]

_print_lock = threading.Lock()


def log(msg):
    with _print_lock:
        print(f"[{datetime.now().strftime('%H:%M:%S.%f')[:-3]}] {msg}", flush=True)


class CBSState:
    """In-memory CBS ledger. All mutations happen under self.lock."""

    def __init__(self, path=DATA_PATH):
        self.path = path
        self.lock = threading.RLock()
        self.reset()

    # ---------------- data ----------------
    def _load_master(self):
        if not os.path.exists(self.path):
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_CBS_DATA, f, indent=2)
            log(f"[*] Created default account master: {self.path}")
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            log(f"[!] Could not read {self.path} ({e}); using built-in defaults")
            data = copy.deepcopy(DEFAULT_CBS_DATA)
        settings = copy.deepcopy(DEFAULT_CBS_DATA["settings"])
        settings.update(data.get("settings", {}))
        data["settings"] = settings
        data.setdefault("accounts", {})
        data.setdefault("cards", {})
        return data

    def reset(self):
        with self.lock:
            data = self._load_master()
            self.settings = data["settings"]
            self.cards = data["cards"]
            self.accounts = {}
            for acc_no, a in data["accounts"].items():
                bal = rupees_to_paise(a.get("balance", "0")) or 0
                self.accounts[acc_no] = {
                    "name": a.get("name", acc_no),
                    "status": str(a.get("status", "ACTIVE")).upper(),
                    "ledger": bal,
                    "available": bal,
                    "min_balance": rupees_to_paise(a.get("min_balance", "0")) or 0,
                    "limits": a.get("limits", {}),
                    "history": [],
                }
            self.txns = []            # all financial 0200 records
            self.by_rrn = {}          # rrn -> txn
            self.by_key90 = {}        # DE90[:31] -> txn
            self.rev_seen = set()     # DE 90 / RRN keys of processed 0420s
            self.counters = {}        # (account, channel, date) -> count

    # ---------------- helpers ----------------
    def limit_for(self, acct, channel, key):
        acc_lim = (acct.get("limits") or {}).get(channel, {})
        if key in acc_lim:
            return acc_lim[key]
        return (self.settings.get("limits", {}).get(channel) or {}).get(key)

    def count_key(self, acc_no, channel):
        return (acc_no, channel, datetime.now().strftime("%Y%m%d"))

    def de54(self, acct, sub_channel):
        acct_type = "20" if sub_channel == "ECOM" else "10"
        return build_de54(acct["ledger"], acct["available"], acct_type, self.settings.get("currency", "356"))

    def mini_statement(self, acct):
        lines = []
        for h in acct["history"][-10:][::-1]:
            lines.append(f"{h['date']} {h['dc']} {h['desc'][:10]:<10}{paise_to_str(h['amount']):>16}")
        bal = acct["available"]
        lines.append(f"{'Available Balance':<17}{paise_to_str(abs(bal)):>17}{'+' if bal >= 0 else '-'}")
        return "".join(lines)[:999]

    def post(self, acct, dc, amount, desc):
        sign = -1 if dc == "D" else 1
        acct["ledger"] += sign * amount
        acct["available"] += sign * amount
        acct["history"].append({"date": datetime.now().strftime("%d%m%y"), "dc": dc, "desc": desc, "amount": amount})


STATE = CBSState()


# ----------------------------------------------------------------------------
# Classification helpers
# ----------------------------------------------------------------------------
def sub_channel_of(f, port_channel):
    if port_channel in ("UPI", "IMPS"):
        return port_channel
    mcc = f.get(18)
    if mcc == "6011":
        return "ATM"
    if mcc:
        if f.get(25) == "59" or str(f.get(22, "")).startswith("81"):
            return "ECOM"
        return "POS"
    return port_channel or "UPI"


def classify(f, settings):
    """Return 'BAL', 'MINI', 'LIST', 'DR', 'CR' or None for unsupported."""
    proc = str(f.get(3, ""))
    if len(proc) != 6 or not proc.isdigit():
        return None
    p2 = proc[:2]
    if p2 == "31":
        return "BAL"
    if p2 == "38":
        return "MINI"
    if p2 == "41":
        return "LIST"
    if p2 in settings.get("credit_proc_prefixes", []):
        return "CR"
    if p2 in settings.get("debit_proc_prefixes", []):
        rule = settings.get("direction_rule") or {}
        de = rule.get("de")
        token = rule.get("credit_token")
        if de and token and token in str(f.get(int(de), "")):
            return "CR"
        return "DR"
    return None


def card_expired(f, card_rec):
    exp = None
    if f.get(14):
        exp = str(f[14])
    elif f.get(35) and "=" in str(f[35]):
        exp = str(f[35]).split("=", 1)[1][:4]
    elif card_rec and card_rec.get("expiry"):
        exp = str(card_rec["expiry"])
    if not exp or len(exp) != 4 or not exp.isdigit():
        return False
    return exp < datetime.now().strftime("%y%m")


def desc_for(kind, sub):
    if kind == "DR":
        return {"ATM": "To ATM", "POS": "POS Purch", "ECOM": "ECOM Purch", "UPI": "UPI DR", "IMPS": "IMPS DR"}.get(sub, "Debit")
    return {"UPI": "UPI CR", "IMPS": "IMPS CR"}.get(sub, "Credit")


# ----------------------------------------------------------------------------
# Core processing
# ----------------------------------------------------------------------------
def process_request(req_str, port_channel=None):
    """
    Returns (resp_iso or None, info, action) where action = {'delay': secs, 'drop': bool}
    """
    st = STATE
    parsed = parse_iso_ex(req_str)
    mti = parsed["mti"]
    f = parsed["fields"]
    info = {"req_mti": mti, "rrn": f.get(37, "-"), "proc": f.get(3, "-"), "error": parsed["error"], "note": ""}
    action = {"delay": 0, "drop": False}

    if not mti:
        return None, info, action

    resp_mti = expected_response_mti(mti)
    resp = dict(f)
    info["resp_mti"] = resp_mti

    def done(rc, note=""):
        resp[39] = rc
        info["rc"] = rc
        info["note"] = note
        return format_iso(resp_mti, resp), info, action

    # ---- format validation ----
    if not parsed["complete"]:
        return done("30", parsed["error"] or "malformed")
    if parsed["trailing"]:
        return done("30", f"{len(parsed['trailing'])} unexpected trailing chars")

    # ---- network management ----
    if mti in ("0800", "0820"):
        code = f.get(70)
        if not code:
            return done("30", "DE 70 missing")
        if code == "999":
            st.reset()
            return done("00", "MOCK STATE RESET")
        if code in st.settings.get("network_codes", []):
            return done("00", {"001": "sign-on", "002": "sign-off", "101": "key exchange",
                               "201": "cut-over", "301": "echo"}.get(code, ""))
        return done("12", f"unsupported network code {code}")

    if mti in ("0420", "0421", "0400"):
        return process_reversal(mti, f, resp, done, port_channel)

    if mti != "0200":
        return done("12", f"unsupported MTI {mti}")

    return process_financial(f, resp, done, action, port_channel)


def process_financial(f, resp, done, action, port_channel):
    st = STATE
    settings = st.settings
    sub = sub_channel_of(f, port_channel)
    if sub == "ATM":
        resp.pop(48, None)

    missing = [d for d in MANDATORY_FIN if not f.get(d)]
    if missing:
        return done("30", f"mandatory DE missing: {missing}")

    kind = classify(f, settings)
    if kind is None:
        return done("12", f"unsupported processing code {f.get(3)}")

    amount = None
    if kind in ("DR", "CR") or 4 in f:
        amount = n12_to_paise(f.get(4))
        if amount is None or len(str(f.get(4, ""))) != 12:
            return done("13", "amount not numeric n12")
    if kind in ("DR", "CR") and not amount:
        return done("13", "zero amount")

    if f.get(49) and f[49] != settings.get("currency", "356"):
        return done("12", f"currency {f[49]} not supported")

    with st.lock:
        rrn = f.get(37)
        if rrn in st.by_rrn:
            return done("94", "duplicate RRN")

        record = {"rrn": rrn, "stan": f.get(11), "de7": f.get(7), "acq": str(f.get(32, "0")).zfill(11)[-11:],
                  "amount": amount or 0, "kind": kind, "channel": sub, "account": None, "state": "DECLINED"}

        def decline(rc, note):
            st.by_rrn[rrn] = record
            st.by_key90[f"0200{record['stan']}{record['de7']}{record['acq']}"] = record
            st.txns.append(record)
            return done(rc, note)

        # ---- card checks ----
        pan = str(f.get(2, ""))
        card = st.cards.get(pan)
        card_based = bool(card) or 35 in f or 14 in f
        acc_no = str(f.get(102, "")).strip() or None
        if card_based:
            if pan[:6] not in settings.get("valid_bins", []):
                return decline("15", f"BIN {pan[:6]} not issued")
            if not card:
                return decline("14", "card not found")
            if card_expired(f, card):
                return decline("54", "expired card")
            cstat = str(card.get("status", "ACTIVE")).upper()
            if cstat == "LOST":
                return decline("41", "lost card")
            if cstat == "STOLEN":
                return decline("43", "stolen card")
            if cstat in ("HOTLISTED", "RESTRICTED", "BLOCKED"):
                return decline("62", "restricted card")
            if acc_no and acc_no != card["account"] and acc_no not in card.get("linked", []):
                return decline("57", "DE 102 not linked to card (tampering)")
            acc_no = acc_no or card["account"]

        if not acc_no:
            return decline("30", "no account (DE 102) to process")

        acct = st.accounts.get(acc_no)
        if not acct:
            return decline("14", f"account {acc_no} not found")
        record["account"] = acc_no

        status = acct["status"]
        if status == "CLOSED":
            return decline("52", "account closed")
        if kind == "DR" and status == "DORMANT":
            resp[54] = st.de54(acct, sub)
            return decline("57", "dormant account - debit not permitted")
        if (kind == "DR" and status in ("TOTAL_FREEZE", "DEBIT_FREEZE")) or \
           (kind == "CR" and status in ("TOTAL_FREEZE", "CREDIT_FREEZE")):
            resp[54] = st.de54(acct, sub)
            return decline("62", f"{status.lower()}")

        # ---- enquiries ----
        if kind in ("BAL", "MINI", "LIST"):
            st.by_rrn[rrn] = record
            record["state"] = "ENQUIRY"
            if kind in ("BAL", "MINI"):
                resp[54] = st.de54(acct, sub)
            if kind == "MINI":
                resp[63] = st.mini_statement(acct)
            return done("00", kind)

        # ---- limits ----
        per_txn = rupees_to_paise(st.limit_for(acct, sub, "per_txn") or "0")
        if per_txn and amount > per_txn:
            resp[54] = st.de54(acct, sub)
            return decline("61", f"exceeds {sub} per-txn limit {paise_to_str(per_txn)}")
        if kind == "DR":
            daily = st.limit_for(acct, sub, "daily_count")
            ck = st.count_key(acc_no, sub)
            if daily is not None and st.counters.get(ck, 0) >= int(daily):
                resp[54] = st.de54(acct, sub)
                return decline("65", f"exceeds {sub} daily count {daily}")
            if acct["available"] - amount < acct["min_balance"]:
                resp[54] = st.de54(acct, sub)
                return decline("51", "insufficient funds / min balance")

        # ---- faults (debits only) ----
        amt_str = paise_to_str(amount)
        faults = settings.get("faults", {})
        if kind == "DR" and amt_str in (faults.get("rc") or {}):
            return decline(faults["rc"][amt_str], "fault injection (rc)")

        # ---- post ----
        st.post(acct, "D" if kind == "DR" else "C", amount, desc_for(kind, sub))
        if kind == "DR":
            ck = st.count_key(acc_no, sub)
            st.counters[ck] = st.counters.get(ck, 0) + 1
        record["state"] = "POSTED"
        st.by_rrn[rrn] = record
        st.by_key90[f"0200{record['stan']}{record['de7']}{record['acq']}"] = record
        st.txns.append(record)
        resp[54] = st.de54(acct, sub)

        if kind == "DR":
            if amt_str in (faults.get("delay") or {}):
                action["delay"] = float(faults["delay"][amt_str])
            if amt_str in (faults.get("drop") or []):
                action["drop"] = True
        return done("00", f"{kind} {amt_str} posted")


def process_reversal(mti, f, resp, done, port_channel):
    st = STATE
    sub = sub_channel_of(f, port_channel)
    if sub == "ATM":
        resp.pop(48, None)
    if not f.get(37) and not f.get(90):
        return done("30", "reversal without DE 37 / DE 90")

    with st.lock:
        de90 = str(f.get(90, ""))
        txn = st.by_key90.get(de90[:31]) if len(de90) >= 31 else None
        if txn is None and f.get(37):
            txn = st.by_rrn.get(f[37])
            if txn is not None and txn.get("state") == "ENQUIRY":
                txn = None
        rev_key = de90[:31] or f.get(37)

        if txn is None:
            return done("25", "original not found")

        acct = st.accounts.get(txn.get("account") or "")
        if acct:
            resp[54] = st.de54(acct, sub)

        if txn["state"] == "DECLINED":
            return done("21", "original was declined - nothing to reverse")

        if txn["state"] in ("REVERSED", "PARTIAL_REVERSED"):
            if mti == "0421":
                return done("00", "repeat reversal acknowledged (no double credit)")
            return done("94", "duplicate reversal")

        req_amount = n12_to_paise(f.get(4))
        refund = txn["amount"]
        new_state = "REVERSED"
        if f.get(95):
            actual = n12_to_paise(str(f[95])[:12])
            if actual is None or actual >= txn["amount"]:
                return done("13", "invalid DE 95 replacement amount")
            refund = txn["amount"] - actual
            new_state = "PARTIAL_REVERSED"
        elif req_amount != txn["amount"]:
            return done("13", f"reversal amount {paise_to_str(req_amount)} != original {paise_to_str(txn['amount'])}")

        if not acct:
            return done("21", "account no longer available")

        st.post(acct, "C" if txn["kind"] == "DR" else "D", refund, "Reversal")
        txn["state"] = new_state
        st.rev_seen.add(rev_key)
        if txn["kind"] == "DR" and new_state == "REVERSED":
            ck = st.count_key(txn["account"], txn["channel"])
            st.counters[ck] = max(0, st.counters.get(ck, 0) - 1)
        resp[54] = st.de54(acct, sub)
        rc = "09" if txn["channel"] == "ECOM" else "00"
        return done(rc, f"{new_state.lower()} {paise_to_str(refund)}")


# ----------------------------------------------------------------------------
# Network layer
# ----------------------------------------------------------------------------
def handle_client(client, addr, port_channel):
    buf = b""
    try:
        client.settimeout(300)
        while True:
            data = client.recv(65536)
            if not data:
                break
            buf += data
            while buf:
                framing, msg, rest = extract_frame(buf)
                if framing is None:
                    break
                buf = rest
                req_str, meta = decode_iso_bytes(msg)
                try:
                    resp_str, info, action = process_request(req_str, port_channel)
                except Exception as e:
                    log(f"[!] {addr[0]} processing error: {type(e).__name__}: {e}")
                    continue
                if resp_str is None:
                    log(f"[!] {addr[0]} unreadable message ({len(msg)} bytes) - ignored")
                    continue

                rc = info.get("rc", "--")
                tag = f"[{port_channel or 'AUTO'}]"
                log(f"{tag} [>] {info['req_mti']} RRN={info['rrn']} DE3={info['proc']}  [<] {info.get('resp_mti')} "
                    f"DE39={rc} {describe_rc(rc)['label']} | {info.get('note', '')}")

                if action.get("drop"):
                    log(f"{tag} [x] FAULT: dropping connection without response")
                    return
                if action.get("delay"):
                    log(f"{tag} [~] FAULT: delaying response {action['delay']}s")
                    time.sleep(action["delay"])

                wire = meta["prefix"] + encode_iso_str(resp_str, meta["bitmap_fmt"], meta["charset"])
                try:
                    client.sendall(frame_bytes(wire, framing))
                except OSError:
                    log(f"{tag} [-] peer gone before response could be sent")
                    return
    except socket.timeout:
        pass
    except (ConnectionResetError, BrokenPipeError):
        pass
    except Exception as e:
        log(f"[!] {addr[0]}:{addr[1]} error: {e}")
    finally:
        try:
            client.close()
        except OSError:
            pass


def serve(port, channel, host="0.0.0.0"):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(50)
    log(f"[*] CBS SIMULATOR READY on {host}:{port} (channel: {channel or 'AUTO'})")
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr, channel), daemon=True).start()


def parse_args(argv):
    pairs = []
    for a in argv:
        if ":" in a:
            p, ch = a.split(":", 1)
            pairs.append((int(p), ch.strip().upper() or None))
        else:
            pairs.append((int(a), None))
    if not pairs:
        pairs = [(int(p), ch) for p, ch in STATE.settings.get("ports", {}).items()]
    return pairs


def main():
    pairs = parse_args(sys.argv[1:])
    log(f"[*] Accounts: {len(STATE.accounts)} | Cards: {len(STATE.cards)} | Master: {STATE.path}")
    threads = []
    for port, ch in pairs:
        t = threading.Thread(target=serve, args=(port, ch), daemon=True)
        t.start()
        threads.append(t)
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(0.5)
    except KeyboardInterrupt:
        log("[*] Shutting down")


if __name__ == "__main__":
    main()
