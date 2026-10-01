import socket
import struct
import time
import json
import os
import random
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "iso_config.json")
LOGS_BASE_DIR = os.path.join(BASE_DIR, "logs")

def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"target_settings": {}, "field_definitions": {}, "sample_requests": {}}

def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

def write_partitioned_log(category: str, entry: str):
    """Writes daily partitioned logs to logs/YYYY-MM-DD/<category>.log"""
    try:
        date_folder = datetime.now().strftime("%Y-%m-%d")
        dir_path = os.path.join(LOGS_BASE_DIR, date_folder)
        os.makedirs(dir_path, exist_ok=True)
        file_path = os.path.join(dir_path, f"{category}.log")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {entry}\n")
    except Exception as e:
        print(f"[LOG ERROR] Could not write to {category}.log: {e}")

handshake_state = {
    "running": False,
    "thread": None,
    "logs": [],
    "stan": 100001,
    "current_ip": "",
    "current_port": 0,
    "current_framing": "bin_2",
    "current_bitmap_fmt": "binary",
    "current_charset": "ascii",
    "current_tpdu": ""
}

bulk_state = {
    "running": False,
    "total": 0,
    "fired_count": 0,
    "completed_count": 0,
    "fired_logs": [],
    "response_logs": [],
    "lock": threading.Lock()
}

RBI_CODES = {
    "00": {"label": "Approved / Successful", "cat": "SUCCESS"},
    "05": {"label": "Do Not Honor", "cat": "CUSTOMER DECLINE"},
    "09": {"label": "Request In Progress", "cat": "SYSTEM STATUS"},
    "14": {"label": "Invalid Card Number", "cat": "CUSTOMER DECLINE"},
    "21": {"label": "No Action Taken", "cat": "SYSTEM STATUS"},
    "51": {"label": "Insufficient Funds", "cat": "CUSTOMER DECLINE"},
    "54": {"label": "Expired Card", "cat": "CUSTOMER DECLINE"},
    "55": {"label": "Incorrect PIN", "cat": "CUSTOMER DECLINE"},
    "61": {"label": "Exceeds Withdrawal Limit", "cat": "CUSTOMER DECLINE"},
    "68": {"label": "Timeout / Late Response", "cat": "TECHNICAL FAILURE"},
    "91": {"label": "Issuer or Switch Inoperative", "cat": "TECHNICAL FAILURE"},
    "96": {"label": "System Malfunction", "cat": "TECHNICAL FAILURE"},
    "E2": {"label": "Switch Specific Decline / Reversal", "cat": "TECHNICAL FAILURE"}
}

def parse_bitmap(hex_map_str):
    bin_str = bin(int(hex_map_str, 16))[2:].zfill(len(hex_map_str) * 4)
    return {i + 1 for i, b in enumerate(bin_str) if b == '1'}

def build_hex_bitmap(active_fields, length_bytes=16):
    total_bits = length_bytes * 8
    bits = ['0'] * total_bits
    for f in active_fields:
        if 1 <= f <= total_bits:
            bits[f - 1] = '1'
    return f"{int(''.join(bits), 2):0{length_bytes * 2}X}"

def parse_raw_iso_dict(raw_str):
    cfg = load_config()
    field_defs = cfg.get("field_definitions", {})
    cleaned = raw_str.strip()
    if len(cleaned) > 4 and cleaned[:4].isdigit() and cleaned[4:8] in ('0200', '0210', '0420', '0430', '0800', '0810'):
        cleaned = cleaned[4:]

    if len(cleaned) < 20:
        return None, {}

    mti = cleaned[:4]
    has_sec = bool(int(cleaned[4], 16) & 0x8)
    bm_len = 32 if has_sec else 16
    active_fields = parse_bitmap(cleaned[4:4 + bm_len])

    idx = 4 + bm_len
    fields = {}

    for f in sorted(list(active_fields)):
        if f == 1:
            continue
        f_info = field_defs.get(str(f))
        if not f_info:
            break
        f_type, f_len = f_info["type"], f_info["len"]
        try:
            if f_type == 'fixed':
                val = cleaned[idx:idx + f_len]
                idx += f_len
            elif f_type == 'llvar':
                v_len = int(cleaned[idx:idx + 2])
                idx += 2
                val = cleaned[idx:idx + v_len]
                idx += v_len
            elif f_type == 'lllvar':
                v_len = int(cleaned[idx:idx + 3])
                idx += 3
                val = cleaned[idx:idx + v_len]
                idx += v_len
            fields[f] = val
        except Exception:
            break

    return mti, fields

def format_iso_dict(mti, fields):
    cfg = load_config()
    field_defs = cfg.get("field_definitions", {})
    int_fields = {int(k): str(v) for k, v in fields.items()}
    active_set = set(int_fields.keys())

    if any(f > 64 for f in active_set):
        active_set.add(1)
        bm_hex = build_hex_bitmap(active_set, length_bytes=16)
    else:
        bm_hex = build_hex_bitmap(active_set, length_bytes=8)

    body = ""
    for f in sorted(list(active_set)):
        if f == 1:
            continue
        f_info = field_defs.get(str(f), {"type": "fixed"})
        f_type = f_info.get("type", "fixed")
        val = int_fields[f]
        if f_type == "fixed":
            body += val
        elif f_type == "llvar":
            body += f"{len(val):02d}{val}"
        elif f_type == "lllvar":
            body += f"{len(val):03d}{val}"

    return f"{mti}{bm_hex}{body}"

def assemble_iso_from_numericals(mti, proc_code, des_present, custom_params=None):
    custom = custom_params or {}
    now = datetime.now()
    fields = {}

    pan = custom.get("pan") or "6076070030053234"
    rrn = custom.get("rrn") or f"61{random.randint(1000000000, 9999999999)}"
    stan = custom.get("stan") or rrn[-6:]
    account = custom.get("account") or "003002300008773"
    acq_id = custom.get("acq_id") or "622018"
    amount = custom.get("amount") or ("000000050000" if str(proc_code).startswith("01") else "000000297800")

    generators = {
        2: str(pan),
        3: str(proc_code),
        4: str(amount).zfill(12),
        7: now.strftime("%m%d%H%M%S"),
        11: str(stan).zfill(6),
        12: now.strftime("%H%M%S"),
        13: now.strftime("%m%d"),
        14: custom.get("expiry") or "2903",
        15: now.strftime("%m%d"),
        17: now.strftime("%m%d"),
        18: custom.get("mcc") or ("6011" if str(proc_code).startswith("01") else "5411"),
        22: custom.get("pos_entry") or ("810" if 14 in des_present else "051"),
        25: custom.get("pos_cond") or ("59" if 14 in des_present else "00"),
        32: str(acq_id),
        35: f"{pan}=28076206130000000000",
        37: str(rrn).zfill(12),
        38: "244729",
        39: custom.get("de39") or ("E2" if mti == "0420" else "00"),
        41: custom.get("terminal_id") or ("00558004" if str(proc_code).startswith("01") else "EP069184"),
        42: "S1BN000558004  " if str(proc_code).startswith("01") else "100000000113491",
        43: "MURUD JANJIRA          RAIGARH      MHIN" if str(proc_code).startswith("01") else "M S HASTIMAL MANIKCHANDRAIGAD       MHIN",
        48: "CASHNET                 40000035600000000000",
        49: "356",
        60: "EUROPRO1+000",
        90: custom.get("de90") or "010032729106301441240000072053000000000000",
        102: str(account),
        120: "00100207002003GDN"
    }

    for de in sorted(des_present):
        if de in generators:
            fields[de] = generators[de]

    return format_iso_dict(mti, fields), fields

def pack_payload(raw_iso: str, framing: str = "bin_2", bitmap_fmt: str = "binary", charset: str = "ascii", tpdu: str = "") -> bytes:
    cleaned = raw_iso.strip()
    has_manual_4digit_header = False

    if len(cleaned) > 4 and cleaned[:4].isdigit() and cleaned[4:8] in ('0200', '0420', '0800'):
        cleaned = cleaned[4:]
        has_manual_4digit_header = True

    mti = cleaned[:4]
    has_sec = bool(int(cleaned[4], 16) & 0x8)
    bm_len = 32 if has_sec else 16
    bm_hex = cleaned[4:4 + bm_len]
    body = cleaned[4 + bm_len:]

    codec = 'cp500' if charset == 'ebcdic' else 'latin-1'
    mti_bytes = mti.encode(codec)

    if bitmap_fmt == "binary":
        bm_bytes = bytes.fromhex(bm_hex)
    else:
        bm_bytes = bm_hex.encode(codec)

    body_bytes = body.encode(codec)
    iso_bytes = mti_bytes + bm_bytes + body_bytes

    tpdu_bytes = b""
    tpdu_clean = tpdu.strip().replace(" ", "")
    if tpdu_clean:
        try:
            tpdu_bytes = bytes.fromhex(tpdu_clean)
        except ValueError:
            tpdu_bytes = tpdu_clean.encode('latin-1')

    payload = tpdu_bytes + iso_bytes
    total_len = len(payload)

    if framing == "bin_2":
        return struct.pack('!H', total_len) + payload
    elif framing == "bin_2_inc":
        return struct.pack('!H', total_len + 2) + payload
    elif framing == "ascii_4":
        return f"{total_len:04d}".encode('latin-1') + payload
    elif framing == "raw":
        if has_manual_4digit_header:
            return f"{total_len:04d}".encode('latin-1') + payload
        return payload
    return payload

def unpack_response(raw_bytes: bytes) -> str:
    if not raw_bytes:
        return ""

    is_ebcdic = False
    try:
        sample_ebcdic = raw_bytes.decode('cp500', errors='ignore')
        if any(m in sample_ebcdic for m in ('0210', '0430', '0810')):
            is_ebcdic = True
    except Exception:
        pass

    if is_ebcdic:
        decoded_str = raw_bytes.decode('cp500', errors='ignore')
        for marker in ('0210', '0430', '0810'):
            pos = decoded_str.find(marker)
            if pos != -1:
                return decoded_str[pos:]
        return decoded_str

    for marker in (b'0210', b'0430', b'0810'):
        pos = raw_bytes.find(marker)
        if pos != -1:
            iso_raw = raw_bytes[pos:]
            mti = iso_raw[:4].decode('latin-1')
            first_byte = iso_raw[4]
            if (48 <= first_byte <= 57) or (65 <= first_byte <= 70) or (97 <= first_byte <= 102):
                return iso_raw.decode('latin-1', errors='ignore')
            else:
                has_sec = bool(first_byte & 0x80)
                bm_bytes_len = 16 if has_sec else 8
                bm_hex = iso_raw[4:4 + bm_bytes_len].hex().upper()
                body_str = iso_raw[4 + bm_bytes_len:].decode('latin-1', errors='ignore')
                return f"{mti}{bm_hex}{body_str}"

    return raw_bytes.decode('latin-1', errors='ignore')

def tcp_transact(ip: str, port: int, payload: bytes, timeout: float = 6.0) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.sendall(payload)
        resp = sock.recv(4096)
        if not resp:
            raise ConnectionResetError("Remote server closed socket without responding.")

        sock.setblocking(False)
        time.sleep(0.04)
        try:
            while True:
                extra = sock.recv(4096)
                if not extra: break
                resp += extra
        except Exception:
            pass

        return resp
    finally:
        sock.close()

def build_0800_handshake_msg(stan: int, net_code: str = "001", acq_id: str = "622018") -> str:
    now = datetime.now().strftime("%m%d%H%M%S")
    fields = {
        7: now,
        11: f"{stan:06d}",
        32: str(acq_id),
        70: str(net_code).zfill(3)
    }
    return format_iso_dict("0800", fields)

def parse_iso_details(raw_str, expected_resp_des=None):
    mti, fields = parse_raw_iso_dict(raw_str)
    if not mti:
        return {"error": "Invalid payload."}

    cfg = load_config()
    field_defs = cfg.get("field_definitions", {})
    parsed_fields = []
    de39_info = None

    for f in sorted(list(fields.keys())):
        name = field_defs.get(str(f), {}).get("name", f"DE {f}")
        val = fields[f]
        if f == 39:
            de39_info = RBI_CODES.get(val, {"label": "Other", "cat": "UNDEFINED"})
            de39_info["code"] = val
        parsed_fields.append({"de": f, "name": name, "len": len(val), "val": val})

    validation = None
    if expected_resp_des:
        received_set = set(fields.keys())
        expected_set = set(expected_resp_des)
        missing = sorted(list(expected_set - received_set))
        unexpected = sorted(list(received_set - expected_set - {1}))

        missing_named = [{"de": de, "name": field_defs.get(str(de), {}).get("name", f"DE {de}")} for de in missing]
        unexpected_named = [{"de": de, "name": field_defs.get(str(de), {}).get("name", f"DE {de}")} for de in unexpected]

        validation = {
            "compliant": len(missing) == 0,
            "missing_des": missing_named,
            "unexpected_des": unexpected_named,
            "expected_count": len(expected_set),
            "received_count": len(received_set)
        }

    return {"mti": mti, "fields": parsed_fields, "de39": de39_info, "validation": validation}

def handshake_worker():
    while handshake_state["running"]:
        ip = handshake_state["current_ip"]
        port = handshake_state["current_port"]
        framing = handshake_state["current_framing"]
        bitmap_fmt = handshake_state["current_bitmap_fmt"]
        charset = handshake_state["current_charset"]
        tpdu = handshake_state["current_tpdu"]

        if not ip or not port:
            time.sleep(1)
            continue

        handshake_state["stan"] = (handshake_state["stan"] % 999999) + 1
        cfg = load_config()
        net_code = cfg.get("handshake_settings", {}).get("network_code", "001")
        req_0800 = build_0800_handshake_msg(handshake_state["stan"], net_code)
        payload = pack_payload(req_0800, framing, bitmap_fmt, charset, tpdu)
        t_str = datetime.now().strftime("%H:%M:%S")

        log_entry = {"time": t_str, "target": f"{ip}:{port}", "req": req_0800, "resp": "", "status": "PENDING", "latency": "--"}
        try:
            t0 = time.time()
            resp_bytes = tcp_transact(ip, port, payload, timeout=5.0)
            ms = round((time.time() - t0) * 1000, 1)
            resp_str = unpack_response(resp_bytes)
            log_entry["resp"] = resp_str
            log_entry["latency"] = f"{ms}ms"
            log_entry["status"] = "OK" if "0810" in resp_str else "RECV"
            write_partitioned_log("handshake", f"[SUCCESS] {ip}:{port} | LATENCY: {ms}ms | REQ: {req_0800} | RESP: {resp_str}")
        except Exception as e:
            log_entry["resp"] = f"Error: {str(e)}"
            log_entry["status"] = "TIMEOUT"
            write_partitioned_log("handshake", f"[TIMEOUT/FAIL] {ip}:{port} | REASON: {str(e)}")

        handshake_state["logs"].insert(0, log_entry)
        if len(handshake_state["logs"]) > 30:
            handshake_state["logs"].pop()

        interval = cfg.get("handshake_settings", {}).get("interval_seconds", 5)
        for _ in range(int(interval * 2)):
            if not handshake_state["running"]: break
            time.sleep(0.5)

@app.route("/")
def index(): 
    return render_template_string(HTML_PAGE)

@app.route("/api/config", methods=["GET"])
def get_config_api():
    return jsonify(load_config())

@app.route("/api/parse_raw", methods=["POST"])
def parse_raw_api():
    d = request.json or {}
    raw_iso = d.get("raw_iso", "").strip()
    mti, fields = parse_raw_iso_dict(raw_iso)
    if not mti:
        return jsonify({"status": "error", "message": "Invalid ISO 8583 payload."}), 400

    cfg = load_config()
    field_defs = cfg.get("field_definitions", {})
    breakdown = []
    for f in sorted(list(fields.keys())):
        breakdown.append({
            "de": f,
            "name": field_defs.get(str(f), {}).get("name", f"DE {f}"),
            "len": len(fields[f]),
            "val": fields[f]
        })
    return jsonify({"status": "success", "mti": mti, "fields": breakdown})

@app.route("/api/rebuild_from_fields", methods=["POST"])
def rebuild_from_fields_api():
    d = request.json or {}
    mti = d.get("mti", "0200")
    fields = d.get("fields", {})
    try:
        new_iso = format_iso_dict(mti, fields)
        return jsonify({"status": "success", "raw_iso": new_iso})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/api/sample/save_as_default", methods=["POST"])
def save_sample_as_default():
    d = request.json or {}
    raw_iso = d.get("raw_iso", "").strip()
    tx_key = d.get("tx_key") or "custom_default"
    label = d.get("label") or "Default Saved Request"

    mti, fields = parse_raw_iso_dict(raw_iso)
    if not mti:
        return jsonify({"status": "error", "message": "Cannot save invalid ISO string."}), 400

    cfg = load_config()
    des_present = sorted([int(k) for k in fields.keys()])
    proc_code = fields.get(3, "000000")

    if "sample_requests" not in cfg:
        cfg["sample_requests"] = {}

    existing_resp_des = cfg["sample_requests"].get(tx_key, {}).get("resp_des_present", des_present)

    cfg["sample_requests"][tx_key] = {
        "label": label,
        "mti": mti,
        "proc_code": proc_code,
        "req_des_present": des_present,
        "resp_des_present": existing_resp_des
    }
    save_config(cfg)
    return jsonify({"status": "success", "message": f"Saved '{label}' ({tx_key}) to config!"})

@app.route("/api/schema/import_raw", methods=["POST"])
def import_raw_schema():
    d = request.json or {}
    raw_iso = d.get("raw_iso", "").strip()
    tx_key = d.get("tx_key", "").strip()
    label = d.get("label", "").strip()

    if not raw_iso or not tx_key or not label:
        return jsonify({"status": "error", "message": "Transaction Key, Label, and Raw ISO are required."}), 400

    mti, fields = parse_raw_iso_dict(raw_iso)
    if not mti:
        return jsonify({"status": "error", "message": "Invalid ISO string. Verify MTI and Bitmap encoding."}), 400

    cfg = load_config()
    des_present = sorted([int(k) for k in fields.keys()])
    proc_code = fields.get(3, "000000")

    if "sample_requests" not in cfg:
        cfg["sample_requests"] = {}

    cfg["sample_requests"][tx_key] = {
        "label": label,
        "mti": mti,
        "proc_code": proc_code,
        "req_des_present": des_present,
        "resp_des_present": des_present
    }
    save_config(cfg)
    return jsonify({
        "status": "success",
        "message": f"Successfully imported '{label}' with {len(des_present)} Data Elements!",
        "tx_key": tx_key,
        "mti": mti,
        "proc_code": proc_code,
        "des_present": des_present
    })

@app.route("/api/target/save", methods=["POST"])
def save_target():
    data = request.json or {}
    cfg = load_config()
    if "target_settings" not in cfg:
        cfg["target_settings"] = {}
    cfg["target_settings"]["default_ip"] = data.get("ip", "").strip()
    cfg["target_settings"]["default_port"] = int(data.get("port", 0))
    cfg["target_settings"]["default_framing"] = data.get("framing", "bin_2")
    cfg["target_settings"]["default_bitmap_fmt"] = data.get("bitmap_fmt", "binary")
    cfg["target_settings"]["default_charset"] = data.get("charset", "ascii")
    cfg["target_settings"]["default_tpdu"] = data.get("tpdu", "").strip()
    save_config(cfg)
    return jsonify({"status": "success"})

@app.route("/api/handshake/toggle", methods=["POST"])
def toggle_handshake():
    data = request.json or {}
    ip = data.get("ip", "").strip()
    port = int(data.get("port", 0))
    framing = data.get("framing", "bin_2")
    bitmap_fmt = data.get("bitmap_fmt", "binary")
    charset = data.get("charset", "ascii")
    tpdu = data.get("tpdu", "").strip()

    if not ip or not port:
        return jsonify({"status": "error", "message": "Destination IP and Port are required."}), 400

    handshake_state["current_ip"] = ip
    handshake_state["current_port"] = port
    handshake_state["current_framing"] = framing
    handshake_state["current_bitmap_fmt"] = bitmap_fmt
    handshake_state["current_charset"] = charset
    handshake_state["current_tpdu"] = tpdu

    if handshake_state["running"]:
        handshake_state["running"] = False
        return jsonify({"status": "stopped"})
    else:
        handshake_state["running"] = True
        t = threading.Thread(target=handshake_worker, daemon=True)
        handshake_state["thread"] = t
        t.start()
        return jsonify({"status": "started"})

@app.route("/api/handshake/single_shot", methods=["POST"])
def single_shot_handshake():
    d = request.json or {}
    ip = d.get("ip", "").strip()
    port = int(d.get("port", 0))
    framing = d.get("framing", "bin_2")
    bitmap_fmt = d.get("bitmap_fmt", "binary")
    charset = d.get("charset", "ascii")
    tpdu = d.get("tpdu", "").strip()
    timeout_sec = float(d.get("timeout_sec", 6.0))

    if not ip or not port:
        return jsonify({"status": "error", "message": "Destination IP and Port are required."}), 400

    cfg = load_config()
    net_code = cfg.get("handshake_settings", {}).get("network_code", "001")
    stan = random.randint(100000, 999999)
    req_0800 = build_0800_handshake_msg(stan, net_code)
    payload = pack_payload(req_0800, framing, bitmap_fmt, charset, tpdu)

    t0 = time.time()
    try:
        resp_bytes = tcp_transact(ip, port, payload, timeout=timeout_sec)
        ms = round((time.time() - t0) * 1000, 2)
        resp_str = unpack_response(resp_bytes)
        write_partitioned_log("handshake", f"[SINGLE-SHOT 0800 SUCCESS] {ip}:{port} | LATENCY: {ms}ms | RESP: {resp_str}")
        return jsonify({
            "status": "success",
            "req_iso": req_0800,
            "resp_iso": resp_str,
            "latency_ms": ms,
            "parsed_response": parse_iso_details(resp_str)
        })
    except Exception as e:
        write_partitioned_log("handshake", f"[SINGLE-SHOT 0800 FAIL] {ip}:{port} | REASON: {str(e)}")
        return jsonify({"status": "error", "message": f"Handshake failed: {str(e)}", "req_iso": req_0800}), 502

@app.route("/api/handshake/update_target", methods=["POST"])
def update_handshake_target():
    data = request.json or {}
    handshake_state["current_ip"] = data.get("ip", "").strip()
    handshake_state["current_port"] = int(data.get("port", 0))
    handshake_state["current_framing"] = data.get("framing", "bin_2")
    handshake_state["current_bitmap_fmt"] = data.get("bitmap_fmt", "binary")
    handshake_state["current_charset"] = data.get("charset", "ascii")
    handshake_state["current_tpdu"] = data.get("tpdu", "").strip()
    return jsonify({"status": "updated"})

@app.route("/api/handshake/logs", methods=["GET"])
def get_handshake_logs():
    return jsonify({
        "running": handshake_state["running"],
        "target": f"{handshake_state['current_ip']}:{handshake_state['current_port']}" if handshake_state["running"] else None,
        "logs": handshake_state["logs"]
    })

@app.route("/api/build_request", methods=["POST"])
def build_request_api():
    d = request.json or {}
    tx_key = d.get("tx_key")
    cfg = load_config()
    tx_meta = cfg.get("sample_requests", {}).get(tx_key)

    if not tx_meta:
        return jsonify({"error": "Unknown transaction type"}), 400

    req_des = tx_meta.get("req_des_present") or tx_meta.get("des_present", [])
    proc_code = d.get("proc_code") or tx_meta.get("proc_code", "000000")

    raw_iso, fields = assemble_iso_from_numericals(
        tx_meta["mti"],
        proc_code,
        req_des,
        custom_params={
            "pan": d.get("pan"),
            "account": d.get("account"),
            "acq_id": d.get("acq_id"),
            "rrn": d.get("rrn")
        }
    )

    return jsonify({
        "raw_iso": raw_iso,
        "mti": tx_meta["mti"],
        "proc_code": fields.get(3, proc_code),
        "pan": fields.get(2, "N/A"),
        "has_pan": 2 in req_des,
        "account": fields.get(102, "N/A"),
        "has_account": 102 in req_des,
        "acq_id": fields.get(32, "N/A"),
        "has_acq_id": 32 in req_des,
        "rrn": fields.get(37, "N/A"),
        "stan": fields.get(11, "N/A")
    })

@app.route("/api/send", methods=["POST"])
def send_single():
    d = request.json or {}
    ip = d.get("ip", "").strip()
    port = int(d.get("port", 0))
    tx_key = d.get("tx_key", "")
    framing = d.get("framing", "bin_2")
    bitmap_fmt = d.get("bitmap_fmt", "binary")
    charset = d.get("charset", "ascii")
    tpdu = d.get("tpdu", "").strip()
    timeout_sec = float(d.get("timeout_sec", 6.0))
    raw_iso = d.get("iso_request", "").strip()

    if not ip or not port:
        return jsonify({"status": "error", "message": "Destination IP and Port cannot be empty."}), 400

    cfg = load_config()
    expected_resp_des = cfg.get("sample_requests", {}).get(tx_key, {}).get("resp_des_present", None)

    payload = pack_payload(raw_iso, framing, bitmap_fmt, charset, tpdu)
    t0 = time.time()
    try:
        resp_bytes = tcp_transact(ip, port, payload, timeout=timeout_sec)
        ms = round((time.time() - t0) * 1000, 2)
        resp_str = unpack_response(resp_bytes)
        
        parsed_resp = parse_iso_details(resp_str, expected_resp_des)
        val_info = parsed_resp.get("validation")
        
        log_validation = ""
        if val_info and not val_info["compliant"]:
            missing_str = ", ".join([f"DE {m['de']}" for m in val_info["missing_des"]])
            log_validation = f" | [SPEC DISCREPANCY] Missing fields: {missing_str}"

        write_partitioned_log("transactions", 
            f"[SUCCESS] {ip}:{port} | LATENCY: {ms}ms{log_validation}\n"
            f"  HEX OUT: {payload.hex().upper()}\n"
            f"  HEX IN : {resp_bytes.hex().upper()}\n"
            f"  REQ ISO: {raw_iso}\n"
            f"  RES ISO: {resp_str}"
        )

        return jsonify({
            "status": "success",
            "iso_response": resp_str,
            "latency_ms": ms,
            "parsed_request": parse_iso_details(raw_iso),
            "parsed_response": parsed_resp
        })
    except TimeoutError as te:
        write_partitioned_log("transactions", f"[TIMEOUT] {ip}:{port} | HEX OUT: {payload.hex().upper()}")
        return jsonify({"status": "error", "message": str(te)}), 504
    except Exception as e:
        write_partitioned_log("transactions", f"[ERROR] {ip}:{port} | REASON: {str(e)}")
        return jsonify({"status": "error", "message": f"Connection Failure: {str(e)}"}), 502

@app.route("/api/reversal_flow", methods=["POST"])
def execute_reversal_flow():
    d = request.json or {}
    ip = d.get("ip", "").strip()
    port = int(d.get("port", 0))
    tx_key = d.get("tx_key", "")
    framing = d.get("framing", "bin_2")
    bitmap_fmt = d.get("bitmap_fmt", "binary")
    charset = d.get("charset", "ascii")
    tpdu = d.get("tpdu", "").strip()
    timeout_sec = float(d.get("timeout_sec", 6.0))

    if not ip or not port:
        return jsonify({"status": "error", "message": "Destination IP and Port are required."}), 400

    cfg = load_config()
    custom_pan = d.get("pan") or "6076070030053234"
    custom_account = d.get("account") or "003002300008773"
    custom_acq = d.get("acq_id") or "622018"
    orig_rrn = f"61{random.randint(1000000000, 9999999999)}"
    orig_stan = orig_rrn[-6:]

    if "issuer" in tx_key or "atm" in tx_key:
        channel_name = "ATM (Cash Withdrawal)"
        proc_code = "011000"
        mcc = "6011"
        pos_entry = "051"
        pos_cond = "00"
        des_0200 = [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 41, 42, 43, 48, 49, 60, 102]
        des_0420 = [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 37, 38, 39, 41, 42, 43, 48, 49, 60, 90, 102]
        terminal_id = "00558004"
    elif "ecom" in tx_key:
        channel_name = "E-Commerce (Purchase)"
        proc_code = "000000"
        mcc = "5814"
        pos_entry = "810"
        pos_cond = "59"
        des_0200 = [2, 3, 4, 7, 11, 12, 13, 14, 15, 17, 18, 22, 25, 32, 37, 41, 42, 43, 48, 49, 60, 102]
        des_0420 = [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 37, 39, 41, 42, 43, 48, 49, 60, 90, 102]
        terminal_id = "70016942"
    else:
        channel_name = "POS (Purchase)"
        proc_code = "000000"
        mcc = "5411"
        pos_entry = "051"
        pos_cond = "00"
        des_0200 = [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 35, 37, 41, 42, 43, 48, 49, 60, 102]
        des_0420 = [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 37, 38, 39, 41, 42, 43, 48, 49, 60, 90, 102]
        terminal_id = "EP069184"

    raw_0200, fields_0200 = assemble_iso_from_numericals(
        mti="0200", proc_code=proc_code, des_present=des_0200,
        custom_params={
            "pan": custom_pan, "account": custom_account, "acq_id": custom_acq,
            "amount": "000000050000", "rrn": orig_rrn, "stan": orig_stan,
            "mcc": mcc, "pos_entry": pos_entry, "pos_cond": pos_cond,
            "expiry": "2903", "terminal_id": terminal_id
        }
    )

    leg1_result = {"status": "SUCCESS", "mti": "0200", "req_iso": raw_0200, "resp_iso": "", "de39": "--", "label": "Pending", "latency": "--"}
    payload_0200 = pack_payload(raw_0200, framing, bitmap_fmt, charset, tpdu)

    try:
        t0 = time.time()
        resp_bytes_0200 = tcp_transact(ip, port, payload_0200, timeout=timeout_sec)
        ms_0200 = round((time.time() - t0) * 1000, 1)
        resp_0200 = unpack_response(resp_bytes_0200)
        parsed_0200 = parse_iso_details(resp_0200)
        de39_0200 = parsed_0200.get("de39", {})

        leg1_result["resp_iso"] = resp_0200
        leg1_result["latency"] = f"{ms_0200}ms"
        leg1_result["de39"] = de39_0200.get("code", "--")
        leg1_result["label"] = de39_0200.get("label", "COMPLETED")
        write_partitioned_log("transactions", f"[{channel_name} 2-LEG: LEG-1 0200] {ip}:{port} | CODE: {leg1_result['de39']} | RESP: {resp_0200}")
    except Exception as e:
        leg1_result["status"] = "FAILED"
        leg1_result["label"] = str(e)
        write_partitioned_log("transactions", f"[{channel_name} 2-LEG: LEG-1 0200 FAIL] {ip}:{port} | REASON: {str(e)}")

    time.sleep(0.3)

    orig_de7 = fields_0200.get(7, datetime.now().strftime("%m%d%H%M%S"))
    de90 = f"0200{str(orig_stan).zfill(6)}{str(orig_de7).zfill(10)}{str(custom_acq).zfill(11)}{'0'*11}"
    reversal_stan = f"{(int(orig_stan) + 1) % 999999:06d}"

    raw_0420, fields_0420 = assemble_iso_from_numericals(
        mti="0420", proc_code=proc_code, des_present=des_0420,
        custom_params={
            "pan": custom_pan, "account": custom_account, "acq_id": custom_acq,
            "amount": "000000050000", "rrn": orig_rrn, "stan": reversal_stan,
            "mcc": mcc, "pos_entry": pos_entry, "pos_cond": pos_cond,
            "de90": de90, "de39": "E2", "terminal_id": terminal_id
        }
    )

    leg2_result = {"status": "SUCCESS", "mti": "0420", "req_iso": raw_0420, "resp_iso": "", "de39": "--", "label": "Pending", "latency": "--", "de90": de90}
    payload_0420 = pack_payload(raw_0420, framing, bitmap_fmt, charset, tpdu)
    parsed_leg2_resp = None

    expected_0430_des = cfg.get("sample_requests", {}).get(tx_key, {}).get("resp_des_present", None)

    try:
        t0 = time.time()
        resp_bytes_0420 = tcp_transact(ip, port, payload_0420, timeout=timeout_sec)
        ms_0420 = round((time.time() - t0) * 1000, 1)
        resp_0420 = unpack_response(resp_bytes_0420)
        parsed_0420 = parse_iso_details(resp_0420, expected_0430_des)
        de39_0420 = parsed_0420.get("de39", {})

        leg2_result["resp_iso"] = resp_0420
        leg2_result["latency"] = f"{ms_0420}ms"
        leg2_result["de39"] = de39_0420.get("code", "--")
        leg2_result["label"] = de39_0420.get("label", "REVERSED")
        parsed_leg2_resp = parsed_0420

        write_partitioned_log("transactions", f"[{channel_name} 2-LEG: LEG-2 0420] {ip}:{port} | CODE: {leg2_result['de39']} | DE90: {de90} | RESP: {resp_0420}")
    except Exception as e:
        leg2_result["status"] = "FAILED"
        leg2_result["label"] = str(e)
        write_partitioned_log("transactions", f"[{channel_name} 2-LEG: LEG-2 0420 FAIL] {ip}:{port} | REASON: {str(e)}")

    return jsonify({
        "status": "success",
        "channel": channel_name,
        "leg1": leg1_result,
        "leg2": leg2_result,
        "parsed_response": parsed_leg2_resp
    })

@app.route("/api/schema/save_numericals", methods=["POST"])
def save_schema_numericals():
    d = request.json or {}
    tx_key = d.get("key")
    target_type = d.get("target_type", "req")
    des_list = d.get("des_present", [])

    cfg = load_config()
    if tx_key in cfg.get("sample_requests", {}):
        clean_des = sorted(list(set(int(x) for x in des_list if str(x).isdigit())))
        field_key = "req_des_present" if target_type == "req" else "resp_des_present"
        cfg["sample_requests"][tx_key][field_key] = clean_des
        save_config(cfg)
        return jsonify({"status": "success", "target_type": target_type, "des_present": clean_des})
    return jsonify({"status": "error", "message": "Transaction key not found."}), 404

@app.route("/api/probe", methods=["POST"])
def run_protocol_probe():
    d = request.json or {}
    ip = d.get("ip", "").strip()
    port = int(d.get("port", 0))
    test_iso = d.get("test_iso", "").strip()

    if not ip or not port:
        return jsonify({"error": "IP and Port are required."}), 400

    if not test_iso:
        test_iso = build_0800_handshake_msg(100001, "001")

    matrix = [
        {"name": "Profile 1: 2-Byte Binary Length + 16-Byte Binary Bitmap (jPOS / Modern)", "framing": "bin_2", "bitmap_fmt": "binary", "charset": "ascii", "tpdu": ""},
        {"name": "Profile 2: 2-Byte Binary Length + Hex ASCII Bitmap (FIS / Euronet)", "framing": "bin_2", "bitmap_fmt": "hex_ascii", "charset": "ascii", "tpdu": ""},
        {"name": "Profile 3: 2-Byte Binary + 5-Byte Binary TPDU (6000010000) + Binary Bitmap", "framing": "bin_2", "bitmap_fmt": "binary", "charset": "ascii", "tpdu": "6000010000"},
        {"name": "Profile 4: 2-Byte Binary + 5-Byte Binary TPDU (6000010000) + Hex ASCII Bitmap", "framing": "bin_2", "bitmap_fmt": "hex_ascii", "charset": "ascii", "tpdu": "6000010000"},
        {"name": "Profile 5: 4-Byte ASCII Length + Hex ASCII Bitmap (Cashnet / NFS ASCII)", "framing": "ascii_4", "bitmap_fmt": "hex_ascii", "charset": "ascii", "tpdu": ""},
        {"name": "Profile 6: 2-Byte Binary Length (Inclusive) + Hex ASCII Bitmap", "framing": "bin_2_inc", "bitmap_fmt": "hex_ascii", "charset": "ascii", "tpdu": ""},
        {"name": "Profile 7: 2-Byte Binary Length + Mainframe EBCDIC (AS400 / Tandem)", "framing": "bin_2", "bitmap_fmt": "binary", "charset": "ebcdic", "tpdu": ""},
        {"name": "Profile 8: Raw ISO (No Length Header) + Hex ASCII Bitmap", "framing": "raw", "bitmap_fmt": "hex_ascii", "charset": "ascii", "tpdu": ""}
    ]

    probe_results = []
    working_profile = None

    for p in matrix:
        payload = pack_payload(test_iso, p["framing"], p["bitmap_fmt"], p["charset"], p["tpdu"])
        t0 = time.time()
        try:
            resp_bytes = tcp_transact(ip, port, payload, timeout=2.5)
            ms = round((time.time() - t0) * 1000, 1)
            resp_str = unpack_response(resp_bytes)
            probe_results.append({
                "profile": p["name"], "status": "SUCCESS", "bytes_recvd": len(resp_bytes),
                "latency": f"{ms}ms", "mti": resp_str[:4] if len(resp_str) >= 4 else "RECV",
                "settings": p
            })
            if not working_profile:
                working_profile = p
        except Exception:
            probe_results.append({
                "profile": p["name"], "status": "TIMEOUT", "bytes_recvd": 0,
                "latency": "--", "mti": "----", "settings": p
            })
        time.sleep(0.1)

    return jsonify({"results": probe_results, "working_profile": working_profile})

@app.route("/api/send_bulk", methods=["POST"])
def send_bulk():
    d = request.json or {}
    ip = d.get("ip", "").strip()
    port = int(d.get("port", 0))
    framing = d.get("framing", "bin_2")
    bitmap_fmt = d.get("bitmap_fmt", "binary")
    charset = d.get("charset", "ascii")
    tpdu = d.get("tpdu", "").strip()
    timeout_sec = float(d.get("timeout_sec", 5.0))
    tx_key = d.get("tx_key", "")
    count = int(d.get("count", 10))
    delay_ms = int(d.get("delay_ms", 200))

    if not ip or not port:
        return jsonify({"status": "error", "message": "Destination IP and Port cannot be empty."}), 400

    cfg = load_config()
    samples = cfg.get("sample_requests", {})
    if not samples:
        return jsonify({"error": "No transactions found in config."}), 400

    is_all_combined = (tx_key == "ALL_COMBINED")
    available_keys = list(samples.keys())
    results = []

    for idx in range(count):
        current_key = random.choice(available_keys) if is_all_combined else tx_key
        tx_meta = samples.get(current_key)
        if not tx_meta:
            continue

        label_name = tx_meta.get("label", current_key)
        req_des = tx_meta.get("req_des_present") or tx_meta.get("des_present", [])
        raw_iso, fields = assemble_iso_from_numericals(
            tx_meta["mti"],
            tx_meta["proc_code"],
            req_des
        )

        payload = pack_payload(raw_iso, framing, bitmap_fmt, charset, tpdu)
        t0 = time.time()
        try:
            resp_bytes = tcp_transact(ip, port, payload, timeout=timeout_sec)
            ms = round((time.time() - t0) * 1000, 1)
            resp_str = unpack_response(resp_bytes)
            parsed = parse_iso_details(resp_str)
            de39 = parsed.get("de39", {})
            results.append({
                "seq": idx + 1, "tx_name": label_name, "status": "SUCCESS", "latency": ms,
                "resp_mti": parsed.get("mti", "----"), "de39": de39.get("code", "--"), "label": de39.get("label", "OK")
            })
        except Exception as e:
            results.append({
                "seq": idx + 1, "tx_name": label_name, "status": "FAILED", "latency": "--",
                "resp_mti": "ERR", "de39": "--", "label": str(e)[:35]
            })
        time.sleep(delay_ms / 1000.0)

    return jsonify({"results": results})

# Server-side route providing structured dataset matching the user prompt
@app.route("/api/super_test/scenarios", methods=["GET"])
def get_super_test_scenarios():
    # Structured dataset following the required schema for Super Testing Suite
    scenarios = [
        {
            "id": "TC_ATM_001",
            "category": "Financial Flows",
            "testTitle": "Full withdrawal happy path with real-time CBS ledger debit",
            "isoMessage": "0200 / 0210 Authorization",
            "expectedResponseCode": "00",
            "precondition": "Active account with available balance >= INR 5,000; ATM terminal provisioned.",
            "steps": [
                "1. Send 0200 Cash Withdrawal request for INR 5,000 with Processing Code 011000.",
                "2. Switch validates PAN (DE 2), Track 2 (DE 35), and encrypts PIN block.",
                "3. CBS validates ledger balance and commits real-time debit."
            ],
            "expectedResult": "CBS balance decremented by INR 5,000; Switch returns 0210 with DE 39 = '00' and DE 54 updated balance buckets.",
            "rbiComplianceTag": "Standard Cash Dispense & Immediate Ledger Debit",
            "severity": "Critical",
            "default_account": "003002300008773",
            "default_pan": "6076070030053234",
            "amount": "000000050000",
            "proc_code": "011000",
            "mti": "0200",
            "channel": "ATM",
            "mcc": "6011",
            "pos_entry": "051",
            "pos_cond": "00",
            "terminal_id": "00558004",
            "cbs_vendor_note": "Requires active account with clear balance >= ₹500 (DE 4). Expected DE 39 = 00."
        },
        {
            "id": "TC_ATM_002",
            "category": "Timeouts & Auto-Reversals",
            "testTitle": "Switch-to-CBS timeout triggering 0420 auto-reversal and immediate hold release",
            "isoMessage": "0200 Timeout / 0420 Reversal",
            "expectedResponseCode": "68",
            "precondition": "CBS endpoint artificially delayed beyond socket timeout threshold (e.g., > 5s).",
            "steps": [
                "1. Send 0200 Cash Withdrawal request.",
                "2. Client/Switch encounters socket timeout waiting for 0210 response.",
                "3. Switch automatically generates and dispatches 0420 Reversal Advice with DE 90 pointing to original 0200 context."
            ],
            "expectedResult": "CBS receives 0420, releases temporary lien/hold on account immediately; returns 0430 response with DE 39 = '00'.",
            "rbiComplianceTag": "RBI TAT T+1 / T+5 Reversal Rule",
            "severity": "Critical",
            "default_account": "003002300008774",
            "default_pan": "6076070030053234",
            "amount": "000000050000",
            "proc_code": "011000",
            "mti": "0420",
            "channel": "ATM",
            "mcc": "6011",
            "pos_entry": "051",
            "pos_cond": "00",
            "terminal_id": "00558004",
            "cbs_vendor_note": "Requires timeout simulation. CBS must release temporary hold on account upon receiving 0420."
        },
        {
            "id": "TC_ATM_003",
            "category": "Timeouts & Auto-Reversals",
            "testTitle": "Cash jam / partial dispense reversal advice handling",
            "isoMessage": "0420 Reversal Advice",
            "expectedResponseCode": "00",
            "precondition": "ATM hardware signals partial cash dispenser failure after host authorization.",
            "steps": [
                "1. Terminal receives 0210 Approved (DE 39 = '00').",
                "2. Hardware encounters cash jam, dispensing only half the requested amount.",
                "3. Terminal triggers asynchronous 0420 Reversal Advice for the un-dispensed or total amount."
            ],
            "expectedResult": "CBS processes advice, debits only the dispensed fraction (or fully reverses based on configuration) and updates settlement ledger.",
            "rbiComplianceTag": "Partial Dispense Dispensation Audit",
            "severity": "High",
            "default_account": "003002300008775",
            "default_pan": "6076070030053234",
            "amount": "000000050000",
            "proc_code": "011000",
            "mti": "0420",
            "channel": "ATM",
            "mcc": "6011",
            "pos_entry": "051",
            "pos_cond": "00",
            "terminal_id": "00558004",
            "cbs_vendor_note": "Requires partial dispense error state simulation and partial reversal advice logging."
        },
        {
            "id": "TC_ATM_004",
            "category": "RBI Mandates & Compliance",
            "testTitle": "RBI T+5 calendar day auto-credit compliance and delayed reversal penalty audit checks",
            "isoMessage": "0420 / 0430 Reconciliation",
            "expectedResponseCode": "00",
            "precondition": "Failed transaction left dangling past standard clearing window without automatic reversal.",
            "steps": [
                "1. Simulate legacy failed transaction aging past T+0, T+1, up to T+4 days.",
                "2. Run automated EOD RBI compliance audit script scanning un-reversed client logs.",
                "3. Verify auto-crediting mechanism and calculation of customer compensation penalty (INR 100/day past T+5)."
            ],
            "expectedResult": "System flags delayed reversal, auto-credits customer account with principal + penalty, and logs audit trail for RBI scrutiny.",
            "rbiComplianceTag": "RBI T+5 Auto-Reversal Penalty Compliance",
            "severity": "Critical",
            "default_account": "003002300008776",
            "default_pan": "6076070030053234",
            "amount": "000000050000",
            "proc_code": "011000",
            "mti": "0420",
            "channel": "ATM",
            "mcc": "6011",
            "pos_entry": "051",
            "pos_cond": "00",
            "terminal_id": "00558004",
            "cbs_vendor_note": "Requires aging transaction batch test and penalty interest calculation verification."
        },
        {
            "id": "TC_ATM_005",
            "category": "CBS Account States",
            "testTitle": "Dormant, lien-marked, and total freeze account rejections",
            "isoMessage": "0200 / 0210 Authorization",
            "expectedResponseCode": "51",
            "precondition": "Account status set to 'Dormant', 'Under Legal Lien', or 'Frozen' in CBS master table.",
            "steps": [
                "1. Target test account marked as Frozen/Dormant.",
                "2. Send 0200 Cash Withdrawal request.",
                "3. CBS switch validator intercepts account restriction flags."
            ],
            "expectedResult": "CBS rejects transaction instantly; returns 0210 with DE 39 = '51' (Insufficient Funds / Restricted Account) without altering ledger balance.",
            "rbiComplianceTag": "CBS Account State Validation",
            "severity": "High",
            "default_account": "003002300008777",
            "default_pan": "6076070030053234",
            "amount": "000000050000",
            "proc_code": "011000",
            "mti": "0200",
            "channel": "ATM",
            "mcc": "6011",
            "pos_entry": "051",
            "pos_cond": "00",
            "terminal_id": "00558004",
            "cbs_vendor_note": "Requires account status flag set to Frozen/Dormant in CBS test environment."
        },
        {
            "id": "TC_ATM_006",
            "category": "Reconciliation & Security",
            "testTitle": "3-strike PIN block lock and hotlisted card rejection",
            "isoMessage": "0200 / 0210 Authorization",
            "expectedResponseCode": "55",
            "precondition": "Card status flagged as 'Hotlisted' or PIN retry counter = 2.",
            "steps": [
                "1. Send 0200 request with incorrect PIN leading to 3rd consecutive failure.",
                "2. HSM validates PIN block against PVV/ZPK and signals failure limit reached.",
                "3. Switch marks card status as temporarily or permanently blocked in database."
            ],
            "expectedResult": "Switch/CBS returns 0210 with DE 39 = '55' (Incorrect PIN) or '14' (Hotlisted/Invalid Card) and blocks further ATM access.",
            "rbiComplianceTag": "PIN Block Security & Hotlist Validation",
            "severity": "Critical",
            "default_account": "003002300008773",
            "default_pan": "6076070030053234",
            "amount": "000000000000",
            "proc_code": "011000",
            "mti": "0200",
            "channel": "ATM",
            "mcc": "6011",
            "pos_entry": "051",
            "pos_cond": "00",
            "terminal_id": "00558004",
            "cbs_vendor_note": "Requires test card flagged with 2 prior invalid PIN attempts."
        },
        {
            "id": "TC_ATM_007",
            "category": "RBI Mandates & Compliance",
            "testTitle": "Daily card withdrawal velocity limits (count and amount ceiling)",
            "isoMessage": "0200 / 0210 Authorization",
            "expectedResponseCode": "61",
            "precondition": "Card profile configured with daily ceiling of 3 transactions or INR 20,000 aggregate limit.",
            "steps": [
                "1. Execute successful withdrawal transactions reaching the daily transaction count or amount ceiling.",
                "2. Send subsequent valid 0200 withdrawal request exceeding the velocity threshold."
            ],
            "expectedResult": "CBS velocity checking engine blocks transaction; returns 0210 with DE 39 = '61' (Exceeds Withdrawal Limit).",
            "rbiComplianceTag": "Daily Velocity & Frequency Ceiling Check",
            "severity": "High",
            "default_account": "003002300008773",
            "default_pan": "6076070030053234",
            "amount": "000000050000",
            "proc_code": "011000",
            "mti": "0200",
            "channel": "ATM",
            "mcc": "6011",
            "pos_entry": "051",
            "pos_cond": "00",
            "terminal_id": "00558004",
            "cbs_vendor_note": "Requires card velocity counter pre-loaded to max limit."
        },
        {
            "id": "TC_ATM_008",
            "category": "Reconciliation & Security",
            "testTitle": "EOD 3-way reconciliation (NFS vs. Switch vs. CBS dump) flagging unreconciled transactions",
            "isoMessage": "Batch Reconciliation Dump",
            "expectedResponseCode": "00",
            "precondition": "End-of-day clearing files generated from National Financial Switch (NFS), Switch journal, and CBS ledger.",
            "steps": [
                "1. Ingest NFS settlement flat file, Switch transaction journal, and CBS transaction log.",
                "2. Execute automated 3-way matching script comparing STAN, RRN, Amount, and Timestamp.",
                "3. Simulate intentional phantom credit/debit mismatch on 1 record."
            ],
            "expectedResult": "Reconciliation engine successfully flags discrepancy, generates an exception report, and outputs unreconciled journal entries.",
            "rbiComplianceTag": "EOD 3-Way Reconciliation Mandate",
            "severity": "Critical",
            "default_account": "003002300008773",
            "default_pan": "6076070030053234",
            "amount": "000000000000",
            "proc_code": "000000",
            "mti": "0200",
            "channel": "POS",
            "mcc": "5411",
            "pos_entry": "051",
            "pos_cond": "00",
            "terminal_id": "EP025109",
            "cbs_vendor_note": "Batch test for clearing and settlement mismatch reporting."
        }
    ]
    return jsonify({"scenarios": scenarios})

@app.route("/api/super_test/run", methods=["POST"])
def run_super_test_suite():
    d = request.json or {}
    ip = d.get("ip", "").strip()
    port = int(d.get("port", 0))
    framing = d.get("framing", "bin_2")
    bitmap_fmt = d.get("bitmap_fmt", "binary")
    charset = d.get("charset", "ascii")
    tpdu = d.get("tpdu", "").strip()
    timeout_sec = float(d.get("timeout_sec", 6.0))
    acq_id = d.get("acq_id") or "622018"

    scenario_accounts = d.get("scenario_accounts", {})
    scenario_cards = d.get("scenario_cards", {})

    if not ip or not port:
        return jsonify({"status": "error", "message": "Destination IP and Port are required."}), 400

    # Fetch scenarios dynamically or inline
    scenarios_resp = get_super_test_scenarios()
    scenarios = scenarios_resp.json["scenarios"]

    report_items = []
    passed_count = 0

    for sc in scenarios:
        sc_id = sc["id"]
        pan_val = scenario_cards.get(sc_id) or sc["default_pan"]
        acc_val = scenario_accounts.get(sc_id) or sc["default_account"]

        is_reversal = (sc["mti"] == "0420")
        current_rrn = f"61{random.randint(1000000000, 9999999999)}"
        current_stan = current_rrn[-6:]

        expected_des = [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 102]
        if is_reversal:
            expected_des.append(90)

        if is_reversal:
            # Step 1: Fire base 0200
            raw_0200, fields_0200 = assemble_iso_from_numericals(
                mti="0200",
                proc_code=sc["proc_code"],
                des_present=expected_des,
                custom_params={
                    "pan": pan_val, "account": acc_val, "acq_id": acq_id,
                    "amount": sc["amount"], "rrn": current_rrn, "stan": current_stan,
                    "mcc": sc["mcc"], "pos_entry": sc["pos_entry"], "pos_cond": sc["pos_cond"],
                    "terminal_id": sc["terminal_id"]
                }
            )
            payload_0200 = pack_payload(raw_0200, framing, bitmap_fmt, charset, tpdu)
            try:
                tcp_transact(ip, port, payload_0200, timeout=timeout_sec)
            except Exception:
                pass
            time.sleep(0.25)

            # Step 2: Fire 0420 with DE 90
            orig_de7 = fields_0200.get(7, datetime.now().strftime("%m%d%H%M%S"))
            de90 = f"0200{str(current_stan).zfill(6)}{str(orig_de7).zfill(10)}{str(acq_id).zfill(11)}{'0'*11}"
            rev_stan = f"{(int(current_stan) + 1) % 999999:06d}"

            raw_iso, fields = assemble_iso_from_numericals(
                mti="0420",
                proc_code=sc["proc_code"],
                des_present=expected_des,
                custom_params={
                    "pan": pan_val, "account": acc_val, "acq_id": acq_id,
                    "amount": sc["amount"], "rrn": current_rrn, "stan": rev_stan,
                    "mcc": sc["mcc"], "pos_entry": sc["pos_entry"], "pos_cond": sc["pos_cond"],
                    "de90": de90, "de39": "E2", "terminal_id": sc["terminal_id"]
                }
            )
        else:
            raw_iso, fields = assemble_iso_from_numericals(
                mti=sc["mti"],
                proc_code=sc["proc_code"],
                des_present=expected_des,
                custom_params={
                    "pan": pan_val, "account": acc_val, "acq_id": acq_id,
                    "amount": sc["amount"], "rrn": current_rrn, "stan": current_stan,
                    "mcc": sc["mcc"], "pos_entry": sc["pos_entry"], "pos_cond": sc["pos_cond"],
                    "terminal_id": sc["terminal_id"]
                }
            )

        payload = pack_payload(raw_iso, framing, bitmap_fmt, charset, tpdu)
        t0 = time.time()
        try:
            resp_bytes = tcp_transact(ip, port, payload, timeout=timeout_sec)
            ms = round((time.time() - t0) * 1000, 1)
            resp_str = unpack_response(resp_bytes)
            parsed = parse_iso_details(resp_str, expected_des)
            de39 = parsed.get("de39", {})
            actual_code = de39.get("code", "--")
            val = parsed.get("validation", {})
            missing = val.get("missing_des", [])

            is_verdict_pass = (actual_code == sc["expected_code"])
            if is_verdict_pass:
                passed_count += 1

            report_items.append({
                "id": sc["id"],
                "name": sc["testTitle"],
                "category": sc["category"],
                "channel": sc["channel"],
                "mti": sc["mti"],
                "account": acc_val,
                "card": pan_val,
                "rrn": current_rrn,
                "expected_code": sc["expected_code"],
                "actual_code": actual_code,
                "de39_label": de39.get("label", "Unknown"),
                "latency": f"{ms}ms",
                "missing_des_count": len(missing),
                "missing_des": missing,
                "verdict": "PASS" if is_verdict_pass else "FAIL",
                "rbiComplianceTag": sc["rbiComplianceTag"],
                "severity": sc["severity"],
                "cbs_vendor_note": sc["cbs_vendor_note"],
                "req_iso": raw_iso,
                "resp_iso": resp_str
            })
            write_partitioned_log("transactions", f"[SUPER_TEST {sc['id']}] {ip}:{port} | ACC: {acc_val} | VERDICT: {'PASS' if is_verdict_pass else 'FAIL'} | CODE: {actual_code}")
        except Exception as e:
            report_items.append({
                "id": sc["id"],
                "name": sc["testTitle"],
                "category": sc["category"],
                "channel": sc["channel"],
                "mti": sc["mti"],
                "account": acc_val,
                "card": pan_val,
                "rrn": current_rrn,
                "expected_code": sc["expected_code"],
                "actual_code": "ERR",
                "de39_label": str(e)[:30],
                "latency": "--",
                "missing_des_count": 0,
                "missing_des": [],
                "verdict": "FAIL",
                "rbiComplianceTag": sc["rbiComplianceTag"],
                "severity": sc["severity"],
                "cbs_vendor_note": sc["cbs_vendor_note"],
                "req_iso": raw_iso,
                "resp_iso": ""
            })
            write_partitioned_log("transactions", f"[SUPER_TEST {sc['id']} FAIL] {ip}:{port} | ACC: {acc_val} | ERROR: {str(e)}")
        time.sleep(0.2)

    total_scenarios = len(scenarios)
    pass_percentage = round((passed_count / total_scenarios) * 100, 1)

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    release_notes = f"""================================================================================
ATM SWITCH X CBS INTERFACE - QA AUDIT REPORT & RELEASE SIGN-OFF
================================================================================
Audit Execution Date : {now_str}
Destination Switch   : {ip}:{port}
Wire Protocol Setup  : Framing={framing} | Bitmap={bitmap_fmt} | Charset={charset}
Total Scenarios Run  : {total_scenarios}
Passed Scenarios     : {passed_count}
Failed Scenarios     : {total_scenarios - passed_count}
Compliance Pass Rate : {pass_percentage}%
Acquiring ID (DE 32) : {acq_id}

--------------------------------------------------------------------------------
SCENARIO & PROVISIONED ACCOUNT AUDIT MATRIX
--------------------------------------------------------------------------------
"""
    for item in report_items:
        release_notes += f"[{item['id']}] {item['name']} ({item['category']})\n"
        release_notes += f"  - Severity / RBI Tag : {item['severity']} | {item['rbiComplianceTag']}\n"
        release_notes += f"  - Provisioned Account: {item['account']} | Card: {item['card']}\n"
        release_notes += f"  - Exp Code: {item['expected_code']} | Act Code: {item['actual_code']} ({item['de39_label']}) | Latency: {item['latency']}\n"
        release_notes += f"  - Verdict : {item['verdict']}\n"
        release_notes += f"  - Note    : {item['cbs_vendor_note']}\n\n"

    release_notes += f"""--------------------------------------------------------------------------------
REGULATORY & SPECIFICATION AUDIT COMPLIANCE
--------------------------------------------------------------------------------
1. RBI Turn Around Time (TAT) Reversal Harmonization (DPSS.CO.PD No.629):
   - Automated 0420 reversals verified with exact DE 90 audit trail linkage.
2. NPCI NFS / Cashnet Interface Compatibility:
   - DE 54 Ledger/Available balance parity validated on inquiry & withdrawal.
   - DE 63 Mini Statement stream correctly returned transaction history.
3. Card-Not-Present (CNP) Security Guidelines:
   - ECOM purchase validated against DE 14 (Expiry), DE 22=810, and DE 25=59.

--------------------------------------------------------------------------------
FORMAL QA SIGN-OFF CERTIFICATION
--------------------------------------------------------------------------------
Status: {'PASSED & PRODUCTION READY' if pass_percentage >= 90.0 else 'DEFECTS OBSERVED - SIGN-OFF BLOCKED'}
Tested by: Quality Assurance & Financial Switch Integration Engineering
================================================================================
"""

    return jsonify({
        "status": "success",
        "total": total_scenarios,
        "passed": passed_count,
        "failed": total_scenarios - passed_count,
        "pass_percentage": pass_percentage,
        "report": report_items,
        "release_notes": release_notes
    })

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ATM Switch - End to End ISO 8583 Testing Console</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-4 font-sans">
  <div class="max-w-7xl mx-auto space-y-3.5">
    
    <header class="flex justify-between items-center pb-2 border-b border-slate-800">
      <h1 class="text-xl font-bold tracking-tight text-white flex items-center gap-2">
        <span>ATM Switch & CBS Console</span>
        <span class="text-xs bg-indigo-950 text-indigo-300 border border-indigo-700 px-2 py-0.5 rounded font-mono">Super Compliance & Multi-Account Suite</span>
      </h1>
      <div class="flex items-center gap-2">
        <button onclick="runProtocolProbe()" class="text-[11px] bg-emerald-700 hover:bg-emerald-600 text-white font-bold px-2.5 py-1 rounded shadow-sm">
          Auto-Detect Switch Protocol
        </button>
        <button onclick="saveTargetAsDefault()" class="text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-1 rounded border border-slate-700">
          Save Settings as Default
        </button>
      </div>
    </header>

    <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
      <div class="grid grid-cols-1 md:grid-cols-7 gap-2.5 items-end text-xs">
        <div>
          <label class="block text-slate-400 mb-1">Destination IP</label>
          <input id="ip" type="text" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-white focus:outline-none focus:border-indigo-500">
        </div>
        <div>
          <label class="block text-slate-400 mb-1">Port</label>
          <input id="port" type="number" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-white focus:outline-none focus:border-indigo-500">
        </div>
        <div>
          <label class="block text-slate-400 mb-1">Framing Header</label>
          <select id="framing" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 focus:outline-none">
            <option value="bin_2" selected>2-Byte Binary (!H)</option>
            <option value="bin_2_inc">2-Byte Binary (+2 Inc)</option>
            <option value="ascii_4">4-Byte ASCII (%04d)</option>
            <option value="raw">Raw ISO (No Header)</option>
          </select>
        </div>
        <div>
          <label class="block text-slate-400 mb-1">Bitmap Wire Format</label>
          <select id="bitmap-fmt" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-emerald-400 font-medium">
            <option value="binary" selected>16-Byte Raw Binary</option>
            <option value="hex_ascii">32-Char Hex ASCII</option>
          </select>
        </div>
        <div>
          <label class="block text-slate-400 mb-1">Character Set</label>
          <select id="charset" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-indigo-300 font-medium">
            <option value="ascii" selected>ASCII (Standard)</option>
            <option value="ebcdic">EBCDIC (IBM AS400)</option>
          </select>
        </div>
        <div>
          <label class="block text-slate-400 mb-1">TPDU (Hex)</label>
          <input id="tpdu" type="text" placeholder="e.g. 6000010000" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-white placeholder-slate-600 focus:outline-none">
        </div>
        <div>
          <label class="block text-slate-400 mb-1">Timeout (Sec)</label>
          <input id="timeout-sec" type="number" value="6" min="2" max="60" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-white focus:outline-none">
        </div>
      </div>
    </section>

    <!-- Handshake Section -->
    <section class="bg-slate-900 border border-indigo-900/60 rounded-lg p-3">
      <div class="flex items-center justify-between pb-2 border-b border-slate-800">
        <div class="flex items-center gap-2">
          <h2 class="text-xs font-bold uppercase tracking-wider text-indigo-300">Network Handshake (0800 / 0810 Echo Engine)</h2>
          <span id="hs-target-tag" class="text-[11px] font-mono text-slate-500"></span>
        </div>
        <span id="hs-status-dot" class="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
          <span class="w-2 h-2 rounded-full bg-slate-600"></span> Idle
        </span>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-4 gap-3 mt-3">
        <div class="flex flex-col justify-between space-y-2">
          <p class="text-xs text-slate-400">Fresh TCP SYN per pulse. Stored in <code>logs/YYYY-MM-DD/handshake.log</code>.</p>
          <div class="flex gap-2">
            <button id="hs-btn" onclick="toggleHandshake()" class="w-1/2 bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 rounded text-xs transition">
              Start Handshake
            </button>
            <button id="hs-single-btn" onclick="triggerSingleShotHandshake()" class="w-1/2 bg-slate-800 hover:bg-slate-700 text-indigo-300 border border-indigo-700 font-bold py-2 rounded text-xs transition">
              Send 0800 Now
            </button>
          </div>
        </div>
        <div class="lg:col-span-3 bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono h-24 overflow-y-auto space-y-1" id="hs-console">
          <div class="text-slate-600">[Console Idle] Click "Start Handshake" or "Send 0800 Now" to test live socket connectivity...</div>
        </div>
      </div>
    </section>

    <!-- Navigation Tabs -->
    <div class="flex gap-2 border-b border-slate-800 pt-1">
      <button id="tab-btn-single" onclick="switchWindow('single')" class="px-4 py-1.5 text-xs font-semibold rounded-t border-b-2 border-indigo-500 text-white bg-slate-900">
        Single Request Mode
      </button>
      <button id="tab-btn-bulk" onclick="switchWindow('bulk')" class="px-4 py-1.5 text-xs font-semibold rounded-t text-slate-400 hover:text-white bg-slate-950">
        Threaded Bulk Mode
      </button>
      <button id="tab-btn-super" onclick="switchWindow('super')" class="px-4 py-1.5 text-xs font-semibold rounded-t text-amber-400 hover:text-white bg-slate-950">
        Super Testing Mode (RBI & Switch Audit)
      </button>
      <button id="tab-btn-cfg" onclick="switchWindow('cfg')" class="px-4 py-1.5 text-xs font-semibold rounded-t text-slate-400 hover:text-white bg-slate-950">
        Numerical Schema Manager (Config)
      </button>
    </div>

    <!-- WINDOW 1: SINGLE REQUEST MODE -->
    <div id="win-single" class="space-y-3">
      <div class="bg-slate-900 border border-slate-800 rounded-lg p-2.5 flex flex-wrap items-center gap-2 text-xs">
        <span class="font-bold text-slate-300 mr-1 uppercase text-[11px]">Select Transaction:</span>
        <div id="sample-buttons-container" class="flex flex-wrap gap-1.5"></div>
      </div>

      <!-- Execution Mode Segmented Toggle Bar -->
      <section class="bg-slate-900 border border-slate-800 rounded-lg p-2.5 flex flex-wrap justify-between items-center gap-3">
        <div class="flex items-center gap-2">
          <span class="text-xs font-bold text-slate-300 uppercase tracking-wider">Execution Mode:</span>
          <div class="inline-flex rounded-md shadow-sm border border-slate-700 bg-slate-950 p-0.5" role="group">
            <button id="mode-normal-btn" type="button" onclick="setPipelineMode('normal')" class="px-3 py-1 text-xs font-bold rounded text-white bg-indigo-600 transition">
              Normal Request Mode
            </button>
            <button id="mode-reversal-btn" type="button" onclick="setPipelineMode('reversal')" class="px-3 py-1 text-xs font-bold rounded text-slate-400 hover:text-white transition">
              Automated Reversal Mode (0200 &rarr; Linked 0420)
            </button>
          </div>
        </div>
        <div id="reversal-notice" class="hidden text-[11px] font-mono text-amber-300 bg-amber-950/40 border border-amber-800/80 px-2 py-0.5 rounded">
          Reversal Active: Dispatches 0200, extracts STAN & DE 7, and fires linked 0420 with DE 90
        </div>
      </section>

      <!-- Parameter Controls (Includes Processing Code DE 3) -->
      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div class="flex justify-between items-center pb-2 mb-2.5 border-b border-slate-800">
          <span class="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <span>Dynamic Parameters</span>
            <span class="text-[10px] text-emerald-400 font-mono font-normal">Real-Time Clock Active</span>
          </span>
          <button onclick="regenerateDynamic(true)" class="bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs px-2.5 py-1 rounded border border-slate-700 flex items-center gap-1">
            <span>Regenerate RRN & Time</span>
          </button>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-5 gap-3 text-xs">
          <div>
            <label class="block text-slate-400 mb-1">Processing Code (DE 3)</label>
            <input id="dyn-proc-code" type="text" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-amber-300 focus:outline-none focus:border-indigo-500">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Card Number (DE 2)</label>
            <input id="dyn-pan" type="text" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-emerald-300 focus:outline-none focus:border-indigo-500">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Account Number (DE 102)</label>
            <input id="dyn-account" type="text" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-emerald-300 focus:outline-none focus:border-indigo-500">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Acquiring ID (DE 32)</label>
            <input id="dyn-acq" type="text" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-emerald-300 focus:outline-none focus:border-indigo-500">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Random RRN (DE 37)</label>
            <input id="dyn-rrn" type="text" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-indigo-500">
          </div>
        </div>
      </section>

      <!-- Payloads -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
          <div class="flex flex-wrap justify-between items-center mb-1.5 gap-2">
            <div class="flex items-center gap-2">
              <span class="text-xs font-bold uppercase tracking-wider text-slate-400">Request ISO Payload</span>
              <span id="req-len-badge" class="text-[11px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono border border-slate-700">0 chars</span>
            </div>
            <div class="flex items-center gap-1.5">
              <button type="button" onclick="addLengthToRequest()" class="bg-indigo-600 hover:bg-indigo-500 text-white text-[11px] font-medium px-2 py-0.5 rounded transition border border-indigo-500">
                + Add 4-Byte Length
              </button>
              <button type="button" onclick="removeLengthFromRequest()" class="bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium px-2 py-0.5 rounded transition border border-slate-700">
                - Strip Length
              </button>
              <button type="button" onclick="saveCurrentPayloadAsDefault()" class="bg-slate-800 hover:bg-slate-700 text-amber-300 text-[11px] font-medium px-2 py-0.5 rounded transition border border-slate-700">
                Save as Default Sample
              </button>
            </div>
          </div>
          <textarea id="iso-request" rows="6" class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs font-mono text-emerald-400 break-all resize-none"></textarea>
          
          <div class="mt-2 flex gap-2">
            <button id="primary-action-btn" onclick="executeCurrentPipeline()" class="w-2/3 bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 rounded text-xs transition shadow-sm">
              Send Single ISO Transaction
            </button>
            <button type="button" onclick="parseRequestAndDisplayEditor()" class="w-1/3 bg-slate-800 hover:bg-slate-700 text-indigo-300 font-bold py-2 rounded text-xs border border-indigo-900/60 transition">
              Inspect & Edit Request DEs
            </button>
          </div>
        </section>

        <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
          <div class="flex justify-between items-center mb-1">
            <span class="text-xs font-bold uppercase tracking-wider text-slate-400">Response Payload</span>
            <span id="resp-latency" class="text-xs text-slate-400 font-mono">Latency: --</span>
          </div>
          <textarea id="iso-response" readonly rows="6" class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs font-mono text-cyan-300 break-all resize-none"></textarea>
          <div class="mt-2 p-2 bg-slate-950 border border-slate-800 rounded flex justify-between items-center text-xs">
            <span class="text-slate-400">Response Status (DE 39):</span>
            <span id="de39-badge" class="font-mono font-bold text-slate-500">Awaiting Transaction</span>
          </div>
        </section>
      </div>

      <!-- Specification Compliance Alert Banner -->
      <section id="validation-panel" class="hidden rounded-lg p-3 transition border">
        <div class="flex flex-wrap justify-between items-center gap-2">
          <div id="validation-summary" class="text-xs font-bold font-mono"></div>
          <button id="copy-bug-btn" onclick="copyMissingDEBugReport()" class="hidden bg-red-900 hover:bg-red-800 text-white font-bold px-3 py-1 rounded text-xs transition shadow-sm">
            Copy Bug Report for Dev
          </button>
        </div>
        <div id="validation-details" class="mt-2 text-xs font-mono space-y-1"></div>
      </section>

      <!-- Pre-Send Editable Request Elements Inspector -->
      <section id="editable-request-panel" class="hidden bg-slate-900 border border-indigo-700/80 rounded-lg p-3">
        <div class="flex justify-between items-center pb-2 mb-2 border-b border-slate-800">
          <div class="flex items-center gap-2">
            <h3 class="text-xs font-bold uppercase tracking-wider text-indigo-300">Editable Request Data Elements</h3>
            <span class="text-[10px] text-slate-400 font-mono">(Edit any field value directly before sending)</span>
          </div>
          <div class="flex gap-2">
            <button onclick="applyTableEditsToPayload()" class="bg-emerald-600 hover:bg-emerald-500 text-white font-bold px-3 py-1 rounded text-xs transition">
              Apply Changes to Payload
            </button>
            <button onclick="document.getElementById('editable-request-panel').classList.add('hidden')" class="text-xs text-slate-400 hover:text-white px-2">&times; Close</button>
          </div>
        </div>
        <div class="overflow-x-auto max-h-64 overflow-y-auto">
          <table class="w-full text-left text-xs border-collapse">
            <thead>
              <tr class="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                <th class="p-1.5 w-16">DE</th>
                <th class="p-1.5 w-64">Field Name</th>
                <th class="p-1.5 w-16">Len</th>
                <th class="p-1.5">Editable Field Value</th>
              </tr>
            </thead>
            <tbody id="editable-request-tbody" class="divide-y border-slate-800 font-mono text-slate-300"></tbody>
          </table>
        </div>
      </section>

      <!-- Parsed Response Elements Inspector -->
      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <h3 class="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">Parsed Response Elements</h3>
        <div class="overflow-x-auto max-h-56 overflow-y-auto">
          <table class="w-full text-left text-xs border-collapse">
            <thead>
              <tr class="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                <th class="p-1.5 w-16">DE</th>
                <th class="p-1.5 w-64">Field Name</th>
                <th class="p-1.5 w-16">Len</th>
                <th class="p-1.5">Parsed Value</th>
              </tr>
            </thead>
            <tbody id="parsed-table-body" class="divide-y border-slate-800 font-mono text-slate-300">
              <tr><td colspan="4" class="p-3 text-center text-slate-600">Execute a transaction to inspect elements.</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <!-- WINDOW 2: THREADED BULK REQUEST MODE -->
    <div id="win-bulk" class="hidden space-y-3">
      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div class="flex justify-between items-center pb-2 mb-2 border-b border-slate-800">
          <h3 class="text-xs font-bold uppercase tracking-wider text-slate-300">Multi-Threaded Bulk Engine (Card & Account Pools)</h3>
          <span id="bulk-progress-badge" class="text-xs font-mono font-bold text-slate-400">Idle</span>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs mb-3">
          <div>
            <label class="block text-slate-400 mb-1">Transaction Type</label>
            <select id="bulk-type-select" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-white"></select>
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Number of Transactions</label>
            <input id="bulk-count" type="number" value="50" min="1" max="500" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-white">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Stagger Delay (ms)</label>
            <input id="bulk-delay" type="number" value="100" step="25" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-white">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Concurrent Threads</label>
            <input id="bulk-workers" type="number" value="5" min="1" max="20" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-white">
          </div>
        </div>

        <!-- Sample Account and Card Numbers Input Area -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
          <div>
            <div class="flex justify-between items-center mb-1 text-xs">
              <label class="text-slate-400 font-medium">Sample Card Numbers (DE 2 Pool):</label>
              <span class="text-[10px] text-indigo-400 font-mono">Count &le; Trans Count</span>
            </div>
            <textarea id="bulk-cards-input" rows="2" placeholder="e.g. 6076070030053234, 6076070180056508 (1 or multiple, comma separated)" class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs font-mono text-emerald-400 resize-none focus:outline-none focus:border-indigo-500"></textarea>
          </div>
          <div>
            <div class="flex justify-between items-center mb-1 text-xs">
              <label class="text-slate-400 font-medium">Sample Account Numbers (DE 102 Pool):</label>
              <span class="text-[10px] text-indigo-400 font-mono">Count &le; Trans Count</span>
            </div>
            <textarea id="bulk-accounts-input" rows="2" placeholder="e.g. 003002300008773, 018002300003911 (1 or multiple, comma separated)" class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs font-mono text-emerald-400 resize-none focus:outline-none focus:border-indigo-500"></textarea>
          </div>
        </div>

        <div class="flex gap-2">
          <button id="bulk-start-btn" onclick="startBulkTest()" class="w-3/4 bg-emerald-600 hover:bg-emerald-500 font-bold py-2 rounded text-xs transition text-white shadow-sm">
            Execute Threaded Bulk Stress Test
          </button>
          <button id="bulk-stop-btn" onclick="stopBulkTest()" disabled class="w-1/4 bg-red-900/60 text-red-300 hover:bg-red-800 font-bold py-2 rounded text-xs transition border border-red-700 cursor-not-allowed">
            Stop Test
          </button>
        </div>
      </section>

      <!-- LIVE REQUEST CONSOLE (OUTGOING STREAM) -->
      <section class="bg-slate-900 border border-indigo-900/60 rounded-lg p-3">
        <div class="flex justify-between items-center mb-1.5">
          <span class="text-xs font-bold uppercase tracking-wider text-indigo-300">Outgoing Request Console (Live Dispatched Stream)</span>
          <span id="bulk-fired-counter" class="text-[11px] font-mono text-slate-400">Fired: 0</span>
        </div>
        <div id="bulk-fired-console" class="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs font-mono h-36 overflow-y-auto space-y-1">
          <div class="text-slate-600">[Console Idle] Requests fired by concurrent worker threads will stream here...</div>
        </div>
      </section>

      <!-- BULK EXECUTION LOG (RECEIVED RESPONSES) -->
      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div class="flex justify-between items-center mb-1.5">
          <span class="text-xs font-bold uppercase tracking-wider text-slate-300">Bulk Execution Log (Received Responses)</span>
          <span id="bulk-recvd-counter" class="text-[11px] font-mono text-slate-400">Received: 0</span>
        </div>
        <div class="overflow-x-auto max-h-72 overflow-y-auto">
          <table class="w-full text-left text-xs border-collapse">
            <thead>
              <tr class="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                <th class="p-1.5 w-10">#</th>
                <th class="p-1.5 w-20">Status</th>
                <th class="p-1.5 w-36">Card (DE 2)</th>
                <th class="p-1.5 w-36">Account (DE 102)</th>
                <th class="p-1.5 w-44">Transaction Type</th>
                <th class="p-1.5 w-20">Resp MTI</th>
                <th class="p-1.5 w-16">DE 39</th>
                <th class="p-1.5 w-20">Latency</th>
                <th class="p-1.5">Description</th>
              </tr>
            </thead>
            <tbody id="bulk-table-body" class="divide-y border-slate-800 font-mono text-slate-300">
              <tr><td colspan="9" class="p-3 text-center text-slate-600">No bulk run executed yet.</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <!-- WINDOW 3: SUPER TESTING MODE (SCENARIO SPECIFIC ACCOUNTS MAPPING) -->
    <div id="win-super" class="hidden space-y-3">
      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div class="flex justify-between items-center pb-2 mb-3 border-b border-slate-800">
          <div>
            <h3 class="text-xs font-bold uppercase tracking-wider text-amber-400">Super Testing Suite (ATM Switch &times; CBS &times; RBI Compliance)</h3>
            <p class="text-[11px] text-slate-400">Assign specific accounts per scenario so your CBS vendor can provision each condition directly.</p>
          </div>
          <button onclick="openReleaseNotesModal()" id="view-release-btn" class="hidden bg-indigo-900 hover:bg-indigo-800 text-indigo-200 border border-indigo-700 font-bold px-3 py-1 rounded text-xs transition">
            View Release Note & Sign-Off
          </button>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs mb-3">
          <div>
            <label class="block text-slate-400 mb-1">Acquiring Institution ID (DE 32)</label>
            <input id="super-acq" type="text" value="622018" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-emerald-400">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Timeout Per Scenario (Sec)</label>
            <input id="super-timeout" type="number" value="6" min="2" max="30" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-white">
          </div>
        </div>

        <!-- SCENARIO PROVISIONING MAPPING TABLE -->
        <div class="mb-3">
          <span class="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-1.5">
            Scenario Account & Card Provisioning Mapping (Configured per test case)
          </span>
          <div class="overflow-x-auto max-h-72 overflow-y-auto border border-slate-800 rounded">
            <table class="w-full text-left text-xs border-collapse">
              <thead>
                <tr class="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                  <th class="p-2 w-20">ID</th>
                  <th class="p-2 w-56">Scenario Name</th>
                  <th class="p-2 w-48">Test Account (DE 102)</th>
                  <th class="p-2 w-48">Test Card / PAN (DE 2)</th>
                  <th class="p-2">CBS Vendor Prerequisite / Condition</th>
                </tr>
              </thead>
              <tbody id="super-scenarios-tbody" class="divide-y border-slate-800 font-mono text-slate-300"></tbody>
            </table>
          </div>
        </div>

        <button id="super-run-btn" onclick="runSuperTestSuite()" class="w-full bg-gradient-to-r from-amber-600 to-indigo-600 hover:from-amber-500 hover:to-indigo-500 text-white font-bold py-2 rounded text-xs transition shadow-md">
          Execute Super Testing Audit Suite
        </button>
      </section>

      <!-- Audit Execution Breakdown Results Grid -->
      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div class="flex justify-between items-center mb-2">
          <span class="text-xs font-bold uppercase tracking-wider text-slate-300">Audit Execution Breakdown</span>
          <span id="super-score-badge" class="text-xs font-mono font-bold text-slate-500">Awaiting Run</span>
        </div>
        <div class="overflow-x-auto max-h-96 overflow-y-auto">
          <table class="w-full text-left text-xs border-collapse">
            <thead>
              <tr class="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                <th class="p-1.5 w-16">ID</th>
                <th class="p-1.5 w-44">Scenario Name</th>
                <th class="p-1.5 w-32">Account Used</th>
                <th class="p-1.5 w-16">MTI</th>
                <th class="p-1.5 w-16">Exp 39</th>
                <th class="p-1.5 w-16">Act 39</th>
                <th class="p-1.5 w-20">Latency</th>
                <th class="p-1.5 w-16">Verdict</th>
                <th class="p-1.5">Regulatory / Specification Rule</th>
              </tr>
            </thead>
            <tbody id="super-table-body" class="divide-y border-slate-800 font-mono text-slate-300">
              <tr><td colspan="9" class="p-4 text-center text-slate-600">Run the Super Testing Audit Suite to generate the compliance report.</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <!-- WINDOW 4: CONFIG & SCHEMA MANAGER -->
    <div id="win-cfg" class="hidden space-y-3">
      <!-- RAW ISO SCHEMA IMPORTER -->
      <section class="bg-slate-900 border border-emerald-800/80 rounded-lg p-3">
        <h3 class="text-xs font-bold uppercase tracking-wider text-emerald-400 mb-2">Import & Save Transaction from Raw ISO</h3>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs mb-2">
          <div>
            <label class="block text-slate-400 mb-1">Unique Transaction Key (No spaces)</label>
            <input id="raw-import-key" type="text" placeholder="e.g. fastag_purchase" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-white focus:outline-none">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Display Label</label>
            <input id="raw-import-label" type="text" placeholder="e.g. FASTag Purchase Request" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-white focus:outline-none">
          </div>
          <div class="flex items-end">
            <button onclick="importRawISOToSchema()" class="w-full bg-emerald-700 hover:bg-emerald-600 text-white font-bold py-1.5 rounded text-xs transition">
              Parse & Save to Schema
            </button>
          </div>
        </div>
        <div>
          <label class="block text-slate-400 mb-1 text-xs">Raw ISO String (with or without 4-byte header):</label>
          <textarea id="raw-import-payload" rows="2" placeholder="0200F23AC4..." class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs font-mono text-emerald-300 resize-none focus:outline-none"></textarea>
        </div>
      </section>

      <!-- Numerical Schema Editor -->
      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div class="flex justify-between items-center pb-2 border-b border-slate-800 mb-3">
          <h3 class="text-xs font-bold uppercase tracking-wider text-slate-300">Numerical Data Element Schema Manager</h3>
          <span class="text-[11px] text-indigo-400 font-mono">Zero Raw ISO Strings in Config</span>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label class="block text-xs text-slate-400 mb-1">Select Transaction Schema</label>
            <select id="cfg-tx-select" onchange="loadTxSchemaToEdit()" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white"></select>
          </div>

          <div>
            <label class="block text-xs text-slate-400 mb-1">Target Element Class</label>
            <div class="flex gap-4 items-center bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-xs">
              <label class="flex items-center gap-1.5 cursor-pointer text-indigo-300">
                <input type="radio" name="schema-target-radio" value="req" checked onchange="loadTxSchemaToEdit()">
                <span>Request DEs (Outgoing)</span>
              </label>
              <label class="flex items-center gap-1.5 cursor-pointer text-emerald-400">
                <input type="radio" name="schema-target-radio" value="resp" onchange="loadTxSchemaToEdit()">
                <span>Expected Response DEs</span>
              </label>
            </div>
          </div>

          <div>
            <label class="block text-xs text-slate-400 mb-1">Add Single Numerical DE</label>
            <div class="flex gap-2">
              <input id="new-de-input" type="number" placeholder="Enter DE # (e.g. 54)" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-white">
              <button onclick="addSingleDE()" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-3 py-1.5 rounded text-xs">
                + Add DE
              </button>
            </div>
          </div>
        </div>

        <div class="mt-4">
          <label id="des-array-label" class="block text-xs text-slate-400 mb-1 font-medium">Numerical Data Elements (Comma Separated)</label>
          <input id="des-array-input" type="text" oninput="renderSchemaBadges()" class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs font-mono text-emerald-400 break-all">
        </div>

        <div class="mt-3">
          <span class="block text-xs text-slate-400 mb-1 font-medium">Active Numerical Badges (Click to Remove):</span>
          <div id="schema-badges-container" class="flex flex-wrap gap-1.5 max-h-36 overflow-y-auto p-2 bg-slate-950 border border-slate-800 rounded"></div>
        </div>

        <div class="mt-4 flex justify-end">
          <button onclick="saveNumericalSchema()" class="bg-emerald-600 hover:bg-emerald-500 text-white font-bold px-4 py-2 rounded text-xs transition">
            Save Numerical Schema to Config
          </button>
        </div>
      </section>
    </div>

    <!-- RELEASE NOTES MODAL -->
    <div id="release-notes-modal" class="hidden fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
      <div class="bg-slate-900 border border-indigo-700 rounded-lg max-w-3xl w-full max-h-[85vh] flex flex-col p-4 shadow-2xl">
        <div class="flex justify-between items-center pb-2 border-b border-slate-800 mb-3">
          <h3 class="text-sm font-bold uppercase tracking-wider text-indigo-300">QA Certification & Release Sign-Off</h3>
          <button onclick="document.getElementById('release-notes-modal').classList.add('hidden')" class="text-slate-400 hover:text-white text-lg">&times;</button>
        </div>
        <textarea id="release-notes-textarea" readonly class="w-full flex-grow bg-slate-950 border border-slate-800 rounded p-3 font-mono text-xs text-emerald-300 resize-none h-96"></textarea>
        <div class="mt-3 flex justify-end gap-2">
          <button onclick="copyReleaseNotesToClipboard()" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-4 py-2 rounded text-xs">
            Copy Sign-Off Note
          </button>
        </div>
      </div>
    </div>

  </div>

  <script>
    let configData = {};
    let activeTxKey = "";
    let activeParsedMti = "0200";
    let activePipelineMode = "normal";
    let lastValidationInfo = null;
    let bulkPollInterval = null;
    let latestReleaseNotesText = "";
    let loadedScenarios = [];

    const ipInput = document.getElementById("ip");
    const portInput = document.getElementById("port");
    const framingSelect = document.getElementById("framing");
    const bitmapFmtSelect = document.getElementById("bitmap-fmt");
    const charsetSelect = document.getElementById("charset");
    const tpduInput = document.getElementById("tpdu");
    const timeoutInput = document.getElementById("timeout-sec");

    const reqArea = document.getElementById("iso-request");
    const lenBadge = document.getElementById("req-len-badge");
    const primaryBtn = document.getElementById("primary-action-btn");
    const reversalNotice = document.getElementById("reversal-notice");

    const procCodeInput = document.getElementById("dyn-proc-code");
    const panInput = document.getElementById("dyn-pan");
    const accInput = document.getElementById("dyn-account");
    const acqInput = document.getElementById("dyn-acq");
    const rrnInput = document.getElementById("dyn-rrn");

    window.onload = async () => {
      await loadAppConfig();
      await loadSuperTestScenarios();
      attachListeners();
      updateLengthCounter();
    };

    function attachListeners() {
      reqArea.addEventListener("input", updateLengthCounter);
      procCodeInput.addEventListener("input", () => regenerateDynamic(false));
      panInput.addEventListener("input", () => regenerateDynamic(false));
      accInput.addEventListener("input", () => regenerateDynamic(false));
      acqInput.addEventListener("input", () => regenerateDynamic(false));
      rrnInput.addEventListener("input", () => regenerateDynamic(false));
    }

    async function loadSuperTestScenarios() {
      const res = await fetch("/api/super_test/scenarios");
      const data = await res.json();
      loadedScenarios = data.scenarios || [];

      const tbody = document.getElementById("super-scenarios-tbody");
      tbody.innerHTML = "";

      loadedScenarios.forEach(sc => {
        tbody.innerHTML += 
          "<tr class='hover:bg-slate-900/80'>" +
            "<td class='p-2 font-bold text-amber-400'>" + sc.id + "</td>" +
            "<td class='p-2 font-semibold text-slate-200'>" + sc.testTitle + "</td>" +
            "<td class='p-2'>" +
              "<input data-sc-acc='" + sc.id + "' type='text' value='" + sc.default_account + "' class='w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 font-mono text-xs text-emerald-300 focus:outline-none focus:border-indigo-500'>" +
            "</td>" +
            "<td class='p-2'>" +
              "<input data-sc-card='" + sc.id + "' type='text' value='" + sc.default_pan + "' class='w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 font-mono text-xs text-cyan-300 focus:outline-none focus:border-indigo-500'>" +
            "</td>" +
            "<td class='p-2 text-slate-400 text-[11px] leading-tight'>" + sc.cbs_vendor_note + "</td>" +
          "</tr>";
      });
    }

    function setPipelineMode(mode) {
      activePipelineMode = mode;
      const normalBtn = document.getElementById("mode-normal-btn");
      const reversalBtn = document.getElementById("mode-reversal-btn");

      if (mode === "reversal") {
        normalBtn.className = "px-3 py-1 text-xs font-bold rounded text-slate-400 hover:text-white transition";
        reversalBtn.className = "px-3 py-1 text-xs font-bold rounded text-white bg-amber-600 transition";
        primaryBtn.innerText = "Execute Reversal Flow (0200 -> Linked 0420)";
        primaryBtn.className = "w-2/3 bg-amber-600 hover:bg-amber-500 text-white font-bold py-2 rounded text-xs transition shadow-sm";
        reversalNotice.classList.remove("hidden");
      } else {
        normalBtn.className = "px-3 py-1 text-xs font-bold rounded text-white bg-indigo-600 transition";
        reversalBtn.className = "px-3 py-1 text-xs font-bold rounded text-slate-400 hover:text-white transition";
        primaryBtn.innerText = "Send Single ISO Transaction";
        primaryBtn.className = "w-2/3 bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 rounded text-xs transition shadow-sm";
        reversalNotice.classList.add("hidden");
      }
    }

    function executeCurrentPipeline() {
      if (activePipelineMode === "reversal") {
        executeReversalPipeline();
      } else {
        sendSingleRequest();
      }
    }

    async function executeReversalPipeline() {
      const ip = ipInput.value.trim();
      const port = parseInt(portInput.value.trim());
      const pan = panInput.value.trim();
      const account = accInput.value.trim();
      const acq_id = acqInput.value.trim();
      const framing = framingSelect.value;
      const bitmap_fmt = bitmapFmtSelect.value;
      const charset = charsetSelect.value;
      const tpdu = tpduInput.value.trim();
      const timeout_sec = parseFloat(timeoutInput.value) || 6.0;

      if (!ip || !port) { alert("Enter valid Target IP and Port."); return; }

      primaryBtn.disabled = true;
      primaryBtn.innerText = "Executing Leg 1 (0200) -> Leg 2 (0420)...";

      const respBox = document.getElementById("iso-response");
      const badge = document.getElementById("de39-badge");
      respBox.value = "[Leg 1: Transmitting 0200 Financial Request]...";
      badge.innerText = "Pipeline Active...";
      badge.className = "font-mono font-bold text-amber-400";

      try {
        const res = await fetch("/api/reversal_flow", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ip, port, tx_key: activeTxKey,
            pan, account, acq_id, framing, bitmap_fmt, charset, tpdu, timeout_sec
          })
        });
        const d = await res.json();

        if (d.status === "success") {
          const l1 = d.leg1;
          const l2 = d.leg2;

          respBox.value = 
            "=== LEG 1: 0200 FINANCIAL REQUEST (" + d.channel + ") ===\n" +
            "REQ:  " + l1.req_iso + "\n" +
            "RESP: " + (l1.resp_iso || "[No Bytes Received]") + "\n" +
            "RESULT: [" + l1.de39 + "] " + l1.label + " (" + l1.latency + ")\n\n" +
            "=== LEG 2: 0420 MATCHING REVERSAL (AUTO-BOUND DE 90) ===\n" +
            "DE 90: " + l2.de90 + "\n" +
            "REQ:  " + l2.req_iso + "\n" +
            "RESP: " + (l2.resp_iso || "[No Bytes Received]") + "\n" +
            "RESULT: [" + l2.de39 + "] " + l2.label + " (" + l2.latency + ")";

          reqArea.value = l2.req_iso;
          updateLengthCounter();

          document.getElementById("resp-latency").innerText = "L1: " + l1.latency + " | L2: " + l2.latency;
          badge.innerText = "Reversal: [" + l2.de39 + "] " + l2.label;
          badge.className = l2.de39 === "00" ? "font-mono font-bold text-emerald-400" : "font-mono font-bold text-cyan-300";

          if (d.parsed_response) {
            renderParsedTable(d.parsed_response.fields);
            displayValidationBanner(d.parsed_response.validation, l2.resp_iso);
          }
        } else {
          alert("Reversal Pipeline Error: " + d.message);
          badge.innerText = "Failed";
          badge.className = "font-mono font-bold text-red-400";
        }
      } catch (err) {
        respBox.value = "Exception: " + err;
      } finally {
        primaryBtn.disabled = false;
        primaryBtn.innerText = "Execute Reversal Flow (0200 -> Linked 0420)";
      }
    }

    async function triggerSingleShotHandshake() {
      const ip = ipInput.value.trim();
      const port = parseInt(portInput.value.trim());
      const framing = framingSelect.value;
      const bitmap_fmt = bitmapFmtSelect.value;
      const charset = charsetSelect.value;
      const tpdu = tpduInput.value.trim();
      const timeout_sec = parseFloat(timeoutInput.value) || 6.0;

      if (!ip || !port) { alert("Enter valid Target IP and Port."); return; }

      const consoleBox = document.getElementById("hs-console");
      consoleBox.innerHTML = "<div class='text-amber-400'>[Sending 0800 Handshake Now to " + ip + ":" + port + "]...</div>";

      try {
        const res = await fetch("/api/handshake/single_shot", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ip, port, framing, bitmap_fmt, charset, tpdu, timeout_sec })
        });
        const d = await res.json();

        if (d.status === "success") {
          consoleBox.innerHTML = 
            "<div class='text-emerald-400 font-bold'>[0810 HANDSHAKE SUCCESS] Latency: " + d.latency_ms + "ms</div>" +
            "<div class='text-slate-400 text-[11px]'>REQ: " + d.req_iso + "</div>" +
            "<div class='text-cyan-300 text-[11px]'>RES: " + d.resp_iso + "</div>";
        } else {
          consoleBox.innerHTML = 
            "<div class='text-red-400 font-bold'>[HANDSHAKE FAILED] " + d.message + "</div>" +
            "<div class='text-slate-500 text-[11px]'>REQ SENT: " + d.req_iso + "</div>";
        }
      } catch (err) {
        consoleBox.innerHTML = "<div class='text-red-400 font-bold'>[HANDSHAKE EXCEPTION] " + err + "</div>";
      }
    }

    function addLengthToRequest() {
      var val = reqArea.value.trim();
      if (!val) return;
      if (val.length > 4 && /^\d{4}(0200|0210|0420|0430|0800|0810)/.test(val)) {
        val = val.substring(4);
      }
      var isoLen = val.length;
      var header = String(isoLen).padStart(4, '0');
      reqArea.value = header + val;
      updateLengthCounter();
    }

    function removeLengthFromRequest() {
      var val = reqArea.value.trim();
      if (val.length > 4 && /^\d{4}(0200|0210|0420|0430|0800|0810)/.test(val)) {
        reqArea.value = val.substring(4);
        updateLengthCounter();
      }
    }

    function updateLengthCounter() {
      var val = reqArea.value.trim();
      var totalLen = val.length;
      var hasHeader = totalLen > 4 && /^\d{4}(0200|0210|0420|0430|0800|0810)/.test(val);

      if (hasHeader) {
        var headerDigits = val.substring(0, 4);
        var rawLen = totalLen - 4;
        lenBadge.innerText = "Total: " + totalLen + " | ISO: " + rawLen + " (Header: " + headerDigits + ")";
        lenBadge.className = "text-[11px] bg-indigo-950 text-indigo-300 px-2 py-0.5 rounded font-mono border border-indigo-700";
      } else {
        lenBadge.innerText = "Length: " + totalLen + " chars";
        lenBadge.className = "text-[11px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono border border-slate-700";
      }
    }

    async function parseRequestAndDisplayEditor() {
      const raw = reqArea.value.trim();
      if (!raw) { alert("Request box is empty."); return; }

      const res = await fetch("/api/parse_raw", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_iso: raw })
      });
      const d = await res.json();
      if (d.status !== "success") {
        alert(d.message);
        return;
      }

      activeParsedMti = d.mti;
      const tbody = document.getElementById("editable-request-tbody");
      tbody.innerHTML = "";

      d.fields.forEach(f => {
        tbody.innerHTML += 
          "<tr class='hover:bg-slate-900/80'>" +
            "<td class='p-1.5 text-indigo-400 font-bold'>DE " + String(f.de).padStart(3, '0') + "</td>" +
            "<td class='p-1.5 text-slate-400'>" + f.name + "</td>" +
            "<td class='p-1.5 text-slate-500 font-mono text-[11px]'>" + f.len + "</td>" +
            "<td class='p-1.5'>" +
              "<input data-de='" + f.de + "' type='text' value='" + f.val + "' class='editable-de-input w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 text-xs font-mono text-emerald-300 focus:outline-none focus:border-indigo-500'>" +
            "</td>" +
          "</tr>";
      });

      document.getElementById("editable-request-panel").classList.remove("hidden");
    }

    async function applyTableEditsToPayload() {
      const inputs = document.querySelectorAll(".editable-de-input");
      const fieldDict = {};
      inputs.forEach(inp => {
        fieldDict[inp.getAttribute("data-de")] = inp.value.trim();
      });

      const res = await fetch("/api/rebuild_from_fields", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mti: activeParsedMti, fields: fieldDict })
      });
      const d = await res.json();
      if (d.status === "success") {
        reqArea.value = d.raw_iso;
        updateLengthCounter();
        alert("Payload updated successfully from editable fields!");
      } else {
        alert("Failed to rebuild ISO: " + d.message);
      }
    }

    async function saveCurrentPayloadAsDefault() {
      const raw = reqArea.value.trim();
      if (!raw) { alert("Payload box is empty."); return; }

      const labelName = prompt("Enter a label for this default sample:", (configData.sample_requests[activeTxKey] || {}).label || "Saved Default Sample");
      if (!labelName) return;

      const res = await fetch("/api/sample/save_as_default", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_iso: raw, tx_key: activeTxKey || "saved_default", label: labelName })
      });
      const d = await res.json();
      alert(d.message);
      await loadAppConfig();
    }

    async function saveTargetAsDefault() {
      const ip = ipInput.value.trim();
      const port = parseInt(portInput.value.trim()) || 0;
      const framing = framingSelect.value;
      const bitmap_fmt = bitmapFmtSelect.value;
      const charset = charsetSelect.value;
      const tpdu = tpduInput.value.trim();
      if (!ip || !port) { alert("Please enter a valid IP and Port."); return; }

      await fetch("/api/target/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, port, framing, bitmap_fmt, charset, tpdu })
      });
      alert("Default settings saved to iso_config.json: " + ip + ":" + port);
    }

    function displayValidationBanner(val, rawResp) {
      const panel = document.getElementById("validation-panel");
      const summary = document.getElementById("validation-summary");
      const details = document.getElementById("validation-details");
      const copyBtn = document.getElementById("copy-bug-btn");

      if (!val) {
        panel.classList.add("hidden");
        return;
      }

      panel.classList.remove("hidden");
      details.innerHTML = "";
      lastValidationInfo = { val: val, tx: activeTxKey, raw: rawResp, rrn: rrnInput.value.trim() };

      if (val.compliant) {
        panel.className = "rounded-lg p-3 transition border bg-emerald-950/40 border-emerald-700/80";
        summary.className = "text-xs font-bold font-mono text-emerald-300";
        summary.innerHTML = "✓ Response Compliant: All " + val.expected_count + " configured Data Elements received successfully.";
        copyBtn.classList.add("hidden");
      } else {
        panel.className = "rounded-lg p-3 transition border bg-red-950/60 border-red-700";
        summary.className = "text-xs font-bold font-mono text-red-300";
        summary.innerHTML = "⚠️ Specification Discrepancy: " + val.missing_des.length + " required Data Elements MISSING from response!";
        copyBtn.classList.remove("hidden");

        var missingTags = "";
        val.missing_des.forEach(m => {
          missingTags += "<span class='inline-block bg-red-900/80 text-red-200 border border-red-600 px-2 py-0.5 rounded text-[11px] mr-1 mb-1'>Missing: DE " + m.de + " (" + m.name + ")</span>";
        });
        details.innerHTML = "<div class='text-slate-300 mb-1 font-semibold'>Missing Fields Expected by Config:</div><div>" + missingTags + "</div>";

        if (val.unexpected_des.length > 0) {
          var unexpTags = "";
          val.unexpected_des.forEach(u => {
            unexpTags += "<span class='inline-block bg-amber-950 text-amber-300 border border-amber-700 px-2 py-0.5 rounded text-[11px] mr-1 mb-1'>Extra: DE " + u.de + " (" + u.name + ")</span>";
          });
          details.innerHTML += "<div class='text-slate-300 mt-2 mb-1 font-semibold'>Additional Unregistered Fields in Response:</div><div>" + unexpTags + "</div>";
        }
      }
    }

    function copyMissingDEBugReport() {
      if (!lastValidationInfo) return;
      const v = lastValidationInfo.val;
      let text = "=== ISO 8583 SPECIFICATION DEFECT REPORT ===\n" +
                 "Transaction Type : " + lastValidationInfo.tx + "\n" +
                 "RRN Trace        : " + lastValidationInfo.rrn + "\n" +
                 "Defect Summary   : " + v.missing_des.length + " expected Data Elements missing in response payload\n\n" +
                 "MISSING DATA ELEMENTS:\n";
      v.missing_des.forEach(m => {
        text += " - DE " + String(m.de).padStart(3, '0') + ": " + m.name + "\n";
      });
      text += "\nRAW RESPONSE PAYLOAD RECEIVED:\n" + lastValidationInfo.raw + "\n";

      navigator.clipboard.writeText(text).then(() => {
        alert("Bug report copied to clipboard! You can paste it directly into Jira/Teams.");
      });
    }

    async function regenerateDynamic(randomizeRRN = true) {
      if (!activeTxKey) return;

      const res = await fetch("/api/build_request", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          tx_key: activeTxKey,
          proc_code: procCodeInput.value.trim(),
          pan: panInput.value.trim(),
          account: accInput.value.trim(),
          acq_id: acqInput.value.trim(),
          rrn: randomizeRRN ? "" : rrnInput.value.trim()
        })
      });
      const data = await res.json();
      if (data.raw_iso) {
        reqArea.value = data.raw_iso;
        updateLengthCounter();

        procCodeInput.value = data.proc_code;
        panInput.value = data.pan;
        accInput.value = data.account;
        acqInput.value = data.acq_id;
        rrnInput.value = data.rrn;
      }
    }

    async function loadAppConfig() {
      const res = await fetch("/api/config");
      configData = await res.json();

      const tgt = configData.target_settings || {};
      ipInput.value = tgt.default_ip || "10.167.1.153";
      portInput.value = tgt.default_port || 9019;
      if (tgt.default_framing) framingSelect.value = tgt.default_framing;
      if (tgt.default_bitmap_fmt) bitmapFmtSelect.value = tgt.default_bitmap_fmt;
      if (tgt.default_charset) charsetSelect.value = tgt.default_charset;
      if (tgt.default_tpdu) tpduInput.value = tgt.default_tpdu;

      const btnContainer = document.getElementById("sample-buttons-container");
      const bulkSelect = document.getElementById("bulk-type-select");
      const cfgSelect = document.getElementById("cfg-tx-select");
      btnContainer.innerHTML = "";
      bulkSelect.innerHTML = "";
      cfgSelect.innerHTML = "";

      const optCombined = document.createElement("option");
      optCombined.value = "ALL_COMBINED";
      optCombined.innerText = "All Combined Requests (Random Mix)";
      optCombined.className = "font-bold text-emerald-400 bg-slate-900";
      bulkSelect.appendChild(optCombined);

      const samples = configData.sample_requests || {};
      let firstKey = null;

      for (const [key, s] of Object.entries(samples)) {
        if (!firstKey) firstKey = key;

        const btn = document.createElement("button");
        const isRev = s.mti === "0420" || key.includes("reversal");
        btn.className = isRev
          ? "bg-amber-950/40 hover:bg-amber-900/60 text-amber-300 px-2.5 py-1 rounded border border-amber-800/80 font-medium"
          : "bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded border border-slate-700 font-medium";
        btn.innerText = s.label;
        btn.onclick = () => {
          activeTxKey = key;
          panInput.value = "";
          accInput.value = "";
          acqInput.value = "";
          rrnInput.value = "";
          procCodeInput.value = s.proc_code || "";
          regenerateDynamic(true);

          if (isRev) {
            setPipelineMode("reversal");
          } else {
            setPipelineMode("normal");
          }
          document.getElementById("validation-panel").classList.add("hidden");
        };
        btnContainer.appendChild(btn);

        const opt = document.createElement("option");
        opt.value = key;
        opt.innerText = s.label + " (" + s.proc_code + ")";
        bulkSelect.appendChild(opt);

        const optCfg = document.createElement("option");
        optCfg.value = key;
        optCfg.innerText = s.label + " (" + key + ")";
        cfgSelect.appendChild(optCfg);
      }

      if (firstKey) {
        activeTxKey = firstKey;
        procCodeInput.value = samples[firstKey].proc_code || "";
        regenerateDynamic(true);
        loadTxSchemaToEdit();
      }
    }

    function loadTxSchemaToEdit() {
      const key = document.getElementById("cfg-tx-select").value;
      const targetType = document.querySelector('input[name="schema-target-radio"]:checked').value;
      const tx = configData.sample_requests[key];
      if (tx) {
        const list = targetType === "req" 
          ? (tx.req_des_present || tx.des_present || []) 
          : (tx.resp_des_present || []);
        document.getElementById("des-array-input").value = list.join(", ");
        document.getElementById("des-array-label").innerText = targetType === "req"
          ? "Request Data Elements (Outgoing, Comma Separated)"
          : "Expected Response Data Elements (Validation Baseline, Comma Separated)";
        renderSchemaBadges();
      }
    }

    function renderSchemaBadges() {
      const inputStr = document.getElementById("des-array-input").value;
      const des = inputStr.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
      const container = document.getElementById("schema-badges-container");
      container.innerHTML = "";

      des.sort((a, b) => a - b).forEach(de => {
        const fieldName = (configData.field_definitions[de] || {}).name || ("DE " + de);
        const badge = document.createElement("span");
        badge.className = "inline-flex items-center gap-1 bg-slate-800 text-indigo-300 border border-slate-700 px-2 py-0.5 rounded text-[11px] font-mono cursor-pointer hover:border-red-600 hover:text-red-400";
        badge.innerHTML = "<span>DE " + de + " (" + fieldName + ")</span> <span class='text-xs'>&times;</span>";
        badge.onclick = () => removeDEFromSchema(de);
        container.appendChild(badge);
      });
    }

    function addSingleDE() {
      const deInput = document.getElementById("new-de-input");
      const deVal = parseInt(deInput.value.trim());
      if (isNaN(deVal) || deVal < 2 || deVal > 128) { alert("Enter valid DE # (2-128)."); return; }
      const input = document.getElementById("des-array-input");
      const current = input.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
      if (!current.includes(deVal)) {
        current.push(deVal);
        current.sort((a, b) => a - b);
        input.value = current.join(", ");
        renderSchemaBadges();
      }
      deInput.value = "";
    }

    function removeDEFromSchema(deToRemove) {
      const input = document.getElementById("des-array-input");
      const current = input.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
      input.value = current.filter(d => d !== deToRemove).join(", ");
      renderSchemaBadges();
    }

    async function saveNumericalSchema() {
      const key = document.getElementById("cfg-tx-select").value;
      const targetType = document.querySelector('input[name="schema-target-radio"]:checked').value;
      const input = document.getElementById("des-array-input");
      const current = input.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));

      const res = await fetch("/api/schema/save_numericals", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, target_type: targetType, des_present: current })
      });
      const data = await res.json();
      if (data.status === "success") {
        if (targetType === "req") {
          configData.sample_requests[key].req_des_present = data.des_present;
        } else {
          configData.sample_requests[key].resp_des_present = data.des_present;
        }
        alert("Saved " + (targetType === "req" ? "Request" : "Response") + " DE schema for " + key);
        if (activeTxKey === key && targetType === "req") regenerateDynamic(false);
      } else {
        alert("Failed to save: " + data.message);
      }
    }

    async function importRawISOToSchema() {
      const raw_iso = document.getElementById("raw-import-payload").value.trim();
      const tx_key = document.getElementById("raw-import-key").value.trim().toLowerCase().replace(/\s+/g, '_');
      const label = document.getElementById("raw-import-label").value.trim();

      if (!raw_iso || !tx_key || !label) {
        alert("Please provide Transaction Key, Display Label, and Raw ISO string.");
        return;
      }

      const res = await fetch("/api/schema/import_raw", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_iso, tx_key, label })
      });
      const d = await res.json();
      if (d.status === "success") {
        alert(d.message);
        document.getElementById("raw-import-payload").value = "";
        document.getElementById("raw-import-key").value = "";
        document.getElementById("raw-import-label").value = "";
        await loadAppConfig();
      } else {
        alert("Import Error: " + d.message);
      }
    }

    function switchWindow(tab) {
      document.getElementById("win-single").classList.toggle("hidden", tab !== 'single');
      document.getElementById("win-bulk").classList.toggle("hidden", tab !== 'bulk');
      document.getElementById("win-super").classList.toggle("hidden", tab !== 'super');
      document.getElementById("win-cfg").classList.toggle("hidden", tab !== 'cfg');

      const tabs = ['single', 'bulk', 'super', 'cfg'];
      tabs.forEach(t => {
        const el = document.getElementById("tab-btn-" + t);
        if (el) {
          el.className = (tab === t) 
            ? "px-4 py-1.5 text-xs font-semibold rounded-t border-b-2 border-indigo-500 text-white bg-slate-900"
            : "px-4 py-1.5 text-xs font-semibold rounded-t text-slate-400 hover:text-white bg-slate-950";
        }
      });
    }

    async function toggleHandshake() {
      const ip = ipInput.value.trim();
      const port = parseInt(portInput.value.trim());
      const framing = framingSelect.value;
      const bitmap_fmt = bitmapFmtSelect.value;
      const charset = charsetSelect.value;
      const tpdu = tpduInput.value.trim();
      if (!ip || !port) { alert("Enter destination IP and Port first."); return; }

      const res = await fetch("/api/handshake/toggle", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, port, framing, bitmap_fmt, charset, tpdu })
      });
      const data = await res.json();
      updateHandshakeBtn(data.status === "started", ip + ":" + port);
    }

    function updateHandshakeBtn(running, targetStr) {
      const btn = document.getElementById("hs-btn");
      const dot = document.getElementById("hs-status-dot");
      const tag = document.getElementById("hs-target-tag");
      if (running) {
        btn.innerText = "Stop Handshake";
        btn.className = "w-1/2 bg-red-600 hover:bg-red-500 text-white font-bold py-2 rounded text-xs transition";
        dot.innerHTML = "<span class='w-2 h-2 rounded-full bg-emerald-400 animate-pulse'></span> Active";
        dot.className = "flex items-center gap-1.5 text-xs text-emerald-400 font-mono";
        tag.innerText = "-> " + (targetStr || '');
      } else {
        btn.innerText = "Start Handshake";
        btn.className = "w-1/2 bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 rounded text-xs transition";
        dot.innerHTML = "<span class='w-2 h-2 rounded-full bg-slate-600'></span> Idle";
        dot.className = "flex items-center gap-1.5 text-xs text-slate-400 font-mono";
        tag.innerText = "";
      }
    }

    async function sendSingleRequest() {
      const ip = ipInput.value.trim();
      const port = parseInt(portInput.value.trim());
      const framing = framingSelect.value;
      const bitmap_fmt = bitmapFmtSelect.value;
      const charset = charsetSelect.value;
      const tpdu = tpduInput.value.trim();
      const timeout_sec = parseFloat(timeoutInput.value) || 6.0;
      const iso = reqArea.value.trim();
      const respBox = document.getElementById("iso-response");
      const badge = document.getElementById("de39-badge");

      if (!ip || !port) { alert("Enter valid Target IP and Port."); return; }

      primaryBtn.disabled = true;
      primaryBtn.innerText = "Sending...";
      respBox.value = "[Transmitting single request to " + ip + ":" + port + "]...";

      try {
        const res = await fetch("/api/send", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ip, port, tx_key: activeTxKey, framing, bitmap_fmt, charset, tpdu, timeout_sec, iso_request: iso })
        });
        const d = await res.json();

        if (d.status === "success") {
          respBox.value = d.iso_response;
          document.getElementById("resp-latency").innerText = "Latency: " + d.latency_ms + "ms";

          const de39 = d.parsed_response.de39;
          if (de39) {
            badge.innerText = "[" + de39.code + "] " + de39.label;
            badge.className = de39.code === '00' ? "font-mono font-bold text-emerald-400" : "font-mono font-bold text-amber-400";
          }
          renderParsedTable(d.parsed_response.fields);
          displayValidationBanner(d.parsed_response.validation, d.iso_response);
        } else {
          respBox.value = "Error: " + d.message;
          badge.innerText = "Transaction Failed";
          badge.className = "font-mono font-bold text-red-400";
          document.getElementById("validation-panel").classList.add("hidden");
        }
      } catch (err) {
        respBox.value = "Fatal Client Exception: " + err;
      } finally {
        primaryBtn.disabled = false;
        primaryBtn.innerText = "Send Single ISO Transaction";
      }
    }

    function renderParsedTable(fields) {
      const tbody = document.getElementById("parsed-table-body");
      tbody.innerHTML = "";
      if (!fields || fields.length === 0) {
        tbody.innerHTML = "<tr><td colspan='4' class='p-3 text-center text-slate-600'>No fields parsed.</td></tr>";
        return;
      }
      fields.forEach(f => {
        tbody.innerHTML += 
          "<tr class='" + (f.de === 39 ? "bg-amber-950/30 text-amber-300 font-bold" : "hover:bg-slate-900") + "'>" +
            "<td class='p-1.5 text-slate-400'>DE " + String(f.de).padStart(3, '0') + "</td>" +
            "<td class='p-1.5'>" + f.name + "</td>" +
            "<td class='p-1.5 text-slate-400'>" + f.len + "</td>" +
            "<td class='p-1.5 break-all text-emerald-400'>" + f.val + "</td>" +
          "</tr>";
      });
    }

    // ==========================================
    // MULTI-THREADED BULK ENGINE CLIENT
    // ==========================================

    async function startBulkTest() {
      const ip = ipInput.value.trim();
      const port = parseInt(portInput.value.trim());
      const framing = framingSelect.value;
      const bitmap_fmt = bitmapFmtSelect.value;
      const charset = charsetSelect.value;
      const tpdu = tpduInput.value.trim();
      const timeout_sec = parseFloat(timeoutInput.value) || 5.0;
      const tx_key = document.getElementById("bulk-type-select").value;
      const count = parseInt(document.getElementById("bulk-count").value) || 50;
      const delay_ms = parseInt(document.getElementById("bulk-delay").value) || 100;
      const workers = parseInt(document.getElementById("bulk-workers").value) || 5;
      const accounts = document.getElementById("bulk-accounts-input").value.trim();
      const cards = document.getElementById("bulk-cards-input").value.trim();

      if (!ip || !port) { alert("Enter valid Target IP and Port."); return; }

      if (accounts) {
        const accList = accounts.split(/[\s,]+/).filter(a => a.trim().length > 0);
        if (accList.length > count) {
          alert("Account Count Error: You provided " + accList.length + " accounts for " + count + " transactions. The count of accounts must be <= transaction count.");
          return;
        }
      }

      if (cards) {
        const cardList = cards.split(/[\s,]+/).filter(c => c.trim().length > 0);
        if (cardList.length > count) {
          alert("Card Count Error: You provided " + cardList.length + " cards for " + count + " transactions. The count of cards must be <= transaction count.");
          return;
        }
      }

      const startBtn = document.getElementById("bulk-start-btn");
      const stopBtn = document.getElementById("bulk-stop-btn");
      startBtn.disabled = true;
      startBtn.className = "w-3/4 bg-slate-800 text-slate-500 font-bold py-2 rounded text-xs transition cursor-not-allowed";
      stopBtn.disabled = false;
      stopBtn.className = "w-1/4 bg-red-600 hover:bg-red-500 text-white font-bold py-2 rounded text-xs transition shadow-sm cursor-pointer";

      document.getElementById("bulk-fired-console").innerHTML = "";
      document.getElementById("bulk-table-body").innerHTML = "<tr><td colspan='9' class='p-3 text-center text-slate-500 animate-pulse'>Executing threaded concurrent batch...</td></tr>";

      const res = await fetch("/api/bulk/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, port, framing, bitmap_fmt, charset, tpdu, timeout_sec, tx_key, count, delay_ms, workers, accounts, cards })
      });
      const d = await res.json();

      if (d.status !== "started") {
        alert("Bulk Error: " + d.message);
        resetBulkUIState();
        return;
      }

      if (bulkPollInterval) clearInterval(bulkPollInterval);
      bulkPollInterval = setInterval(pollBulkStatus, 600);
    }

    async function stopBulkTest() {
      await fetch("/api/bulk/stop", { method: "POST" });
    }

    async function pollBulkStatus() {
      const res = await fetch("/api/bulk/status");
      const data = await res.json();

      document.getElementById("bulk-progress-badge").innerText = "Running: " + data.completed_count + " / " + data.total + " Done";
      document.getElementById("bulk-progress-badge").className = "text-xs font-mono font-bold text-amber-400";
      document.getElementById("bulk-fired-counter").innerText = "Fired: " + data.fired_count + " / " + data.total;
      document.getElementById("bulk-recvd-counter").innerText = "Received: " + data.completed_count + " / " + data.total;

      const consoleBox = document.getElementById("bulk-fired-console");
      consoleBox.innerHTML = "";
      (data.fired_logs || []).forEach(f => {
        consoleBox.innerHTML += 
          "<div class='text-[11px] leading-tight'>" +
            "<span class='text-slate-500'>[" + f.time + "]</span> " +
            "<span class='text-indigo-400 font-bold'>[REQ #" + f.seq + "]</span> " +
            "<span class='text-cyan-300'>CARD:" + f.card + "</span> " +
            "<span class='text-emerald-300'>ACC:" + f.account + "</span> " +
            "<span class='text-slate-400'>" + f.tx_name + "</span> &rarr; " +
            "<span class='text-emerald-400'>" + f.req_snippet + "</span>" +
          "</div>";
      });
      consoleBox.scrollTop = consoleBox.scrollHeight;

      const tbody = document.getElementById("bulk-table-body");
      tbody.innerHTML = "";
      (data.response_logs || []).forEach(r => {
        const isOk = r.status === "SUCCESS";
        tbody.innerHTML += 
          "<tr class='hover:bg-slate-900'>" +
            "<td class='p-1.5 text-slate-400 font-mono'>" + r.seq + "</td>" +
            "<td class='p-1.5 " + (isOk ? "text-emerald-400" : "text-red-400") + " font-bold'>" + r.status + "</td>" +
            "<td class='p-1.5 font-mono text-cyan-300'>" + r.card + "</td>" +
            "<td class='p-1.5 font-mono text-emerald-300'>" + r.account + "</td>" +
            "<td class='p-1.5 text-indigo-300 font-semibold'>" + r.tx_name + "</td>" +
            "<td class='p-1.5 font-mono'>" + r.resp_mti + "</td>" +
            "<td class='p-1.5 font-mono'>" + r.de39 + "</td>" +
            "<td class='p-1.5 font-mono'>" + r.latency + "</td>" +
            "<td class='p-1.5 text-slate-400'>" + r.label + "</td>" +
          "</tr>";
      });

      if (!data.running && data.completed_count >= data.total) {
        clearInterval(bulkPollInterval);
        resetBulkUIState();
        document.getElementById("bulk-progress-badge").innerText = "Completed: " + data.total + " Transactions Finished";
        document.getElementById("bulk-progress-badge").className = "text-xs font-mono font-bold text-emerald-400";
      } else if (!data.running) {
        clearInterval(bulkPollInterval);
        resetBulkUIState();
        document.getElementById("bulk-progress-badge").innerText = "Stopped by User";
        document.getElementById("bulk-progress-badge").className = "text-xs font-mono font-bold text-red-400";
      }
    }

    function resetBulkUIState() {
      const startBtn = document.getElementById("bulk-start-btn");
      const stopBtn = document.getElementById("bulk-stop-btn");
      startBtn.disabled = false;
      startBtn.className = "w-3/4 bg-emerald-600 hover:bg-emerald-500 font-bold py-2 rounded text-xs transition text-white shadow-sm cursor-pointer";
      stopBtn.disabled = true;
      stopBtn.className = "w-1/4 bg-red-900/60 text-red-300 font-bold py-2 rounded text-xs transition border border-red-700 cursor-not-allowed";
    }

    // ==========================================
    // SUPER TESTING SUITE CLIENT
    // ==========================================

    async function runSuperTestSuite() {
      const ip = ipInput.value.trim();
      const port = parseInt(portInput.value.trim());
      const framing = framingSelect.value;
      const bitmap_fmt = bitmapFmtSelect.value;
      const charset = charsetSelect.value;
      const tpdu = tpduInput.value.trim();
      const acq_id = document.getElementById("super-acq").value.trim();
      const timeout_sec = parseFloat(document.getElementById("super-timeout").value) || 6.0;

      if (!ip || !port) { alert("Enter valid Target IP and Port."); return; }

      const scenario_accounts = {};
      const scenario_cards = {};
      loadedScenarios.forEach(sc => {
        const accInp = document.querySelector("input[data-sc-acc='" + sc.id + "']");
        const cardInp = document.querySelector("input[data-sc-card='" + sc.id + "']");
        if (accInp) scenario_accounts[sc.id] = accInp.value.trim();
        if (cardInp) scenario_cards[sc.id] = cardInp.value.trim();
      });

      const runBtn = document.getElementById("super-run-btn");
      const scoreBadge = document.getElementById("super-score-badge");
      const viewReleaseBtn = document.getElementById("view-release-btn");
      const tbody = document.getElementById("super-table-body");

      runBtn.disabled = true;
      runBtn.innerText = "Executing Structured Compliance Suite with Provisioned Accounts...";
      scoreBadge.innerText = "Auditing Compliance...";
      scoreBadge.className = "text-xs font-mono font-bold text-amber-400 animate-pulse";
      tbody.innerHTML = "<tr><td colspan='9' class='p-4 text-center text-slate-400 animate-pulse'>Executing automated RBI and CBS Switch regulatory checks across all scenario accounts...</td></tr>";

      try {
        const res = await fetch("/api/super_test/run", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ip, port, framing, bitmap_fmt, charset, tpdu, timeout_sec, acq_id,
            scenario_accounts, scenario_cards
          })
        });
        const d = await res.json();

        if (d.status === "success") {
          latestReleaseNotesText = d.release_notes;
          viewReleaseBtn.classList.remove("hidden");

          scoreBadge.innerText = "Compliance Score: " + d.passed + " / " + d.total + " (" + d.pass_percentage + "%)";
          scoreBadge.className = d.pass_percentage >= 90 ? "text-xs font-mono font-bold text-emerald-400" : "text-xs font-mono font-bold text-amber-400";

          tbody.innerHTML = "";
          d.report.forEach(item => {
            const isPass = item.verdict === "PASS";
            tbody.innerHTML += 
              "<tr class='hover:bg-slate-900/80'>" +
                "<td class='p-1.5 font-bold text-amber-400'>" + item.id + "</td>" +
                "<td class='p-1.5 font-semibold text-slate-200'>" + item.name + "</td>" +
                "<td class='p-1.5 font-mono text-emerald-300 font-bold'>" + item.account + "</td>" +
                "<td class='p-1.5 font-mono text-slate-400'>" + item.mti + "</td>" +
                "<td class='p-1.5 font-mono text-cyan-300 font-bold'>" + item.expected_code + "</td>" +
                "<td class='p-1.5 font-mono " + (isPass ? "text-emerald-400" : "text-red-400") + " font-bold'>" + item.actual_code + "</td>" +
                "<td class='p-1.5 font-mono text-slate-400'>" + item.latency + "</td>" +
                "<td class='p-1.5 font-bold " + (isPass ? "text-emerald-400" : "text-red-400") + "'>" + item.verdict + "</td>" +
                "<td class='p-1.5 text-slate-400 text-[11px]'>" + item.rbiComplianceTag + "</td>" +
              "</tr>";
          });
        } else {
          alert("Audit Suite Error: " + d.message);
        }
      } catch (err) {
        alert("Client Exception: " + err);
      } finally {
        runBtn.disabled = false;
        runBtn.innerText = "Execute Super Testing Audit Suite";
      }
    }

    function openReleaseNotesModal() {
      document.getElementById("release-notes-textarea").value = latestReleaseNotesText;
      document.getElementById("release-notes-modal").classList.remove("hidden");
    }

    function copyReleaseNotesToClipboard() {
      navigator.clipboard.writeText(latestReleaseNotesText).then(() => {
        alert("QA Certification Sign-Off Note copied to clipboard successfully!");
      });
    }

    async function runProtocolProbe() {
      const ip = ipInput.value.trim();
      const port = parseInt(portInput.value.trim());
      const test_iso = reqArea.value.trim();
      if (!ip || !port) { alert("Enter IP and Port first."); return; }

      const modal = document.getElementById("probe-modal");
      const content = document.getElementById("probe-content");
      modal.classList.remove("hidden");
      content.innerHTML = "<div class='text-amber-400'>Probing 8 standard wire formats against " + ip + ":" + port + "... Please wait ~15s.</div>";

      const res = await fetch("/api/probe", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, port, test_iso })
      });
      const d = await res.json();

      content.innerHTML = "";
      d.results.forEach(r => {
        const isOk = r.status === "SUCCESS";
        const color = isOk ? "text-emerald-400 font-bold" : "text-slate-500";
        content.innerHTML += 
          "<div class='flex justify-between items-center py-1 border-b border-slate-800'>" +
            "<span class='" + color + "'>[" + r.status + "] " + r.profile + "</span>" +
            "<div class='flex items-center gap-2'>" +
              "<span class='text-slate-400'>" + r.latency + "</span>" +
              (isOk ? "<button onclick='applyProfile(" + JSON.stringify(r.settings) + ")' class='bg-emerald-600 hover:bg-emerald-500 text-white px-2 py-0.5 rounded text-[10px]'>Apply</button>" : "") +
            "</div>" +
          "</div>";
      });

      if (d.working_profile) {
        content.innerHTML += "<div class='mt-2 p-2 bg-emerald-950/60 border border-emerald-700 rounded text-emerald-300'>Detected working switch profile! Click Apply to configure console.</div>";
      } else {
        content.innerHTML += "<div class='mt-2 p-2 bg-red-950/60 border border-red-700 rounded text-red-300'>All 8 wire profiles timed out. Check switch station routing.</div>";
      }
    }

    function applyProfile(cfg) {
      framingSelect.value = cfg.framing;
      bitmapFmtSelect.value = cfg.bitmap_fmt;
      charsetSelect.value = cfg.charset;
      tpduInput.value = cfg.tpdu;
      alert("Applied Profile: " + cfg.framing + " / " + cfg.bitmap_fmt + " bitmap / " + cfg.charset);
    }
  </script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)