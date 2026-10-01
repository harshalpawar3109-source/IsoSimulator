import socket
import struct
import time
import json
import os
import random
import re
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "iso_config.json")
LOGS_BASE_DIR = os.path.join(BASE_DIR, "logs")

DEFAULT_CONFIG = {
  "target_settings": {
    "default_ip": "10.167.1.153",
    "default_port": 9019,
    "default_framing": "ascii_4",
    "default_bitmap_fmt": "hex_ascii",
    "default_charset": "ascii",
    "default_tpdu": "",
    "default_timeout": 6.0
  },
  "handshake_settings": {
    "mti": "0800",
    "network_code": "001",
    "interval_seconds": 5
  },
  "field_definitions": {
    "2": { "name": "Primary Account Number (PAN)", "type": "llvar", "len": 2 },
    "3": { "name": "Processing Code", "type": "fixed", "len": 6 },
    "4": { "name": "Amount, Transaction", "type": "fixed", "len": 12 },
    "7": { "name": "Transmission Date & Time", "type": "fixed", "len": 10 },
    "11": { "name": "System Trace Audit Number (STAN)", "type": "fixed", "len": 6 },
    "12": { "name": "Time, Local Transaction", "type": "fixed", "len": 6 },
    "13": { "name": "Date, Local Transaction", "type": "fixed", "len": 4 },
    "14": { "name": "Date, Expiration", "type": "fixed", "len": 4 },
    "15": { "name": "Date, Settlement", "type": "fixed", "len": 4 },
    "17": { "name": "Date, Capture", "type": "fixed", "len": 4 },
    "18": { "name": "Merchant Type (MCC)", "type": "fixed", "len": 4 },
    "22": { "name": "POS Entry Mode", "type": "fixed", "len": 3 },
    "25": { "name": "POS Condition Code", "type": "fixed", "len": 2 },
    "32": { "name": "Acquiring Institution ID Code", "type": "llvar", "len": 2 },
    "35": { "name": "Track 2 Data", "type": "llvar", "len": 2 },
    "37": { "name": "Retrieval Reference Number (RRN)", "type": "fixed", "len": 12 },
    "38": { "name": "Authorization ID Response", "type": "fixed", "len": 6 },
    "39": { "name": "Response Code", "type": "fixed", "len": 2 },
    "41": { "name": "Card Acceptor Terminal ID", "type": "fixed", "len": 8 },
    "42": { "name": "Card Acceptor ID Code", "type": "fixed", "len": 15 },
    "43": { "name": "Card Acceptor Name/Location", "type": "fixed", "len": 40 },
    "48": { "name": "Additional Data - Private", "type": "lllvar", "len": 3 },
    "49": { "name": "Currency Code, Transaction", "type": "fixed", "len": 3 },
    "54": { "name": "Additional Amounts", "type": "lllvar", "len": 3 },
    "60": { "name": "Additional POS / Reserved Private", "type": "lllvar", "len": 3 },
    "63": { "name": "Reserved Private (Mini-Statement)", "type": "lllvar", "len": 3 },
    "70": { "name": "Network Management Information Code", "type": "fixed", "len": 3 },
    "90": { "name": "Original Data Elements", "type": "fixed", "len": 42 },
    "102": { "name": "Account Identification 1", "type": "llvar", "len": 2 },
    "120": { "name": "Reserved Private", "type": "lllvar", "len": 3 }
  },
  "sample_requests": {
    "balance_inquiry": {
      "label": "Balance Enquiry Request",
      "mti": "0200",
      "proc_code": "311000",
      "req_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 41, 42, 43, 48, 49, 60, 102],
      "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 102]
    },
    "cash_withdrawal": {
      "label": "Cash Withdrawal Request",
      "mti": "0200",
      "proc_code": "011000",
      "req_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 41, 42, 43, 48, 49, 60, 102],
      "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 102]
    },
    "mini_statement": {
      "label": "Mini Statement Request",
      "mti": "0200",
      "proc_code": "380000",
      "req_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 41, 42, 43, 48, 49, 60, 102, 120],
      "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 63, 102, 120]
    },
    "issuer_reversal": {
      "label": "Issuer Reversal (0420)",
      "mti": "0420",
      "base_tx": "cash_withdrawal",
      "proc_code": "011000",
      "req_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 37, 38, 39, 41, 42, 43, 48, 49, 60, 90, 102],
      "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 37, 38, 39, 41, 42, 43, 49, 54, 60, 90, 102]
    },
    "pos_purchase": {
      "label": "POS Purchase Request",
      "mti": "0200",
      "proc_code": "000000",
      "req_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 35, 37, 41, 42, 43, 48, 49, 60, 102],
      "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 35, 37, 39, 41, 42, 43, 48, 49, 54, 60, 102]
    },
    "pos_reversal": {
      "label": "POS Reversal (0420)",
      "mti": "0420",
      "base_tx": "pos_purchase",
      "proc_code": "000000",
      "req_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 37, 38, 39, 41, 42, 43, 48, 49, 60, 90, 102],
      "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 37, 38, 39, 41, 42, 43, 48, 49, 54, 60, 90, 102]
    },
    "ecom_purchase": {
      "label": "E-Commerce Purchase",
      "mti": "0200",
      "proc_code": "000000",
      "req_des_present": [2, 3, 4, 7, 11, 12, 13, 14, 15, 17, 18, 22, 25, 32, 37, 41, 42, 43, 48, 49, 60, 102],
      "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 14, 15, 17, 18, 22, 25, 32, 37, 39, 41, 42, 43, 48, 49, 54, 60, 102]
    },
    "ecom_reversal": {
      "label": "E-Commerce Reversal (0420)",
      "mti": "0420",
      "base_tx": "ecom_purchase",
      "proc_code": "000000",
      "req_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 37, 39, 41, 42, 43, 48, 49, 60, 90, 102],
      "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 37, 39, 41, 42, 43, 48, 49, 60, 90, 102]
    }
  }
}

def load_config():
    cfg = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}

    if not cfg or not cfg.get("sample_requests"):
        cfg = DEFAULT_CONFIG
        save_config(cfg)
    else:
        for k, v in DEFAULT_CONFIG.items():
            if k not in cfg:
                cfg[k] = v
    return cfg

def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

def write_partitioned_log(category: str, entry: str):
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

RBI_CODES = {
    "00": {"label": "Approved / Successful", "cat": "SUCCESS"},
    "05": {"label": "Do Not Honor", "cat": "CUSTOMER DECLINE"},
    "06": {"label": "Error / Verification Decline", "cat": "TECHNICAL FAILURE"},
    "09": {"label": "Request In Progress", "cat": "SYSTEM STATUS"},
    "14": {"label": "Invalid Card / Account Number", "cat": "CUSTOMER DECLINE"},
    "15": {"label": "No Such Issuer / Switch Routing Error", "cat": "ROUTING DECLINE"},
    "21": {"label": "No Action Taken", "cat": "SYSTEM STATUS"},
    "46": {"label": "Stolen Card", "cat": "CUSTOMER DECLINE"},
    "51": {"label": "Insufficient Funds", "cat": "CUSTOMER DECLINE"},
    "52": {"label": "No Checking Account", "cat": "CUSTOMER DECLINE"},
    "53": {"label": "No Savings Account / Blocked", "cat": "CUSTOMER DECLINE"},
    "54": {"label": "Expired Card", "cat": "CUSTOMER DECLINE"},
    "55": {"label": "Incorrect PIN / Retry Exceeded", "cat": "CUSTOMER DECLINE"},
    "57": {"label": "Transaction Not Permitted to Cardholder", "cat": "CUSTOMER DECLINE"},
    "61": {"label": "Exceeds Withdrawal Amount Limit", "cat": "CUSTOMER DECLINE"},
    "62": {"label": "Restricted Card / Freeze Account", "cat": "CUSTOMER DECLINE"},
    "68": {"label": "Timeout / Late Response", "cat": "TECHNICAL FAILURE"},
    "91": {"label": "Issuer or Switch Inoperative", "cat": "TECHNICAL FAILURE"},
    "92": {"label": "Financial Institution Cannot Be Routed", "cat": "ROUTING DECLINE"},
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
    if len(cleaned) > 4 and cleaned[:4].isdigit() and cleaned[4:8] in ('0200', '0210', '0220', '0420', '0430', '0800', '0810'):
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
        39: custom.get("de39") or ("E2" if mti in ("0420", "0220") else "00"),
        41: custom.get("terminal_id") or ("00558004" if str(proc_code).startswith("01") else "EP069184"),
        42: "S1BN000558004  " if str(proc_code).startswith("01") else "100000000113491",
        43: "MURUD JANJIRA          RAIGARH      MHIN" if str(proc_code).startswith("01") else "M S HASTIMAL MANIKCHANDRAIGAD       MHIN",
        48: "CASHNET                 40000035600000000000",
        49: "356",
        60: "EUROPRO1+000",
        90: custom.get("de90") or f"0200{str(stan).zfill(6)}{now.strftime('%m%d%H%M%S')}{str(acq_id).zfill(11)[-11:]}{'0'*11}",
        102: str(account),
        120: "00100207002003GDN"
    }

    for de in sorted(des_present):
        if de in generators:
            fields[de] = generators[de]

    return format_iso_dict(mti, fields), fields

def pack_payload(raw_iso: str, framing: str = "ascii_4", bitmap_fmt: str = "hex_ascii", charset: str = "ascii", tpdu: str = "") -> bytes:
    cleaned = raw_iso.strip()
    has_manual_4digit_header = False

    if len(cleaned) > 4 and cleaned[:4].isdigit() and cleaned[4:8] in ('0200', '0210', '0220', '0420', '0430', '0800', '0810'):
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
        if any(m in sample_ebcdic for m in ('0210', '0230', '0430', '0810')):
            is_ebcdic = True
    except Exception:
        pass

    if is_ebcdic:
        decoded_str = raw_bytes.decode('cp500', errors='ignore')
        for marker in ('0210', '0230', '0430', '0810'):
            pos = decoded_str.find(marker)
            if pos != -1:
                return decoded_str[pos:]
        return decoded_str

    for marker in (b'0210', b'0230', b'0430', b'0810'):
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
            de39_info = RBI_CODES.get(val, {"label": "Other / Switch Specific", "cat": "UNDEFINED"})
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

# ==============================================================
# CONSOLIDATED DISTINCT ACCOUNT PROFILES & SUPER TESTING SCENARIOS
# ==============================================================

DISTINCT_ACCOUNT_PROFILES = {
    "standard": {
        "title": "Standard Active Account",
        "description": "General active savings/current account. Used for all standard approved financial, non-financial, and reversal flows.",
        "default_pan": "6076070030053234",
        "default_account": "003002300008773"
    },
    "quota_lien": {
        "title": "Quota Exhausted Account (>3 Metro / >5 Non-Metro)",
        "description": "Used to validate interchange charges and CBS lien marking (hold) upon quota exhaustion.",
        "default_pan": "6076070030053234",
        "default_account": "003002300008774"
    },
    "closed": {
        "title": "Closed Account",
        "description": "Account flagged as Closed in CBS. Validates rejection with RC 14 or RC 52/53.",
        "default_pan": "6076070030053234",
        "default_account": "003002300008775"
    },
    "freeze": {
        "title": "Total / Debit Freeze Account",
        "description": "Account under full or debit freeze in CBS. Validates rejection with RC 62 or RC 57.",
        "default_pan": "6076070030053234",
        "default_account": "003002300008776"
    },
    "insufficient": {
        "title": "Low Balance / Insufficient for Charges Account",
        "description": "Account balance cannot cover transaction amount plus applicable surcharge. Validates RC 51.",
        "default_pan": "6076070030053234",
        "default_account": "003002300008777"
    },
    "min_bal": {
        "title": "Minimum Balance Floor Breach Account",
        "description": "Withdrawal amount breaches mandatory minimum balance floor. Validates RC 51, RC 61, or RC 00 with penalty.",
        "default_pan": "6076070030053234",
        "default_account": "003002300008778"
    },
    "invalid_bin": {
        "title": "Invalid / Unallocated BIN Card",
        "description": "Card PAN with non-existent or unrouted BIN prefix. Validates RC 14, RC 15, or RC 92.",
        "default_pan": "6076070999999999",
        "default_account": "003002300008779"
    }
}

SUPER_TEST_SCENARIOS = [
    {
        "id": "TC_POS_ATM_BAL_00",
        "name": "Balance Enquiry - Standard Approved",
        "group": "standard", "channel": "ATM", "mti": "0200", "proc_code": "311000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000000000",
        "expected_codes": ["00"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 102],
        "cbs_vendor_note": "Positive non-financial: Balance Enquiry fulfilled with RC 00. DE 54 returns Ledger & Available balance in 356 (INR)."
    },
    {
        "id": "TC_POS_ATM_CW_00",
        "name": "Issuer Cash Withdrawal - Standard Approved",
        "group": "standard", "channel": "ATM", "mti": "0200", "proc_code": "011000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000050000",
        "expected_codes": ["00"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 102],
        "cbs_vendor_note": "Positive financial: Standard cash withdrawal approved (RC 00). Ledger debited by transaction amount."
    },
    {
        "id": "TC_POS_ATM_MINI_00",
        "name": "Mini Statement - Standard Approved",
        "group": "standard", "channel": "ATM", "mti": "0200", "proc_code": "380000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000000000",
        "expected_codes": ["00"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 63, 102, 120],
        "cbs_vendor_note": "Positive non-financial: Mini statement returns last 10 transaction lines in DE 63 with RC 00."
    },
    {
        "id": "TC_POS_ATM_REV_00",
        "name": "Issuer Cash Withdrawal Reversal - Approved",
        "group": "standard", "channel": "ATM", "mti": "0420", "proc_code": "011000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000050000",
        "expected_codes": ["00"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 37, 38, 39, 41, 42, 43, 49, 54, 60, 90, 102],
        "cbs_vendor_note": "Reversal: 0420 linked with DE 90 original data elements. CBS releases hold/credit back cash debit."
    },
    {
        "id": "TC_POS_PUR_00",
        "name": "POS Purchase - Standard Approved",
        "group": "standard", "channel": "POS", "mti": "0200", "proc_code": "000000",
        "mcc": "5411", "pos_entry": "051", "pos_cond": "00", "terminal_id": "EP025109", "amount": "000000500000",
        "expected_codes": ["00"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 35, 37, 39, 41, 42, 43, 48, 49, 54, 60, 102],
        "cbs_vendor_note": "POS Financial: Standard merchant purchase approved (RC 00). Echoes DE 48 and updates account balances."
    },
    {
        "id": "TC_POS_REV_00",
        "name": "POS Reversal - Approved",
        "group": "standard", "channel": "POS", "mti": "0420", "proc_code": "000000",
        "mcc": "5411", "pos_entry": "051", "pos_cond": "00", "terminal_id": "EP025109", "amount": "000000500000",
        "expected_codes": ["00"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 37, 38, 39, 41, 42, 43, 48, 49, 54, 60, 90, 102],
        "cbs_vendor_note": "POS Reversal: Echoes original Auth ID (DE 38) & original MTI 0200 in DE 90 to cancel merchant charge."
    },
    {
        "id": "TC_ECOM_PUR_00",
        "name": "E-Commerce Purchase - Approved (CNP)",
        "group": "standard", "channel": "ECOM", "mti": "0200", "proc_code": "000000",
        "mcc": "5814", "pos_entry": "810", "pos_cond": "59", "terminal_id": "70016942", "amount": "000000150000",
        "expected_codes": ["00"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 14, 15, 17, 18, 22, 25, 32, 37, 39, 41, 42, 43, 48, 49, 54, 60, 102],
        "cbs_vendor_note": "ECOM CNP Purchase: Expiration date (DE 14) and 3D-secure condition codes verified. Returns RC 00."
    },
    {
        "id": "TC_ECOM_REV_00",
        "name": "E-Commerce Reversal - Approved",
        "group": "standard", "channel": "ECOM", "mti": "0420", "proc_code": "000000",
        "mcc": "5814", "pos_entry": "810", "pos_cond": "59", "terminal_id": "70016942", "amount": "000000150000",
        "expected_codes": ["00", "09"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 14, 15, 17, 18, 22, 25, 32, 37, 39, 41, 42, 43, 48, 49, 60, 90, 102],
        "cbs_vendor_note": "ECOM Reversal: Cancels e-commerce gateway auth token. Switch returns RC 00 or RC 09 (In Progress)."
    },
    {
        "id": "TC_METRO_LIEN_01",
        "name": "Balance Enquiry after Quota Exhaustion (Lien Mark Validation)",
        "group": "quota_lien", "channel": "ATM", "mti": "0200", "proc_code": "311000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000000000",
        "expected_codes": ["00"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 102],
        "cbs_vendor_note": "Lien Mark Validation: Balance inquiry fulfilled with RC 00. If insufficient balance to cover interchange charge + GST, a lien mark (hold) is applied on the customer account in CBS for subsequent recovery."
    },
    {
        "id": "TC_ACC_CLOSED_01",
        "name": "Account Validation - Closed Account",
        "group": "closed", "channel": "ATM", "mti": "0200", "proc_code": "011000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000050000",
        "expected_codes": ["14", "52", "53"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 60, 102],
        "cbs_vendor_note": "Closed Account Check: Rejects with RC 14 (Invalid Card/Account) or RC 52 (No Checking Account) / RC 53 (No Savings Account)."
    },
    {
        "id": "TC_ACC_FREEZE_01",
        "name": "Account Validation - All Freeze Account (Total / Debit Freeze)",
        "group": "freeze", "channel": "ATM", "mti": "0200", "proc_code": "011000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000050000",
        "expected_codes": ["62", "57"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 60, 102],
        "cbs_vendor_note": "Freeze Account Check: Total or debit frozen account rejects with RC 62 (Restricted Card) or RC 57 (Transaction Not Permitted)."
    },
    {
        "id": "TC_CHG_FIN_PASS_01",
        "name": "Charges Validation - Financial (Balance Covers Amount + Charge)",
        "group": "quota_lien", "channel": "ATM", "mti": "0200", "proc_code": "011000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000050000",
        "expected_codes": ["00"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 102],
        "cbs_vendor_note": "Charges Validation: Account balance covers withdrawal amount + interchange fee (e.g., INR 21 + GST). Returns RC 00."
    },
    {
        "id": "TC_CHG_FIN_FAIL_01",
        "name": "Charges Validation - Financial (Balance Cannot Cover Amount + Charge)",
        "group": "insufficient", "channel": "ATM", "mti": "0200", "proc_code": "011000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000500000",
        "expected_codes": ["51"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 102],
        "cbs_vendor_note": "Charges Validation: Account balance covers base amount but cannot cover amount + interchange charge. Rejects with RC 51."
    },
    {
        "id": "TC_CHG_NONFIN_01",
        "name": "Charges Validation - Non-Financial (Fee Debited / Lien Applied)",
        "group": "quota_lien", "channel": "ATM", "mti": "0200", "proc_code": "380000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000000000",
        "expected_codes": ["00"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 63, 102, 120],
        "cbs_vendor_note": "Non-Financial Charge: Mini statement enquiry fulfilled with RC 00. Non-financial fee debited or marked as lien in CBS."
    },
    {
        "id": "TC_MIN_BAL_FLOOR_01",
        "name": "Minimum Balance Validation (Floor Breach Check)",
        "group": "min_bal", "channel": "ATM", "mti": "0200", "proc_code": "011000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000095000",
        "expected_codes": ["51", "61", "00"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 102],
        "cbs_vendor_note": "Floor Breach: Rejects with RC 51 (Insufficient Funds) or RC 61 (Exceeds Limit), unless CBS allows dipping below threshold subject to penalty (RC 00)."
    },
    {
        "id": "TC_BIN_VAL_01",
        "name": "BIN Validation - Invalid or Unallocated BIN",
        "group": "invalid_bin", "channel": "ATM", "mti": "0200", "proc_code": "011000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000050000",
        "expected_codes": ["14", "15", "92"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 37, 39, 41, 42, 43, 49, 60, 102],
        "cbs_vendor_note": "BIN Check: Unallocated/unregistered BIN prefix triggers RC 14 (Invalid Card Number), RC 15 (No Such Issuer), or RC 92 (Unable to Route)."
    },
    {
        "id": "TC_BAL_AUDIT_FIN_DR",
        "name": "Balance Audit - Financial Debit (Closing = Opening - Amt - Fees)",
        "group": "standard", "channel": "ATM", "mti": "0200", "proc_code": "011000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000050000",
        "expected_codes": ["00"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 102],
        "cbs_vendor_note": "Ledger Balance Audit: Closing Balance in DE 54 must exactly equal Opening Balance minus Transaction Amount minus Applicable Fees (RC 00)."
    },
    {
        "id": "TC_BAL_AUDIT_REV",
        "name": "Balance Audit - Reversal (Closing = Opening + Reversal + Fees)",
        "group": "standard", "channel": "ATM", "mti": "0420", "proc_code": "011000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000050000",
        "expected_codes": ["00"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 37, 38, 39, 41, 42, 43, 49, 54, 60, 90, 102],
        "cbs_vendor_note": "Reversal Audit: Closing Balance must equal Opening Balance plus Reversal Amount plus any reversed interchange fees (RC 00)."
    },
    {
        "id": "TC_BAL_AUDIT_NONFIN",
        "name": "Balance Audit - Non-Financial (Ledger Balance Intact)",
        "group": "quota_lien", "channel": "ATM", "mti": "0200", "proc_code": "311000",
        "mcc": "6011", "pos_entry": "051", "pos_cond": "00", "terminal_id": "00558004", "amount": "000000000000",
        "expected_codes": ["00"], "expected_des": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 102],
        "cbs_vendor_note": "Non-Financial Balance Audit: Opening and Closing Ledger Balance remain intact; lien amount increases by applicable fee if uncollected."
    }
]

# ==============================================================
# FLASK ROUTE DEFINITIONS
# ==============================================================

@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_PAGE)

@app.route("/api/config", methods=["GET"])
def get_config():
    return jsonify(load_config())

@app.route("/api/target/save", methods=["POST"])
def save_target_settings():
    data = request.get_json() or {}
    cfg = load_config()
    cfg["target_settings"] = {
        "default_ip": data.get("ip", "10.167.1.153"),
        "default_port": int(data.get("port", 9019)),
        "default_framing": data.get("framing", "ascii_4"),
        "default_bitmap_fmt": data.get("bitmap_fmt", "hex_ascii"),
        "default_charset": data.get("charset", "ascii"),
        "default_tpdu": data.get("tpdu", ""),
        "default_timeout": float(data.get("timeout_sec", 6.0))
    }
    save_config(cfg)
    return jsonify({"status": "success", "message": "Target settings saved successfully."})

@app.route("/api/transactions/save", methods=["POST"])
def api_save_transaction_type():
    data = request.get_json() or {}
    key = data.get("key", "").strip().lower().replace(" ", "_")
    old_key = data.get("old_key", "").strip()
    label = data.get("label", "").strip()
    mti = data.get("mti", "0200").strip()
    proc_code = data.get("proc_code", "000000").strip()
    base_tx = data.get("base_tx", "")
    
    req_des = sorted(list(set(int(x) for x in data.get("req_des_present", []) if str(x).isdigit())))
    resp_des = sorted(list(set(int(x) for x in data.get("resp_des_present", []) if str(x).isdigit())))

    if not key or not label:
        return jsonify({"status": "error", "message": "Transaction key and label are required."}), 400

    cfg = load_config()
    if "sample_requests" not in cfg:
        cfg["sample_requests"] = {}

    if old_key and old_key in cfg["sample_requests"] and old_key != key:
        del cfg["sample_requests"][old_key]

    cfg["sample_requests"][key] = {
        "label": label,
        "mti": mti,
        "proc_code": proc_code,
        "req_des_present": req_des,
        "resp_des_present": resp_des
    }
    if base_tx:
        cfg["sample_requests"][key]["base_tx"] = base_tx

    save_config(cfg)
    return jsonify({"status": "success", "message": f"Transaction '{label}' saved successfully.", "key": key})

@app.route("/api/transactions/delete", methods=["POST"])
def api_delete_transaction_type():
    data = request.get_json() or {}
    key = data.get("key", "").strip()
    cfg = load_config()
    if "sample_requests" in cfg and key in cfg["sample_requests"]:
        del cfg["sample_requests"][key]
        save_config(cfg)
        return jsonify({"status": "success", "message": f"Transaction '{key}' deleted successfully."})
    return jsonify({"status": "error", "message": f"Transaction '{key}' not found."}), 404

@app.route("/api/build_request", methods=["POST"])
def api_build_request():
    data = request.get_json() or {}
    tx_key = data.get("tx_key")
    cfg = load_config()
    sample = cfg.get("sample_requests", {}).get(tx_key)
    if not sample:
        return jsonify({"error": f"Unknown transaction key: {tx_key}"}), 400

    is_reversal = (sample.get("mti") == "0420" or "reversal" in tx_key)

    if is_reversal:
        base_key = sample.get("base_tx") or ("cash_withdrawal" if "issuer" in tx_key else ("ecom_purchase" if "ecom" in tx_key else "pos_purchase"))
        base_sample = cfg.get("sample_requests", {}).get(base_key, cfg["sample_requests"].get("cash_withdrawal", {}))
        
        proc_code_0200 = data.get("proc_code") or base_sample.get("proc_code", "011000")
        des_0200 = base_sample.get("req_des_present") or [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 41, 42, 43, 48, 49, 60, 102]
        
        raw_iso_0200, fields_0200 = assemble_iso_from_numericals(
            "0200", proc_code_0200, des_0200,
            custom_params={
                "pan": data.get("pan"),
                "account": data.get("account"),
                "acq_id": data.get("acq_id"),
                "rrn": data.get("rrn")
            }
        )

        orig_stan = str(fields_0200.get(11, "000000")).zfill(6)
        orig_dt = str(fields_0200.get(7, datetime.now().strftime("%m%d%H%M%S"))).zfill(10)
        orig_acq = str(fields_0200.get(32, "622018")).zfill(11)[-11:]
        de90 = f"0200{orig_stan}{orig_dt}{orig_acq}{'0'*11}"

        rev_fields = fields_0200.copy()
        rev_fields[90] = de90
        rev_fields[39] = "68"
        if 38 not in rev_fields:
            rev_fields[38] = "244729"

        rev_des = sample.get("req_des_present") or list(rev_fields.keys())
        filtered_rev_fields = {k: v for k, v in rev_fields.items() if k in rev_des or k in (90, 38, 39)}
        raw_iso_0420 = format_iso_dict("0420", filtered_rev_fields)

        return jsonify({
            "is_reversal": True,
            "raw_iso": raw_iso_0200,
            "raw_iso_0200": raw_iso_0200,
            "raw_iso_0420": raw_iso_0420,
            "de90": de90,
            "proc_code": fields_0200.get(3, proc_code_0200),
            "pan": fields_0200.get(2, ""),
            "account": fields_0200.get(102, ""),
            "acq_id": fields_0200.get(32, ""),
            "rrn": fields_0200.get(37, "")
        })

    mti = sample.get("mti", "0200")
    proc_code = data.get("proc_code") or sample.get("proc_code", "000000")
    des_present = sample.get("req_des_present") or sample.get("des_present") or []

    raw_iso, fields = assemble_iso_from_numericals(
        mti, proc_code, des_present,
        custom_params={
            "pan": data.get("pan"),
            "account": data.get("account"),
            "acq_id": data.get("acq_id"),
            "rrn": data.get("rrn")
        }
    )

    return jsonify({
        "is_reversal": False,
        "raw_iso": raw_iso,
        "raw_iso_0200": raw_iso,
        "raw_iso_0420": "",
        "de90": "",
        "proc_code": fields.get(3, proc_code),
        "pan": fields.get(2, ""),
        "account": fields.get(102, ""),
        "acq_id": fields.get(32, ""),
        "rrn": fields.get(37, "")
    })

@app.route("/api/send", methods=["POST"])
def api_send_transaction():
    data = request.get_json() or {}
    ip = data.get("ip")
    port = int(data.get("port", 0))
    tx_key = data.get("tx_key")
    framing = data.get("framing", "ascii_4")
    bitmap_fmt = data.get("bitmap_fmt", "hex_ascii")
    charset = data.get("charset", "ascii")
    tpdu = data.get("tpdu", "")
    timeout_sec = float(data.get("timeout_sec", 6.0))
    iso_req = (data.get("iso_request") or "").strip()
    force_timeout = bool(data.get("force_timeout", False))

    if not ip or not port or not iso_req:
        return jsonify({"status": "error", "message": "Target IP, port, and ISO request cannot be empty."}), 400

    cfg = load_config()
    expected_resp_des = cfg.get("sample_requests", {}).get(tx_key, {}).get("resp_des_present")

    if force_timeout:
        time.sleep(0.3)
        write_partitioned_log("transactions", f"[METHOD 2 SIMULATED TIMEOUT (68)] {ip}:{port} | REQ: {iso_req}")
        return jsonify({
            "status": "success",
            "timed_out": True,
            "iso_response": f"[SIMULATED TIMEOUT / LATE RESPONSE (68)]\nSwitch socket exceeded {timeout_sec}s threshold. Triggered DE 39 = 68.",
            "latency_ms": int(timeout_sec * 1000),
            "parsed_response": {
                "mti": "0210",
                "fields": [],
                "de39": {"code": "68", "label": "Timeout / Late Response", "cat": "TECHNICAL FAILURE"}
            }
        })

    payload = pack_payload(iso_req, framing, bitmap_fmt, charset, tpdu)
    t0 = time.time()
    try:
        resp_bytes = tcp_transact(ip, port, payload, timeout=timeout_sec)
        ms = round((time.time() - t0) * 1000, 1)
        resp_str = unpack_response(resp_bytes)
        parsed = parse_iso_details(resp_str, expected_resp_des=expected_resp_des)
        write_partitioned_log("transactions", f"[TRANSACTION SUCCESS] {ip}:{port} | LATENCY: {ms}ms | REQ: {iso_req} | RESP: {resp_str}")
        return jsonify({
            "status": "success",
            "timed_out": False,
            "iso_response": resp_str,
            "latency_ms": ms,
            "parsed_response": parsed
        })
    except (socket.timeout, TimeoutError):
        ms = round((time.time() - t0) * 1000, 1)
        write_partitioned_log("transactions", f"[TRANSACTION TIMEOUT (68)] {ip}:{port} | LATENCY: {ms}ms | REQ: {iso_req}")
        return jsonify({
            "status": "success",
            "timed_out": True,
            "iso_response": f"[CBS TIMEOUT / LATE RESPONSE]\nSocket timed out after {timeout_sec}s. DE 39 = 68 (Timeout / Late Response).",
            "latency_ms": ms,
            "parsed_response": {
                "mti": "0210",
                "fields": [],
                "de39": {"code": "68", "label": "Timeout / Late Response", "cat": "TECHNICAL FAILURE"}
            }
        })
    except Exception as e:
        if "timed out" in str(e).lower():
            ms = round((time.time() - t0) * 1000, 1)
            write_partitioned_log("transactions", f"[TRANSACTION TIMEOUT (68)] {ip}:{port} | LATENCY: {ms}ms | REQ: {iso_req}")
            return jsonify({
                "status": "success",
                "timed_out": True,
                "iso_response": f"[CBS TIMEOUT / LATE RESPONSE]\nSocket timed out after {timeout_sec}s. DE 39 = 68.",
                "latency_ms": ms,
                "parsed_response": {
                    "mti": "0210",
                    "fields": [],
                    "de39": {"code": "68", "label": "Timeout / Late Response", "cat": "TECHNICAL FAILURE"}
                }
            })
        write_partitioned_log("transactions", f"[TRANSACTION FAILED] {ip}:{port} | ERROR: {str(e)} | REQ: {iso_req}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/execute_linked_0420", methods=["POST"])
def api_execute_linked_0420():
    data = request.get_json() or {}
    ip = data.get("ip")
    port = int(data.get("port", 0))
    framing = data.get("framing", "ascii_4")
    bitmap_fmt = data.get("bitmap_fmt", "hex_ascii")
    charset = data.get("charset", "ascii")
    tpdu = data.get("tpdu", "")
    timeout_sec = float(data.get("timeout_sec", 6.0))
    orig_req_iso = (data.get("orig_req_iso") or "").strip()
    reason_code = data.get("reason_code", "68")

    if not ip or not port or not orig_req_iso:
        return jsonify({"status": "error", "message": "Original request ISO, IP, and Port are required."}), 400

    orig_mti, orig_fields = parse_raw_iso_dict(orig_req_iso)
    if not orig_mti:
        return jsonify({"status": "error", "message": "Could not parse original ISO payload."}), 400

    base_mti = "0200"
    orig_stan = str(orig_fields.get(11, "000000")).zfill(6)
    orig_datetime = str(orig_fields.get(7, datetime.now().strftime("%m%d%H%M%S"))).zfill(10)
    raw_acq = str(orig_fields.get(32, "622018")).strip()
    acq_11 = raw_acq.zfill(11)[-11:]
    fwd_11 = "0" * 11
    
    de90 = f"{base_mti}{orig_stan}{orig_datetime}{acq_11}{fwd_11}"

    rev_fields = orig_fields.copy()
    rev_fields[90] = de90
    rev_fields[39] = reason_code
    if 38 not in rev_fields:
        rev_fields[38] = "244729"

    cfg = load_config()
    pos_rev = cfg.get("sample_requests", {}).get("pos_reversal", {})
    rev_des_template = pos_rev.get("req_des_present") or [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 37, 38, 39, 41, 42, 43, 48, 49, 60, 90, 102]
    filtered_rev_fields = {k: v for k, v in rev_fields.items() if k in rev_des_template or k in (90, 38, 39)}

    rev_req_iso = format_iso_dict("0420", filtered_rev_fields)
    payload = pack_payload(rev_req_iso, framing, bitmap_fmt, charset, tpdu)

    t0 = time.time()
    try:
        resp_bytes = tcp_transact(ip, port, payload, timeout=timeout_sec)
        ms = round((time.time() - t0) * 1000, 1)
        resp_str = unpack_response(resp_bytes)
        parsed = parse_iso_details(resp_str)
        write_partitioned_log("reversals", f"[REVERSAL SUCCESS] {ip}:{port} | LATENCY: {ms}ms | REASON: {reason_code} | DE90: {de90} | RESP: {resp_str}")
        return jsonify({
            "status": "success",
            "rev_req_iso": rev_req_iso,
            "rev_resp_iso": resp_str,
            "de90": de90,
            "latency_ms": ms,
            "parsed_response": parsed
        })
    except Exception as e:
        write_partitioned_log("reversals", f"[REVERSAL FAILED] {ip}:{port} | ERROR: {str(e)} | DE90: {de90}")
        return jsonify({
            "status": "error",
            "message": str(e),
            "rev_req_iso": rev_req_iso,
            "de90": de90
        }), 500

@app.route("/api/parse_raw", methods=["POST"])
def api_parse_raw():
    data = request.get_json() or {}
    raw_iso = data.get("raw_iso", "")
    parsed = parse_iso_details(raw_iso)
    if "error" in parsed:
        return jsonify({"status": "error", "message": parsed["error"]}), 400
    return jsonify({
        "status": "success",
        "mti": parsed["mti"],
        "fields": parsed["fields"]
    })

@app.route("/api/rebuild_from_fields", methods=["POST"])
def api_rebuild_from_fields():
    data = request.get_json() or {}
    mti = data.get("mti", "0200")
    fields = data.get("fields", {})
    try:
        rebuilt = format_iso_dict(mti, fields)
        return jsonify({"status": "success", "raw_iso": rebuilt})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

@app.route("/api/schema/save_numericals", methods=["POST"])
def api_save_numericals():
    data = request.get_json() or {}
    key = data.get("key")
    target_type = data.get("target_type", "req")
    des_present = sorted(list(set(int(x) for x in data.get("des_present", []))))

    cfg = load_config()
    if key not in cfg.get("sample_requests", {}):
        return jsonify({"status": "error", "message": f"Key {key} not found."}), 404

    field_target = "req_des_present" if target_type == "req" else "resp_des_present"
    cfg["sample_requests"][key][field_target] = des_present
    save_config(cfg)

    return jsonify({"status": "success", "des_present": des_present})

@app.route("/api/handshake/update_target", methods=["POST"])
def api_handshake_update_target():
    return jsonify({"status": "updated"})

@app.route("/api/super_test/scenarios", methods=["GET"])
def api_super_test_scenarios():
    return jsonify({
        "profiles": DISTINCT_ACCOUNT_PROFILES,
        "scenarios": SUPER_TEST_SCENARIOS
    })

@app.route("/api/super_test/run", methods=["POST"])
def api_super_test_run():
    data = request.get_json() or {}
    ip = data.get("ip")
    port = int(data.get("port", 0))
    framing = data.get("framing", "ascii_4")
    bitmap_fmt = data.get("bitmap_fmt", "hex_ascii")
    charset = data.get("charset", "ascii")
    tpdu = data.get("tpdu", "")
    timeout_sec = float(data.get("timeout_sec", 6.0))
    acq_id = "622018"
    
    distinct_accounts = data.get("distinct_accounts", {})
    scenario_accounts = data.get("scenario_accounts", {})
    scenario_cards = data.get("scenario_cards", {})

    report = []
    passed = 0

    for sc in SUPER_TEST_SCENARIOS:
        sc_id = sc["id"]
        grp = sc.get("group", "standard")
        grp_data = distinct_accounts.get(grp, {})
        
        acc = scenario_accounts.get(sc_id) or grp_data.get("account") or DISTINCT_ACCOUNT_PROFILES.get(grp, {}).get("default_account", "003002300008773")
        card = scenario_cards.get(sc_id) or grp_data.get("pan") or DISTINCT_ACCOUNT_PROFILES.get(grp, {}).get("default_pan", "6076070030053234")

        custom_params = {
            "account": acc,
            "pan": card,
            "acq_id": acq_id,
            "pos_entry": sc["pos_entry"],
            "pos_cond": sc["pos_cond"],
            "terminal_id": sc["terminal_id"],
            "amount": sc["amount"],
            "mcc": sc["mcc"]
        }

        req_iso, _ = assemble_iso_from_numericals(sc["mti"], sc["proc_code"], sc["expected_des"], custom_params=custom_params)
        payload = pack_payload(req_iso, framing, bitmap_fmt, charset, tpdu)

        t0 = time.time()
        try:
            resp_bytes = tcp_transact(ip, port, payload, timeout=timeout_sec)
            ms = round((time.time() - t0) * 1000, 1)
            resp_str = unpack_response(resp_bytes)
            _, f_resp = parse_raw_iso_dict(resp_str)
            actual_code = f_resp.get(39, "--")
        except Exception:
            ms = round((time.time() - t0) * 1000, 1)
            actual_code = "68"

        exp_codes = sc.get("expected_codes", ["00"])
        verdict = "PASS" if actual_code in exp_codes else "FAIL"
        if verdict == "PASS":
            passed += 1

        report.append({
            "id": sc_id,
            "name": sc["name"],
            "channel": sc.get("channel", "ATM"),
            "group": grp,
            "account": acc,
            "card": card,
            "mti": sc["mti"],
            "expected_code": "/".join(exp_codes),
            "actual_code": actual_code,
            "latency": f"{ms}ms",
            "verdict": verdict,
            "cbs_vendor_note": sc["cbs_vendor_note"]
        })

    total = len(SUPER_TEST_SCENARIOS)
    pct = round((passed / total) * 100, 1) if total > 0 else 0

    sign_off_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    release_notes = f"""=== ATM SWITCH & CBS AUDIT CERTIFICATION NOTE ===
Date Generated : {sign_off_date}
Target Host    : {ip}:{port}
Suite Results  : {passed} of {total} Passed ({pct}% Compliance)

AUDIT BREAKDOWN:
"""
    for r in report:
        release_notes += f"[{r['verdict']}] {r['id']} ({r['channel']}) - {r['name']} | Exp: {r['expected_code']} Act: {r['actual_code']} | Acc: {r['account']} | Latency: {r['latency']}\n"

    return jsonify({
        "status": "success",
        "total": total,
        "passed": passed,
        "pass_percentage": pct,
        "report": report,
        "release_notes": release_notes
    })

# ==============================================================
# HTML TEMPLATE INTERFACE DEFINITION
# ==============================================================

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ATM Switch - End to End ISO 8583 Testing Console</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-4 font-sans">
  <div class="max-w-7xl mx-auto space-y-3.5">
    
    <header class="flex justify-between items-center pb-2 border-b border-slate-800">
      <h1 class="text-xl font-bold tracking-tight text-white flex items-center gap-2">
        <span>ATM Switch &amp; CBS Console</span>
        <span class="text-xs bg-indigo-950 text-indigo-300 border border-indigo-700 px-2 py-0.5 rounded font-mono">Master Audit Suite</span>
      </h1>
      <button onclick="saveTargetAsDefault()" class="text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-1 rounded border border-slate-700 transition">
        Save Settings as Default
      </button>
    </header>

    <!-- Communication & Framing Settings Bar -->
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
            <option value="bin_2">2-Byte Binary (!H)</option>
            <option value="bin_2_inc">2-Byte Binary (+2 Inc)</option>
            <option value="ascii_4" selected>4-Byte ASCII (%04d)</option>
            <option value="raw">Raw ISO (No Header)</option>
          </select>
        </div>
        <div>
          <label class="block text-slate-400 mb-1">Bitmap Wire Format</label>
          <select id="bitmap-fmt" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-emerald-400 font-medium">
            <option value="binary">16-Byte Raw Binary</option>
            <option value="hex_ascii" selected>32-Char Hex ASCII</option>
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
          <input id="timeout-sec" type="number" value="6" min="1" max="60" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-white focus:outline-none">
        </div>
      </div>
    </section>

    <!-- Navigation Tabs -->
    <div class="flex gap-2 border-b border-slate-800 pt-1">
      <button id="tab-btn-single" onclick="switchWindow('single')" class="px-4 py-1.5 text-xs font-semibold rounded-t border-b-2 border-indigo-500 text-white bg-slate-900">
        Single Request Mode
      </button>
      <button id="tab-btn-super" onclick="switchWindow('super')" class="px-4 py-1.5 text-xs font-semibold rounded-t text-amber-400 hover:text-white bg-slate-950">
        Super Testing Mode (CBS &amp; Balance Audit)
      </button>
      <button id="tab-btn-cfg" onclick="switchWindow('cfg')" class="px-4 py-1.5 text-xs font-semibold rounded-t text-slate-400 hover:text-white bg-slate-950">
        Schema Manager (Config)
      </button>
    </div>

    <!-- WINDOW 1: SINGLE REQUEST MODE -->
    <div id="win-single" class="space-y-3">
      
      <!-- Primary Transaction Selection Bar with Add / Edit / Delete -->
      <div class="bg-slate-900 border border-slate-800 rounded-lg p-2.5 flex flex-wrap items-center justify-between gap-2 text-xs">
        <div class="flex flex-wrap items-center gap-2">
          <span class="font-bold text-slate-300 uppercase text-[11px] mr-1">Select Transaction:</span>
          <div id="sample-buttons-container" class="flex flex-wrap gap-1.5"></div>
        </div>
        <div class="flex items-center gap-1.5 ml-auto">
          <button onclick="openAddTxModal()" title="Add custom transaction type" class="bg-emerald-700 hover:bg-emerald-600 text-white font-semibold px-2.5 py-1 rounded text-xs transition flex items-center gap-1">
            <span>+ Add</span>
          </button>
          <button onclick="openEditTxListModal()" title="Edit existing transaction type" class="bg-indigo-700 hover:bg-indigo-600 text-white font-semibold px-2.5 py-1 rounded text-xs transition flex items-center gap-1">
            <span>✎ Edit</span>
          </button>
          <button onclick="openDeleteTxListModal()" title="Delete a transaction type" class="bg-rose-700 hover:bg-rose-600 text-white font-semibold px-2.5 py-1 rounded text-xs transition flex items-center gap-1">
            <span>🗑 Delete</span>
          </button>
        </div>
      </div>

      <!-- DYNAMIC PARAMETERS: Card Number, Account Number, Acquiring ID First -->
      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div class="flex justify-between items-center pb-2 mb-2.5 border-b border-slate-800">
          <span class="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <span>Dynamic Parameters</span>
            <span class="text-[10px] text-emerald-400 font-mono font-normal">Real-Time Clock Active (Shared Across All Transactions)</span>
          </span>
          <button onclick="regenerateDynamic(true)" class="bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs px-2.5 py-1 rounded border border-slate-700 flex items-center gap-1 transition">
            <span>Regenerate RRN &amp; Time</span>
          </button>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-5 gap-3 text-xs">
          <!-- 1. Card Number (DE 2) -->
          <div>
            <label class="block text-slate-400 mb-1 font-medium">Card Number (DE 2)</label>
            <input id="dyn-pan" type="text" placeholder="e.g. 6076070030053234" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-emerald-300 focus:outline-none focus:border-indigo-500">
          </div>
          <!-- 2. Account Number (DE 102) -->
          <div>
            <label class="block text-slate-400 mb-1 font-medium">Account Number (DE 102)</label>
            <input id="dyn-account" type="text" placeholder="e.g. 003002300008773" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-emerald-300 focus:outline-none focus:border-indigo-500">
          </div>
          <!-- 3. Acquiring ID (DE 32) -->
          <div>
            <label class="block text-slate-400 mb-1 font-medium">Acquiring ID (DE 32)</label>
            <input id="dyn-acq" type="text" placeholder="e.g. 622018" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-emerald-300 focus:outline-none focus:border-indigo-500">
          </div>
          <!-- 4. Processing Code (DE 3) -->
          <div>
            <label class="block text-slate-400 mb-1 font-medium">Processing Code (DE 3)</label>
            <input id="dyn-proc-code" type="text" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-amber-300 focus:outline-none focus:border-indigo-500">
          </div>
          <!-- 5. Random RRN (DE 37) -->
          <div>
            <label class="block text-slate-400 mb-1 font-medium">Random RRN (DE 37)</label>
            <input id="dyn-rrn" type="text" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-indigo-500">
          </div>
        </div>
      </section>

      <!-- Payloads Section -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        
        <!-- Request Containers Column -->
        <section class="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-2">
          <div>
            <div class="flex justify-between items-center mb-1">
              <span id="req-box-title" class="text-xs font-bold uppercase tracking-wider text-slate-300">Request ISO Payload (0200)</span>
              <div class="flex items-center gap-1.5">
                <span id="req-len-badge" class="text-[11px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono border border-slate-700">0 chars</span>
                <button type="button" onclick="addLengthToRequest()" class="bg-indigo-600 hover:bg-indigo-500 text-white text-[11px] font-medium px-2 py-0.5 rounded transition">
                  + 4-Byte
                </button>
                <button type="button" onclick="removeLengthFromRequest()" class="bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium px-2 py-0.5 rounded transition">
                  - Strip
                </button>
              </div>
            </div>
            <textarea id="iso-request" rows="5" class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs font-mono text-emerald-400 break-all resize-none"></textarea>
          </div>

          <!-- Leg 2 Linked Reversal Request (0420) -->
          <div id="rev-preview-container" class="hidden border-t border-slate-800 pt-2">
            <div class="flex justify-between items-center mb-1">
              <span class="text-xs font-bold uppercase tracking-wider text-amber-400">Pre-Built Linked Reversal Payload (MTI: 0420)</span>
              <span id="de90-preview-badge" class="text-[10px] font-mono text-slate-400">DE 90 Parity Ready</span>
            </div>
            <textarea id="iso-request-0420" readonly rows="4" class="w-full bg-slate-950 border border-amber-900/60 rounded p-2 text-xs font-mono text-amber-300 break-all resize-none"></textarea>
          </div>
          
          <div class="flex gap-2 pt-1">
            <button id="primary-action-btn" onclick="executePrimaryAction(false)" class="w-1/2 bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 rounded text-xs transition shadow-sm">
              Send Single ISO Transaction
            </button>
            <button id="force-timeout-btn" onclick="executePrimaryAction(true)" title="Method 2: Force late response / 68 timeout to prompt linked 0420 reversal" class="w-1/4 bg-amber-700 hover:bg-amber-600 text-white font-bold py-2 rounded text-xs transition shadow-sm">
              Simulate Timeout (68)
            </button>
            <button type="button" onclick="parseRequestAndDisplayEditor()" class="w-1/4 bg-slate-800 hover:bg-slate-700 text-indigo-300 font-bold py-2 rounded text-xs border border-indigo-900/60 transition">
              Inspect DEs
            </button>
          </div>
        </section>

        <!-- Response Column -->
        <section class="bg-slate-900 border border-slate-800 rounded-lg p-3 flex flex-col justify-between">
          <div>
            <div class="flex justify-between items-center mb-1">
              <span class="text-xs font-bold uppercase tracking-wider text-slate-400">Response Payload / Execution Audit</span>
              <span id="resp-latency" class="text-xs text-slate-400 font-mono">Latency: --</span>
            </div>
            <textarea id="iso-response" readonly rows="11" class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs font-mono text-cyan-300 break-all resize-none"></textarea>
          </div>
          
          <div class="mt-2 p-2 bg-slate-950 border border-slate-800 rounded flex justify-between items-center text-xs">
            <div class="flex items-center gap-2">
              <span class="text-slate-400">Response Status (DE 39):</span>
              <span id="de39-badge" class="font-mono font-bold text-slate-500">Awaiting Transaction</span>
            </div>
            <button id="instant-reversal-btn" onclick="promptReversalModalForCurrent()" class="hidden bg-amber-600 hover:bg-amber-500 text-white font-bold px-2.5 py-0.5 rounded text-[11px] transition shadow-sm">
              Initiate 0420 Reversal
            </button>
          </div>
        </section>
      </div>

      <!-- Editable Request Elements Inspector Panel -->
      <section id="editable-request-panel" class="hidden bg-slate-900 border border-indigo-700/80 rounded-lg p-3">
        <div class="flex justify-between items-center pb-2 mb-2 border-b border-slate-800">
          <div class="flex items-center gap-2">
            <h3 class="text-xs font-bold uppercase tracking-wider text-indigo-300">Editable Request Data Elements</h3>
            <span class="text-[10px] text-slate-400 font-mono">(Edit field values directly before sending)</span>
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

      <!-- Parsed Response Elements Table -->
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

    <!-- WINDOW 2: SUPER TESTING MODE (CONSOLIDATED DISTINCT ACCOUNTS) -->
    <div id="win-super" class="hidden space-y-3">
      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div class="flex justify-between items-center pb-2 mb-3 border-b border-slate-800">
          <div>
            <h3 class="text-xs font-bold uppercase tracking-wider text-amber-400">Super Testing Suite (ATM, POS &amp; ECOM Comprehensive Audit)</h3>
            <p class="text-[11px] text-slate-400">Executes end-to-end verification across approvals, charges, lien holds, minimum balance breaches, and reversals.</p>
          </div>
          <div class="flex gap-2">
            <button onclick="exportAuditReportToExcel()" id="export-excel-btn" class="bg-emerald-700 hover:bg-emerald-600 text-white font-bold px-3 py-1 rounded text-xs transition shadow-sm flex items-center gap-1.5">
              <span>Export Test Case Sheet (.xlsx)</span>
            </button>
            <button onclick="openReleaseNotesModal()" id="view-release-btn" class="hidden bg-indigo-900 hover:bg-indigo-800 text-indigo-200 border border-indigo-700 font-bold px-3 py-1 rounded text-xs transition">
              View Sign-Off Note
            </button>
          </div>
        </div>

        <!-- CONSOLIDATED DISTINCT ACCOUNT INPUTS -->
        <div class="bg-slate-950 border border-indigo-800/60 rounded-lg p-3 mb-3">
          <div class="flex justify-between items-center mb-2">
            <span class="text-xs font-bold uppercase tracking-wider text-indigo-300">Consolidated Distinct Account Inputs</span>
            <span class="text-[10px] text-slate-400">Configure distinct accounts once; automatically mapped to all matching scenarios below</span>
          </div>
          <div id="distinct-accounts-container" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
            <!-- Dynamically populated with the 7 distinct account roles -->
          </div>
        </div>

        <!-- CONFIGURED TEST SCENARIOS LIST -->
        <div class="mb-3">
          <span class="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-1.5">
            Configured Test Cases (19 Scenarios Covering Issuer ATM, POS &amp; ECOM)
          </span>
          <div class="overflow-x-auto max-h-72 overflow-y-auto border border-slate-800 rounded">
            <table class="w-full text-left text-xs border-collapse">
              <thead>
                <tr class="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                  <th class="p-2 w-28">ID</th>
                  <th class="p-2 w-16">Channel</th>
                  <th class="p-2 w-64">Scenario Name</th>
                  <th class="p-2 w-48">Mapped Account (DE 102)</th>
                  <th class="p-2 w-48">Mapped Card (DE 2)</th>
                  <th class="p-2 w-24">Exp RC</th>
                  <th class="p-2">CBS Expected Rule / Regulation</th>
                </tr>
              </thead>
              <tbody id="super-scenarios-tbody" class="divide-y border-slate-800 font-mono text-slate-300"></tbody>
            </table>
          </div>
        </div>

        <button id="super-run-btn" onclick="runSuperTestSuite()" class="w-full bg-gradient-to-r from-amber-600 to-indigo-600 hover:from-amber-500 hover:to-indigo-500 text-white font-bold py-2 rounded text-xs transition shadow-md">
          Execute End-to-End Super Testing Suite
        </button>
      </section>

      <!-- AUDIT EXECUTION BREAKDOWN TABLE -->
      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div class="flex justify-between items-center mb-2">
          <span class="text-xs font-bold uppercase tracking-wider text-slate-300">Audit Execution Breakdown</span>
          <span id="super-score-badge" class="text-xs font-mono font-bold text-slate-500">Awaiting Run</span>
        </div>
        <div class="overflow-x-auto max-h-96 overflow-y-auto">
          <table class="w-full text-left text-xs border-collapse">
            <thead>
              <tr class="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                <th class="p-1.5 w-24">ID</th>
                <th class="p-1.5 w-16">Channel</th>
                <th class="p-1.5 w-56">Scenario Name</th>
                <th class="p-1.5 w-32">Account</th>
                <th class="p-1.5 w-16">MTI</th>
                <th class="p-1.5 w-16">Exp 39</th>
                <th class="p-1.5 w-16">Act 39</th>
                <th class="p-1.5 w-20">Latency</th>
                <th class="p-1.5 w-16">Verdict</th>
                <th class="p-1.5">Validation Requirement</th>
              </tr>
            </thead>
            <tbody id="super-table-body" class="divide-y border-slate-800 font-mono text-slate-300">
              <tr><td colspan="10" class="p-4 text-center text-slate-600">Run the Super Testing Audit Suite to generate compliance results.</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <!-- WINDOW 3: SCHEMA MANAGER -->
    <div id="win-cfg" class="hidden space-y-3">
      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div class="flex justify-between items-center pb-2 border-b border-slate-800 mb-3">
          <h3 class="text-xs font-bold uppercase tracking-wider text-slate-300">Numerical Data Element Schema Manager</h3>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label class="block text-slate-400 mb-1">Select Transaction Schema</label>
            <select id="cfg-tx-select" onchange="loadTxSchemaToEdit()" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white"></select>
          </div>

          <div>
            <label class="block text-slate-400 mb-1">Target Element Class</label>
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
            <label class="block text-slate-400 mb-1">Add Single Numerical DE</label>
            <div class="flex gap-2">
              <input id="new-de-input" type="number" placeholder="Enter DE # (e.g. 54)" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-white">
              <button onclick="addSingleDE()" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-3 py-1.5 rounded text-xs transition">
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

    <!-- MODAL: ADD TRANSACTION TYPE -->
    <div id="add-tx-modal" class="hidden fixed inset-0 bg-black/85 flex items-center justify-center p-4 z-50">
      <div class="bg-slate-900 border border-emerald-600 rounded-lg max-w-xl w-full p-4 shadow-2xl space-y-3">
        <div class="flex justify-between items-center border-b border-slate-800 pb-2">
          <h3 class="text-sm font-bold uppercase tracking-wider text-emerald-400">Add New Transaction Type</h3>
          <button onclick="closeAddTxModal()" class="text-slate-400 hover:text-white text-lg">&times;</button>
        </div>
        <div class="space-y-2.5 text-xs">
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="block text-slate-400 mb-1">Transaction Label Name</label>
              <input id="add-tx-label" type="text" placeholder="e.g. Card to Card Transfer" class="w-full bg-slate-950 border border-slate-700 rounded p-1.5 text-white">
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Transaction Key (ID)</label>
              <input id="add-tx-key" type="text" placeholder="e.g. card_transfer" class="w-full bg-slate-950 border border-slate-700 rounded p-1.5 font-mono text-white">
            </div>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="block text-slate-400 mb-1">MTI</label>
              <input id="add-tx-mti" type="text" value="0200" class="w-full bg-slate-950 border border-slate-700 rounded p-1.5 font-mono text-amber-300">
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Processing Code (DE 3)</label>
              <input id="add-tx-proc" type="text" value="000000" class="w-full bg-slate-950 border border-slate-700 rounded p-1.5 font-mono text-amber-300">
            </div>
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Outgoing Request DEs (Comma Separated)</label>
            <input id="add-tx-req-des" type="text" placeholder="2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 41, 42, 43, 48, 49, 60, 102" class="w-full bg-slate-950 border border-slate-700 rounded p-1.5 font-mono text-emerald-300">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Expected Response DEs (Comma Separated)</label>
            <input id="add-tx-resp-des" type="text" placeholder="2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 102" class="w-full bg-slate-950 border border-slate-700 rounded p-1.5 font-mono text-cyan-300">
          </div>
          <div class="pt-1 border-t border-slate-800">
            <label class="block text-slate-400 mb-1">Or Parse from Raw Request (Optional)</label>
            <div class="flex gap-2">
              <input id="add-tx-raw-iso" type="text" placeholder="Paste full ISO string to auto-extract MTI and DEs..." class="w-full bg-slate-950 border border-slate-700 rounded p-1.5 font-mono text-[11px] text-slate-300">
              <button type="button" onclick="parseRawIntoAddModal()" class="bg-indigo-700 hover:bg-indigo-600 text-white font-bold px-3 py-1 rounded text-xs whitespace-nowrap">Auto-Extract</button>
            </div>
          </div>
        </div>
        <div class="pt-2 flex justify-end gap-2 border-t border-slate-800">
          <button onclick="closeAddTxModal()" class="bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold px-4 py-1.5 rounded text-xs transition">Cancel</button>
          <button onclick="submitAddTransaction()" class="bg-emerald-600 hover:bg-emerald-500 text-white font-bold px-4 py-1.5 rounded text-xs transition">Save Transaction</button>
        </div>
      </div>
    </div>

    <!-- MODAL: EDIT TRANSACTION SELECTION LIST -->
    <div id="edit-tx-list-modal" class="hidden fixed inset-0 bg-black/85 flex items-center justify-center p-4 z-50">
      <div class="bg-slate-900 border border-indigo-600 rounded-lg max-w-md w-full p-4 shadow-2xl space-y-3">
        <div class="flex justify-between items-center border-b border-slate-800 pb-2">
          <h3 class="text-sm font-bold uppercase tracking-wider text-indigo-400">Select Transaction to Edit</h3>
          <button onclick="document.getElementById('edit-tx-list-modal').classList.add('hidden')" class="text-slate-400 hover:text-white text-lg">&times;</button>
        </div>
        <p class="text-slate-400 text-xs">Click on any transaction type below to open its editor:</p>
        <div id="edit-tx-list-container" class="space-y-1.5 max-h-64 overflow-y-auto"></div>
        <div class="pt-2 flex justify-end border-t border-slate-800">
          <button onclick="document.getElementById('edit-tx-list-modal').classList.add('hidden')" class="bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1 rounded text-xs">Close</button>
        </div>
      </div>
    </div>

    <!-- MODAL: EDIT TRANSACTION FORM -->
    <div id="edit-tx-form-modal" class="hidden fixed inset-0 bg-black/85 flex items-center justify-center p-4 z-50">
      <div class="bg-slate-900 border border-indigo-600 rounded-lg max-w-xl w-full p-4 shadow-2xl space-y-3">
        <div class="flex justify-between items-center border-b border-slate-800 pb-2">
          <h3 class="text-sm font-bold uppercase tracking-wider text-indigo-400">Edit Transaction Type</h3>
          <button onclick="closeEditTxFormModal()" class="text-slate-400 hover:text-white text-lg">&times;</button>
        </div>
        <div class="space-y-2.5 text-xs">
          <input id="edit-tx-original-key" type="hidden">
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="block text-slate-400 mb-1">Transaction Label Name</label>
              <input id="edit-tx-label" type="text" class="w-full bg-slate-950 border border-slate-700 rounded p-1.5 text-white">
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Transaction Key (ID)</label>
              <input id="edit-tx-key" type="text" class="w-full bg-slate-950 border border-slate-700 rounded p-1.5 font-mono text-white">
            </div>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="block text-slate-400 mb-1">MTI</label>
              <input id="edit-tx-mti" type="text" class="w-full bg-slate-950 border border-slate-700 rounded p-1.5 font-mono text-amber-300">
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Processing Code (DE 3)</label>
              <input id="edit-tx-proc" type="text" class="w-full bg-slate-950 border border-slate-700 rounded p-1.5 font-mono text-amber-300">
            </div>
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Outgoing Request DEs (Comma Separated)</label>
            <input id="edit-tx-req-des" type="text" class="w-full bg-slate-950 border border-slate-700 rounded p-1.5 font-mono text-emerald-300">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Expected Response DEs (Comma Separated)</label>
            <input id="edit-tx-resp-des" type="text" class="w-full bg-slate-950 border border-slate-700 rounded p-1.5 font-mono text-cyan-300">
          </div>
        </div>
        <div class="pt-2 flex justify-end gap-2 border-t border-slate-800">
          <button onclick="closeEditTxFormModal()" class="bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold px-4 py-1.5 rounded text-xs transition">Cancel</button>
          <button onclick="submitEditTransaction()" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-4 py-1.5 rounded text-xs transition">Save Changes</button>
        </div>
      </div>
    </div>

    <!-- MODAL: DELETE TRANSACTION SELECTION LIST -->
    <div id="delete-tx-list-modal" class="hidden fixed inset-0 bg-black/85 flex items-center justify-center p-4 z-50">
      <div class="bg-slate-900 border border-rose-600 rounded-lg max-w-md w-full p-4 shadow-2xl space-y-3">
        <div class="flex justify-between items-center border-b border-slate-800 pb-2">
          <h3 class="text-sm font-bold uppercase tracking-wider text-rose-400">Select Transaction to Delete</h3>
          <button onclick="document.getElementById('delete-tx-list-modal').classList.add('hidden')" class="text-slate-400 hover:text-white text-lg">&times;</button>
        </div>
        <p class="text-slate-400 text-xs">Choose the transaction type you wish to delete:</p>
        <div id="delete-tx-list-container" class="space-y-1.5 max-h-64 overflow-y-auto"></div>
        <div class="pt-2 flex justify-end border-t border-slate-800">
          <button onclick="document.getElementById('delete-tx-list-modal').classList.add('hidden')" class="bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1 rounded text-xs">Close</button>
        </div>
      </div>
    </div>

    <!-- MODAL: DELETE CONFIRMATION -->
    <div id="delete-confirm-modal" class="hidden fixed inset-0 bg-black/90 flex items-center justify-center p-4 z-50">
      <div class="bg-slate-900 border border-rose-600 rounded-lg max-w-sm w-full p-4 shadow-2xl space-y-3">
        <div class="flex justify-between items-center border-b border-slate-800 pb-2">
          <h3 class="text-sm font-bold uppercase tracking-wider text-rose-400">Confirm Deletion</h3>
          <button onclick="closeDeleteConfirmModal(false)" class="text-slate-400 hover:text-white text-lg">&times;</button>
        </div>
        <p class="text-xs text-slate-300">
          Do you really wish to delete transaction: <br>
          <strong id="delete-target-label" class="text-rose-400 font-mono text-sm block mt-1"></strong>
        </p>
        <input id="delete-target-key" type="hidden">
        <div class="pt-2 flex justify-end gap-2 border-t border-slate-800">
          <button onclick="closeDeleteConfirmModal(false)" class="bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold px-3 py-1 rounded text-xs transition">No</button>
          <button onclick="closeDeleteConfirmModal(true)" class="bg-rose-700 hover:bg-rose-600 text-white font-bold px-3 py-1 rounded text-xs transition">Yes, Delete</button>
        </div>
      </div>
    </div>

    <!-- REVERSAL PROMPT CONFIRMATION MODAL -->
    <div id="reversal-confirm-modal" class="hidden fixed inset-0 bg-black/85 flex items-center justify-center p-4 z-50">
      <div class="bg-slate-900 border border-amber-600 rounded-lg max-w-lg w-full p-4 shadow-2xl space-y-3">
        <div class="flex justify-between items-center border-b border-slate-800 pb-2">
          <h3 class="text-sm font-bold uppercase tracking-wider text-amber-400 flex items-center gap-2">
            <span>Linked 0420 Reversal Confirmation (Method 2)</span>
          </h3>
          <button onclick="closeReversalModal(false)" class="text-slate-400 hover:text-white text-lg">&times;</button>
        </div>
        <div class="space-y-2 text-xs">
          <div class="p-2.5 bg-slate-950 border border-slate-800 rounded space-y-1">
            <div class="text-slate-400">Response Code / Status:</div>
            <div id="modal-de39-display" class="text-base font-bold font-mono text-amber-400">--</div>
            <div id="modal-tx-details" class="text-slate-400 text-[11px] font-mono"></div>
          </div>
          <p class="text-slate-300">
            Do you want to initiate the matching <strong>0420 Reversal</strong> for this transaction under <strong>Method 2 (Timeout / Late Response)</strong> rules?
          </p>
          <div class="text-[11px] text-slate-500 font-mono">
            Original MTI inside DE 90 will strictly bind to <strong>0200</strong> with reason code <strong>68</strong>.
          </div>
        </div>
        <div class="pt-2 flex justify-end gap-2 border-t border-slate-800">
          <button onclick="closeReversalModal(false)" class="bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold px-4 py-1.5 rounded text-xs transition">
            No, Cancel
          </button>
          <button onclick="closeReversalModal(true)" class="bg-amber-600 hover:bg-amber-500 text-white font-bold px-4 py-1.5 rounded text-xs transition shadow-sm">
            Yes, Proceed with Reversal (0420)
          </button>
        </div>
      </div>
    </div>

    <!-- RELEASE NOTES MODAL -->
    <div id="release-notes-modal" class="hidden fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
      <div class="bg-slate-900 border border-indigo-700 rounded-lg max-w-3xl w-full max-h-[85vh] flex flex-col p-4 shadow-2xl">
        <div class="flex justify-between items-center pb-2 border-b border-slate-800 mb-3">
          <h3 class="text-sm font-bold uppercase tracking-wider text-indigo-300">QA Certification &amp; Release Sign-Off</h3>
          <button onclick="document.getElementById('release-notes-modal').classList.add('hidden')" class="text-slate-400 hover:text-white text-lg">&times;</button>
        </div>
        <textarea id="release-notes-textarea" readonly class="w-full flex-grow bg-slate-950 border border-slate-800 rounded p-3 font-mono text-xs text-emerald-300 resize-none h-96"></textarea>
        <div class="mt-3 flex justify-end gap-2">
          <button onclick="copyReleaseNotesToClipboard()" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-4 py-2 rounded text-xs transition">
            Copy Sign-Off Note
          </button>
        </div>
      </div>
    </div>

  </div>

  <script>
    let configData = {};
    let activeTxKey = "cash_withdrawal";
    let isCurrentTxReversalType = false;
    let lastSent0200Iso = "";
    let lastReceived0210Iso = "";
    let lastDe39Code = "";
    let lastDe39Label = "";
    let latestReportData = [];
    let loadedScenarios = [];
    let loadedProfiles = {};

    const ipInput = document.getElementById("ip");
    const portInput = document.getElementById("port");
    const framingSelect = document.getElementById("framing");
    const bitmapFmtSelect = document.getElementById("bitmap-fmt");
    const charsetSelect = document.getElementById("charset");
    const tpduInput = document.getElementById("tpdu");
    const timeoutInput = document.getElementById("timeout-sec");

    const reqArea = document.getElementById("iso-request");
    const reqArea0420 = document.getElementById("iso-request-0420");
    const revPreviewContainer = document.getElementById("rev-preview-container");
    const reqBoxTitle = document.getElementById("req-box-title");
    const lenBadge = document.getElementById("req-len-badge");
    const primaryBtn = document.getElementById("primary-action-btn");
    const instantRevBtn = document.getElementById("instant-reversal-btn");

    const panInput = document.getElementById("dyn-pan");
    const accInput = document.getElementById("dyn-account");
    const acqInput = document.getElementById("dyn-acq");
    const procCodeInput = document.getElementById("dyn-proc-code");
    const rrnInput = document.getElementById("dyn-rrn");

    window.onload = async () => {
      await loadAppConfig();
      await loadSuperTestScenarios();
      attachListeners();
      updateLengthCounter();
    };

    function attachListeners() {
      if (reqArea) reqArea.addEventListener("input", updateLengthCounter);
      if (ipInput) ipInput.addEventListener("input", updateTargetNotification);
      if (portInput) portInput.addEventListener("input", updateTargetNotification);
      if (tpduInput) tpduInput.addEventListener("input", updateTargetNotification);
      if (framingSelect) framingSelect.addEventListener("change", updateTargetNotification);
      if (bitmapFmtSelect) bitmapFmtSelect.addEventListener("change", updateTargetNotification);
      if (charsetSelect) charsetSelect.addEventListener("change", updateTargetNotification);
      if (timeoutInput) timeoutInput.addEventListener("change", updateTargetNotification);

      if (panInput) panInput.addEventListener("input", () => regenerateDynamic(false));
      if (accInput) accInput.addEventListener("input", () => regenerateDynamic(false));
      if (acqInput) acqInput.addEventListener("input", () => regenerateDynamic(false));
      if (procCodeInput) procCodeInput.addEventListener("input", () => regenerateDynamic(false));
      if (rrnInput) rrnInput.addEventListener("input", () => regenerateDynamic(false));
    }

    function updateTargetNotification() {
      const ip = ipInput ? (ipInput.value.trim() || "0.0.0.0") : "0.0.0.0";
      const port = portInput ? (parseInt(portInput.value.trim()) || 0) : 0;
      const framing = framingSelect ? framingSelect.value : "ascii_4";
      const bitmap_fmt = bitmapFmtSelect ? bitmapFmtSelect.value : "hex_ascii";
      const charset = charsetSelect ? charsetSelect.value : "ascii";
      const tpdu = tpduInput ? tpduInput.value.trim() : "";
      const timeout_sec = timeoutInput ? (parseFloat(timeoutInput.value) || 6.0) : 6.0;

      fetch("/api/handshake/update_target", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, port, framing, bitmap_fmt, charset, tpdu, timeout_sec })
      }).catch(err => console.error("Target update failed:", err));
    }

    async function loadSuperTestScenarios() {
      try {
        const res = await fetch("/api/super_test/scenarios");
        const data = await res.json();
        loadedScenarios = data.scenarios || [];
        loadedProfiles = data.profiles || {};

        renderDistinctAccountInputs();
        renderSuperScenariosTable();
      } catch (e) {
        console.error("Failed to load audit scenarios:", e);
      }
    }

    function renderDistinctAccountInputs() {
      const container = document.getElementById("distinct-accounts-container");
      if (!container) return;
      container.innerHTML = "";

      Object.entries(loadedProfiles).forEach(([grpKey, p]) => {
        container.innerHTML += 
          "<div class='p-2 bg-slate-900 border border-slate-800 rounded space-y-1'>" +
            "<div class='font-bold text-amber-400 flex items-center justify-between'>" +
              "<span>" + p.title + "</span>" +
              "<span class='text-[10px] text-slate-500 font-mono'>(" + grpKey + ")</span>" +
            "</div>" +
            "<div class='text-[10px] text-slate-400 leading-tight'>" + p.description + "</div>" +
            "<div class='grid grid-cols-2 gap-1.5 pt-1'>" +
              "<div>" +
                "<label class='block text-[10px] text-slate-400'>Account (DE 102)</label>" +
                "<input id='grp-acc-" + grpKey + "' type='text' value='" + p.default_account + "' oninput='updateGroupAccounts(\"" + grpKey + "\")' class='w-full bg-slate-950 border border-slate-700 rounded px-1.5 py-0.5 text-xs font-mono text-emerald-300 focus:outline-none focus:border-indigo-500'>" +
              "</div>" +
              "<div>" +
                "<label class='block text-[10px] text-slate-400'>Card PAN (DE 2)</label>" +
                "<input id='grp-card-" + grpKey + "' type='text' value='" + p.default_pan + "' oninput='updateGroupAccounts(\"" + grpKey + "\")' class='w-full bg-slate-950 border border-slate-700 rounded px-1.5 py-0.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-indigo-500'>" +
              "</div>" +
            "</div>" +
          "</div>";
      });
    }

    function renderSuperScenariosTable() {
      const tbody = document.getElementById("super-scenarios-tbody");
      if (!tbody) return;
      tbody.innerHTML = "";

      loadedScenarios.forEach(sc => {
        const grp = sc.group || "standard";
        const accInputVal = document.getElementById("grp-acc-" + grp) ? document.getElementById("grp-acc-" + grp).value : (loadedProfiles[grp] ? loadedProfiles[grp].default_account : "003002300008773");
        const cardInputVal = document.getElementById("grp-card-" + grp) ? document.getElementById("grp-card-" + grp).value : (loadedProfiles[grp] ? loadedProfiles[grp].default_pan : "6076070030053234");
        const expStr = (sc.expected_codes || ["00"]).join("/");

        tbody.innerHTML += 
          "<tr class='hover:bg-slate-900/80'>" +
            "<td class='p-2 font-bold text-amber-400 font-mono'>" + sc.id + "</td>" +
            "<td class='p-2 font-bold text-slate-400 font-mono text-[11px]'>" + sc.channel + "</td>" +
            "<td class='p-2 font-semibold text-slate-200'>" + sc.name + "</td>" +
            "<td class='p-2 font-mono text-emerald-300 text-xs'>" +
              "<span id='sc-acc-label-" + sc.id + "'>" + accInputVal + "</span>" +
            "</td>" +
            "<td class='p-2 font-mono text-cyan-300 text-xs'>" +
              "<span id='sc-card-label-" + sc.id + "'>" + cardInputVal + "</span>" +
            "</td>" +
            "<td class='p-2 font-mono text-amber-300 font-bold'>" + expStr + "</td>" +
            "<td class='p-2 text-slate-400 text-[11px] leading-tight'>" + sc.cbs_vendor_note + "</td>" +
          "</tr>";
      });
    }

    function updateGroupAccounts(grpKey) {
      const newAcc = document.getElementById("grp-acc-" + grpKey).value.trim();
      const newCard = document.getElementById("grp-card-" + grpKey).value.trim();

      loadedScenarios.forEach(sc => {
        if (sc.group === grpKey) {
          const accEl = document.getElementById("sc-acc-label-" + sc.id);
          const cardEl = document.getElementById("sc-card-label-" + sc.id);
          if (accEl) accEl.innerText = newAcc;
          if (cardEl) cardEl.innerText = newCard;
        }
      });
    }

    function executePrimaryAction(forceTimeout = false) {
      sendTransactionWithFlow(isCurrentTxReversalType, forceTimeout);
    }

    async function sendTransactionWithFlow(isReversalTrigger, forceTimeout = false) {
      const ip = ipInput ? ipInput.value.trim() : "";
      const port = portInput ? parseInt(portInput.value.trim()) : 0;
      const framing = framingSelect ? framingSelect.value : "ascii_4";
      const bitmap_fmt = bitmapFmtSelect ? bitmapFmtSelect.value : "hex_ascii";
      const charset = charsetSelect ? charsetSelect.value : "ascii";
      const tpdu = tpduInput ? tpduInput.value.trim() : "";
      const timeout_sec = timeoutInput ? (parseFloat(timeoutInput.value) || 6.0) : 6.0;
      const iso = reqArea ? reqArea.value.trim() : "";
      const respBox = document.getElementById("iso-response");
      const badge = document.getElementById("de39-badge");

      if (!ip || !port) { alert("Enter valid Target IP and Port."); return; }
      if (!iso) { alert("Request payload box is empty."); return; }

      if (primaryBtn) {
        primaryBtn.disabled = true;
        primaryBtn.innerText = forceTimeout ? "Simulating Timeout (68)..." : (isReversalTrigger ? "Sending 0200..." : "Sending...");
      }
      if (respBox) respBox.value = forceTimeout ? "[Simulating CBS Timeout / Late Response (68)]..." : "[Transmitting 0200 request to " + ip + ":" + port + "]...";

      lastSent0200Iso = iso;

      try {
        const res = await fetch("/api/send", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ip, port, tx_key: activeTxKey, framing, bitmap_fmt, charset, tpdu, timeout_sec, iso_request: iso, force_timeout: forceTimeout })
        });
        const d = await res.json();

        if (d.status === "success") {
          lastReceived0210Iso = d.iso_response;
          if (respBox) respBox.value = d.iso_response;
          const latBadge = document.getElementById("resp-latency");
          if (latBadge) latBadge.innerText = "Latency: " + d.latency_ms + "ms";

          const de39 = d.parsed_response.de39 || { code: "--", label: "Unknown" };
          lastDe39Code = de39.code;
          lastDe39Label = de39.label;

          if (badge) {
            badge.innerText = "[" + de39.code + "] " + de39.label;
            badge.className = de39.code === '00' ? "font-mono font-bold text-emerald-400" : (de39.code === '68' ? "font-mono font-bold text-amber-400" : "font-mono font-bold text-cyan-300");
          }
          renderParsedTable(d.parsed_response.fields);

          if (instantRevBtn) instantRevBtn.classList.remove("hidden");

          if (d.timed_out || de39.code === '68' || isReversalTrigger) {
            promptReversalModal(de39.code, de39.label);
          }
        } else {
          if (respBox) respBox.value = "Error: " + d.message;
          if (badge) {
            badge.innerText = "Transaction Failed";
            badge.className = "font-mono font-bold text-red-400";
          }
        }
      } catch (err) {
        if (respBox) respBox.value = "Fatal Client Exception: " + err;
      } finally {
        if (primaryBtn) {
          primaryBtn.disabled = false;
          primaryBtn.innerText = isCurrentTxReversalType ? "Send 0200 -> Prompt Reversal (0420)" : "Send Single ISO Transaction";
        }
      }
    }

    function promptReversalModalForCurrent() {
      if (!lastSent0200Iso) {
        alert("Please send a transaction first before initiating reversal.");
        return;
      }
      promptReversalModal(lastDe39Code || "68", lastDe39Label || "Timeout / Late Response");
    }

    function promptReversalModal(rcCode, rcLabel) {
      const modal = document.getElementById("reversal-confirm-modal");
      const de39Display = document.getElementById("modal-de39-display");
      const txDetails = document.getElementById("modal-tx-details");

      if (de39Display) {
        de39Display.innerText = "[" + rcCode + "] " + rcLabel;
        de39Display.className = rcCode === '68' ? "text-base font-bold font-mono text-amber-400" : (rcCode === '00' ? "text-base font-bold font-mono text-emerald-400" : "text-base font-bold font-mono text-cyan-300");
      }

      if (txDetails) {
        const rrn = rrnInput ? rrnInput.value.trim() : "--";
        const stan = rrn.length >= 6 ? rrn.slice(-6) : "--";
        const pan = panInput ? panInput.value.trim() : "--";
        txDetails.innerText = "Target RRN: " + rrn + " | STAN: " + stan + " | Card: " + pan;
      }

      if (modal) modal.classList.remove("hidden");
    }

    async function closeReversalModal(shouldProceed) {
      const modal = document.getElementById("reversal-confirm-modal");
      if (modal) modal.classList.add("hidden");

      if (shouldProceed) {
        await executeLinked0420Reversal();
      }
    }

    async function executeLinked0420Reversal() {
      const ip = ipInput ? ipInput.value.trim() : "";
      const port = portInput ? parseInt(portInput.value.trim()) : 0;
      const framing = framingSelect ? framingSelect.value : "ascii_4";
      const bitmap_fmt = bitmapFmtSelect ? bitmapFmtSelect.value : "hex_ascii";
      const charset = charsetSelect ? charsetSelect.value : "ascii";
      const tpdu = tpduInput ? tpduInput.value.trim() : "";
      const timeout_sec = timeoutInput ? (parseFloat(timeoutInput.value) || 6.0) : 6.0;
      const respBox = document.getElementById("iso-response");
      const badge = document.getElementById("de39-badge");

      if (!lastSent0200Iso) {
        alert("Missing original request ISO.");
        return;
      }

      if (respBox) respBox.value = "[Constructing DE 90 & Transmitting 0420 Reversal to " + ip + ":" + port + "]...";
      if (badge) {
        badge.innerText = "Reversal (0420) In-Flight...";
        badge.className = "font-mono font-bold text-amber-400 animate-pulse";
      }

      try {
        const res = await fetch("/api/execute_linked_0420", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ip, port, framing, bitmap_fmt, charset, tpdu, timeout_sec,
            orig_req_iso: lastSent0200Iso,
            reason_code: "68"
          })
        });
        const d = await res.json();

        if (d.status === "success") {
          const revDe39 = (d.parsed_response && d.parsed_response.de39) || { code: "00", label: "Approved / Reversal Completed" };

          if (respBox) {
            respBox.value = 
              "=== LEG 1: ORIGINAL 0200 TRANSACTION ===\\n" +
              "REQ:  " + lastSent0200Iso + "\\n" +
              "RESP: " + (lastReceived0210Iso || "[No Bytes - Timeout]") + "\\n" +
              "RC:   [" + lastDe39Code + "] " + lastDe39Label + "\\n\\n" +
              "=== LEG 2: AUTO-LINKED 0420 REVERSAL (METHOD 2: DE 90 PARITY, REASON 68) ===\\n" +
              "DE 90: " + d.de90 + "\\n" +
              "REQ:   " + d.rev_req_iso + "\\n" +
              "RESP:  " + d.rev_resp_iso + "\\n" +
              "RC:    [" + revDe39.code + "] " + revDe39.label + " (" + d.latency_ms + "ms)";
          }

          if (reqArea0420) reqArea0420.value = d.rev_req_iso;
          const latBadge = document.getElementById("resp-latency");
          if (latBadge) latBadge.innerText = "Reversal Latency: " + d.latency_ms + "ms";

          if (badge) {
            badge.innerText = "Reversal Result: [" + revDe39.code + "] " + revDe39.label;
            badge.className = revDe39.code === '00' ? "font-mono font-bold text-emerald-400" : "font-mono font-bold text-cyan-300";
          }

          if (d.parsed_response && d.parsed_response.fields) {
            renderParsedTable(d.parsed_response.fields);
          }
        } else {
          alert("Reversal Exception: " + d.message);
          if (badge) {
            badge.innerText = "Reversal Failed";
            badge.className = "font-mono font-bold text-red-400";
          }
        }
      } catch (err) {
        if (respBox) respBox.value = "Fatal Reversal Exception: " + err;
      }
    }

    function addLengthToRequest() {
      if (!reqArea) return;
      var val = reqArea.value.trim();
      if (!val) return;
      if (val.length > 4 && /^\\d{4}(0200|0210|0220|0420|0430|0800|0810)/.test(val)) {
        val = val.substring(4);
      }
      var isoLen = val.length;
      var header = String(isoLen).padStart(4, '0');
      reqArea.value = header + val;
      updateLengthCounter();
    }

    function removeLengthFromRequest() {
      if (!reqArea) return;
      var val = reqArea.value.trim();
      if (val.length > 4 && /^\\d{4}(0200|0210|0220|0420|0430|0800|0810)/.test(val)) {
        reqArea.value = val.substring(4);
        updateLengthCounter();
      }
    }

    function updateLengthCounter() {
      if (!reqArea || !lenBadge) return;
      var val = reqArea.value.trim();
      var totalLen = val.length;
      var hasHeader = totalLen > 4 && /^\\d{4}(0200|0210|0220|0420|0430|0800|0810)/.test(val);

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
      if (!reqArea) return;
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

      const tbody = document.getElementById("editable-request-tbody");
      if (!tbody) return;
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

      const panel = document.getElementById("editable-request-panel");
      if (panel) panel.classList.remove("hidden");
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
        body: JSON.stringify({ mti: "0200", fields: fieldDict })
      });
      const d = await res.json();
      if (d.status === "success") {
        if (reqArea) reqArea.value = d.raw_iso;
        updateLengthCounter();
        alert("Payload updated successfully from editable fields!");
      } else {
        alert("Failed to rebuild ISO: " + d.message);
      }
    }

    async function saveTargetAsDefault() {
      const ip = ipInput ? ipInput.value.trim() : "";
      const port = portInput ? parseInt(portInput.value.trim()) : 0;
      const framing = framingSelect ? framingSelect.value : "ascii_4";
      const bitmap_fmt = bitmapFmtSelect ? bitmapFmtSelect.value : "hex_ascii";
      const charset = charsetSelect ? charsetSelect.value : "ascii";
      const tpdu = tpduInput ? tpduInput.value.trim() : "";
      const timeout_sec = timeoutInput ? (parseFloat(timeoutInput.value) || 6.0) : 6.0;
      if (!ip || !port) { alert("Please enter a valid IP and Port."); return; }

      await fetch("/api/target/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, port, framing, bitmap_fmt, charset, tpdu, timeout_sec })
      });
      alert("Default settings saved to iso_config.json: " + ip + ":" + port);
    }

    // Dynamic Parameter Regeneration: Preserves pasted Card, Account, and Acquiring ID across all transactions
    async function regenerateDynamic(randomizeRRN = true) {
      if (!activeTxKey) return;

      try {
        const res = await fetch("/api/build_request", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            tx_key: activeTxKey,
            proc_code: procCodeInput ? procCodeInput.value.trim() : "",
            pan: panInput ? panInput.value.trim() : "",
            account: accInput ? accInput.value.trim() : "",
            acq_id: acqInput ? acqInput.value.trim() : "",
            rrn: randomizeRRN ? "" : (rrnInput ? rrnInput.value.trim() : "")
          })
        });
        const data = await res.json();
        if (data.raw_iso) {
          if (reqArea) reqArea.value = data.raw_iso_0200 || data.raw_iso;
          updateLengthCounter();

          if (procCodeInput) procCodeInput.value = data.proc_code;
          // Retain pasted/typed credentials if present, else assign response defaults
          if (panInput && !panInput.value.trim()) panInput.value = data.pan;
          if (accInput && !accInput.value.trim()) accInput.value = data.account;
          if (acqInput && !acqInput.value.trim()) acqInput.value = data.acq_id;
          if (rrnInput) rrnInput.value = data.rrn;

          isCurrentTxReversalType = data.is_reversal;

          if (isCurrentTxReversalType) {
            if (revPreviewContainer) revPreviewContainer.classList.remove("hidden");
            if (reqArea0420) reqArea0420.value = data.raw_iso_0420 || "";
            if (reqBoxTitle) reqBoxTitle.innerText = "Leg 1: Original Request Payload (MTI: 0200)";
            if (primaryBtn) {
              primaryBtn.innerText = "Send 0200 -> Prompt Reversal (0420)";
              primaryBtn.className = "w-1/2 bg-amber-600 hover:bg-amber-500 text-white font-bold py-2 rounded text-xs transition shadow-sm";
            }
          } else {
            if (revPreviewContainer) revPreviewContainer.classList.add("hidden");
            if (reqBoxTitle) reqBoxTitle.innerText = "Request ISO Payload (0200)";
            if (primaryBtn) {
              primaryBtn.innerText = "Send Single ISO Transaction";
              primaryBtn.className = "w-1/2 bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 rounded text-xs transition shadow-sm";
            }
          }
        }
      } catch (e) {
        console.error("Failed to regenerate dynamic parameters:", e);
      }
    }

    async function loadAppConfig() {
      try {
        const res = await fetch("/api/config");
        configData = await res.json();

        const tgt = configData.target_settings || {};
        if (ipInput) ipInput.value = tgt.default_ip || "10.167.1.153";
        if (portInput) portInput.value = tgt.default_port || 9019;
        if (tgt.default_framing && framingSelect) framingSelect.value = tgt.default_framing;
        if (tgt.default_bitmap_fmt && bitmapFmtSelect) bitmapFmtSelect.value = tgt.default_bitmap_fmt;
        if (tgt.default_charset && charsetSelect) charsetSelect.value = tgt.default_charset;
        if (tgt.default_tpdu && tpduInput) tpduInput.value = tgt.default_tpdu;
        if (tgt.default_timeout && timeoutInput) timeoutInput.value = tgt.default_timeout;

        const btnContainer = document.getElementById("sample-buttons-container");
        const cfgSelect = document.getElementById("cfg-tx-select");
        if (btnContainer) btnContainer.innerHTML = "";
        if (cfgSelect) cfgSelect.innerHTML = "";

        const samples = configData.sample_requests || {};
        let firstKey = null;

        for (const [key, s] of Object.entries(samples)) {
          if (!firstKey) firstKey = key;

          const btn = document.createElement("button");
          btn.id = "btn-sample-" + key;
          const isRev = s.mti === "0420" || key.includes("reversal");
          btn.className = isRev
            ? "bg-amber-950/40 hover:bg-amber-900/60 text-amber-300 px-2.5 py-1 rounded border border-amber-800/80 font-medium transition text-xs"
            : "bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded border border-slate-700 font-medium transition text-xs";
          btn.innerText = s.label;
          btn.onclick = () => {
            activeTxKey = key;
            highlightActiveTxButton(key);
            if (procCodeInput) procCodeInput.value = s.proc_code || "";
            // Shared parameters: panInput, accInput, acqInput are preserved seamlessly
            regenerateDynamic(true);
          };
          if (btnContainer) btnContainer.appendChild(btn);

          const optCfg = document.createElement("option");
          optCfg.value = key;
          optCfg.innerText = s.label + " (" + key + ")";
          if (cfgSelect) cfgSelect.appendChild(optCfg);
        }

        if (firstKey) {
          activeTxKey = firstKey;
          highlightActiveTxButton(firstKey);
          if (procCodeInput) procCodeInput.value = samples[firstKey].proc_code || "";
          await regenerateDynamic(true);
          loadTxSchemaToEdit();
        }
      } catch (e) {
        console.error("Error in loadAppConfig:", e);
      }
    }

    function highlightActiveTxButton(activeKey) {
      const samples = configData.sample_requests || {};
      for (const [key, s] of Object.entries(samples)) {
        const btn = document.getElementById("btn-sample-" + key);
        if (btn) {
          const isRev = s.mti === "0420" || key.includes("reversal");
          if (key === activeKey) {
            btn.className = isRev
              ? "bg-amber-600 text-white font-bold px-2.5 py-1 rounded border border-amber-500 shadow-sm text-xs"
              : "bg-indigo-600 text-white font-bold px-2.5 py-1 rounded border border-indigo-500 shadow-sm text-xs";
          } else {
            btn.className = isRev
              ? "bg-amber-950/40 hover:bg-amber-900/60 text-amber-300 px-2.5 py-1 rounded border border-amber-800/80 font-medium transition text-xs"
              : "bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 rounded border border-slate-700 font-medium transition text-xs";
          }
        }
      }
    }

    // ==============================================================
    // TRANSACTION CRUD (ADD, EDIT, DELETE)
    // ==============================================================

    function openAddTxModal() {
      document.getElementById("add-tx-label").value = "";
      document.getElementById("add-tx-key").value = "";
      document.getElementById("add-tx-mti").value = "0200";
      document.getElementById("add-tx-proc").value = "000000";
      document.getElementById("add-tx-req-des").value = "2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 41, 42, 43, 48, 49, 60, 102";
      document.getElementById("add-tx-resp-des").value = "2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 102";
      document.getElementById("add-tx-raw-iso").value = "";
      document.getElementById("add-tx-modal").classList.remove("hidden");
    }

    function closeAddTxModal() {
      document.getElementById("add-tx-modal").classList.add("hidden");
    }

    async function parseRawIntoAddModal() {
      const raw = document.getElementById("add-tx-raw-iso").value.trim();
      if (!raw) { alert("Please paste a raw ISO payload to extract elements."); return; }

      const res = await fetch("/api/parse_raw", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_iso: raw })
      });
      const d = await res.json();
      if (d.status === "success") {
        document.getElementById("add-tx-mti").value = d.mti;
        const deNumbers = d.fields.map(f => f.de);
        document.getElementById("add-tx-req-des").value = deNumbers.join(", ");
        const procField = d.fields.find(f => f.de === 3);
        if (procField) document.getElementById("add-tx-proc").value = procField.val;
        alert("Extracted MTI " + d.mti + " and " + deNumbers.length + " DEs!");
      } else {
        alert("Extraction failed: " + d.message);
      }
    }

    async function submitAddTransaction() {
      const label = document.getElementById("add-tx-label").value.trim();
      let key = document.getElementById("add-tx-key").value.trim().toLowerCase().replace(/\\s+/g, '_');
      if (!key && label) key = label.toLowerCase().replace(/\\s+/g, '_');
      const mti = document.getElementById("add-tx-mti").value.trim() || "0200";
      const proc_code = document.getElementById("add-tx-proc").value.trim() || "000000";

      const reqDesStr = document.getElementById("add-tx-req-des").value;
      const respDesStr = document.getElementById("add-tx-resp-des").value;
      const req_des = reqDesStr.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
      const resp_des = respDesStr.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));

      if (!label || !key) { alert("Transaction Label and Key are required."); return; }

      const res = await fetch("/api/transactions/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, label, mti, proc_code, req_des_present: req_des, resp_des_present: resp_des })
      });
      const d = await res.json();
      if (d.status === "success") {
        alert(d.message);
        closeAddTxModal();
        await loadAppConfig();
      } else {
        alert(d.message);
      }
    }

    function openEditTxListModal() {
      const container = document.getElementById("edit-tx-list-container");
      container.innerHTML = "";
      const samples = configData.sample_requests || {};

      Object.entries(samples).forEach(([k, s]) => {
        const btn = document.createElement("button");
        btn.className = "w-full text-left p-2 rounded bg-slate-950 hover:bg-indigo-950 border border-slate-800 hover:border-indigo-600 transition flex justify-between items-center text-xs";
        btn.innerHTML = "<span class='font-semibold text-slate-200'>" + s.label + "</span><span class='font-mono text-slate-500 text-[11px]'>" + k + "</span>";
        btn.onclick = () => {
          document.getElementById("edit-tx-list-modal").classList.add("hidden");
          openEditTxFormModal(k, s);
        };
        container.appendChild(btn);
      });

      document.getElementById("edit-tx-list-modal").classList.remove("hidden");
    }

    function openEditTxFormModal(key, s) {
      document.getElementById("edit-tx-original-key").value = key;
      document.getElementById("edit-tx-key").value = key;
      document.getElementById("edit-tx-label").value = s.label || "";
      document.getElementById("edit-tx-mti").value = s.mti || "0200";
      document.getElementById("edit-tx-proc").value = s.proc_code || "000000";
      document.getElementById("edit-tx-req-des").value = (s.req_des_present || []).join(", ");
      document.getElementById("edit-tx-resp-des").value = (s.resp_des_present || []).join(", ");
      document.getElementById("edit-tx-form-modal").classList.remove("hidden");
    }

    function closeEditTxFormModal() {
      document.getElementById("edit-tx-form-modal").classList.add("hidden");
    }

    async function submitEditTransaction() {
      const old_key = document.getElementById("edit-tx-original-key").value;
      const key = document.getElementById("edit-tx-key").value.trim().toLowerCase().replace(/\\s+/g, '_');
      const label = document.getElementById("edit-tx-label").value.trim();
      const mti = document.getElementById("edit-tx-mti").value.trim() || "0200";
      const proc_code = document.getElementById("edit-tx-proc").value.trim() || "000000";

      const reqDesStr = document.getElementById("edit-tx-req-des").value;
      const respDesStr = document.getElementById("edit-tx-resp-des").value;
      const req_des = reqDesStr.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
      const resp_des = respDesStr.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));

      if (!label || !key) { alert("Label and Key cannot be empty."); return; }

      const res = await fetch("/api/transactions/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ old_key, key, label, mti, proc_code, req_des_present: req_des, resp_des_present: resp_des })
      });
      const d = await res.json();
      if (d.status === "success") {
        alert(d.message);
        closeEditTxFormModal();
        await loadAppConfig();
      } else {
        alert(d.message);
      }
    }

    function openDeleteTxListModal() {
      const container = document.getElementById("delete-tx-list-container");
      container.innerHTML = "";
      const samples = configData.sample_requests || {};

      Object.entries(samples).forEach(([k, s]) => {
        const btn = document.createElement("button");
        btn.className = "w-full text-left p-2 rounded bg-slate-950 hover:bg-rose-950 border border-slate-800 hover:border-rose-600 transition flex justify-between items-center text-xs";
        btn.innerHTML = "<span class='font-semibold text-slate-200'>" + s.label + "</span><span class='font-mono text-slate-500 text-[11px]'>" + k + "</span>";
        btn.onclick = () => {
          document.getElementById("delete-tx-list-modal").classList.add("hidden");
          promptDeleteConfirmation(k, s.label);
        };
        container.appendChild(btn);
      });

      document.getElementById("delete-tx-list-modal").classList.remove("hidden");
    }

    function promptDeleteConfirmation(key, label) {
      document.getElementById("delete-target-key").value = key;
      document.getElementById("delete-target-label").innerText = label + " (" + key + ")";
      document.getElementById("delete-confirm-modal").classList.remove("hidden");
    }

    async function closeDeleteConfirmModal(confirmed) {
      const modal = document.getElementById("delete-confirm-modal");
      modal.classList.add("hidden");

      if (confirmed) {
        const key = document.getElementById("delete-target-key").value;
        const res = await fetch("/api/transactions/delete", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ key })
        });
        const d = await res.json();
        if (d.status === "success") {
          alert(d.message);
          await loadAppConfig();
        } else {
          alert(d.message);
        }
      }
    }

    // ==============================================================
    // SCHEMA MANAGER & CONFIG
    // ==============================================================

    function loadTxSchemaToEdit() {
      const cfgSelect = document.getElementById("cfg-tx-select");
      if (!cfgSelect) return;
      const key = cfgSelect.value;
      const radio = document.querySelector('input[name="schema-target-radio"]:checked');
      const targetType = radio ? radio.value : "req";
      const tx = (configData.sample_requests || {})[key];
      if (tx) {
        const list = targetType === "req" 
          ? (tx.req_des_present || tx.des_present || []) 
          : (tx.resp_des_present || []);
        const desInput = document.getElementById("des-array-input");
        const desLabel = document.getElementById("des-array-label");
        if (desInput) desInput.value = list.join(", ");
        if (desLabel) desLabel.innerText = targetType === "req"
          ? "Request Data Elements (Outgoing, Comma Separated)"
          : "Expected Response Data Elements (Validation Baseline, Comma Separated)";
        renderSchemaBadges();
      }
    }

    function renderSchemaBadges() {
      const desInput = document.getElementById("des-array-input");
      if (!desInput) return;
      const inputStr = desInput.value;
      const des = inputStr.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
      const container = document.getElementById("schema-badges-container");
      if (!container) return;
      container.innerHTML = "";

      des.sort((a, b) => a - b).forEach(de => {
        const fieldName = ((configData.field_definitions || {})[de] || {}).name || ("DE " + de);
        const badge = document.createElement("span");
        badge.className = "inline-flex items-center gap-1 bg-slate-800 text-indigo-300 border border-slate-700 px-2 py-0.5 rounded text-[11px] font-mono cursor-pointer hover:border-red-600 hover:text-red-400";
        badge.innerHTML = "<span>DE " + de + " (" + fieldName + ")</span> <span class='text-xs'>&times;</span>";
        badge.onclick = () => removeDEFromSchema(de);
        container.appendChild(badge);
      });
    }

    function addSingleDE() {
      const deInput = document.getElementById("new-de-input");
      if (!deInput) return;
      const deVal = parseInt(deInput.value.trim());
      if (isNaN(deVal) || deVal < 2 || deVal > 128) { alert("Enter valid DE # (2-128)."); return; }
      const input = document.getElementById("des-array-input");
      if (!input) return;
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
      if (!input) return;
      const current = input.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
      input.value = current.filter(d => d !== deToRemove).join(", ");
      renderSchemaBadges();
    }

    async function saveNumericalSchema() {
      const cfgSelect = document.getElementById("cfg-tx-select");
      if (!cfgSelect) return;
      const key = cfgSelect.value;
      const radio = document.querySelector('input[name="schema-target-radio"]:checked');
      const targetType = radio ? radio.value : "req";
      const input = document.getElementById("des-array-input");
      if (!input) return;
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
        alert("Saved schema successfully for " + key);
        if (activeTxKey === key && targetType === "req") regenerateDynamic(false);
      } else {
        alert("Failed to save: " + data.message);
      }
    }

    function switchWindow(tab) {
      const winSingle = document.getElementById("win-single");
      const winSuper = document.getElementById("win-super");
      const winCfg = document.getElementById("win-cfg");

      if (winSingle) winSingle.classList.toggle("hidden", tab !== 'single');
      if (winSuper) winSuper.classList.toggle("hidden", tab !== 'super');
      if (winCfg) winCfg.classList.toggle("hidden", tab !== 'cfg');

      ['single', 'super', 'cfg'].forEach(t => {
        const el = document.getElementById("tab-btn-" + t);
        if (el) {
          el.className = (tab === t) 
            ? "px-4 py-1.5 text-xs font-semibold rounded-t border-b-2 border-indigo-500 text-white bg-slate-900"
            : "px-4 py-1.5 text-xs font-semibold rounded-t text-slate-400 hover:text-white bg-slate-950";
        }
      });
    }

    function renderParsedTable(fields) {
      const tbody = document.getElementById("parsed-table-body");
      if (!tbody) return;
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

    // ==============================================================
    // SUPER TESTING SUITE RUNNER
    // ==============================================================

    async function runSuperTestSuite() {
      const ip = ipInput ? ipInput.value.trim() : "";
      const port = portInput ? parseInt(portInput.value.trim()) : 0;
      const framing = framingSelect ? framingSelect.value : "ascii_4";
      const bitmap_fmt = bitmapFmtSelect ? bitmapFmtSelect.value : "hex_ascii";
      const charset = charsetSelect ? charsetSelect.value : "ascii";
      const tpdu = tpduInput ? tpduInput.value.trim() : "";
      const timeout_sec = timeoutInput ? (parseFloat(timeoutInput.value) || 6.0) : 6.0;

      if (!ip || !port) { alert("Enter valid Target IP and Port."); return; }

      const distinct_accounts = {};
      Object.keys(loadedProfiles).forEach(grpKey => {
        const accInp = document.getElementById("grp-acc-" + grpKey);
        const cardInp = document.getElementById("grp-card-" + grpKey);
        distinct_accounts[grpKey] = {
          account: accInp ? accInp.value.trim() : "",
          pan: cardInp ? cardInp.value.trim() : ""
        };
      });

      const runBtn = document.getElementById("super-run-btn");
      const scoreBadge = document.getElementById("super-score-badge");
      const viewReleaseBtn = document.getElementById("view-release-btn");
      const tbody = document.getElementById("super-table-body");

      if (runBtn) {
        runBtn.disabled = true;
        runBtn.innerText = "Executing End-to-End Test Suite Across Issuer ATM, POS & ECOM...";
      }
      if (scoreBadge) {
        scoreBadge.innerText = "Auditing Compliance...";
        scoreBadge.className = "text-xs font-mono font-bold text-amber-400 animate-pulse";
      }
      if (tbody) tbody.innerHTML = "<tr><td colspan='10' class='p-4 text-center text-slate-400 animate-pulse'>Executing automated CBS Switch checks...</td></tr>";

      try {
        const res = await fetch("/api/super_test/run", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ip, port, framing, bitmap_fmt, charset, tpdu, timeout_sec, distinct_accounts })
        });
        const d = await res.json();

        if (d.status === "success") {
          latestReportData = d.report || [];
          document.getElementById("release-notes-textarea").value = d.release_notes;
          if (viewReleaseBtn) viewReleaseBtn.classList.remove("hidden");

          if (scoreBadge) {
            scoreBadge.innerText = "Compliance Score: " + d.passed + " / " + d.total + " (" + d.pass_percentage + "%)";
            scoreBadge.className = d.pass_percentage >= 90 ? "text-xs font-mono font-bold text-emerald-400" : "text-xs font-mono font-bold text-amber-400";
          }

          if (tbody) {
            tbody.innerHTML = "";
            d.report.forEach(item => {
              const isPass = item.verdict === "PASS";
              tbody.innerHTML += 
                "<tr class='hover:bg-slate-900/80'>" +
                  "<td class='p-1.5 font-bold text-amber-400 font-mono'>" + item.id + "</td>" +
                  "<td class='p-1.5 font-bold text-slate-400 font-mono text-[11px]'>" + item.channel + "</td>" +
                  "<td class='p-1.5 font-semibold text-slate-200'>" + item.name + "</td>" +
                  "<td class='p-1.5 font-mono text-emerald-300 font-bold'>" + item.account + "</td>" +
                  "<td class='p-1.5 font-mono text-slate-400'>" + item.mti + "</td>" +
                  "<td class='p-1.5 font-mono text-cyan-300 font-bold'>" + item.expected_code + "</td>" +
                  "<td class='p-1.5 font-mono " + (isPass ? "text-emerald-400" : "text-red-400") + " font-bold'>" + item.actual_code + "</td>" +
                  "<td class='p-1.5 font-mono text-slate-400'>" + item.latency + "</td>" +
                  "<td class='p-1.5 font-bold " + (isPass ? "text-emerald-400" : "text-red-400") + "'>" + item.verdict + "</td>" +
                  "<td class='p-1.5 text-slate-400 text-[11px]'>" + item.cbs_vendor_note + "</td>" +
                "</tr>";
            });
          }
        } else {
          alert("Audit Suite Error: " + d.message);
        }
      } catch (err) {
        alert("Client Exception: " + err);
      } finally {
        if (runBtn) {
          runBtn.disabled = false;
          runBtn.innerText = "Execute End-to-End Super Testing Suite";
        }
      }
    }

    function exportAuditReportToExcel() {
      if (!latestReportData || latestReportData.length === 0) {
        alert("Please run the Super Testing Suite first to generate test case results.");
        return;
      }

      const rows = latestReportData.map((item, index) => ({
        "Test Case #": index + 1,
        "Scenario ID": item.id,
        "Channel": item.channel,
        "Test Scenario Name": item.name,
        "Account Group": item.group,
        "Test Card (PAN)": item.card,
        "Account Number": item.account,
        "Request MTI": item.mti,
        "Expected DE 39": item.expected_code,
        "Actual DE 39": item.actual_code,
        "Execution Latency": item.latency,
        "Status / Verdict": item.verdict,
        "CBS Regulatory / Validation Rule": item.cbs_vendor_note
      }));

      const worksheet = XLSX.utils.json_to_sheet(rows);
      const workbook = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(workbook, worksheet, "CBS_Issuer_Audit");

      worksheet['!cols'] = [
        { wch: 12 }, { wch: 22 }, { wch: 10 }, { wch: 45 }, { wch: 18 },
        { wch: 22 }, { wch: 20 }, { wch: 14 }, { wch: 16 }, { wch: 14 },
        { wch: 18 }, { wch: 16 }, { wch: 70 }
      ];

      const dateStr = new Date().toISOString().slice(0, 10);
      XLSX.writeFile(workbook, `ATM_Switch_CBS_Audit_Report_${dateStr}.xlsx`);
    }

    function openReleaseNotesModal() {
      const modal = document.getElementById("release-notes-modal");
      if (modal) modal.classList.remove("hidden");
    }

    function copyReleaseNotesToClipboard() {
      const txt = document.getElementById("release-notes-textarea").value;
      navigator.clipboard.writeText(txt).then(() => {
        alert("QA Certification Sign-Off Note copied to clipboard successfully!");
      });
    }
  </script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)