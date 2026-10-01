"""
iso_engine.py - Shared ISO 8583 engine
=======================================
Single source of truth for:
  * Field (DE) definitions and RBI / NPCI response-code table
  * Bitmap build / parse (+ bit flipping for tamper tests)
  * Amount (n12 <-> rupees) and DE 54 balance helpers
  * ISO string <-> dict  (parse_iso / parse_iso_ex / format_iso)
  * Wire encoding (ASCII / EBCDIC, hex-ASCII / binary bitmap, TPDU)
  * Length-header framing (ascii_4 / bin_2 / bin_2_inc / raw)
  * Length-aware socket read (recv_framed) and client transact (tcp_transact)
  * Server-side frame extraction (extract_frame) used by the mock CBS

Both iso_tester_app.py (Switch side) and iso8583_cbs_sim.py (CBS side) import
this module, so a field definition fixed here is fixed everywhere.
"""

import socket
import struct
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP

# ----------------------------------------------------------------------------
# MTI tables
# ----------------------------------------------------------------------------
VALID_MTIS = (
    "0100", "0110", "0120", "0130",
    "0200", "0210", "0220", "0230",
    "0400", "0410", "0420", "0421", "0430",
    "0800", "0810", "0820", "0830",
)

RESPONSE_MTI_MAP = {
    "0100": "0110", "0120": "0130",
    "0200": "0210", "0220": "0230",
    "0400": "0410", "0420": "0430", "0421": "0430",
    "0800": "0810", "0820": "0830",
}

_MTI_ASCII = tuple(m.encode("latin-1") for m in VALID_MTIS)
_MTI_EBCDIC = tuple(m.encode("cp500") for m in VALID_MTIS)
_HEX_CHARS = set("0123456789ABCDEFabcdef")

# Private-use DEs that are treated as LLLVAR when no definition exists
PRIVATE_LLLVAR_FALLBACK = {104, 120, 121, 122, 123, 124, 125, 126, 127}

# ----------------------------------------------------------------------------
# Field definitions (string keys so they can be merged with JSON configs)
# ----------------------------------------------------------------------------
COMMON_FIELD_DEFINITIONS = {
    "2": {"name": "Primary Account Number (PAN)", "type": "llvar", "len": 2},
    "3": {"name": "Processing Code", "type": "fixed", "len": 6},
    "4": {"name": "Amount, Transaction", "type": "fixed", "len": 12},
    "5": {"name": "Amount, Settlement", "type": "fixed", "len": 12},
    "6": {"name": "Amount, Cardholder Billing", "type": "fixed", "len": 12},
    "7": {"name": "Transmission Date & Time", "type": "fixed", "len": 10},
    "8": {"name": "Amount, Cardholder Billing Fee", "type": "fixed", "len": 8},
    "9": {"name": "Conversion Rate, Settlement", "type": "fixed", "len": 8},
    "10": {"name": "Conversion Rate, Cardholder Billing", "type": "fixed", "len": 8},
    "11": {"name": "System Trace Audit Number (STAN)", "type": "fixed", "len": 6},
    "12": {"name": "Time, Local Transaction", "type": "fixed", "len": 6},
    "13": {"name": "Date, Local Transaction", "type": "fixed", "len": 4},
    "14": {"name": "Date, Expiration", "type": "fixed", "len": 4},
    "15": {"name": "Date, Settlement", "type": "fixed", "len": 4},
    "16": {"name": "Date, Conversion", "type": "fixed", "len": 4},
    "17": {"name": "Date, Capture", "type": "fixed", "len": 4},
    "18": {"name": "Merchant Type (MCC)", "type": "fixed", "len": 4},
    "19": {"name": "Acquiring Institution Country Code", "type": "fixed", "len": 3},
    "20": {"name": "PAN Extended, Country Code", "type": "fixed", "len": 3},
    "21": {"name": "Forwarding Institution Country Code", "type": "fixed", "len": 3},
    "22": {"name": "POS Entry Mode", "type": "fixed", "len": 3},
    "23": {"name": "Card Sequence Number (CSN)", "type": "fixed", "len": 3},
    "24": {"name": "Network International Identifier (NII)", "type": "fixed", "len": 3},
    "25": {"name": "POS Condition Code", "type": "fixed", "len": 2},
    "26": {"name": "POS PIN Capture Code", "type": "fixed", "len": 2},
    "27": {"name": "Authorization ID Response Length", "type": "fixed", "len": 1},
    "28": {"name": "Amount, Transaction Fee", "type": "fixed", "len": 9},
    "29": {"name": "Amount, Settlement Fee", "type": "fixed", "len": 9},
    "30": {"name": "Amount, Transaction Processing Fee", "type": "fixed", "len": 9},
    "31": {"name": "Amount, Settlement Processing Fee", "type": "fixed", "len": 9},
    "32": {"name": "Acquiring Institution ID Code", "type": "llvar", "len": 2},
    "33": {"name": "Forwarding Institution ID Code", "type": "llvar", "len": 2},
    "35": {"name": "Track 2 Data", "type": "llvar", "len": 2},
    "36": {"name": "Track 3 Data", "type": "lllvar", "len": 3},
    "37": {"name": "Retrieval Reference Number (RRN)", "type": "fixed", "len": 12},
    "38": {"name": "Authorization ID Response", "type": "fixed", "len": 6},
    "39": {"name": "Response Code", "type": "fixed", "len": 2},
    "40": {"name": "Service Restriction Code", "type": "fixed", "len": 3},
    "41": {"name": "Card Acceptor Terminal ID", "type": "fixed", "len": 8},
    "42": {"name": "Card Acceptor ID Code", "type": "fixed", "len": 15},
    "43": {"name": "Card Acceptor Name/Location", "type": "fixed", "len": 40},
    "44": {"name": "Additional Response Data", "type": "llvar", "len": 2},
    "45": {"name": "Track 1 Data", "type": "llvar", "len": 2},
    "46": {"name": "Amounts, Fees / Additional Data (ISO)", "type": "lllvar", "len": 3},
    "47": {"name": "Additional Data - National", "type": "lllvar", "len": 3},
    "48": {"name": "Additional Data - Private / NPCI Private Tags", "type": "lllvar", "len": 3},
    "49": {"name": "Currency Code, Transaction", "type": "fixed", "len": 3},
    "50": {"name": "Currency Code, Settlement", "type": "fixed", "len": 3},
    "51": {"name": "Currency Code, Cardholder Billing", "type": "fixed", "len": 3},
    "52": {"name": "PIN Data Block", "type": "fixed", "len": 16},
    "53": {"name": "Security Related Control Information", "type": "fixed", "len": 16},
    "54": {"name": "Additional Amounts", "type": "lllvar", "len": 3},
    "55": {"name": "ICC / EMV Chip Data (TLV Format)", "type": "lllvar", "len": 3},
    "56": {"name": "Message Reason Code / Original Data", "type": "lllvar", "len": 3},
    "57": {"name": "Authorization Life Cycle Code", "type": "llvar", "len": 2},
    "58": {"name": "Authorizing Agent Institution ID", "type": "llvar", "len": 2},
    "59": {"name": "Transport Data / Echo Data", "type": "lllvar", "len": 3},
    "60": {"name": "Additional POS / Reserved Private", "type": "lllvar", "len": 3},
    "61": {"name": "Other Amounts / Reserved Private", "type": "lllvar", "len": 3},
    "62": {"name": "Reserved Private", "type": "lllvar", "len": 3},
    "63": {"name": "Reserved Private (Mini-Statement)", "type": "lllvar", "len": 3},
    "64": {"name": "Primary MAC", "type": "fixed", "len": 16},
    "70": {"name": "Network Management Information Code", "type": "fixed", "len": 3},
    "90": {"name": "Original Data Elements", "type": "fixed", "len": 42},
    "91": {"name": "File Update Code", "type": "fixed", "len": 1},
    "95": {"name": "Replacement Amounts", "type": "fixed", "len": 42},
    "100": {"name": "Receiving Institution ID Code", "type": "llvar", "len": 2},
    "101": {"name": "File Name / Settlement Identifier", "type": "llvar", "len": 2},
    "102": {"name": "Account Identification 1", "type": "llvar", "len": 2},
    "103": {"name": "Account Identification 2", "type": "llvar", "len": 2},
    "104": {"name": "Transaction Specific Data / NPCI Private", "type": "lllvar", "len": 3},
    "120": {"name": "Reserved Private", "type": "lllvar", "len": 3},
    "121": {"name": "Reserved Private (Token / Virtual ID)", "type": "lllvar", "len": 3},
    "122": {"name": "Reserved Private (Additional Route / Switch Info)", "type": "lllvar", "len": 3},
    "123": {"name": "Reserved Private (Terminal Verification / Device Data)", "type": "lllvar", "len": 3},
    "124": {"name": "Reserved Private (Channel Info)", "type": "lllvar", "len": 3},
    "125": {"name": "Reserved Private (Supporting Data)", "type": "lllvar", "len": 3},
    "126": {"name": "Reserved Private (Custom Routing Data)", "type": "lllvar", "len": 3},
    "127": {"name": "Reserved Private (Network Switch Specific)", "type": "lllvar", "len": 3},
    "128": {"name": "Secondary MAC", "type": "fixed", "len": 16},
}

# ----------------------------------------------------------------------------
# Response codes
# ----------------------------------------------------------------------------
RBI_CODES = {
    "00": {"label": "Approved / Successful", "cat": "SUCCESS"},
    "05": {"label": "Do Not Honor", "cat": "CUSTOMER DECLINE"},
    "06": {"label": "Error / Verification Decline", "cat": "TECHNICAL FAILURE"},
    "09": {"label": "Request In Progress", "cat": "SYSTEM STATUS"},
    "12": {"label": "Invalid Transaction", "cat": "CUSTOMER DECLINE"},
    "13": {"label": "Invalid Amount", "cat": "CUSTOMER DECLINE"},
    "14": {"label": "Invalid Card Number / Account", "cat": "CUSTOMER DECLINE"},
    "15": {"label": "No Such Issuer / Unallocated BIN", "cat": "ROUTING DECLINE"},
    "21": {"label": "No Action Taken", "cat": "SYSTEM STATUS"},
    "25": {"label": "Unable to Locate Original Record", "cat": "SYSTEM STATUS"},
    "30": {"label": "Format Error", "cat": "TECHNICAL FAILURE"},
    "46": {"label": "Stolen Card", "cat": "CUSTOMER DECLINE"},
    "51": {"label": "Insufficient Funds", "cat": "CUSTOMER DECLINE"},
    "52": {"label": "No Checking Account", "cat": "CUSTOMER DECLINE"},
    "53": {"label": "No Savings Account / Blocked", "cat": "CUSTOMER DECLINE"},
    "54": {"label": "Expired Card", "cat": "CUSTOMER DECLINE"},
    "55": {"label": "Incorrect PIN / Retry Exceeded", "cat": "CUSTOMER DECLINE"},
    "57": {"label": "Transaction Not Permitted to Cardholder", "cat": "CUSTOMER DECLINE"},
    "61": {"label": "Exceeds Withdrawal Amount Limit", "cat": "CUSTOMER DECLINE"},
    "62": {"label": "Restricted Card / Freeze", "cat": "CUSTOMER DECLINE"},
    "68": {"label": "Timeout / Late Response", "cat": "TECHNICAL FAILURE"},
    "86": {"label": "Cannot Verify PIN / Switch Error", "cat": "TECHNICAL FAILURE"},
    "91": {"label": "Issuer or Switch Inoperative", "cat": "TECHNICAL FAILURE"},
    "92": {"label": "Unable to Route Transaction", "cat": "TECHNICAL FAILURE"},
    "94": {"label": "Duplicate Transmission", "cat": "TECHNICAL FAILURE"},
    "96": {"label": "System Malfunction", "cat": "TECHNICAL FAILURE"},
    "E2": {"label": "Switch Specific Decline / Reversal", "cat": "TECHNICAL FAILURE"},
}


def describe_rc(code):
    """Return a NEW dict describing a response code (never mutates RBI_CODES)."""
    info = dict(RBI_CODES.get(code, {"label": "Other / Unmapped", "cat": "UNDEFINED"}))
    info["code"] = code
    return info


def expected_response_mti(req_mti):
    req_mti = str(req_mti or "")
    if req_mti in RESPONSE_MTI_MAP:
        return RESPONSE_MTI_MAP[req_mti]
    if len(req_mti) == 4 and req_mti.isdigit():
        return req_mti[:2] + str(min(int(req_mti[2]) + 1, 9)) + req_mti[3]
    return ""


def get_field_def(de, field_defs=None):
    """Return (type, len, name) for a DE, or None if undefined."""
    key = str(int(de))
    info = None
    if field_defs:
        info = field_defs.get(key) or field_defs.get(int(de)) if isinstance(field_defs, dict) else None
    if not info:
        info = COMMON_FIELD_DEFINITIONS.get(key)
    if info:
        return info.get("type", "fixed"), int(info.get("len", 0)), info.get("name", f"DE {key}")
    if int(de) in PRIVATE_LLLVAR_FALLBACK:
        return "lllvar", 3, f"DE {key} (Private)"
    return None


def field_name(de, field_defs=None):
    d = get_field_def(de, field_defs)
    return d[2] if d else f"DE {de}"


# ----------------------------------------------------------------------------
# Bitmap helpers
# ----------------------------------------------------------------------------
def parse_bitmap(hex_map_str):
    bin_str = bin(int(hex_map_str, 16))[2:].zfill(len(hex_map_str) * 4)
    return {i + 1 for i, b in enumerate(bin_str) if b == "1"}


def build_hex_bitmap(active_fields, length_bytes=16):
    total_bits = length_bytes * 8
    bits = ["0"] * total_bits
    for f in active_fields:
        if 1 <= f <= total_bits:
            bits[f - 1] = "1"
    return f"{int(''.join(bits), 2):0{length_bytes * 2}X}"


# ----------------------------------------------------------------------------
# ISO string <-> dict
# ----------------------------------------------------------------------------
def strip_length_header(raw_str):
    """Remove a manual 4-digit ASCII length prefix (e.g. '0319' + '0200...')."""
    s = (raw_str or "").strip().lstrip(">").strip()
    if len(s) > 8 and s[:4].isdigit() and s[4:8] in VALID_MTIS:
        return s[4:], True
    return s, False


def parse_iso_ex(raw_str, field_defs=None):
    """
    Parse an ISO string (hex-ASCII bitmap form).
    Returns dict: mti, fields{int:str}, complete(bool), error(str|None), trailing(str)
    'complete' is False when the message is malformed or a DE could not be decoded.
    """
    result = {"mti": None, "fields": {}, "complete": False, "error": None, "trailing": ""}
    cleaned, _ = strip_length_header(raw_str)

    if len(cleaned) < 20:
        result["error"] = "Message too short to contain MTI + bitmap."
        return result

    mti = cleaned[:4]
    if not mti.isdigit():
        result["error"] = f"Invalid MTI '{mti}'."
        return result

    if cleaned[4] not in _HEX_CHARS:
        result["error"] = "Bitmap is not hex-ASCII."
        return result

    has_sec = bool(int(cleaned[4], 16) & 0x8)
    bm_len = 32 if has_sec else 16
    bitmap_hex = cleaned[4:4 + bm_len]
    if len(bitmap_hex) < bm_len or any(c not in _HEX_CHARS for c in bitmap_hex):
        result["error"] = f"Bitmap must be {bm_len} hex characters."
        return result

    result["mti"] = mti
    active = parse_bitmap(bitmap_hex)
    idx = 4 + bm_len
    fields = {}
    error = None

    for f in sorted(active):
        if f == 1:
            continue
        fdef = get_field_def(f, field_defs)
        if not fdef:
            error = f"DE {f} is set in bitmap but has no definition - parsing stopped."
            break
        f_type, f_len, _ = fdef

        if f_type == "fixed":
            if f_len <= 0:
                error = f"DE {f} has invalid fixed length {f_len}."
                break
            if idx + f_len > len(cleaned):
                error = f"DE {f} truncated (needs {f_len} chars, {len(cleaned) - idx} left)."
                break
            fields[f] = cleaned[idx:idx + f_len]
            idx += f_len
        elif f_type in ("llvar", "lllvar"):
            prefix = 2 if f_type == "llvar" else 3
            len_str = cleaned[idx:idx + prefix]
            if len(len_str) < prefix or not len_str.isdigit():
                error = f"DE {f} length prefix '{len_str}' is not numeric."
                break
            v_len = int(len_str)
            idx += prefix
            if idx + v_len > len(cleaned):
                error = f"DE {f} declares {v_len} chars but only {len(cleaned) - idx} remain."
                break
            fields[f] = cleaned[idx:idx + v_len]
            idx += v_len
        else:
            error = f"DE {f} has unknown type '{f_type}'."
            break

    result["fields"] = fields
    result["error"] = error
    result["complete"] = error is None
    if error is None:
        result["trailing"] = cleaned[idx:]
    return result


def parse_iso(raw_str, field_defs=None):
    """Compatibility wrapper -> (mti, fields). mti is None if unparseable."""
    r = parse_iso_ex(raw_str, field_defs)
    return r["mti"], r["fields"]


def format_iso_layout(mti, fields, field_defs=None):
    """
    Build an ISO string and return its layout:
      (iso_str, layout) where layout = {
         "bitmap": (start, length),
         de: {"prefix_start", "prefix_len", "value_start", "value_len"}  for every DE
      }
    The layout lets test tooling tamper with exact byte positions (length prefixes,
    bitmap bits, truncation) for negative / security testing.
    """
    int_fields = {}
    for k, v in (fields or {}).items():
        de = int(k)
        if de == 1:
            continue
        int_fields[de] = "" if v is None else str(v)

    active = set(int_fields.keys())
    if any(f > 64 for f in active):
        bm_hex = build_hex_bitmap(active | {1}, length_bytes=16)
    else:
        bm_hex = build_hex_bitmap(active, length_bytes=8)

    layout = {"bitmap": (4, len(bm_hex))}
    parts = [str(mti), bm_hex]
    pos = 4 + len(bm_hex)
    for f in sorted(active):
        fdef = get_field_def(f, field_defs)
        if not fdef:
            raise ValueError(f"DE {f} has no field definition; add it to the schema first.")
        f_type, _, _ = fdef
        val = int_fields[f]
        if f_type == "fixed":
            prefix = ""
        elif f_type == "llvar":
            if len(val) > 99:
                raise ValueError(f"DE {f} value exceeds LLVAR max length 99.")
            prefix = f"{len(val):02d}"
        elif f_type == "lllvar":
            if len(val) > 999:
                raise ValueError(f"DE {f} value exceeds LLLVAR max length 999.")
            prefix = f"{len(val):03d}"
        else:
            raise ValueError(f"DE {f} has unknown type '{f_type}'.")
        layout[f] = {"prefix_start": pos, "prefix_len": len(prefix),
                     "value_start": pos + len(prefix), "value_len": len(val)}
        parts.append(prefix + val)
        pos += len(prefix) + len(val)

    return "".join(parts), layout


def format_iso(mti, fields, field_defs=None):
    """Build an ISO string (hex-ASCII bitmap) from MTI + {de: value}."""
    return format_iso_layout(mti, fields, field_defs)[0]


def set_bitmap_bit(iso_str, de, on=True):
    """Flip one bitmap bit in an ISO string (hex bitmap) without touching the body."""
    has_sec = bool(int(iso_str[4], 16) & 0x8)
    bm_len = 32 if has_sec else 16
    bm_hex = iso_str[4:4 + bm_len]
    bits = list(bin(int(bm_hex, 16))[2:].zfill(bm_len * 4))
    if 1 <= de <= len(bits):
        bits[de - 1] = "1" if on else "0"
    new_bm = f"{int(''.join(bits), 2):0{bm_len}X}"
    return iso_str[:4] + new_bm + iso_str[4 + bm_len:]


# ----------------------------------------------------------------------------
# Amount / balance helpers
# ----------------------------------------------------------------------------
def amount_to_n12(value):
    """
    '500.00' / '500' (rupees, if it contains a dot) / 500.5 -> '000000050000'
    A pure digit string is treated as an ISO n12 value and zero-filled.
    Anything unparseable is returned unchanged (useful for tamper tests).
    """
    if value is None:
        return None
    s = str(value).strip()
    if s.isdigit():
        return s.zfill(12) if len(s) <= 12 else s
    try:
        paise = int((Decimal(s) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    except (InvalidOperation, ValueError):
        return s
    if paise < 0:
        return s
    return f"{paise:012d}"


def n12_to_paise(value):
    s = str(value or "").strip()
    return int(s) if s.isdigit() else None


def paise_to_str(paise):
    if paise is None:
        return "--"
    sign = "-" if paise < 0 else ""
    paise = abs(int(paise))
    return f"{sign}{paise // 100}.{paise % 100:02d}"


def rupees_to_paise(value):
    """'500.00' / '-500.00' / 500 -> signed paise int (for expectations)."""
    try:
        return int((Decimal(str(value).strip()) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    except (InvalidOperation, ValueError):
        return None


def parse_de54(value):
    """
    DE 54 Additional Amounts -> list of 20-char blocks:
      acct_type(2) amount_type(2) currency(3) sign(C/D) amount(12)
    Amount type 01 = ledger, 02 = available.
    """
    out = []
    s = str(value or "")
    for i in range(0, len(s) - 19, 20):
        blk = s[i:i + 20]
        amt = blk[8:20]
        if not amt.isdigit() or blk[7] not in "CD":
            continue
        paise = int(amt) * (-1 if blk[7] == "D" else 1)
        out.append({"acct_type": blk[0:2], "amount_type": blk[2:4], "currency": blk[4:7],
                    "sign": blk[7], "paise": paise})
    return out


def available_balance(value):
    """Available balance (type 02, falling back to ledger 01) in paise, or None."""
    blocks = parse_de54(value)
    for t in ("02", "01"):
        for b in blocks:
            if b["amount_type"] == t:
                return b["paise"]
    return None


def build_de54(ledger_paise, available_paise, acct_type="10", currency="356"):
    def blk(t, p):
        return f"{acct_type}{t}{currency}{'C' if p >= 0 else 'D'}{abs(int(p)):012d}"
    return blk("01", ledger_paise) + blk("02", available_paise)


# ----------------------------------------------------------------------------
# Wire encoding / decoding
# ----------------------------------------------------------------------------
def encode_iso_str(iso_str, bitmap_fmt="hex_ascii", charset="ascii"):
    """ISO string (hex bitmap) -> bytes in the requested wire format."""
    cleaned, _ = strip_length_header(iso_str)
    if len(cleaned) < 20 or not cleaned[:4].isdigit():
        raise ValueError("Payload does not start with a valid 4-digit MTI.")
    if cleaned[4] not in _HEX_CHARS:
        raise ValueError("Bitmap is not valid hex.")
    has_sec = bool(int(cleaned[4], 16) & 0x8)
    bm_len = 32 if has_sec else 16
    bm_hex = cleaned[4:4 + bm_len]
    if len(bm_hex) < bm_len or any(c not in _HEX_CHARS for c in bm_hex):
        raise ValueError(f"Bitmap must be {bm_len} hex characters.")

    codec = "cp500" if charset == "ebcdic" else "latin-1"
    mti_bytes = cleaned[:4].encode(codec)
    bm_bytes = bytes.fromhex(bm_hex) if bitmap_fmt == "binary" else bm_hex.encode(codec)
    body_bytes = cleaned[4 + bm_len:].encode(codec, errors="replace")
    return mti_bytes + bm_bytes + body_bytes


def frame_bytes(payload, framing="ascii_4"):
    n = len(payload)
    if framing == "bin_2":
        return struct.pack("!H", n) + payload
    if framing == "bin_2_inc":
        return struct.pack("!H", n + 2) + payload
    if framing == "ascii_4":
        return f"{n:04d}".encode("latin-1") + payload
    return payload


def parse_tpdu(tpdu):
    t = (tpdu or "").strip().replace(" ", "")
    if not t:
        return b""
    try:
        return bytes.fromhex(t)
    except ValueError:
        return t.encode("latin-1")


def pack_payload(raw_iso, framing="ascii_4", bitmap_fmt="hex_ascii", charset="ascii", tpdu=""):
    """ISO string -> framed bytes ready for the socket."""
    cleaned, had_manual_header = strip_length_header(raw_iso)
    iso_bytes = encode_iso_str(cleaned, bitmap_fmt, charset)
    payload = parse_tpdu(tpdu) + iso_bytes
    if framing == "raw" and had_manual_header:
        return frame_bytes(payload, "ascii_4")
    return frame_bytes(payload, framing)


def _is_mti_like(b):
    """4 ASCII digits or 4 EBCDIC digits (any MTI, known or not)."""
    return len(b) == 4 and (b.isdigit() or all(0xF0 <= x <= 0xF9 for x in b))


def _strip_frame_header(data):
    """Remove a length header from received bytes if one is present."""
    if len(data) >= 8 and data[:4].isdigit():
        if data[4:8] in _MTI_ASCII or data[4:8] in _MTI_EBCDIC:
            return data[4:]
        if _is_mti_like(data[4:8]) and int(data[:4]) == len(data) - 4:
            return data[4:]
    if len(data) >= 6:
        n = struct.unpack("!H", data[:2])[0]
        if n in (len(data) - 2, len(data)) and _is_mti_like(data[2:6]):
            return data[2:]
    if len(data) > 4 and data[:4].isdigit() and data[:4] not in _MTI_ASCII and int(data[:4]) == len(data) - 4:
        return data[4:]  # ASCII header followed by TPDU
    return data


def _locate_mti(body):
    """Return (codec, position) of the earliest MTI marker, or (None, None)."""
    if len(body) >= 4 and body[:4].isdigit():
        return "latin-1", 0
    if len(body) >= 4 and all(0xF0 <= x <= 0xF9 for x in body[:4]):
        return "cp500", 0
    best = (None, None)
    for codec, markers in (("latin-1", _MTI_ASCII), ("cp500", _MTI_EBCDIC)):
        for m in markers:
            p = body.find(m)
            if p != -1 and (best[1] is None or p < best[1]):
                best = (codec, p)
    return best


def decode_iso_bytes(data):
    """
    Wire bytes -> (iso_str with hex bitmap, meta)
    meta = {charset, bitmap_fmt, prefix(bytes before MTI, e.g. TPDU)}
    """
    meta = {"charset": "ascii", "bitmap_fmt": "hex_ascii", "prefix": b""}
    if not data:
        return "", meta
    body = _strip_frame_header(data)
    codec, pos = _locate_mti(body)
    if pos is None:
        return body.decode("latin-1", errors="ignore"), meta

    meta["prefix"] = body[:pos]
    meta["charset"] = "ebcdic" if codec == "cp500" else "ascii"
    iso = body[pos:]
    mti = iso[:4].decode(codec)
    rest = iso[4:]
    if not rest:
        return mti, meta

    probe = rest[:16].decode(codec, errors="ignore")
    if len(probe) == 16 and all(c in _HEX_CHARS for c in probe):
        meta["bitmap_fmt"] = "hex_ascii"
        return mti + rest.decode(codec, errors="ignore"), meta

    meta["bitmap_fmt"] = "binary"
    bl = 16 if (rest[0] & 0x80) else 8
    bm_hex = rest[:bl].hex().upper()
    return mti + bm_hex + rest[bl:].decode(codec, errors="ignore"), meta


def unpack_response(raw_bytes):
    """Wire bytes -> ISO string (hex bitmap)."""
    iso, _ = decode_iso_bytes(raw_bytes)
    return iso


# ----------------------------------------------------------------------------
# Socket helpers
# ----------------------------------------------------------------------------
def _expected_total_len(buf, framing):
    """Total bytes (incl. header) the peer will send, or None if unknown."""
    if len(buf) >= 8 and buf[:4].isdigit() and (buf[4:8] in _MTI_ASCII or buf[4:8] in _MTI_EBCDIC):
        return 4 + int(buf[:4])
    if len(buf) >= 6 and (buf[2:6] in _MTI_ASCII or buf[2:6] in _MTI_EBCDIC):
        n = struct.unpack("!H", buf[:2])[0]
        return n if framing == "bin_2_inc" else 2 + n
    if framing == "ascii_4" and len(buf) >= 4 and buf[:4].isdigit() and buf[:4] not in _MTI_ASCII:
        return 4 + int(buf[:4])
    if framing in ("bin_2", "bin_2_inc") and len(buf) >= 2:
        n = struct.unpack("!H", buf[:2])[0]
        return n if framing == "bin_2_inc" else 2 + n
    return None


def recv_framed(sock, framing="ascii_4", timeout=6.0, max_len=100000):
    """
    Read exactly one framed message. Uses the length header when present;
    falls back to an idle-gap read (300 ms) for headerless/raw peers.
    Raises socket.timeout if nothing arrives within `timeout`.
    """
    sock.settimeout(timeout)
    buf = sock.recv(4096)
    if not buf:
        raise ConnectionResetError("Remote server closed socket without responding.")

    expected = _expected_total_len(buf, framing)
    if expected is not None and 0 < expected <= max_len:
        while len(buf) < expected:
            chunk = sock.recv(min(65536, expected - len(buf)))
            if not chunk:
                break
            buf += chunk
        return buf

    sock.settimeout(0.3)
    try:
        while len(buf) < max_len:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
    except (socket.timeout, BlockingIOError):
        pass
    return buf


def tcp_transact(ip, port, payload, timeout=6.0, framing="ascii_4"):
    """Open a connection, send one framed message, read one framed response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, int(port)))
        sock.sendall(payload)
        return recv_framed(sock, framing, timeout)
    finally:
        sock.close()


def extract_frame(buf):
    """
    Server side: pull one complete message out of a receive buffer.
    Returns (framing, message_bytes, remaining) or (None, None, buf) when incomplete.
    """
    if not buf:
        return None, None, buf

    if len(buf) >= 8 and buf[:4].isdigit() and (buf[4:8] in _MTI_ASCII or buf[4:8] in _MTI_EBCDIC):
        n = int(buf[:4])
        if len(buf) >= 4 + n:
            return "ascii_4", buf[4:4 + n], buf[4 + n:]
        return None, None, buf

    if len(buf) >= 6 and _is_mti_like(buf[2:6]) and not buf[:4].isdigit():
        n = struct.unpack("!H", buf[:2])[0]
        if len(buf) == n:
            return "bin_2_inc", buf[2:n], b""
        if len(buf) >= 2 + n:
            return "bin_2", buf[2:2 + n], buf[2 + n:]
        return None, None, buf

    if buf[:4] in _MTI_ASCII or buf[:4] in _MTI_EBCDIC:
        return "raw", buf, b""

    if len(buf) >= 4 and buf[:4].isdigit():
        n = int(buf[:4])
        if len(buf) >= 4 + n:
            return "ascii_4", buf[4:4 + n], buf[4 + n:]
        return None, None, buf

    return "raw", buf, b""
