import socket
import sys

# Field definitions aligned with ISO8583_Parsed_Data_Element_Reference.docx
FIELD_DEFS = {
    2: ('Primary Account Number (PAN)', 'llvar', 2),
    3: ('Processing Code', 'fixed', 6),
    4: ('Amount, Transaction', 'fixed', 12),
    7: ('Transmission Date & Time', 'fixed', 10),
    11: ('System Trace Audit Number (STAN)', 'fixed', 6),
    12: ('Time, Local Transaction', 'fixed', 6),
    13: ('Date, Local Transaction', 'fixed', 4),
    14: ('Date, Expiration', 'fixed', 4),
    15: ('Date, Settlement', 'fixed', 4),
    17: ('Date, Capture', 'fixed', 4),
    18: ('Merchant Type (MCC)', 'fixed', 4),
    22: ('POS Entry Mode', 'fixed', 3),
    25: ('POS Condition Code', 'fixed', 2),
    32: ('Acquiring Institution ID Code', 'llvar', 2),
    35: ('Track 2 Data', 'llvar', 2),
    37: ('Retrieval Reference Number (RRN)', 'fixed', 12),
    38: ('Authorization ID Response', 'fixed', 6),
    39: ('Response Code', 'fixed', 2),
    41: ('Card Acceptor Terminal ID', 'fixed', 8),
    42: ('Card Acceptor ID Code', 'fixed', 15),
    43: ('Card Acceptor Name/Location', 'fixed', 40),
    48: ('Additional Data - Private', 'lllvar', 3),
    49: ('Currency Code, Transaction', 'fixed', 3),
    54: ('Additional Amounts', 'lllvar', 3),
    60: ('Additional POS / Reserved Private', 'lllvar', 3),
    63: ('Reserved Private (Mini-Statement)', 'lllvar', 3),
    90: ('Original Data Elements', 'fixed', 42),
    102: ('Account Identification 1', 'llvar', 2),
    120: ('Reserved Private', 'lllvar', 3)
}

def parse_bitmap(hex_map_str):
    bin_str = bin(int(hex_map_str, 16))[2:].zfill(len(hex_map_str) * 4)
    return {i + 1 for i, bit in enumerate(bin_str) if bit == '1'}

def build_hex_bitmap(active_fields, length_bytes=16):
    total_bits = length_bytes * 8
    bits = ['0'] * total_bits
    for f in active_fields:
        if 1 <= f <= total_bits:
            bits[f - 1] = '1'
    return f"{int(''.join(bits), 2):0{length_bytes * 2}X}"

def parse_iso(raw_str):
    mti = raw_str[:4]
    has_secondary = bool(int(raw_str[4], 16) & 0x8)
    bm_len = 32 if has_secondary else 16
    
    bitmap_hex = raw_str[4:4 + bm_len]
    active_fields = parse_bitmap(bitmap_hex)
    
    idx = 4 + bm_len
    fields = {}
    
    for f in sorted(list(active_fields)):
        if f == 1:
            continue
        if f not in FIELD_DEFS:
            break
        _, f_type, f_len = FIELD_DEFS[f]
        if f_type == 'fixed':
            fields[f] = raw_str[idx:idx + f_len]
            idx += f_len
        elif f_type == 'llvar':
            v_len = int(raw_str[idx:idx + 2])
            idx += 2
            fields[f] = raw_str[idx:idx + v_len]
            idx += v_len
        elif f_type == 'lllvar':
            v_len = int(raw_str[idx:idx + 3])
            idx += 3
            fields[f] = raw_str[idx:idx + v_len]
            idx += v_len
            
    return mti, fields

def format_iso(mti, fields):
    active_fields = set(fields.keys())
    if any(f > 64 for f in active_fields):
        active_fields.add(1)
        bm_hex = build_hex_bitmap(active_fields, length_bytes=16)
    else:
        bm_hex = build_hex_bitmap(active_fields, length_bytes=8)

    body = ""
    for f in sorted(list(active_fields)):
        if f == 1:
            continue
        _, f_type, _ = FIELD_DEFS[f]
        val = str(fields[f])
        if f_type == 'fixed':
            body += val
        elif f_type == 'llvar':
            body += f"{len(val):02d}{val}"
        elif f_type == 'lllvar':
            body += f"{len(val):03d}{val}"

    return f"{mti}{bm_hex}{body}"

def generate_cbs_response(req_str):
    mti, f = parse_iso(req_str)
    resp = f.copy()
    resp_mti = '0210' if mti == '0200' else '0430'
    
    proc_code = f.get(3, '000000')
    mcc = f.get(18, '6011')
    is_atm = (mcc == '6011')

    # Response Code (DE 39)
    resp[39] = '00'

    # Financial Responses (0210)
    if resp_mti == '0210':
        # Default balance structure (DE 54): Ledger (1001) + Available (1002) in INR (356)
        if proc_code.startswith('38'):
            # Mini-Statement (Doc Ref 5.1)
            resp.pop(48, None)
            resp[54] = "1001356C0000000015161002356C000000001516"
            resp[63] = (
                "010726 D To ATM              500.00"
                "010726 D To ATM             1500.00"
                "010726 D To ATM             2000.00"
                "300626 D To ATM             2000.00"
                "300626 D To SMS                2.83"
                "300626 C BY CAS             6000.00"
                "260626 D To ATM              500.00"
                "250626 D To ATM             1500.00"
                "240626 D To ATM             1000.00"
                "300925 C Saving                1.00"
                "Available Balance            15.16+"
            )
        elif proc_code.startswith('01') or proc_code.startswith('31'):
            # Cash Withdrawal / Balance Inquiry (Doc Ref 5.2, 5.3)
            resp.pop(48, None)
            resp[54] = "1001356C0000000015161002356C000000001516"
        else:
            # POS / ECOM Purchase (Doc Ref 5.4, 5.5) - Keep DE 48
            acc_pfx = "200" if proc_code.startswith('00') and f.get(14) else "100"
            resp[54] = f"{acc_pfx}1356C000006478535{acc_pfx}2356C000006478535"

    # Reversal Responses (0430)
    elif resp_mti == '0430':
        # Preserve Original Data Elements (DE 90) and Auth ID (DE 38)
        if is_atm:
            resp.pop(48, None)
            resp[54] = "1001356C0000006700401002356C000000670040"
        elif mcc == '5814':
            # ECOM Reversal (Doc Ref 5.8) - Returns 09 (In Progress) and no DE 54
            resp[39] = '09'
            resp.pop(54, None)
        else:
            # POS Reversal (Doc Ref 5.6)
            resp[54] = "1001356C0000065383401002356C000006538340"

    return format_iso(resp_mti, resp)

def start_server(host='0.0.0.0', port=9000):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] CBS ISO 8583 SIMULATOR READY on {host}:{port}")

    while True:
        client, addr = server.accept()
        try:
            while True:
                data = client.recv(4096)
                if not data:
                    break

                header_type = "RAW"
                if len(data) > 4 and data[:4].isdigit() and data[4:8] in (b'0200', b'0420'):
                    header_type = "ASCII_4"
                    raw_payload = data[4:].decode('latin-1')
                elif len(data) > 2 and data[2:6] in (b'0200', b'0420'):
                    header_type = "BIN_2"
                    raw_payload = data[2:].decode('latin-1')
                else:
                    raw_payload = data.decode('latin-1').strip()

                resp_payload = generate_cbs_response(raw_payload)

                if header_type == "ASCII_4":
                    resp_packet = f"{len(resp_payload):04d}{resp_payload}".encode('latin-1')
                elif header_type == "BIN_2":
                    resp_packet = len(resp_payload).to_bytes(2, byteorder='big') + resp_payload.encode('latin-1')
                else:
                    resp_packet = resp_payload.encode('latin-1')

                client.sendall(resp_packet)
                print(f"[<] Responded: {resp_payload[:4]} DE39={resp_payload[raw_payload.find('618'):raw_payload.find('618')+2] if False else '00/09'}")
        except Exception:
            pass
        finally:
            client.close()

if __name__ == '__main__':
    start_server(port=int(sys.argv[1]) if len(sys.argv) > 1 else 9000)