"""
iso_tester_app.py - Payment Switch & CBS Console (Switch -> CBS tester)
=======================================================================
Screens
  * Single Request  - build / send / parse / edit any ATM, UPI, IMPS message,
                      linked 0420 reversal with DE 90.
  * Testing Suite   - end-to-end Switch <-> CBS test cases maintained per channel
                      (atm_testcases.json / upi_testcases.json / imps_testcases.json):
                      network, positive, negative account & card, boundary,
                      reversal, duplicate, security / format, timeout / fault.
                      Multi-step flows with balance verification (DE 54),
                      linked reversals, duplicates and tampered messages.
                      Add / edit / clone / delete cases, edit profiles and
                      channel settings, run all / selected / single, drill
                      into every step, export test cases and results to Excel.
  * Schema Config   - request / expected-response DE lists per transaction.

Modules: iso_engine.py (ISO pack/parse/framing), suite_runner.py (test execution),
         testcase_catalog.py (default test cases + storage).
Run:     python iso_tester_app.py      ->  http://localhost:5000
"""

import socket
import time
import json
import os
import random
from datetime import datetime

from flask import Flask, request, jsonify, Response

from iso_engine import (
    COMMON_FIELD_DEFINITIONS,
    describe_rc,
    expected_response_mti,
    get_field_def,
    parse_iso_ex,
    format_iso,
    pack_payload,
    unpack_response,
    tcp_transact,
)
from suite_runner import (
    assemble_iso_from_numericals as _assemble_fields_iso,
    build_de90,
    fit_fixed,
    resolve_tx,
    run_testcase,
)
from testcase_catalog import (
    CATEGORIES,
    catalog_path,
    default_catalog,
    load_catalog,
    merge_defaults,
    save_catalog,
    validate_testcase,
)

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_BASE_DIR = os.path.join(BASE_DIR, "logs")

CHANNEL_CONFIG_PATHS = {
    "ATM": os.path.join(BASE_DIR, "iso_config.json"),
    "UPI": os.path.join(BASE_DIR, "upi_config.json"),
    "IMPS": os.path.join(BASE_DIR, "imps_config.json")
}

DEFAULT_ATM_CONFIG = {
    "target_settings": {
        "default_ip": "10.167.1.153", "default_port": 9019,
        "default_framing": "ascii_4", "default_bitmap_fmt": "hex_ascii",
        "default_charset": "ascii", "default_tpdu": "", "default_timeout": 6.0
    },
    "field_definitions": COMMON_FIELD_DEFINITIONS,
    "sample_requests": {
        "issuer_cash_withdrawal": {
            "label": "Issuer Cash Withdrawal Request", "mti": "0200", "proc_code": "011000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 41, 42, 43, 46, 48, 49, 60, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 46, 49, 54, 60, 102]
        },
        "balance_inquiry": {
            "label": "Balance Enquiry Request", "mti": "0200", "proc_code": "311000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 41, 42, 43, 48, 49, 60, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 102]
        },
        "mini_statement": {
            "label": "Mini Statement Request", "mti": "0200", "proc_code": "380000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 41, 42, 43, 48, 49, 60, 102, 120],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 49, 54, 60, 63, 102, 120]
        },
        "pos_purchase": {
            "label": "POS Purchase Request", "mti": "0200", "proc_code": "000000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 35, 37, 41, 42, 43, 48, 49, 60, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 35, 37, 39, 41, 42, 43, 48, 49, 54, 60, 102]
        },
        "ecom_purchase": {
            "label": "E-Commerce Purchase", "mti": "0200", "proc_code": "000000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 14, 15, 17, 18, 22, 25, 32, 37, 41, 42, 43, 48, 49, 60, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 14, 15, 17, 18, 22, 25, 32, 37, 39, 41, 42, 43, 48, 49, 54, 60, 102]
        },
        "pos_reversal": {
            "label": "POS Reversal (0420)", "mti": "0420", "base_tx": "pos_purchase", "proc_code": "000000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 37, 38, 39, 41, 42, 43, 48, 49, 60, 90, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 37, 38, 39, 41, 42, 43, 48, 49, 54, 60, 90, 102]
        },
        "issuer_reversal": {
            "label": "Issuer Reversal (0420)", "mti": "0420", "base_tx": "issuer_cash_withdrawal", "proc_code": "011000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 37, 38, 39, 41, 42, 43, 48, 49, 60, 90, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 37, 38, 39, 41, 42, 43, 49, 54, 60, 90, 102]
        },
        "ecom_reversal": {
            "label": "E-Commerce Reversal (0420)", "mti": "0420", "base_tx": "ecom_purchase", "proc_code": "000000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 37, 39, 41, 42, 43, 48, 49, 60, 90, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 25, 32, 37, 39, 41, 42, 43, 48, 49, 60, 90, 102]
        }
    }
}

DEFAULT_UPI_CONFIG = {
    "target_settings": {
        "default_ip": "10.167.1.153", "default_port": 9020,
        "default_framing": "ascii_4", "default_bitmap_fmt": "hex_ascii",
        "default_charset": "ascii", "default_tpdu": "", "default_timeout": 6.0
    },
    "field_definitions": COMMON_FIELD_DEFINITIONS,
    "sample_requests": {
        "upi_list_account": {
            "label": "UPI List Account (ReqListAcc)", "mti": "0200", "proc_code": "410000",
            "req_des_present": [2, 3, 7, 11, 12, 13, 37, 48, 49, 102],
            "resp_des_present": [2, 3, 7, 11, 12, 13, 37, 39, 48, 49, 102]
        },
        "upi_balance_enquiry": {
            "label": "UPI Balance Enquiry (ReqBalEnq)", "mti": "0200", "proc_code": "310000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 37, 48, 49, 54, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 37, 39, 48, 49, 54, 102]
        },
        "upi_inward": {
            "label": "UPI Inward Pay (Credit / RespPay)", "mti": "0200", "proc_code": "000000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 32, 37, 48, 49, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 32, 37, 39, 48, 49, 54, 102]
        },
        "upi_outward": {
            "label": "UPI Outward Pay (Debit / ReqPay)", "mti": "0200", "proc_code": "000000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 32, 37, 48, 49, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 32, 37, 39, 48, 49, 54, 102]
        },
        "upi_outward_reversal": {
            "label": "UPI Outward Pay Reversal (0420)", "mti": "0420", "base_tx": "upi_outward", "proc_code": "000000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 32, 37, 38, 39, 48, 49, 90, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 32, 37, 38, 39, 48, 49, 54, 90, 102]
        }
    }
}

DEFAULT_IMPS_CONFIG = {
    "target_settings": {
        "default_ip": "10.167.1.153", "default_port": 9021,
        "default_framing": "ascii_4", "default_bitmap_fmt": "hex_ascii",
        "default_charset": "ascii", "default_tpdu": "", "default_timeout": 6.0
    },
    "field_definitions": COMMON_FIELD_DEFINITIONS,
    "sample_requests": {
        "imps_list_account": {
            "label": "IMPS Account Verification / List Account", "mti": "0200", "proc_code": "410000",
            "req_des_present": [2, 3, 7, 11, 12, 13, 37, 48, 49, 102],
            "resp_des_present": [2, 3, 7, 11, 12, 13, 37, 39, 48, 49, 102]
        },
        "imps_balance_enquiry": {
            "label": "IMPS Balance Enquiry Request", "mti": "0200", "proc_code": "310000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 37, 48, 49, 54, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 37, 39, 48, 49, 54, 102]
        },
        "imps_inward": {
            "label": "IMPS Inward Remittance (P2A Credit)", "mti": "0200", "proc_code": "000000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 32, 37, 48, 49, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 32, 37, 39, 48, 49, 54, 102]
        },
        "imps_outward": {
            "label": "IMPS Outward Remittance (P2A Debit)", "mti": "0200", "proc_code": "000000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 32, 37, 48, 49, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 32, 37, 39, 48, 49, 54, 102]
        },
        "imps_outward_reversal": {
            "label": "IMPS Outward Remittance Reversal (0420)", "mti": "0420", "base_tx": "imps_outward", "proc_code": "000000",
            "req_des_present": [2, 3, 4, 7, 11, 12, 13, 32, 37, 38, 39, 48, 49, 90, 102],
            "resp_des_present": [2, 3, 4, 7, 11, 12, 13, 32, 37, 38, 39, 48, 49, 54, 90, 102]
        }
    }
}

CHANNEL_DEFAULT_CONFIGS = {
    "ATM": DEFAULT_ATM_CONFIG,
    "UPI": DEFAULT_UPI_CONFIG,
    "IMPS": DEFAULT_IMPS_CONFIG
}


# ==============================================================
# CONFIG HELPERS
# ==============================================================

def norm_channel(channel):
    ch = (channel or "ATM").strip().upper()
    return ch if ch in CHANNEL_CONFIG_PATHS else "ATM"


def get_channel_config_path(channel="ATM"):
    return CHANNEL_CONFIG_PATHS[norm_channel(channel)]


def classify_tx_channel(key: str, tx_dict: dict) -> str:
    k = (key or "").lower()
    label = (tx_dict.get("label") or "").lower()
    if "imps" in k or "imps" in label:
        return "IMPS"
    if "upi" in k or "upi" in label:
        return "UPI"
    return "ATM"


def save_config(cfg, channel="ATM"):
    config_path = get_channel_config_path(channel)
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"[CONFIG SAVE ERROR] {e}")


def _read_config_file(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def segregate_and_sync_all_configs():
    """
    Ensures UPI transactions live only in upi_config.json, IMPS only in
    imps_config.json, ATM only in iso_config.json, and every config carries
    the full common field-definition set.
    """
    all_harvested_samples = {}
    channel_configs = {}

    for ch in ("ATM", "UPI", "IMPS"):
        cfg = _read_config_file(get_channel_config_path(ch))
        if not cfg or not cfg.get("sample_requests"):
            cfg = json.loads(json.dumps(CHANNEL_DEFAULT_CONFIGS[ch]))
        channel_configs[ch] = cfg
        for k, v in cfg.get("sample_requests", {}).items():
            if k not in all_harvested_samples:
                all_harvested_samples[k] = v

    channel_samples = {"ATM": {}, "UPI": {}, "IMPS": {}}
    for k, v in all_harvested_samples.items():
        channel_samples[classify_tx_channel(k, v)][k] = v

    for ch in ("ATM", "UPI", "IMPS"):
        for dk, dv in CHANNEL_DEFAULT_CONFIGS[ch]["sample_requests"].items():
            if dk not in channel_samples[ch]:
                channel_samples[ch][dk] = dv

    for ch in ("ATM", "UPI", "IMPS"):
        cfg = channel_configs[ch]
        cfg["sample_requests"] = channel_samples[ch]
        cfg_fields = cfg.setdefault("field_definitions", {})
        for fk, fv in COMMON_FIELD_DEFINITIONS.items():
            if fk not in cfg_fields:
                cfg_fields[fk] = fv
        save_config(cfg, ch)


def load_config(channel="ATM"):
    ch = norm_channel(channel)
    cfg = _read_config_file(get_channel_config_path(ch))
    if not cfg or not cfg.get("sample_requests"):
        cfg = json.loads(json.dumps(CHANNEL_DEFAULT_CONFIGS[ch]))
        save_config(cfg, ch)
    return cfg


def get_field_defs(channel="ATM"):
    return load_config(channel).get("field_definitions", COMMON_FIELD_DEFINITIONS)


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
        print(f"[LOG ERROR] {e}")


# ==============================================================
# ISO HELPERS (thin wrappers over iso_engine)
# ==============================================================

def parse_raw_iso_dict(raw_str, channel="ATM"):
    r = parse_iso_ex(raw_str, get_field_defs(channel))
    return r["mti"], r["fields"]


def format_iso_dict(mti, fields, channel="ATM"):
    return format_iso(mti, fields, get_field_defs(channel))


def assemble_iso_from_numericals(mti, proc_code, des_present, custom_params=None, channel="ATM"):
    """Build an ISO message from DE numbers using the shared generators in suite_runner."""
    return _assemble_fields_iso(mti, proc_code, des_present, custom_params, channel, get_field_defs(channel))


def parse_iso_details(raw_str, expected_resp_des=None, channel="ATM", req_mti=None):
    field_defs = get_field_defs(channel)
    r = parse_iso_ex(raw_str, field_defs)
    if not r["mti"]:
        return {"error": r["error"] or "Invalid payload.", "mti": None, "fields": [], "de39": None,
                "validation": None, "complete": False, "parse_error": r["error"], "mti_ok": None}

    fields = r["fields"]
    parsed_fields = []
    for f in sorted(fields.keys()):
        fdef = get_field_def(f, field_defs)
        parsed_fields.append({"de": f, "name": fdef[2] if fdef else f"DE {f}", "len": len(fields[f]), "val": fields[f]})

    de39_info = describe_rc(fields[39]) if 39 in fields else None

    validation = None
    if expected_resp_des:
        received_set = set(fields.keys())
        expected_set = set(int(x) for x in expected_resp_des)
        missing = sorted(expected_set - received_set)
        unexpected = sorted(received_set - expected_set - {1})

        def named(de):
            fdef = get_field_def(de, field_defs)
            return {"de": de, "name": fdef[2] if fdef else f"DE {de}"}

        validation = {
            "compliant": len(missing) == 0,
            "missing_des": [named(d) for d in missing],
            "unexpected_des": [named(d) for d in unexpected],
            "expected_count": len(expected_set),
            "received_count": len(received_set)
        }

    mti_ok = None
    exp_mti = expected_response_mti(req_mti) if req_mti else ""
    if exp_mti:
        mti_ok = (r["mti"] == exp_mti)

    return {"mti": r["mti"], "fields": parsed_fields, "de39": de39_info, "validation": validation,
            "complete": r["complete"], "parse_error": r["error"], "mti_ok": mti_ok,
            "expected_mti": exp_mti or None}


# ==============================================================
# UI TEMPLATE (RAW STRING LITERAL)
# ==============================================================

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Payment Switch & CBS Console - Multi-Channel Test Suite</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js"></script>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen p-4 font-sans">
  <div class="max-w-7xl mx-auto space-y-3.5">

    <header class="flex justify-between items-center pb-2 border-b border-slate-800">
      <h1 class="text-xl font-bold tracking-tight text-white flex items-center gap-2">
        <span>Payment Switch & CBS Console</span>
        <span class="text-xs bg-indigo-950 text-indigo-300 border border-indigo-700 px-2 py-0.5 rounded font-mono">Master Audit Suite</span>
      </h1>
      <button onclick="saveTargetAsDefault()" class="text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-300 px-2 py-1 rounded border border-slate-700">
        Save Target Defaults (<span class="channel-label-text">ATM</span>)
      </button>
    </header>

    <div class="flex items-center justify-between bg-slate-900 border border-slate-800 rounded-lg p-2.5">
      <div class="flex items-center gap-3">
        <span class="text-xs font-bold uppercase tracking-wider text-slate-400">Payment Channel:</span>
        <div class="flex bg-slate-950 p-1 rounded border border-slate-800 gap-1 font-mono text-xs">
          <button id="mode-btn-ATM" onclick="selectChannelMode('ATM')" class="px-4 py-1.5 rounded font-bold transition bg-indigo-600 text-white shadow-sm">ATM</button>
          <button id="mode-btn-UPI" onclick="selectChannelMode('UPI')" class="px-4 py-1.5 rounded font-bold transition text-slate-400 hover:text-white">UPI</button>
          <button id="mode-btn-IMPS" onclick="selectChannelMode('IMPS')" class="px-4 py-1.5 rounded font-bold transition text-slate-400 hover:text-white">IMPS</button>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <span id="active-channel-indicator" class="text-xs font-mono font-bold text-indigo-300 bg-indigo-950/80 border border-indigo-700/80 px-3 py-1 rounded">
          ATM Engine Active
        </span>
      </div>
    </div>

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

    <div class="flex gap-2 border-b border-slate-800 pt-1">
      <button id="tab-btn-single" onclick="switchWindow('single')" class="px-4 py-1.5 text-xs font-semibold rounded-t border-b-2 border-indigo-500 text-white bg-slate-900">
        Single Request Mode (<span class="channel-label-text">ATM</span>)
      </button>
      <button id="tab-btn-super" onclick="switchWindow('super')" class="px-4 py-1.5 text-xs font-semibold rounded-t text-amber-400 hover:text-white bg-slate-950">
        Testing Suite (<span class="channel-label-text">ATM</span>)
      </button>
      <button id="tab-btn-cfg" onclick="switchWindow('cfg')" class="px-4 py-1.5 text-xs font-semibold rounded-t text-slate-400 hover:text-white bg-slate-950">
        Schema Config (<span class="channel-label-text">ATM</span>)
      </button>
    </div>

    <!-- WINDOW 1: SINGLE REQUEST MODE -->
    <div id="win-single" class="space-y-3">
      <div class="bg-slate-900 border border-slate-800 rounded-lg p-2.5 flex flex-wrap items-center justify-between gap-2 text-xs">
        <div class="flex flex-wrap items-center gap-2">
          <span class="font-bold text-slate-300 uppercase text-[11px] mr-1">Select Transaction:</span>
          <div id="sample-buttons-container" class="flex flex-wrap gap-1.5"></div>
        </div>
        <div class="flex items-center gap-1.5 ml-auto">
          <button onclick="openAddTxModal()" class="bg-emerald-700 hover:bg-emerald-600 text-white font-bold px-2.5 py-1 rounded text-xs transition flex items-center gap-1 shadow-sm">+ Add</button>
          <button onclick="openSelectTxModal('edit')" class="bg-indigo-700 hover:bg-indigo-600 text-white font-bold px-2.5 py-1 rounded text-xs transition flex items-center gap-1 shadow-sm">&#9998; Edit</button>
          <button onclick="openSelectTxModal('delete')" class="bg-rose-700 hover:bg-rose-600 text-white font-bold px-2.5 py-1 rounded text-xs transition flex items-center gap-1 shadow-sm">&#10005; Delete</button>
        </div>
      </div>

      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div class="flex justify-between items-center pb-2 mb-2.5 border-b border-slate-800">
          <span class="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <span>Dynamic Parameters</span>
            <span class="text-[10px] text-emerald-400 font-mono font-normal">Real-Time Clock Active</span>
          </span>
          <button onclick="regenerateDynamic(true)" class="bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs px-2.5 py-1 rounded border border-slate-700">Regenerate RRN & Time</button>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-5 gap-3 text-xs">
          <div>
            <label class="block text-slate-400 mb-1">Card / PAN (DE 2)</label>
            <input id="dyn-pan" type="text" placeholder="e.g. 6072930130054479" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-emerald-300 focus:outline-none focus:border-indigo-500">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Account Number (DE 102)</label>
            <input id="dyn-account" type="text" placeholder="e.g. 101303130001356" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-emerald-300 focus:outline-none focus:border-indigo-500">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Acquiring / Member ID (DE 32)</label>
            <input id="dyn-acq" type="text" placeholder="e.g. 800024" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-emerald-300 focus:outline-none focus:border-indigo-500">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Processing Code (DE 3)</label>
            <input id="dyn-proc-code" type="text" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-amber-300 focus:outline-none focus:border-indigo-500">
          </div>
          <div>
            <label class="block text-slate-400 mb-1">Random RRN (DE 37)</label>
            <input id="dyn-rrn" type="text" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-cyan-300 focus:outline-none focus:border-indigo-500">
          </div>
        </div>
      </section>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <!-- REQUEST BOX -->
        <section class="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-2">
          <div>
            <div class="flex justify-between items-center mb-1">
              <span id="req-box-title" class="text-xs font-bold uppercase tracking-wider text-slate-300">Request ISO Payload</span>
              <div class="flex items-center gap-1.5">
                <span id="req-len-badge" class="text-[11px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono border border-slate-700">0 chars</span>
                <button type="button" onclick="addLengthToRequest()" class="bg-indigo-600 hover:bg-indigo-500 text-white text-[11px] font-medium px-2 py-0.5 rounded transition">+ 4-Byte</button>
                <button type="button" onclick="removeLengthFromRequest()" class="bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium px-2 py-0.5 rounded transition">- Strip</button>
              </div>
            </div>
            <textarea id="iso-request" rows="5" placeholder="Request ISO string..." class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs font-mono text-emerald-400 break-all resize-none"></textarea>
          </div>

          <div id="rev-preview-container" class="hidden border-t border-slate-800 pt-2">
            <div class="flex justify-between items-center mb-1">
              <span class="text-xs font-bold uppercase tracking-wider text-amber-400">Pre-Built Linked Reversal Payload (MTI: 0420)</span>
              <span class="text-[10px] font-mono text-slate-400">DE 90 Parity Ready</span>
            </div>
            <textarea id="iso-request-0420" readonly rows="4" class="w-full bg-slate-950 border border-amber-900/60 rounded p-2 text-xs font-mono text-amber-300 break-all resize-none"></textarea>
          </div>

          <div class="flex gap-2 pt-1">
            <button id="primary-action-btn" onclick="executePrimaryAction(false)" class="w-5/12 bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 rounded text-xs transition shadow-sm">Send Transaction</button>
            <button type="button" onclick="parseManualRequestToTable()" class="w-3/12 bg-emerald-700 hover:bg-emerald-600 text-white font-bold py-2 rounded text-xs transition shadow-sm">&#9889; Parse Request</button>
            <button id="force-timeout-btn" onclick="executePrimaryAction(true)" class="w-2/12 bg-amber-700 hover:bg-amber-600 text-white font-bold py-2 rounded text-xs transition shadow-sm">Timeout (68)</button>
            <button type="button" onclick="parseRequestAndDisplayEditor()" class="w-2/12 bg-slate-800 hover:bg-slate-700 text-indigo-300 font-bold py-2 rounded text-xs border border-indigo-900/60 transition">Inspect</button>
          </div>
        </section>

        <!-- RESPONSE BOX -->
        <section class="bg-slate-900 border border-slate-800 rounded-lg p-3 flex flex-col justify-between">
          <div>
            <div class="flex justify-between items-center mb-1">
              <span class="text-xs font-bold uppercase tracking-wider text-slate-400">Response Payload / Raw Input</span>
              <div class="flex items-center gap-1.5">
                <span id="resp-latency" class="text-xs text-slate-400 font-mono mr-1">Latency: --</span>
                <button type="button" onclick="parseManualResponse()" class="bg-cyan-700 hover:bg-cyan-600 text-white text-[11px] font-bold px-2 py-0.5 rounded transition shadow-sm">
                  &#9889; Parse Raw Response
                </button>
                <button type="button" onclick="document.getElementById('iso-response').value=''" class="bg-slate-800 hover:bg-slate-700 text-slate-400 text-[11px] px-2 py-0.5 rounded transition">
                  Clear
                </button>
              </div>
            </div>
            <textarea id="iso-response" rows="11" placeholder="Incoming responses will appear here. You can also paste any raw response ISO payload here and click 'Parse Raw Response'..." class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs font-mono text-cyan-300 break-all resize-none"></textarea>
          </div>

          <div class="mt-2 p-2 bg-slate-950 border border-slate-800 rounded flex justify-between items-center text-xs">
            <div class="flex items-center gap-2">
              <span class="text-slate-400">Response Status (DE 39):</span>
              <span id="de39-badge" class="font-mono font-bold text-slate-500">Awaiting Transaction / Parse</span>
            </div>
            <button id="instant-reversal-btn" onclick="promptReversalModalForCurrent()" class="hidden bg-amber-600 hover:bg-amber-500 text-white font-bold px-2.5 py-0.5 rounded text-[11px] transition shadow-sm">Initiate 0420 Reversal</button>
          </div>
          <div id="resp-checks" class="hidden mt-2 p-2 bg-rose-950/40 border border-rose-800/70 rounded text-[11px] font-mono text-rose-300 space-y-0.5"></div>
        </section>
      </div>

      <section id="editable-request-panel" class="hidden bg-slate-900 border border-indigo-700/80 rounded-lg p-3">
        <div class="flex justify-between items-center pb-2 mb-2 border-b border-slate-800">
          <h3 id="editable-request-title" class="text-xs font-bold uppercase tracking-wider text-indigo-300">Editable Request Data Elements</h3>
          <div class="flex gap-2">
            <button onclick="applyTableEditsToPayload()" class="bg-emerald-600 hover:bg-emerald-500 text-white font-bold px-3 py-1 rounded text-xs transition">Apply to Payload</button>
            <button onclick="document.getElementById('editable-request-panel').classList.add('hidden')" class="text-xs text-slate-400 hover:text-white px-2">&times; Close</button>
          </div>
        </div>
        <div class="overflow-x-auto max-h-64 overflow-y-auto">
          <table class="w-full text-left text-xs border-collapse">
            <thead>
              <tr class="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                <th class="p-1.5 w-16">DE</th><th class="p-1.5 w-64">Field Name</th><th class="p-1.5 w-16">Len</th><th class="p-1.5">Field Value</th>
              </tr>
            </thead>
            <tbody id="editable-request-tbody" class="divide-y border-slate-800 font-mono text-slate-300"></tbody>
          </table>
        </div>
      </section>

      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <h3 id="parsed-table-title" class="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">Parsed Elements</h3>
        <div class="overflow-x-auto max-h-56 overflow-y-auto">
          <table class="w-full text-left text-xs border-collapse">
            <thead>
              <tr class="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                <th class="p-1.5 w-16">DE</th><th class="p-1.5 w-64">Field Name</th><th class="p-1.5 w-16">Len</th><th class="p-1.5">Parsed Value</th>
              </tr>
            </thead>
            <tbody id="parsed-table-body" class="divide-y border-slate-800 font-mono text-slate-300">
              <tr><td colspan="4" class="p-3 text-center text-slate-600">Execute or Parse a transaction to inspect elements.</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <!-- WINDOW 2: TESTING SUITE -->
    <div id="win-super" class="hidden space-y-3">
      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div class="flex flex-wrap justify-between items-center gap-2 pb-2 mb-3 border-b border-slate-800">
          <div>
            <h3 class="text-xs font-bold uppercase tracking-wider text-amber-400">
              End-to-End Test Suite &mdash; <span class="channel-label-text">ATM</span> (Switch &rarr; CBS)
            </h3>
            <p id="suite-file-label" class="text-[11px] text-slate-400">Catalog: --</p>
          </div>
          <div class="flex flex-wrap gap-1.5">
            <button onclick="openTestcaseEditor(null, false)" class="bg-emerald-700 hover:bg-emerald-600 text-white font-bold px-2.5 py-1 rounded text-xs">+ Add Test Case</button>
            <button onclick="openSettingsEditor()" class="bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 px-2.5 py-1 rounded text-xs">&#9881; Channel Settings</button>
            <button onclick="exportCatalogToExcel()" class="bg-indigo-800 hover:bg-indigo-700 text-indigo-100 border border-indigo-600 px-2.5 py-1 rounded text-xs">Export Test Cases (.xlsx)</button>
            <button onclick="restoreDefaults('merge')" class="bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 px-2.5 py-1 rounded text-xs">Add Missing Defaults</button>
            <button onclick="restoreDefaults('reset')" class="bg-rose-900 hover:bg-rose-800 text-rose-100 border border-rose-700 px-2.5 py-1 rounded text-xs">Reset to Defaults</button>
          </div>
        </div>

        <details class="bg-slate-950 border border-indigo-800/70 rounded-lg p-3 mb-3">
          <summary class="cursor-pointer text-xs font-bold uppercase tracking-wider text-indigo-300">
            Test Accounts &amp; Cards (<span id="profile-count">0</span> profiles) &mdash; click to edit
          </summary>
          <div class="flex justify-between items-center my-2">
            <p class="text-[11px] text-slate-400">Edit to match accounts in your CBS. Values are sent as DE 2 / DE 102 / expiry (DE 14, Track 2).</p>
            <button onclick="saveProfiles()" class="bg-emerald-700 hover:bg-emerald-600 text-white font-bold px-2.5 py-1 rounded text-xs">Save Profiles</button>
          </div>
          <div id="distinct-profiles-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5"></div>
        </details>

        <div class="flex flex-wrap items-center gap-2 mb-2 text-xs">
          <select id="suite-cat-filter" onchange="renderCatalogTable()" class="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200">
            <option value="">All Categories</option>
          </select>
          <select id="suite-pri-filter" onchange="renderCatalogTable()" class="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200">
            <option value="">All Priorities</option><option>P1</option><option>P2</option><option>P3</option>
          </select>
          <input id="suite-search" oninput="renderCatalogTable()" placeholder="Search ID / name / expected..." class="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 w-64">
          <label class="flex items-center gap-1.5 text-slate-300 cursor-pointer">
            <input type="checkbox" id="suite-select-all" onchange="toggleSelectAll(this.checked)"> Select all visible
          </label>
          <span id="suite-selected-count" class="ml-auto font-mono text-slate-400">0 selected</span>
        </div>
        <div id="suite-cat-summary" class="flex flex-wrap gap-1.5 mb-2"></div>

        <div class="overflow-x-auto max-h-96 overflow-y-auto border border-slate-800 rounded">
          <table class="w-full text-left text-xs border-collapse">
            <thead class="sticky top-0">
              <tr class="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                <th class="p-2 w-8"></th><th class="p-2 w-28">ID</th><th class="p-2 w-36">Category</th><th class="p-2 w-10">Pri</th>
                <th class="p-2">Test Case</th><th class="p-2 w-32">Profile</th><th class="p-2 w-12">Steps</th>
                <th class="p-2 w-72">Expected Result</th><th class="p-2 w-40">Actions</th>
              </tr>
            </thead>
            <tbody id="suite-catalog-tbody" class="divide-y divide-slate-800 font-mono text-slate-300"></tbody>
          </table>
        </div>

        <div class="flex flex-wrap items-center gap-4 mt-3 text-xs">
          <label class="flex items-center gap-1.5 text-slate-300 cursor-pointer">
            <input type="checkbox" id="suite-reset-mock"> Reset mock CBS before run <span class="text-slate-500">(mock only &mdash; sends 0800 DE 70 = 999)</span>
          </label>
          <label class="flex items-center gap-1.5 text-slate-300 cursor-pointer">
            <input type="checkbox" id="suite-stop-on-fail"> Stop on first failure
          </label>
        </div>
        <div class="flex gap-2 mt-2">
          <button id="suite-run-selected-btn" onclick="runSuite('selected')" class="flex-1 bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 rounded text-xs">Run Selected</button>
          <button id="suite-run-all-btn" onclick="runSuite('all')" class="flex-1 bg-gradient-to-r from-amber-600 to-indigo-600 hover:from-amber-500 hover:to-indigo-500 text-white font-bold py-2 rounded text-xs">
            Run All Enabled (<span class="channel-label-text">ATM</span>)
          </button>
          <button id="suite-stop-btn" onclick="stopSuite()" class="hidden w-32 bg-rose-700 hover:bg-rose-600 text-white font-bold py-2 rounded text-xs">Stop</button>
        </div>
        <div id="suite-progress-wrap" class="hidden mt-2">
          <div class="h-1.5 bg-slate-800 rounded"><div id="suite-progress-bar" class="h-1.5 bg-indigo-500 rounded transition-all" style="width:0%"></div></div>
          <div id="suite-progress-text" class="text-[11px] font-mono text-slate-400 mt-1"></div>
        </div>
      </section>

      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <div class="flex flex-wrap justify-between items-center gap-2 mb-2">
          <span class="text-xs font-bold uppercase tracking-wider text-slate-300">Execution Results</span>
          <div class="flex items-center gap-2">
            <span id="super-score-badge" class="text-xs font-mono font-bold text-slate-500">Awaiting Run</span>
            <button onclick="exportResultsToExcel()" class="bg-emerald-700 hover:bg-emerald-600 text-white font-bold px-2.5 py-1 rounded text-xs">Export Results (.xlsx)</button>
            <button onclick="openReleaseNotesModal()" id="view-release-btn" class="hidden bg-indigo-900 hover:bg-indigo-800 text-indigo-200 border border-indigo-700 font-bold px-2.5 py-1 rounded text-xs">View Sign-Off Note</button>
          </div>
        </div>
        <div id="suite-result-summary" class="flex flex-wrap gap-1.5 mb-2"></div>
        <div class="overflow-x-auto max-h-[32rem] overflow-y-auto border border-slate-800 rounded">
          <table class="w-full text-left text-xs border-collapse">
            <thead class="sticky top-0">
              <tr class="bg-slate-950 text-slate-400 border-b border-slate-800 font-mono">
                <th class="p-1.5 w-6"></th><th class="p-1.5 w-28">ID</th><th class="p-1.5 w-36">Category</th><th class="p-1.5">Test Case</th>
                <th class="p-1.5 w-16">Steps</th><th class="p-1.5 w-20">Final RC</th><th class="p-1.5 w-20">Duration</th><th class="p-1.5 w-16">Verdict</th>
                <th class="p-1.5 w-96">First Failure</th>
              </tr>
            </thead>
            <tbody id="suite-results-tbody" class="divide-y divide-slate-800 font-mono text-slate-300">
              <tr><td colspan="9" class="p-4 text-center text-slate-600">Run test cases to see results. Click a row to see each step.</td></tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>

    <!-- WINDOW 3: SCHEMA CONFIG -->
    <div id="win-cfg" class="hidden space-y-3">
      <section class="bg-slate-900 border border-slate-800 rounded-lg p-3">
        <h3 class="text-xs font-bold uppercase tracking-wider text-slate-300 mb-3">
          Numerical DE Schema Config (<span class="channel-label-text">ATM</span>)
        </h3>

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
              <input id="new-de-input" type="number" placeholder="DE # (e.g. 54)" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-white">
              <button onclick="addSingleDE()" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-3 py-1.5 rounded text-xs">+ Add</button>
            </div>
          </div>
        </div>

        <div class="mt-4">
          <label id="des-array-label" class="block text-xs text-slate-400 mb-1 font-medium">Numerical Data Elements (Comma Separated)</label>
          <input id="des-array-input" type="text" oninput="renderSchemaBadges()" class="w-full bg-slate-950 border border-slate-700 rounded p-2 text-xs font-mono text-emerald-400 break-all">
        </div>

        <div class="mt-3">
          <span class="block text-xs text-slate-400 mb-1 font-medium">Active DE Badges (Click to Remove):</span>
          <div id="schema-badges-container" class="flex flex-wrap gap-1.5 max-h-36 overflow-y-auto p-2 bg-slate-950 border border-slate-800 rounded"></div>
        </div>

        <div class="mt-4 flex justify-end">
          <button onclick="saveNumericalSchema()" class="bg-emerald-600 hover:bg-emerald-500 text-white font-bold px-4 py-2 rounded text-xs transition">
            Save Schema to Config (<span class="channel-label-text">ATM</span>)
          </button>
        </div>
      </section>
    </div>

    <!-- MODAL 1: ADD / EDIT TRANSACTION -->
    <div id="tx-form-modal" class="hidden fixed inset-0 bg-black/85 flex items-center justify-center p-4 z-50">
      <div class="bg-slate-900 border border-indigo-600 rounded-lg max-w-xl w-full p-4 shadow-2xl space-y-3">
        <div class="flex justify-between items-center border-b border-slate-800 pb-2">
          <h3 id="tx-form-title" class="text-sm font-bold uppercase tracking-wider text-indigo-300">Add New Transaction</h3>
          <button onclick="closeTxFormModal()" class="text-slate-400 hover:text-white text-lg">&times;</button>
        </div>
        <div class="space-y-2.5 text-xs max-h-[75vh] overflow-y-auto pr-1">
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="block text-slate-400 mb-1">Transaction Label *</label>
              <input id="tx-form-label" type="text" placeholder="e.g. Transaction Label" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-white">
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Key *</label>
              <input id="tx-form-key" type="text" placeholder="e.g. transaction_key" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-amber-300">
            </div>
          </div>
          <div class="grid grid-cols-2 gap-2">
            <div>
              <label class="block text-slate-400 mb-1">MTI</label>
              <input id="tx-form-mti" type="text" value="0200" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-white">
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Processing Code (DE 3)</label>
              <input id="tx-form-proc" type="text" value="000000" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-emerald-300">
            </div>
          </div>

          <div>
            <div class="flex justify-between items-center mb-1">
              <label class="text-slate-400 font-medium">Raw Request ISO Payload</label>
              <button type="button" onclick="parseModalRawRequest()" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-2.5 py-0.5 rounded text-[11px] transition shadow-sm flex items-center gap-1">
                <span>&#9889; Parse Request</span>
              </button>
            </div>
            <textarea id="tx-form-raw" rows="3" placeholder="Paste full raw request ISO string here..." class="w-full bg-slate-950 border border-slate-700 rounded p-2 font-mono text-[11px] text-emerald-400 resize-none"></textarea>
          </div>

          <div>
            <label class="block text-slate-400 mb-1">Request Data Elements (Comma Separated)</label>
            <input id="tx-form-req-des" type="text" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-white">
          </div>

          <div>
            <div class="flex justify-between items-center mb-1">
              <label class="text-slate-400 font-medium">Raw Response ISO Payload (Optional)</label>
              <button type="button" onclick="parseModalRawResponse()" class="bg-emerald-600 hover:bg-emerald-500 text-white font-bold px-2.5 py-0.5 rounded text-[11px] transition shadow-sm flex items-center gap-1">
                <span>&#9889; Parse Response</span>
              </button>
            </div>
            <textarea id="tx-form-raw-resp" rows="3" placeholder="Paste full raw response ISO string here..." class="w-full bg-slate-950 border border-slate-700 rounded p-2 font-mono text-[11px] text-cyan-300 resize-none"></textarea>
          </div>

          <div>
            <label class="block text-slate-400 mb-1">Expected Response Elements (Comma Separated)</label>
            <input id="tx-form-resp-des" type="text" class="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 font-mono text-white">
          </div>
        </div>
        <div class="pt-2 flex justify-end gap-2 border-t border-slate-800">
          <button onclick="closeTxFormModal()" class="bg-slate-800 hover:bg-slate-700 text-slate-300 px-4 py-1.5 rounded text-xs">Cancel</button>
          <button onclick="saveTxForm()" class="bg-emerald-600 hover:bg-emerald-500 text-white font-bold px-4 py-1.5 rounded text-xs shadow-sm">Save Transaction</button>
        </div>
      </div>
    </div>

    <!-- MODAL 2: SELECT TRANSACTION -->
    <div id="select-tx-modal" class="hidden fixed inset-0 bg-black/85 flex items-center justify-center p-4 z-50">
      <div class="bg-slate-900 border border-indigo-700 rounded-lg max-w-md w-full p-4 shadow-2xl space-y-3">
        <div class="flex justify-between items-center border-b border-slate-800 pb-2">
          <h3 id="select-tx-title" class="text-sm font-bold uppercase tracking-wider text-indigo-300">Select Transaction</h3>
          <button onclick="closeSelectTxModal()" class="text-slate-400 hover:text-white text-lg">&times;</button>
        </div>
        <div id="select-tx-list" class="space-y-1.5 max-h-64 overflow-y-auto pr-1"></div>
        <div class="pt-2 flex justify-end border-t border-slate-800">
          <button onclick="closeSelectTxModal()" class="bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1 rounded text-xs">Cancel</button>
        </div>
      </div>
    </div>

    <!-- MODAL 3: CONFIRM DELETE -->
    <div id="confirm-delete-modal" class="hidden fixed inset-0 bg-black/85 flex items-center justify-center p-4 z-50">
      <div class="bg-slate-900 border border-rose-600 rounded-lg max-w-sm w-full p-4 shadow-2xl space-y-3">
        <div class="flex justify-between items-center border-b border-slate-800 pb-2">
          <h3 class="text-sm font-bold uppercase tracking-wider text-rose-400">Confirm Deletion</h3>
          <button onclick="closeDeleteConfirmModal(false)" class="text-slate-400 hover:text-white text-lg">&times;</button>
        </div>
        <p id="confirm-delete-text" class="text-xs text-slate-200">Delete this transaction?</p>
        <div class="pt-2 flex justify-end gap-2 border-t border-slate-800">
          <button onclick="closeDeleteConfirmModal(false)" class="bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded text-xs">Cancel</button>
          <button onclick="closeDeleteConfirmModal(true)" class="bg-rose-600 hover:bg-rose-500 text-white font-bold px-3 py-1.5 rounded text-xs">Delete</button>
        </div>
      </div>
    </div>

    <!-- MODAL 4: REVERSAL CONFIRMATION -->
    <div id="reversal-confirm-modal" class="hidden fixed inset-0 bg-black/85 flex items-center justify-center p-4 z-50">
      <div class="bg-slate-900 border border-amber-600 rounded-lg max-w-lg w-full p-4 shadow-2xl space-y-3">
        <div class="flex justify-between items-center border-b border-slate-800 pb-2">
          <h3 class="text-sm font-bold uppercase tracking-wider text-amber-400">Linked 0420 Reversal Confirmation</h3>
          <button onclick="closeReversalModal(false)" class="text-slate-400 hover:text-white text-lg">&times;</button>
        </div>
        <div class="space-y-2 text-xs">
          <div class="p-2.5 bg-slate-950 border border-slate-800 rounded space-y-1">
            <div class="text-slate-400">Response Code / Status:</div>
            <div id="modal-de39-display" class="text-base font-bold font-mono text-amber-400">--</div>
            <div id="modal-tx-details" class="text-slate-400 text-[11px] font-mono"></div>
          </div>
          <p class="text-slate-300">Trigger matching <strong>0420 Reversal</strong> (DE 90 Parity, Reason 68)?</p>
        </div>
        <div class="pt-2 flex justify-end gap-2 border-t border-slate-800">
          <button onclick="closeReversalModal(false)" class="bg-slate-800 hover:bg-slate-700 text-slate-300 px-4 py-1.5 rounded text-xs">Cancel</button>
          <button onclick="closeReversalModal(true)" class="bg-amber-600 hover:bg-amber-500 text-white font-bold px-4 py-1.5 rounded text-xs shadow-sm">Proceed (0420)</button>
        </div>
      </div>
    </div>

    <!-- MODAL 5: RELEASE NOTES -->
    <div id="release-notes-modal" class="hidden fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
      <div class="bg-slate-900 border border-indigo-700 rounded-lg max-w-3xl w-full max-h-[85vh] flex flex-col p-4 shadow-2xl">
        <div class="flex justify-between items-center pb-2 border-b border-slate-800 mb-3">
          <h3 class="text-sm font-bold uppercase tracking-wider text-indigo-300">Sign-Off Note</h3>
          <button onclick="document.getElementById('release-notes-modal').classList.add('hidden')" class="text-slate-400 hover:text-white text-lg">&times;</button>
        </div>
        <textarea id="release-notes-textarea" readonly class="w-full flex-grow bg-slate-950 border border-slate-800 rounded p-3 font-mono text-xs text-emerald-300 resize-none h-96"></textarea>
        <div class="mt-3 flex justify-end gap-2">
          <button onclick="copyReleaseNotesToClipboard()" class="bg-indigo-600 hover:bg-indigo-500 text-white font-bold px-4 py-2 rounded text-xs">Copy Note</button>
        </div>
      </div>
    </div>

    <!-- MODAL 6: TEST CASE / SETTINGS JSON EDITOR -->
    <div id="tc-editor-modal" class="hidden fixed inset-0 bg-black/85 flex items-center justify-center p-4 z-50">
      <div class="bg-slate-900 border border-emerald-600 rounded-lg max-w-5xl w-full max-h-[92vh] flex flex-col p-4 shadow-2xl space-y-2">
        <div class="flex justify-between items-center border-b border-slate-800 pb-2">
          <h3 id="tc-editor-title" class="text-sm font-bold uppercase tracking-wider text-emerald-300">Test Case Editor</h3>
          <button onclick="closeEditor()" class="text-slate-400 hover:text-white text-lg">&times;</button>
        </div>
        <div id="tc-editor-help" class="text-[11px] text-slate-400 leading-relaxed"></div>
        <textarea id="tc-editor-text" spellcheck="false" class="w-full flex-grow min-h-[26rem] bg-slate-950 border border-slate-700 rounded p-2 font-mono text-[11px] text-emerald-300 resize-none"></textarea>
        <div id="tc-editor-errors" class="hidden p-2 bg-rose-950/50 border border-rose-800 rounded text-[11px] font-mono text-rose-300"></div>
        <div class="flex justify-end gap-2 pt-1">
          <button onclick="formatEditorJson()" class="bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded text-xs">Format JSON</button>
          <button onclick="closeEditor()" class="bg-slate-800 hover:bg-slate-700 text-slate-300 px-4 py-1.5 rounded text-xs">Cancel</button>
          <button onclick="saveEditor()" class="bg-emerald-600 hover:bg-emerald-500 text-white font-bold px-4 py-1.5 rounded text-xs">Save</button>
        </div>
      </div>
    </div>

  </div>

  <script>
    let configData = {};
    let currentChannel = "ATM";
    let activeTxKey = "";
    let isCurrentTxReversalType = false;
    let lastSent0200Iso = "";
    let lastReceived0210Iso = "";
    let lastDe39Code = "";
    let lastDe39Label = "";
    let activeSelectTxMode = "";
    let pendingDeleteKey = "";
    let inspectedMti = "0200";

    const HEADER_RE = /^\d{4}(0100|0110|0120|0130|0200|0210|0220|0230|0400|0410|0420|0421|0430|0800|0810|0820|0830)/;

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

    // ---------- Utilities ----------
    function escapeHtml(v) {
      return String(v === undefined || v === null ? "" : v)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
    }

    function cleanIso(s) {
      return String(s || "").trim().replace(/^>+/, "").trim();
    }

    function getTargetSettings() {
      return {
        ip: ipInput ? ipInput.value.trim() : "",
        port: portInput ? (parseInt(portInput.value.trim()) || 0) : 0,
        framing: framingSelect ? framingSelect.value : "ascii_4",
        bitmap_fmt: bitmapFmtSelect ? bitmapFmtSelect.value : "hex_ascii",
        charset: charsetSelect ? charsetSelect.value : "ascii",
        tpdu: tpduInput ? tpduInput.value.trim() : "",
        timeout_sec: timeoutInput ? (parseFloat(timeoutInput.value) || 6.0) : 6.0
      };
    }

    function rcBadgeClass(code, base) {
      if (code === '00') return base + " text-emerald-400";
      if (code === '68') return base + " text-amber-400";
      return base + " text-cyan-300";
    }

    window.onload = async () => {
      attachListeners();
      await selectChannelMode("ATM");
      updateLengthCounter();
    };

    function attachListeners() {
      if (reqArea) reqArea.addEventListener("input", updateLengthCounter);
      [ipInput, portInput, tpduInput].forEach(el => { if (el) el.addEventListener("input", updateTargetNotification); });
      [framingSelect, bitmapFmtSelect, charsetSelect, timeoutInput].forEach(el => { if (el) el.addEventListener("change", updateTargetNotification); });
      [panInput, accInput, acqInput, procCodeInput, rrnInput].forEach(el => { if (el) el.addEventListener("input", () => regenerateDynamic(false)); });
    }

    function updateTargetNotification() {
      const t = getTargetSettings();
      fetch("/api/handshake/update_target", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.assign({ channel: currentChannel }, t))
      }).catch(err => console.error("Target update failed:", err));
    }

    async function selectChannelMode(channel) {
      currentChannel = channel;
      ['ATM', 'UPI', 'IMPS'].forEach(ch => {
        const btn = document.getElementById("mode-btn-" + ch);
        if (btn) {
          btn.className = (ch === channel)
            ? "px-4 py-1.5 rounded font-bold transition bg-indigo-600 text-white shadow-sm flex items-center gap-1.5"
            : "px-4 py-1.5 rounded font-bold transition text-slate-400 hover:text-white flex items-center gap-1.5";
        }
      });

      const configFile = channel === 'ATM' ? 'iso_config.json' : `${channel.toLowerCase()}_config.json`;
      const indicator = document.getElementById("active-channel-indicator");
      if (indicator) indicator.innerText = `${channel} Engine Active (Config: ${configFile})`;

      document.querySelectorAll(".channel-label-text").forEach(el => { el.innerText = channel; });

      await loadAppConfig();
      await loadSuiteCatalog();
      suiteResults = [];
      const rtb = document.getElementById("suite-results-tbody");
      if (rtb) rtb.innerHTML = `<tr><td colspan="9" class="p-4 text-center text-slate-600">Run test cases to see results. Click a row to see each step.</td></tr>`;
      renderScore();
    }

    function renderSampleButtonsForChannel() {
      const btnContainer = document.getElementById("sample-buttons-container");
      if (!btnContainer) return;
      btnContainer.innerHTML = "";

      const samples = configData.sample_requests || {};
      const keys = Object.keys(samples);

      if (keys.length === 0) {
        btnContainer.innerHTML = `<span class='text-xs text-slate-500 italic'>No transactions configured for ${escapeHtml(currentChannel)}.</span>`;
        return;
      }

      if (!samples[activeTxKey]) activeTxKey = keys[0];

      keys.forEach(key => {
        const s = samples[key];
        const btn = document.createElement("button");
        btn.id = "btn-sample-" + key;
        btn.innerText = s.label;
        btn.onclick = () => {
          activeTxKey = key;
          highlightActiveTxButton(key);
          if (procCodeInput) procCodeInput.value = s.proc_code || "";
          regenerateDynamic(true);
        };
        btnContainer.appendChild(btn);
      });

      highlightActiveTxButton(activeTxKey);
      if (procCodeInput) procCodeInput.value = samples[activeTxKey].proc_code || "";
      regenerateDynamic(true);
    }

    function openAddTxModal() {
      document.getElementById("tx-form-title").innerText = `Add New ${currentChannel} Transaction Type`;
      document.getElementById("tx-form-key").value = "";
      document.getElementById("tx-form-key").disabled = false;
      document.getElementById("tx-form-label").value = "";
      document.getElementById("tx-form-mti").value = "0200";
      document.getElementById("tx-form-proc").value = "000000";
      document.getElementById("tx-form-raw").value = "";
      document.getElementById("tx-form-raw-resp").value = "";

      if (currentChannel === 'UPI') {
        document.getElementById("tx-form-label").placeholder = "e.g. UPI Credit Request";
        document.getElementById("tx-form-key").placeholder = "e.g. upi_credit_request";
        document.getElementById("tx-form-req-des").value = "2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 32, 37, 41, 49, 50, 102, 104, 123, 124, 127";
        document.getElementById("tx-form-resp-des").value = "2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 32, 37, 39, 41, 49, 50, 54, 102, 104, 123, 124, 127";
      } else if (currentChannel === 'IMPS') {
        document.getElementById("tx-form-label").placeholder = "e.g. IMPS P2A Request";
        document.getElementById("tx-form-key").placeholder = "e.g. imps_p2a_request";
        document.getElementById("tx-form-req-des").value = "2, 3, 4, 7, 11, 12, 13, 32, 37, 48, 49, 102";
        document.getElementById("tx-form-resp-des").value = "2, 3, 4, 7, 11, 12, 13, 32, 37, 39, 48, 49, 54, 102";
      } else {
        document.getElementById("tx-form-label").placeholder = "e.g. Issuer Cash Withdrawal Request";
        document.getElementById("tx-form-key").placeholder = "e.g. issuer_cash_withdrawal";
        document.getElementById("tx-form-req-des").value = "2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 41, 42, 43, 46, 48, 49, 60, 102";
        document.getElementById("tx-form-resp-des").value = "2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 35, 37, 39, 41, 42, 43, 46, 49, 54, 60, 102";
      }
      document.getElementById("tx-form-modal").classList.remove("hidden");
    }

    function openSelectTxModal(mode) {
      activeSelectTxMode = mode;
      document.getElementById("select-tx-title").innerText = mode === "edit"
        ? `Select ${currentChannel} Transaction to Edit`
        : `Select ${currentChannel} Transaction to Delete`;

      const list = document.getElementById("select-tx-list");
      list.innerHTML = "";

      const samples = configData.sample_requests || {};
      for (const [key, s] of Object.entries(samples)) {
        const row = document.createElement("div");
        row.className = "flex items-center justify-between p-2 bg-slate-950 hover:bg-slate-800 border border-slate-800 rounded cursor-pointer transition";
        row.innerHTML = `
          <div>
            <div class="font-bold text-slate-200 text-xs">${escapeHtml(s.label)}</div>
            <div class="text-[10px] font-mono text-slate-400">Key: ${escapeHtml(key)} | MTI: ${escapeHtml(s.mti)} | DE 3: ${escapeHtml(s.proc_code || 'N/A')}</div>
          </div>
          <span class="text-xs ${mode === 'delete' ? 'text-rose-400 font-bold' : 'text-indigo-400 font-bold'}">
            ${mode === 'delete' ? 'Delete &#10005;' : 'Edit &#9998;'}
          </span>
        `;
        row.onclick = () => {
          closeSelectTxModal();
          if (mode === 'edit') loadTxIntoEditModal(key, s);
          else promptDeleteConfirm(key, s.label);
        };
        list.appendChild(row);
      }

      document.getElementById("select-tx-modal").classList.remove("hidden");
    }

    function closeSelectTxModal() {
      document.getElementById("select-tx-modal").classList.add("hidden");
    }

    function loadTxIntoEditModal(key, tx) {
      document.getElementById("tx-form-title").innerText = `Edit ${currentChannel} Transaction: ${tx.label}`;
      document.getElementById("tx-form-key").value = key;
      document.getElementById("tx-form-key").disabled = true;
      document.getElementById("tx-form-label").value = tx.label || "";
      document.getElementById("tx-form-mti").value = tx.mti || "0200";
      document.getElementById("tx-form-proc").value = tx.proc_code || "000000";
      document.getElementById("tx-form-raw").value = "";
      document.getElementById("tx-form-raw-resp").value = "";
      document.getElementById("tx-form-req-des").value = (tx.req_des_present || []).join(", ");
      document.getElementById("tx-form-resp-des").value = (tx.resp_des_present || []).join(", ");
      document.getElementById("tx-form-modal").classList.remove("hidden");
    }

    function closeTxFormModal() {
      document.getElementById("tx-form-modal").classList.add("hidden");
    }

    async function callParseRaw(raw) {
      const res = await fetch("/api/parse_raw", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_iso: raw, channel: currentChannel })
      });
      return await res.json();
    }

    async function parseModalRawRequest() {
      const raw = document.getElementById("tx-form-raw").value.trim();
      if (!raw) { alert("Please paste a raw Request ISO string into the box first."); return; }
      try {
        const d = await callParseRaw(raw);
        if (d.status === "success") {
          document.getElementById("tx-form-mti").value = d.mti;
          const procField = d.fields.find(f => f.de === 3);
          if (procField) document.getElementById("tx-form-proc").value = procField.val;
          const des = d.fields.map(f => f.de).sort((a, b) => a - b);
          document.getElementById("tx-form-req-des").value = des.join(", ");
          alert(`Parsed ${des.length} Request Data Elements.` + (d.parse_error ? `\nWARNING: ${d.parse_error}` : ""));
        } else {
          alert("Request Parse Error: " + d.message);
        }
      } catch (e) {
        alert("Failed to parse request: " + e);
      }
    }

    async function parseModalRawResponse() {
      const raw = document.getElementById("tx-form-raw-resp").value.trim();
      if (!raw) { alert("Please paste a raw Response ISO string into the box first."); return; }
      try {
        const d = await callParseRaw(raw);
        if (d.status === "success") {
          const des = d.fields.map(f => f.de).sort((a, b) => a - b);
          document.getElementById("tx-form-resp-des").value = des.join(", ");
          alert(`Parsed ${des.length} Response Data Elements.` + (d.parse_error ? `\nWARNING: ${d.parse_error}` : ""));
        } else {
          alert("Response Parse Error: " + d.message);
        }
      } catch (e) {
        alert("Failed to parse response: " + e);
      }
    }

    async function saveTxForm() {
      const key = document.getElementById("tx-form-key").value.trim().toLowerCase().replace(/[^a-z0-9_]/g, '_');
      const label = document.getElementById("tx-form-label").value.trim();
      const mti = document.getElementById("tx-form-mti").value.trim();
      const proc_code = document.getElementById("tx-form-proc").value.trim();
      const raw_req = document.getElementById("tx-form-raw").value.trim();

      const req_des = document.getElementById("tx-form-req-des").value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
      const resp_des = document.getElementById("tx-form-resp-des").value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));

      if (!key || !label) { alert("Transaction label and key are required."); return; }
      if (!/^\d{4}$/.test(mti)) { alert("MTI must be 4 digits."); return; }

      try {
        const res = await fetch("/api/transaction/save", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ channel: currentChannel, key, label, mti, proc_code, raw_req, req_des_present: req_des, resp_des_present: resp_des })
        });
        const d = await res.json();
        if (d.status === "success") {
          closeTxFormModal();
          activeTxKey = key;
          await loadAppConfig();
          alert(d.message);
        } else {
          alert("Error: " + d.message);
        }
      } catch (err) {
        alert("Failed to save transaction: " + err);
      }
    }

    function promptDeleteConfirm(key, label) {
      pendingDeleteKey = key;
      document.getElementById("confirm-delete-text").innerHTML =
        `Delete ${escapeHtml(currentChannel)} transaction <strong>"${escapeHtml(label)}"</strong> (${escapeHtml(key)})?`;
      document.getElementById("confirm-delete-modal").classList.remove("hidden");
    }

    async function closeDeleteConfirmModal(confirmed) {
      document.getElementById("confirm-delete-modal").classList.add("hidden");
      if (!confirmed || !pendingDeleteKey) return;

      try {
        const res = await fetch("/api/transaction/delete", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ channel: currentChannel, key: pendingDeleteKey })
        });
        const d = await res.json();
        if (d.status === "success") {
          await loadAppConfig();
          alert(d.message);
        } else {
          alert("Delete failed: " + d.message);
        }
      } catch (err) {
        alert("Delete exception: " + err);
      } finally {
        pendingDeleteKey = "";
      }
    }

    function executePrimaryAction(forceTimeout = false) {
      sendTransactionWithFlow(isCurrentTxReversalType, forceTimeout);
    }

    function renderResponseChecks(parsed) {
      const box = document.getElementById("resp-checks");
      if (!box) return;
      const issues = [];
      if (parsed) {
        if (parsed.parse_error) issues.push("PARSE: " + parsed.parse_error);
        if (parsed.mti_ok === false) issues.push(`MTI: expected ${parsed.expected_mti}, received ${parsed.mti}`);
        if (parsed.mti && !parsed.de39) issues.push("DE 39 (Response Code) missing in response");
        if (parsed.validation && !parsed.validation.compliant) {
          issues.push("Missing expected DEs: " + parsed.validation.missing_des.map(x => x.de).join(", "));
        }
        if (parsed.validation && parsed.validation.unexpected_des.length) {
          issues.push("Unexpected DEs (info): " + parsed.validation.unexpected_des.map(x => x.de).join(", "));
        }
      }
      if (issues.length === 0) {
        box.classList.add("hidden");
        box.innerHTML = "";
      } else {
        box.innerHTML = issues.map(i => `<div>&#9888; ${escapeHtml(i)}</div>`).join("");
        box.classList.remove("hidden");
      }
    }

    async function sendTransactionWithFlow(isReversalTrigger, forceTimeout = false) {
      const t = getTargetSettings();
      const iso = reqArea ? cleanIso(reqArea.value) : "";
      const respBox = document.getElementById("iso-response");
      const badge = document.getElementById("de39-badge");

      if (!t.ip || !t.port) { alert("Enter valid Target IP and Port."); return; }
      if (!iso) { alert("Request payload box is empty."); return; }

      if (primaryBtn) {
        primaryBtn.disabled = true;
        primaryBtn.innerText = forceTimeout ? "Simulating Timeout (68)..." : (isReversalTrigger ? "Sending 0200..." : "Sending...");
      }
      if (respBox) respBox.value = forceTimeout
        ? `[Simulating CBS Timeout / Late Response (68) for ${currentChannel}]...`
        : `[Transmitting request to ${t.ip}:${t.port}]...`;
      renderResponseChecks(null);

      lastSent0200Iso = iso;
      lastReceived0210Iso = "";

      try {
        const res = await fetch("/api/send", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(Object.assign({ channel: currentChannel, tx_key: activeTxKey, iso_request: iso, force_timeout: forceTimeout }, t))
        });
        const d = await res.json();

        if (d.status === "success") {
          lastReceived0210Iso = d.timed_out ? "" : d.iso_response;
          if (respBox) respBox.value = d.iso_response;
          const latBadge = document.getElementById("resp-latency");
          if (latBadge) latBadge.innerText = "Latency: " + d.latency_ms + "ms";

          const pr = d.parsed_response || {};
          const de39 = pr.de39 || { code: "--", label: pr.parse_error ? "Unparseable / No DE 39" : "DE 39 Missing" };
          lastDe39Code = de39.code;
          lastDe39Label = de39.label;

          if (badge) {
            badge.innerText = "[" + de39.code + "] " + de39.label;
            badge.className = rcBadgeClass(de39.code, "font-mono font-bold");
          }
          renderParsedTable(pr.fields || [], `Response${pr.mti ? " (MTI: " + pr.mti + ")" : ""}`);
          renderResponseChecks(pr);

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
          primaryBtn.innerText = isCurrentTxReversalType ? "Send 0200 -> Prompt Reversal (0420)" : "Send Transaction";
        }
      }
    }

    async function parseManualRequestToTable() {
      const raw = reqArea ? cleanIso(reqArea.value) : "";
      if (!raw) { alert("Request payload box is empty. Paste a raw request string first."); return; }
      try {
        const d = await callParseRaw(raw);
        if (d.status === "success") {
          renderParsedTable(d.fields, `Request (MTI: ${d.mti})`, d.parse_error);
        } else {
          alert("Request Parse Error: " + d.message);
        }
      } catch (e) {
        alert("Parse Request Exception: " + e);
      }
    }

    async function parseManualResponse() {
      const respBox = document.getElementById("iso-response");
      const raw = respBox ? cleanIso(respBox.value) : "";
      if (!raw) { alert("Response payload box is empty. Paste a raw response string first."); return; }
      try {
        const d = await callParseRaw(raw);
        if (d.status === "success") {
          renderParsedTable(d.fields, `Response (MTI: ${d.mti})`, d.parse_error);
          const badge = document.getElementById("de39-badge");
          if (d.de39) {
            lastDe39Code = d.de39.code;
            lastDe39Label = d.de39.label;
            if (badge) {
              badge.innerText = "[" + d.de39.code + "] " + d.de39.label;
              badge.className = rcBadgeClass(d.de39.code, "font-mono font-bold");
            }
          } else if (badge) {
            badge.innerText = "DE 39 not present";
            badge.className = "font-mono font-bold text-slate-400";
          }
        } else {
          alert("Response Parse Error: " + d.message);
        }
      } catch (e) {
        alert("Parse Response Exception: " + e);
      }
    }

    function promptReversalModalForCurrent() {
      if (!lastSent0200Iso) { alert("Please send a transaction first before initiating reversal."); return; }
      promptReversalModal(lastDe39Code || "68", lastDe39Label || "Timeout / Late Response");
    }

    function promptReversalModal(rcCode, rcLabel) {
      const modal = document.getElementById("reversal-confirm-modal");
      const de39Display = document.getElementById("modal-de39-display");
      const txDetails = document.getElementById("modal-tx-details");

      if (de39Display) {
        de39Display.innerText = "[" + rcCode + "] " + rcLabel;
        de39Display.className = rcBadgeClass(rcCode, "text-base font-bold font-mono");
      }

      if (txDetails) {
        const rrn = rrnInput ? rrnInput.value.trim() : "--";
        const stan = rrn.length >= 6 ? rrn.slice(-6) : "--";
        const pan = panInput ? panInput.value.trim() : "--";
        txDetails.innerText = `Channel: ${currentChannel} | Target RRN: ${rrn} | STAN: ${stan} | Account/Card: ${pan}`;
      }

      if (modal) modal.classList.remove("hidden");
    }

    async function closeReversalModal(shouldProceed) {
      const modal = document.getElementById("reversal-confirm-modal");
      if (modal) modal.classList.add("hidden");
      if (shouldProceed) await executeLinked0420Reversal();
    }

    async function executeLinked0420Reversal() {
      const t = getTargetSettings();
      const respBox = document.getElementById("iso-response");
      const badge = document.getElementById("de39-badge");

      if (!lastSent0200Iso) { alert("Missing original request ISO."); return; }

      if (respBox) respBox.value = `[Constructing DE 90 & Transmitting 0420 Reversal to ${t.ip}:${t.port}]...`;
      if (badge) {
        badge.innerText = "Reversal (0420) In-Flight...";
        badge.className = "font-mono font-bold text-amber-400 animate-pulse";
      }

      try {
        const res = await fetch("/api/execute_linked_0420", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(Object.assign({ channel: currentChannel, orig_req_iso: lastSent0200Iso, reason_code: "68" }, t))
        });
        const d = await res.json();

        if (d.status === "success") {
          const pr = d.parsed_response || {};
          const revDe39 = pr.de39 || { code: "--", label: "DE 39 Missing in 0430" };

          if (respBox) {
            respBox.value =
              `=== LEG 1: ORIGINAL TRANSACTION (${currentChannel}) ===\n` +
              "REQ:  " + lastSent0200Iso + "\n" +
              "RESP: " + (lastReceived0210Iso || "[No Bytes - Timeout]") + "\n" +
              "RC:   [" + lastDe39Code + "] " + lastDe39Label + "\n\n" +
              `=== LEG 2: AUTO-LINKED 0420 REVERSAL (${currentChannel} METHOD 2) ===\n` +
              "DE 90: " + d.de90 + "\n" +
              "REQ:   " + d.rev_req_iso + "\n" +
              "RESP:  " + d.rev_resp_iso + "\n" +
              "RC:    [" + revDe39.code + "] " + revDe39.label + " (" + d.latency_ms + "ms)";
          }

          if (reqArea0420) reqArea0420.value = d.rev_req_iso;
          const latBadge = document.getElementById("resp-latency");
          if (latBadge) latBadge.innerText = "Reversal Latency: " + d.latency_ms + "ms";

          if (badge) {
            badge.innerText = "Reversal Result: [" + revDe39.code + "] " + revDe39.label;
            badge.className = revDe39.code === '00' ? "font-mono font-bold text-emerald-400" : "font-mono font-bold text-cyan-300";
          }

          renderParsedTable(pr.fields || [], "Reversal Response");
          renderResponseChecks(pr);
        } else {
          if (respBox) respBox.value = "Reversal Error: " + d.message;
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
      let val = cleanIso(reqArea.value);
      if (!val) return;
      if (val.length > 4 && HEADER_RE.test(val)) val = val.substring(4);
      reqArea.value = String(val.length).padStart(4, '0') + val;
      updateLengthCounter();
    }

    function removeLengthFromRequest() {
      if (!reqArea) return;
      const val = cleanIso(reqArea.value);
      if (val.length > 4 && HEADER_RE.test(val)) {
        reqArea.value = val.substring(4);
        updateLengthCounter();
      }
    }

    function updateLengthCounter() {
      if (!reqArea || !lenBadge) return;
      const val = cleanIso(reqArea.value);
      const totalLen = val.length;
      if (totalLen > 4 && HEADER_RE.test(val)) {
        lenBadge.innerText = `Total: ${totalLen} | ISO: ${totalLen - 4} (Header: ${val.substring(0, 4)})`;
        lenBadge.className = "text-[11px] bg-indigo-950 text-indigo-300 px-2 py-0.5 rounded font-mono border border-indigo-700";
      } else {
        lenBadge.innerText = `Length: ${totalLen} chars`;
        lenBadge.className = "text-[11px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono border border-slate-700";
      }
    }

    async function parseRequestAndDisplayEditor() {
      if (!reqArea) return;
      const raw = cleanIso(reqArea.value);
      if (!raw) { alert("Request box is empty."); return; }

      const d = await callParseRaw(raw);
      if (d.status !== "success") { alert(d.message); return; }
      if (d.parse_error) alert("WARNING: request only partially parsed.\n" + d.parse_error);

      inspectedMti = d.mti || "0200";
      const title = document.getElementById("editable-request-title");
      if (title) title.innerText = `Editable Request Data Elements (MTI: ${inspectedMti})`;

      const tbody = document.getElementById("editable-request-tbody");
      if (!tbody) return;
      let html = "";
      d.fields.forEach(f => {
        html += `
          <tr class="hover:bg-slate-900/80">
            <td class="p-1.5 text-indigo-400 font-bold">DE ${String(f.de).padStart(3, '0')}</td>
            <td class="p-1.5 text-slate-400">${escapeHtml(f.name)}</td>
            <td class="p-1.5 text-slate-500 font-mono text-[11px]">${f.len}</td>
            <td class="p-1.5">
              <input data-de="${f.de}" type="text" value="${escapeHtml(f.val)}" class="editable-de-input w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 text-xs font-mono text-emerald-300 focus:outline-none focus:border-indigo-500">
            </td>
          </tr>`;
      });
      tbody.innerHTML = html;

      const panel = document.getElementById("editable-request-panel");
      if (panel) panel.classList.remove("hidden");
    }

    async function applyTableEditsToPayload() {
      const inputs = document.querySelectorAll(".editable-de-input");
      const fieldDict = {};
      inputs.forEach(inp => { fieldDict[inp.getAttribute("data-de")] = inp.value; });

      const res = await fetch("/api/rebuild_from_fields", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mti: inspectedMti, fields: fieldDict, channel: currentChannel })
      });
      const d = await res.json();
      if (d.status === "success") {
        if (reqArea) reqArea.value = d.raw_iso;
        updateLengthCounter();
        alert(`Payload rebuilt from editable fields (MTI ${inspectedMti}).`);
      } else {
        alert("Failed to rebuild ISO: " + d.message);
      }
    }

    async function saveTargetAsDefault() {
      const t = getTargetSettings();
      if (!t.ip || !t.port) { alert("Please enter a valid IP and Port."); return; }
      await fetch("/api/target/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.assign({ channel: currentChannel }, t))
      });
      alert(`Default target settings saved for ${currentChannel}: ${t.ip}:${t.port}`);
    }

    async function regenerateDynamic(randomizeRRN = true) {
      if (!activeTxKey) return;
      const userPan = panInput ? panInput.value.trim() : "";
      const userAcc = accInput ? accInput.value.trim() : "";
      const userAcq = acqInput ? acqInput.value.trim() : "";

      try {
        const res = await fetch("/api/build_request", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            channel: currentChannel, tx_key: activeTxKey,
            proc_code: procCodeInput ? procCodeInput.value.trim() : "",
            pan: userPan, account: userAcc, acq_id: userAcq,
            rrn: randomizeRRN ? "" : (rrnInput ? rrnInput.value.trim() : "")
          })
        });
        const data = await res.json();
        if (data.status !== "success") {
          console.error("build_request failed:", data.message);
          return;
        }

        if (reqArea) reqArea.value = data.raw_iso_0200 || data.raw_iso;
        updateLengthCounter();

        if (procCodeInput) procCodeInput.value = data.proc_code;
        if (panInput && !panInput.value) panInput.value = data.pan;
        if (accInput && !accInput.value) accInput.value = data.account;
        if (acqInput && !acqInput.value) acqInput.value = data.acq_id;
        if (rrnInput) rrnInput.value = data.rrn;

        isCurrentTxReversalType = data.is_reversal;

        if (isCurrentTxReversalType) {
          if (revPreviewContainer) revPreviewContainer.classList.remove("hidden");
          if (reqArea0420) reqArea0420.value = data.raw_iso_0420 || "";
          if (reqBoxTitle) reqBoxTitle.innerText = `Leg 1: Original Request (MTI: 0200)`;
          if (primaryBtn) {
            primaryBtn.innerText = "Send 0200 -> Prompt Reversal (0420)";
            primaryBtn.className = "w-5/12 bg-amber-600 hover:bg-amber-500 text-white font-bold py-2 rounded text-xs transition shadow-sm";
          }
        } else {
          if (revPreviewContainer) revPreviewContainer.classList.add("hidden");
          if (reqBoxTitle) reqBoxTitle.innerText = `Request ISO Payload`;
          if (primaryBtn) {
            primaryBtn.innerText = `Send Transaction`;
            primaryBtn.className = "w-5/12 bg-indigo-600 hover:bg-indigo-500 text-white font-bold py-2 rounded text-xs transition shadow-sm";
          }
        }
      } catch (e) {
        console.error("Failed to regenerate parameters:", e);
      }
    }

    async function loadAppConfig() {
      try {
        const res = await fetch(`/api/config?channel=${encodeURIComponent(currentChannel)}`);
        configData = await res.json();

        const tgt = configData.target_settings || {};
        if (ipInput) ipInput.value = tgt.default_ip || "10.167.1.153";
        if (portInput) portInput.value = tgt.default_port || (currentChannel === 'ATM' ? 9019 : (currentChannel === 'UPI' ? 9020 : 9021));
        if (tgt.default_framing && framingSelect) framingSelect.value = tgt.default_framing;
        if (tgt.default_bitmap_fmt && bitmapFmtSelect) bitmapFmtSelect.value = tgt.default_bitmap_fmt;
        if (tgt.default_charset && charsetSelect) charsetSelect.value = tgt.default_charset;
        if (tpduInput) tpduInput.value = tgt.default_tpdu || "";
        if (timeoutInput) timeoutInput.value = tgt.default_timeout || 6.0;

        const cfgSelect = document.getElementById("cfg-tx-select");
        if (cfgSelect) {
          cfgSelect.innerHTML = "";
          for (const [key, s] of Object.entries(configData.sample_requests || {})) {
            const optCfg = document.createElement("option");
            optCfg.value = key;
            optCfg.innerText = `${s.label} (${key})`;
            cfgSelect.appendChild(optCfg);
          }
        }

        renderSampleButtonsForChannel();
        loadTxSchemaToEdit();
      } catch (e) {
        console.error("Error in loadAppConfig:", e);
      }
    }

    function highlightActiveTxButton(activeKey) {
      const samples = configData.sample_requests || {};
      for (const [key, s] of Object.entries(samples)) {
        const btn = document.getElementById("btn-sample-" + key);
        if (!btn) continue;
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

    function loadTxSchemaToEdit() {
      const cfgSelect = document.getElementById("cfg-tx-select");
      if (!cfgSelect) return;
      const key = cfgSelect.value;
      const radio = document.querySelector('input[name="schema-target-radio"]:checked');
      const targetType = radio ? radio.value : "req";
      const tx = (configData.sample_requests || {})[key];
      const desInput = document.getElementById("des-array-input");
      const desLabel = document.getElementById("des-array-label");
      if (!tx) {
        if (desInput) desInput.value = "";
        renderSchemaBadges();
        return;
      }
      const list = targetType === "req" ? (tx.req_des_present || tx.des_present || []) : (tx.resp_des_present || []);
      if (desInput) desInput.value = list.join(", ");
      if (desLabel) desLabel.innerText = targetType === "req"
        ? `${currentChannel} Request Elements (Outgoing, Comma Separated)`
        : `${currentChannel} Expected Response Elements (Validation Baseline, Comma Separated)`;
      renderSchemaBadges();
    }

    function renderSchemaBadges() {
      const desInput = document.getElementById("des-array-input");
      const container = document.getElementById("schema-badges-container");
      if (!desInput || !container) return;
      const des = desInput.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
      container.innerHTML = "";

      des.sort((a, b) => a - b).forEach(de => {
        const fieldName = ((configData.field_definitions || {})[de] || {}).name || ("DE " + de);
        const badge = document.createElement("span");
        badge.className = "inline-flex items-center gap-1 bg-slate-800 text-indigo-300 border border-slate-700 px-2 py-0.5 rounded text-[11px] font-mono cursor-pointer hover:border-red-600 hover:text-red-400";
        badge.innerHTML = `<span>DE ${de} (${escapeHtml(fieldName)})</span> <span class="text-xs">&times;</span>`;
        badge.onclick = () => removeDEFromSchema(de);
        container.appendChild(badge);
      });
    }

    function addSingleDE() {
      const deInput = document.getElementById("new-de-input");
      const input = document.getElementById("des-array-input");
      if (!deInput || !input) return;
      const deVal = parseInt(deInput.value.trim());
      if (isNaN(deVal) || deVal < 2 || deVal > 128) { alert("Enter valid DE # (2-128)."); return; }
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
      const input = document.getElementById("des-array-input");
      if (!cfgSelect || !input) return;
      const key = cfgSelect.value;
      const radio = document.querySelector('input[name="schema-target-radio"]:checked');
      const targetType = radio ? radio.value : "req";
      const current = input.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));

      const res = await fetch("/api/schema/save_numericals", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: currentChannel, key, target_type: targetType, des_present: current })
      });
      const data = await res.json();
      if (data.status === "success") {
        if (targetType === "req") configData.sample_requests[key].req_des_present = data.des_present;
        else configData.sample_requests[key].resp_des_present = data.des_present;
        alert(`Saved ${currentChannel} schema successfully for ` + key);
        if (activeTxKey === key && targetType === "req") regenerateDynamic(false);
      } else {
        alert("Failed to save: " + data.message);
      }
    }

    function switchWindow(tab) {
      ['single', 'super', 'cfg'].forEach(t => {
        const win = document.getElementById("win-" + t);
        if (win) win.classList.toggle("hidden", tab !== t);
        const el = document.getElementById("tab-btn-" + t);
        if (el) {
          el.className = (tab === t)
            ? "px-4 py-1.5 text-xs font-semibold rounded-t border-b-2 border-indigo-500 text-white bg-slate-900"
            : "px-4 py-1.5 text-xs font-semibold rounded-t text-slate-400 hover:text-white bg-slate-950";
        }
      });
    }

    function renderParsedTable(fields, sourceLabel = "Parsed", warning = null) {
      const tbody = document.getElementById("parsed-table-body");
      const title = document.getElementById("parsed-table-title");
      if (title) title.innerText = `Parsed Elements [${sourceLabel}]`;
      if (!tbody) return;
      let html = "";
      if (warning) {
        html += `<tr class="bg-rose-950/40"><td colspan="4" class="p-1.5 text-rose-300">&#9888; Partial parse: ${escapeHtml(warning)}</td></tr>`;
      }
      if (!fields || fields.length === 0) {
        html += "<tr><td colspan='4' class='p-3 text-center text-slate-600'>No fields parsed.</td></tr>";
        tbody.innerHTML = html;
        return;
      }
      fields.forEach(f => {
        html += `
          <tr class="${f.de === 39 ? 'bg-amber-950/30 text-amber-300 font-bold' : 'hover:bg-slate-900'}">
            <td class="p-1.5 text-slate-400">DE ${String(f.de).padStart(3, '0')}</td>
            <td class="p-1.5">${escapeHtml(f.name)}</td>
            <td class="p-1.5 text-slate-400">${f.len}</td>
            <td class="p-1.5 break-all text-emerald-400">${escapeHtml(f.val)}</td>
          </tr>`;
      });
      tbody.innerHTML = html;
    }

    // ======================================================================
    // END-TO-END TEST SUITE
    // ======================================================================
    let suiteCatalog = { settings: {}, profiles: {}, testcases: [], categories: [], file: "" };
    let suiteResults = [];
    let suiteSelected = new Set();
    let suiteRunning = false;
    let suiteStopRequested = false;
    let editorMode = null;          // 'testcase' | 'settings'
    let editorOriginalId = null;

    const CATEGORY_COLORS = {
      "Network Management": "bg-sky-950 text-sky-300 border-sky-800",
      "Positive": "bg-emerald-950 text-emerald-300 border-emerald-800",
      "Negative - Account": "bg-rose-950 text-rose-300 border-rose-800",
      "Negative - Card": "bg-pink-950 text-pink-300 border-pink-800",
      "Boundary": "bg-amber-950 text-amber-300 border-amber-800",
      "Reversal": "bg-orange-950 text-orange-300 border-orange-800",
      "Duplicate": "bg-violet-950 text-violet-300 border-violet-800",
      "Security / Format": "bg-red-950 text-red-300 border-red-800",
      "Timeout / Fault": "bg-yellow-950 text-yellow-300 border-yellow-800"
    };

    function catBadge(cat) {
      const cls = CATEGORY_COLORS[cat] || "bg-slate-800 text-slate-300 border-slate-700";
      return `<span class="inline-block px-1.5 py-0.5 rounded border text-[10px] ${cls}">${escapeHtml(cat)}</span>`;
    }

    async function loadSuiteCatalog() {
      try {
        const res = await fetch(`/api/suite/catalog?channel=${encodeURIComponent(currentChannel)}`);
        const d = await res.json();
        if (d.status !== "success") { alert("Failed to load test cases: " + d.message); return; }
        suiteCatalog = d.catalog;
        suiteCatalog.categories = d.categories || [];
        suiteCatalog.file = d.file || "";
        suiteSelected = new Set();

        const label = document.getElementById("suite-file-label");
        if (label) label.innerText = `Catalog: ${suiteCatalog.file}  |  ${suiteCatalog.testcases.length} test cases  |  ${Object.keys(suiteCatalog.profiles || {}).length} profiles`;

        const catSel = document.getElementById("suite-cat-filter");
        if (catSel) {
          const current = catSel.value;
          const cats = Array.from(new Set([...(suiteCatalog.categories || []), ...suiteCatalog.testcases.map(t => t.category)]));
          catSel.innerHTML = `<option value="">All Categories</option>` + cats.map(c => `<option value="${escapeHtml(c)}">${escapeHtml(c)}</option>`).join("");
          if (cats.includes(current)) catSel.value = current;
        }
        renderDistinctProfilesGrid();
        renderCatalogTable();
      } catch (e) {
        console.error("loadSuiteCatalog failed", e);
      }
    }

    function filteredTestcases() {
      const cat = (document.getElementById("suite-cat-filter") || {}).value || "";
      const pri = (document.getElementById("suite-pri-filter") || {}).value || "";
      const q = ((document.getElementById("suite-search") || {}).value || "").trim().toLowerCase();
      return (suiteCatalog.testcases || []).filter(t =>
        (!cat || t.category === cat) &&
        (!pri || (t.priority || "") === pri) &&
        (!q || `${t.id} ${t.name} ${t.expected_result || ""} ${t.description || ""}`.toLowerCase().includes(q)));
    }

    function renderCatalogTable() {
      const tbody = document.getElementById("suite-catalog-tbody");
      if (!tbody) return;
      const rows = filteredTestcases();
      if (rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="p-4 text-center text-slate-600">No test cases match the filter.</td></tr>`;
      } else {
        tbody.innerHTML = rows.map(t => {
          const disabled = t.enabled === false;
          const prof = (suiteCatalog.profiles || {})[t.profile || "standard"] || {};
          return `
            <tr class="hover:bg-slate-900/80 align-top ${disabled ? 'opacity-50' : ''}">
              <td class="p-2"><input type="checkbox" data-tc-select="${escapeHtml(t.id)}" ${suiteSelected.has(t.id) ? 'checked' : ''} onchange="toggleSelect(this.dataset.tcSelect, this.checked)"></td>
              <td class="p-2 font-bold text-amber-400">${escapeHtml(t.id)}${disabled ? '<div class="text-[10px] text-slate-500">disabled</div>' : ''}</td>
              <td class="p-2">${catBadge(t.category)}</td>
              <td class="p-2 text-slate-400">${escapeHtml(t.priority || "")}</td>
              <td class="p-2 font-sans text-slate-200" title="${escapeHtml(t.description || "")}">${escapeHtml(t.name)}
                ${t.description ? `<div class="text-[10px] text-slate-500 font-sans">${escapeHtml(t.description)}</div>` : ""}</td>
              <td class="p-2 text-[11px] text-cyan-300" title="${escapeHtml(prof.account || "")}">${escapeHtml(t.profile || "standard")}</td>
              <td class="p-2 text-slate-400 text-center">${(t.steps || []).length}</td>
              <td class="p-2 font-sans text-[11px] text-slate-400">${escapeHtml(t.expected_result || "")}</td>
              <td class="p-2 whitespace-nowrap">
                <button data-id="${escapeHtml(t.id)}" onclick="runSuite('single', this.dataset.id)" class="text-emerald-400 hover:text-emerald-300 mr-1.5" title="Run this test case">&#9654; Run</button>
                <button data-id="${escapeHtml(t.id)}" onclick="openTestcaseEditor(this.dataset.id, false)" class="text-indigo-400 hover:text-indigo-300 mr-1.5">Edit</button>
                <button data-id="${escapeHtml(t.id)}" onclick="openTestcaseEditor(this.dataset.id, true)" class="text-slate-400 hover:text-white mr-1.5">Clone</button>
                <button data-id="${escapeHtml(t.id)}" onclick="deleteTestcase(this.dataset.id)" class="text-rose-400 hover:text-rose-300">Del</button>
              </td>
            </tr>`;
        }).join("");
      }

      const summary = document.getElementById("suite-cat-summary");
      if (summary) {
        const counts = {};
        (suiteCatalog.testcases || []).forEach(t => { counts[t.category] = (counts[t.category] || 0) + 1; });
        summary.innerHTML = Object.entries(counts).map(([c, n]) =>
          `<span class="text-[10px] font-mono">${catBadge(c)} <span class="text-slate-400">${n}</span></span>`).join(" ");
      }
      const selAll = document.getElementById("suite-select-all");
      if (selAll) selAll.checked = rows.length > 0 && rows.every(t => suiteSelected.has(t.id));
      updateSelectedCount();
    }

    function toggleSelect(id, checked) {
      if (checked) suiteSelected.add(id); else suiteSelected.delete(id);
      updateSelectedCount();
    }

    function toggleSelectAll(checked) {
      filteredTestcases().forEach(t => { if (checked) suiteSelected.add(t.id); else suiteSelected.delete(t.id); });
      renderCatalogTable();
    }

    function updateSelectedCount() {
      const el = document.getElementById("suite-selected-count");
      if (el) el.innerText = `${suiteSelected.size} selected / ${(suiteCatalog.testcases || []).length} total`;
    }

    // ---------------- Profiles ----------------
    function renderDistinctProfilesGrid() {
      const container = document.getElementById("distinct-profiles-grid");
      const countEl = document.getElementById("profile-count");
      const profiles = suiteCatalog.profiles || {};
      if (countEl) countEl.innerText = Object.keys(profiles).length;
      if (!container) return;
      container.innerHTML = Object.entries(profiles).map(([key, p]) => `
        <div class="bg-slate-900 border border-slate-800 rounded p-2 text-xs space-y-1.5">
          <div class="flex justify-between items-center">
            <span class="font-bold text-amber-400 font-mono text-[11px]">${escapeHtml(p.title || key)}</span>
            <span class="text-[10px] bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded font-mono">${escapeHtml(key)}</span>
          </div>
          <div class="grid grid-cols-5 gap-1.5">
            <div class="col-span-2">
              <label class="block text-[10px] text-slate-400">Account (DE 102)</label>
              <input data-prof="${escapeHtml(key)}" data-field="account" type="text" value="${escapeHtml(p.account || "")}" class="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 font-mono text-xs text-emerald-300 focus:outline-none focus:border-indigo-500">
            </div>
            <div class="col-span-2">
              <label class="block text-[10px] text-slate-400">Card / PAN (DE 2)</label>
              <input data-prof="${escapeHtml(key)}" data-field="card" type="text" value="${escapeHtml(p.card || "")}" class="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 font-mono text-xs text-cyan-300 focus:outline-none focus:border-indigo-500">
            </div>
            <div>
              <label class="block text-[10px] text-slate-400">Expiry</label>
              <input data-prof="${escapeHtml(key)}" data-field="expiry" type="text" maxlength="4" value="${escapeHtml(p.expiry || "")}" class="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 font-mono text-xs text-slate-200 focus:outline-none focus:border-indigo-500">
            </div>
          </div>
          <p class="text-[10px] text-slate-400 leading-tight">${escapeHtml(p.desc || "")}</p>
        </div>`).join("");
    }

    function collectProfilesFromGrid() {
      const profiles = JSON.parse(JSON.stringify(suiteCatalog.profiles || {}));
      document.querySelectorAll("#distinct-profiles-grid input[data-prof]").forEach(inp => {
        const key = inp.dataset.prof;
        if (profiles[key]) profiles[key][inp.dataset.field] = inp.value.trim();
      });
      return profiles;
    }

    async function saveProfiles() {
      const profiles = collectProfilesFromGrid();
      const res = await fetch("/api/suite/profiles/save", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: currentChannel, profiles })
      });
      const d = await res.json();
      if (d.status === "success") {
        suiteCatalog.profiles = profiles;
        alert(`Profiles saved to ${suiteCatalog.file}.`);
      } else {
        alert("Save failed: " + d.message);
      }
    }

    // ---------------- Editor ----------------
    const TESTCASE_HELP = `
      <b>Step keys:</b> tx (config transaction key) &middot; mti / proc_code / des &middot; amount ("500.00") &middot; profile &middot; direction ("DR"/"CR") &middot;
      set {"DE": "value"} (tokens <code>{step1.37}</code>, <code>{step1.resp.38}</code>) &middot; add / remove [DEs] &middot;
      link {"type": "reversal | repeat_reversal | duplicate | same_rrn", "step": N, "reason": "68", "amount", "partial_amount"} &middot;
      tamper [{"op": "llvar_len|truncate|append|bitmap_set|bitmap_clear|replace", ...}] &middot; timeout_sec &middot; wait_ms<br>
      <b>expect:</b> rc [list] &middot; mti (null = skip) &middot; timeout true &middot; allow_no_response &middot; des / present / absent [DEs] &middot;
      echo [DEs] &middot; regex {"DE": "pattern"} &middot; balance {"from_step": N, "delta": "-500.00"}`;

    function newTestcaseTemplate() {
      const firstTx = Object.keys(configData.sample_requests || {})[0] || "";
      const prefix = currentChannel === "ATM" ? "ATM" : currentChannel;
      return {
        id: `${prefix}_CUSTOM_${String(Date.now()).slice(-4)}`,
        category: "Positive", priority: "P2", enabled: true,
        name: "New test case", description: "", expected_result: "",
        profile: "standard",
        steps: [{ label: "Step 1", tx: firstTx, amount: "100.00", expect: { rc: ["00"] } }]
      };
    }

    function openTestcaseEditor(id, clone) {
      editorMode = "testcase";
      let tc;
      if (id) {
        const found = (suiteCatalog.testcases || []).find(t => t.id === id);
        if (!found) { alert("Test case not found: " + id); return; }
        tc = JSON.parse(JSON.stringify(found));
        if (clone) { tc.id = tc.id + "_COPY"; tc.name = tc.name + " (copy)"; }
      } else {
        tc = newTestcaseTemplate();
      }
      editorOriginalId = (id && !clone) ? id : null;
      document.getElementById("tc-editor-title").innerText = editorOriginalId
        ? `Edit ${currentChannel} Test Case: ${id}` : `New ${currentChannel} Test Case`;
      document.getElementById("tc-editor-help").innerHTML = TESTCASE_HELP +
        `<br><b>Profiles:</b> ${escapeHtml(Object.keys(suiteCatalog.profiles || {}).join(", "))}` +
        `<br><b>Transactions:</b> ${escapeHtml(Object.keys(configData.sample_requests || {}).join(", "))}`;
      document.getElementById("tc-editor-text").value = JSON.stringify(tc, null, 2);
      showEditorErrors([]);
      document.getElementById("tc-editor-modal").classList.remove("hidden");
    }

    function openSettingsEditor() {
      editorMode = "settings";
      editorOriginalId = null;
      document.getElementById("tc-editor-title").innerText = `${currentChannel} Channel Settings`;
      document.getElementById("tc-editor-help").innerHTML = `
        <b>direction_rule</b>: how Outward (DR) / Inward (CR) steps are tagged. Set <code>enabled</code> false if your CBS doesn't use a tag,
        or change <code>de</code> / values to match your CBS (e.g. DE 3 differs &rarr; edit the step's proc_code instead).<br>
        <b>default_echo_des</b>: DEs that must come back unchanged in every response.<br>
        <b>des_check</b>: "strict" fails a test when an approved response lacks a DE listed in the transaction's Expected Response DEs; "info" only notes it.<br>
        <b>step_delay_ms</b>: pause between steps.`;
      document.getElementById("tc-editor-text").value = JSON.stringify(suiteCatalog.settings || {}, null, 2);
      showEditorErrors([]);
      document.getElementById("tc-editor-modal").classList.remove("hidden");
    }

    function closeEditor() {
      document.getElementById("tc-editor-modal").classList.add("hidden");
      editorMode = null;
    }

    function showEditorErrors(errors) {
      const box = document.getElementById("tc-editor-errors");
      if (!box) return;
      if (!errors || errors.length === 0) { box.classList.add("hidden"); box.innerHTML = ""; return; }
      box.innerHTML = errors.map(e => `<div>&#9888; ${escapeHtml(e)}</div>`).join("");
      box.classList.remove("hidden");
    }

    function formatEditorJson() {
      const ta = document.getElementById("tc-editor-text");
      try { ta.value = JSON.stringify(JSON.parse(ta.value), null, 2); showEditorErrors([]); }
      catch (e) { showEditorErrors(["Invalid JSON: " + e.message]); }
    }

    async function saveEditor() {
      let obj;
      try { obj = JSON.parse(document.getElementById("tc-editor-text").value); }
      catch (e) { showEditorErrors(["Invalid JSON: " + e.message]); return; }

      const url = editorMode === "settings" ? "/api/suite/settings/save" : "/api/suite/testcase/save";
      const body = editorMode === "settings"
        ? { channel: currentChannel, settings: obj }
        : { channel: currentChannel, testcase: obj, original_id: editorOriginalId };
      const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const d = await res.json();
      if (d.status === "success") {
        closeEditor();
        await loadSuiteCatalog();
      } else {
        showEditorErrors(d.errors || [d.message]);
      }
    }

    async function deleteTestcase(id) {
      if (!confirm(`Delete ${currentChannel} test case ${id}?`)) return;
      const res = await fetch("/api/suite/testcase/delete", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: currentChannel, id })
      });
      const d = await res.json();
      if (d.status === "success") { suiteSelected.delete(id); await loadSuiteCatalog(); }
      else alert("Delete failed: " + d.message);
    }

    async function restoreDefaults(mode) {
      const msg = mode === "reset"
        ? `Replace ALL ${currentChannel} test cases, profiles and settings with the defaults? Your edits will be lost.`
        : `Add any default ${currentChannel} test cases / profiles that are missing (your edits are kept)?`;
      if (!confirm(msg)) return;
      const res = await fetch("/api/suite/reset", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: currentChannel, mode })
      });
      const d = await res.json();
      if (d.status === "success") { alert(d.message); await loadSuiteCatalog(); }
      else alert("Failed: " + d.message);
    }

    // ---------------- Execution ----------------
    function setRunningUi(running) {
      suiteRunning = running;
      ["suite-run-selected-btn", "suite-run-all-btn"].forEach(id => {
        const b = document.getElementById(id);
        if (b) { b.disabled = running; b.classList.toggle("opacity-50", running); }
      });
      const stop = document.getElementById("suite-stop-btn");
      if (stop) stop.classList.toggle("hidden", !running);
      const wrap = document.getElementById("suite-progress-wrap");
      if (wrap && running) wrap.classList.remove("hidden");
    }

    function stopSuite() {
      suiteStopRequested = true;
      const t = document.getElementById("suite-progress-text");
      if (t) t.innerText += "  |  stopping after current test case...";
    }

    async function runSuite(mode, singleId) {
      if (suiteRunning) return;
      const t = getTargetSettings();
      if (!t.ip || !t.port) { alert("Enter valid Target IP and Port."); return; }

      let ids;
      if (mode === "single") ids = [singleId];
      else if (mode === "selected") ids = (suiteCatalog.testcases || []).filter(x => suiteSelected.has(x.id)).map(x => x.id);
      else ids = (suiteCatalog.testcases || []).filter(x => x.enabled !== false).map(x => x.id);
      if (ids.length === 0) { alert(mode === "selected" ? "Select at least one test case." : "No enabled test cases."); return; }

      const profiles = collectProfilesFromGrid();
      suiteStopRequested = false;
      setRunningUi(true);
      suiteResults = [];
      const tbody = document.getElementById("suite-results-tbody");
      if (tbody) tbody.innerHTML = "";
      document.getElementById("view-release-btn").classList.add("hidden");
      renderScore();

      if (document.getElementById("suite-reset-mock").checked) {
        try {
          const r = await fetch("/api/suite/reset_mock", { method: "POST", headers: { "Content-Type": "application/json" },
            body: JSON.stringify(Object.assign({ channel: currentChannel }, t)) });
          const d = await r.json();
          if (d.status !== "success") alert("Mock reset failed: " + d.message + "\nContinuing with the run.");
        } catch (e) { console.error(e); }
      }

      const bar = document.getElementById("suite-progress-bar");
      const txt = document.getElementById("suite-progress-text");
      const startedAt = Date.now();
      try {
        for (let i = 0; i < ids.length; i++) {
          if (suiteStopRequested) break;
          if (txt) txt.innerText = `Running ${i + 1} / ${ids.length}: ${ids[i]}`;
          let result;
          try {
            const res = await fetch("/api/suite/run_case", {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify(Object.assign({ channel: currentChannel, id: ids[i], profiles }, t))
            });
            const d = await res.json();
            result = d.status === "success" ? d.result : {
              id: ids[i], name: d.message, category: "", verdict: "FAIL", pass_steps: 0, total_steps: 0,
              duration_ms: 0, final_rc: "ERROR", steps: [{ n: 1, label: "Run error", checks: [d.message], notes: [], verdict: "FAIL" }]
            };
          } catch (e) {
            result = { id: ids[i], name: String(e), category: "", verdict: "FAIL", pass_steps: 0, total_steps: 0,
                       duration_ms: 0, final_rc: "ERROR", steps: [{ n: 1, label: "Client error", checks: [String(e)], notes: [], verdict: "FAIL" }] };
          }
          suiteResults.push(result);
          appendResultRow(result, suiteResults.length - 1);
          renderScore();
          if (bar) bar.style.width = `${Math.round(((i + 1) / ids.length) * 100)}%`;
          if (result.verdict !== "PASS" && document.getElementById("suite-stop-on-fail").checked) {
            suiteStopRequested = true;
          }
        }
      } finally {
        const secs = ((Date.now() - startedAt) / 1000).toFixed(1);
        if (txt) txt.innerText = `${suiteStopRequested ? "Stopped" : "Completed"}: ${suiteResults.length} / ${ids.length} test cases in ${secs}s`;
        setRunningUi(false);
        document.getElementById("release-notes-textarea").value = buildSignOffNote();
        document.getElementById("view-release-btn").classList.remove("hidden");
      }
    }

    function firstFailure(r) {
      for (const s of r.steps || []) {
        if (s.verdict !== "PASS") return `S${s.n} ${s.label}: ${(s.checks || [])[0] || "failed"}`;
      }
      return "";
    }

    function appendResultRow(r, idx) {
      const tbody = document.getElementById("suite-results-tbody");
      if (!tbody) return;
      const pass = r.verdict === "PASS";
      const row = document.createElement("tr");
      row.className = "hover:bg-slate-900/80 cursor-pointer align-top";
      row.onclick = () => toggleResultDetail(idx);
      row.innerHTML = `
        <td class="p-1.5 text-slate-500" id="res-caret-${idx}">&#9656;</td>
        <td class="p-1.5 font-bold text-amber-400">${escapeHtml(r.id)}</td>
        <td class="p-1.5">${catBadge(r.category || "")}</td>
        <td class="p-1.5 font-sans text-slate-200">${escapeHtml(r.name)}</td>
        <td class="p-1.5 ${pass ? 'text-emerald-400' : 'text-rose-400'}">${r.pass_steps}/${r.total_steps}</td>
        <td class="p-1.5 text-cyan-300 font-bold">${escapeHtml(r.final_rc)}</td>
        <td class="p-1.5 text-slate-400">${r.duration_ms}ms</td>
        <td class="p-1.5 font-bold ${pass ? 'text-emerald-400' : 'text-red-400'}">${escapeHtml(r.verdict)}</td>
        <td class="p-1.5 text-[11px] text-rose-300 font-sans">${escapeHtml(firstFailure(r))}</td>`;
      tbody.appendChild(row);

      const detail = document.createElement("tr");
      detail.id = `res-detail-${idx}`;
      detail.className = "hidden bg-slate-950";
      const stepsHtml = (r.steps || []).map(s => {
        const ok = s.verdict === "PASS";
        const checks = (s.checks || []).map(c => `<div class="text-rose-300">&#10007; ${escapeHtml(c)}</div>`).join("");
        const notes = (s.notes || []).map(c => `<div class="text-slate-500">&#8226; ${escapeHtml(c)}</div>`).join("");
        return `
          <tr class="border-t border-slate-800 align-top">
            <td class="p-1.5 text-slate-500">${s.n}</td>
            <td class="p-1.5 font-sans text-slate-200">${escapeHtml(s.label)}</td>
            <td class="p-1.5 text-slate-400">${escapeHtml(s.mti || "")}&rarr;${escapeHtml(s.resp_mti || "--")}</td>
            <td class="p-1.5 text-cyan-300">${escapeHtml(s.expected || "")}</td>
            <td class="p-1.5 font-bold ${ok ? 'text-emerald-400' : 'text-rose-400'}">${escapeHtml(s.actual || "")}</td>
            <td class="p-1.5 text-slate-400">${s.latency_ms || 0}ms</td>
            <td class="p-1.5 text-slate-300">${escapeHtml(s.balance || "")}</td>
            <td class="p-1.5 font-bold ${ok ? 'text-emerald-400' : 'text-rose-400'}">${escapeHtml(s.verdict)}</td>
            <td class="p-1.5 text-[11px] font-sans">${checks}${notes}
              <details class="mt-1"><summary class="cursor-pointer text-indigo-400 text-[10px]">ISO request / response</summary>
                <div class="text-[10px] text-emerald-400 break-all mt-1">REQ: ${escapeHtml(s.req_iso || "")}</div>
                <div class="text-[10px] text-cyan-300 break-all mt-1">RESP: ${escapeHtml(s.resp_iso || "(none)")}</div>
              </details>
            </td>
          </tr>`;
      }).join("");
      detail.innerHTML = `
        <td></td>
        <td colspan="8" class="p-2">
          ${r.expected_result ? `<div class="text-[11px] text-slate-400 font-sans mb-1"><b>Expected:</b> ${escapeHtml(r.expected_result)}</div>` : ""}
          <table class="w-full text-left text-[11px] border-collapse">
            <thead><tr class="text-slate-500"><th class="p-1.5 w-6">#</th><th class="p-1.5 w-48">Step</th><th class="p-1.5 w-24">MTI</th>
              <th class="p-1.5 w-24">Exp RC</th><th class="p-1.5 w-20">Act</th><th class="p-1.5 w-16">Latency</th><th class="p-1.5 w-24">Avail Bal</th>
              <th class="p-1.5 w-12">Result</th><th class="p-1.5">Checks / Notes</th></tr></thead>
            <tbody>${stepsHtml}</tbody>
          </table>
        </td>`;
      tbody.appendChild(detail);
    }

    function toggleResultDetail(idx) {
      const d = document.getElementById(`res-detail-${idx}`);
      const c = document.getElementById(`res-caret-${idx}`);
      if (!d) return;
      d.classList.toggle("hidden");
      if (c) c.innerHTML = d.classList.contains("hidden") ? "&#9656;" : "&#9662;";
    }

    function renderScore() {
      const badge = document.getElementById("super-score-badge");
      const summary = document.getElementById("suite-result-summary");
      const total = suiteResults.length;
      const passed = suiteResults.filter(r => r.verdict === "PASS").length;
      if (badge) {
        if (!total) { badge.innerText = "Awaiting Run"; badge.className = "text-xs font-mono font-bold text-slate-500"; }
        else {
          const pct = ((passed / total) * 100).toFixed(1);
          badge.innerText = `${currentChannel}: ${passed} / ${total} passed (${pct}%)`;
          badge.className = passed === total ? "text-xs font-mono font-bold text-emerald-400" : "text-xs font-mono font-bold text-amber-400";
        }
      }
      if (summary) {
        const byCat = {};
        suiteResults.forEach(r => {
          const c = r.category || "Other";
          byCat[c] = byCat[c] || { p: 0, t: 0 };
          byCat[c].t++; if (r.verdict === "PASS") byCat[c].p++;
        });
        summary.innerHTML = Object.entries(byCat).map(([c, v]) =>
          `<span class="text-[10px] font-mono">${catBadge(c)} <span class="${v.p === v.t ? 'text-emerald-400' : 'text-rose-400'}">${v.p}/${v.t}</span></span>`).join(" ");
      }
    }

    function buildSignOffNote() {
      const total = suiteResults.length;
      const passed = suiteResults.filter(r => r.verdict === "PASS").length;
      const pct = total ? ((passed / total) * 100).toFixed(1) : "0.0";
      const t = getTargetSettings();
      const line = "=".repeat(80);
      let note = `${line}\nSWITCH <-> CBS END-TO-END TEST SIGN-OFF NOTE\n${line}\n` +
        `Channel:            ${currentChannel}\nTarget Host:        ${t.ip}:${t.port} (${t.framing}, ${t.bitmap_fmt}, ${t.charset})\n` +
        `Catalog:            ${suiteCatalog.file}\nExecution Date:     ${new Date().toLocaleString()}\n` +
        `Executed:           ${total}\nPassed:             ${passed}\nFailed:             ${total - passed}\n` +
        `Pass Rate:          ${pct}%\nOverall Verdict:    ${total && passed === total ? "ACCEPTANCE PASSED" : "ACTION REQUIRED"}\n${line}\n` +
        `CATEGORY BREAKDOWN:\n`;
      const byCat = {};
      suiteResults.forEach(r => { const c = r.category || "Other"; byCat[c] = byCat[c] || { p: 0, t: 0 }; byCat[c].t++; if (r.verdict === "PASS") byCat[c].p++; });
      Object.entries(byCat).forEach(([c, v]) => { note += `  ${c.padEnd(22)} ${v.p}/${v.t}\n`; });
      note += `${line}\nDETAILED RESULTS:\n\n`;
      suiteResults.forEach(r => {
        note += `[${r.verdict}] ${r.id} - ${r.name} (${r.category})\n`;
        (r.steps || []).forEach(s => {
          note += `   S${s.n} ${s.label}: ${s.mti || ""}->${s.resp_mti || "--"} exp ${s.expected || "-"} act ${s.actual || "-"} [${s.verdict}]\n`;
          (s.checks || []).forEach(c => { note += `      ! ${c}\n`; });
        });
        note += "\n";
      });
      return note;
    }

    function exportResultsToExcel() {
      if (!suiteResults.length) { alert("Run the test suite first."); return; }
      const summary = suiteResults.map((r, i) => ({
        "#": i + 1, "Test Case ID": r.id, "Channel": currentChannel, "Category": r.category, "Priority": r.priority,
        "Test Case": r.name, "Profile": r.profile, "Expected Result": r.expected_result,
        "Steps Passed": `${r.pass_steps}/${r.total_steps}`, "Final RC": r.final_rc, "Duration (ms)": r.duration_ms,
        "Verdict": r.verdict, "First Failure": firstFailure(r)
      }));
      const steps = [];
      suiteResults.forEach(r => (r.steps || []).forEach(s => steps.push({
        "Test Case ID": r.id, "Step": s.n, "Step Label": s.label, "Request MTI": s.mti, "Response MTI": s.resp_mti,
        "Expected RC": s.expected, "Actual": s.actual, "Latency (ms)": s.latency_ms, "Available Balance": s.balance || "",
        "Verdict": s.verdict, "Failed Checks": (s.checks || []).join(" | "), "Notes": (s.notes || []).join(" | "),
        "Request ISO": s.req_iso, "Response ISO": s.resp_iso
      })));
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(summary), "Summary");
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(steps), "Step Details");
      XLSX.writeFile(wb, `${currentChannel}_E2E_Results_${new Date().toISOString().slice(0, 10)}.xlsx`);
    }

    function describeStepForSheet(s) {
      const parts = [];
      if (s.link) parts.push(`${s.link.type} of step ${s.link.step}${s.link.amount ? " amt " + s.link.amount : ""}${s.link.partial_amount ? " partial " + s.link.partial_amount : ""}${s.link.reason ? " reason " + s.link.reason : ""}`);
      if (s.direction) parts.push(s.direction === "CR" ? "Credit" : "Debit");
      if (s.set) parts.push("set " + JSON.stringify(s.set));
      if (s.remove) parts.push("remove DE " + s.remove.join(","));
      if (s.tamper) parts.push("tamper " + s.tamper.map(t => t.op + (t.de ? " DE" + t.de : "")).join(", "));
      return parts.join("; ");
    }

    function describeExpectForSheet(e) {
      e = e || {};
      const parts = [];
      if (e.timeout) parts.push("No response (timeout)");
      if (e.rc) parts.push("RC " + e.rc.join("/"));
      if (e.allow_no_response) parts.push("or no response");
      if (e.present) parts.push("DE present " + e.present.join(","));
      if (e.absent) parts.push("DE absent " + e.absent.join(","));
      if (e.balance) parts.push(`balance ${e.balance.delta} vs step ${e.balance.from_step}`);
      if (e.regex) parts.push("format " + Object.keys(e.regex).map(k => "DE " + k).join(","));
      return parts.join("; ");
    }

    function exportCatalogToExcel() {
      const tcs = suiteCatalog.testcases || [];
      if (!tcs.length) { alert("No test cases."); return; }
      const rows = [];
      tcs.forEach(t => {
        const prof = (suiteCatalog.profiles || {})[t.profile || "standard"] || {};
        (t.steps || []).forEach((s, i) => {
          const tx = (configData.sample_requests || {})[s.tx] || {};
          rows.push({
            "Test Case ID": i === 0 ? t.id : "", "Channel": i === 0 ? currentChannel : "", "Category": i === 0 ? t.category : "",
            "Priority": i === 0 ? (t.priority || "") : "", "Test Case": i === 0 ? t.name : "",
            "Description": i === 0 ? (t.description || "") : "", "Enabled": i === 0 ? (t.enabled === false ? "No" : "Yes") : "",
            "Profile": i === 0 ? (t.profile || "standard") : "", "Account (DE 102)": i === 0 ? (prof.account || "") : "",
            "Card / PAN (DE 2)": i === 0 ? (prof.card || "") : "",
            "Step": i + 1, "Step Description": s.label || "", "Transaction": s.tx || (s.link ? "(linked)" : ""),
            "MTI": s.mti || (s.link ? (s.link.type === "repeat_reversal" ? "0421" : (s.link.type === "reversal" ? "0420" : "")) : (tx.mti || "")),
            "Processing Code": s.proc_code || tx.proc_code || "", "Amount": s.amount || "", "Step Profile": s.profile || "",
            "Data / Linkage": describeStepForSheet(s), "Expected Response": describeExpectForSheet(s.expect),
            "Expected Result": i === 0 ? (t.expected_result || "") : ""
          });
        });
      });
      const wb = XLSX.utils.book_new();
      const ws = XLSX.utils.json_to_sheet(rows);
      ws["!cols"] = [14, 8, 18, 8, 42, 40, 8, 14, 20, 20, 6, 32, 24, 8, 12, 12, 12, 40, 40, 50].map(w => ({ wch: w }));
      XLSX.utils.book_append_sheet(wb, ws, `${currentChannel}_TestCases`);
      XLSX.writeFile(wb, `${currentChannel}_E2E_TestCases.xlsx`);
    }

    function openReleaseNotesModal() {
      const modal = document.getElementById("release-notes-modal");
      if (modal) modal.classList.remove("hidden");
    }

    function copyReleaseNotesToClipboard() {
      const txt = document.getElementById("release-notes-textarea").value;
      navigator.clipboard.writeText(txt).then(() => alert("Copied to clipboard!"));
    }
  </script>
</body>
</html>
"""

# ==============================================================
# FLASK ROOT & API ROUTES
# ==============================================================

def _target_from(data, default_port=9019):
    return {
        "ip": str(data.get("ip", "")).strip(),
        "port": int(data.get("port") or default_port),
        "framing": data.get("framing", "ascii_4"),
        "bitmap_fmt": data.get("bitmap_fmt", "hex_ascii"),
        "charset": data.get("charset", "ascii"),
        "tpdu": data.get("tpdu", ""),
        "timeout_sec": float(data.get("timeout_sec") or 6.0),
    }


@app.route("/")
def index():
    return Response(HTML_PAGE, mimetype="text/html")


@app.route("/api/config", methods=["GET"])
def api_get_config():
    return jsonify(load_config(request.args.get("channel", "ATM")))


@app.route("/api/target/save", methods=["POST"])
def api_target_save():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    cfg = load_config(ch)
    tgt = cfg.setdefault("target_settings", {})
    try:
        if "ip" in data: tgt["default_ip"] = str(data["ip"]).strip()
        if "port" in data: tgt["default_port"] = int(data["port"])
        if "framing" in data: tgt["default_framing"] = str(data["framing"])
        if "bitmap_fmt" in data: tgt["default_bitmap_fmt"] = str(data["bitmap_fmt"])
        if "charset" in data: tgt["default_charset"] = str(data["charset"])
        if "tpdu" in data: tgt["default_tpdu"] = str(data["tpdu"]).strip()
        if "timeout_sec" in data: tgt["default_timeout"] = float(data["timeout_sec"])
    except (TypeError, ValueError) as e:
        return jsonify({"status": "error", "message": f"Invalid target value: {e}"}), 400
    save_config(cfg, ch)
    return jsonify({"status": "success", "message": f"Target settings saved for {ch}."})


@app.route("/api/handshake/update_target", methods=["POST"])
def api_handshake_update_target():
    return jsonify({"status": "success"})


@app.route("/api/schema/save_numericals", methods=["POST"])
def api_schema_save_numericals():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    key = data.get("key")
    target_type = data.get("target_type", "req")
    des_present = sorted({int(x) for x in data.get("des_present", []) if str(x).isdigit() and 2 <= int(x) <= 128})

    cfg = load_config(ch)
    if key not in cfg.get("sample_requests", {}):
        return jsonify({"status": "error", "message": f"Transaction '{key}' not found in {ch}."}), 400

    tx = cfg["sample_requests"][key]
    tx["req_des_present" if target_type == "req" else "resp_des_present"] = des_present
    save_config(cfg, ch)
    return jsonify({"status": "success", "des_present": des_present})


@app.route("/api/build_request", methods=["POST"])
def api_build_request():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    tx_key = data.get("tx_key")
    cfg = load_config(ch)
    sample_requests = cfg.get("sample_requests", {})

    tx_info = sample_requests.get(tx_key)
    if not tx_info:
        if not sample_requests:
            return jsonify({"status": "error", "message": f"No transactions found for {ch}."}), 400
        tx_key = list(sample_requests.keys())[0]
        tx_info = sample_requests[tx_key]

    mti = tx_info.get("mti", "0200")
    proc_code = data.get("proc_code") or tx_info.get("proc_code", "000000")
    req_des = tx_info.get("req_des_present") or tx_info.get("des_present", [2, 3, 4, 7, 11, 12, 13, 37, 48, 49, 102])

    rrn = data.get("rrn") or f"61{random.randint(1000000000, 9999999999)}"
    stan = rrn[-6:]
    pan = data.get("pan") or ("6072930130054479" if ch == "ATM" else "8180073930053234")
    account = data.get("account") or ("101303130001356" if ch == "ATM" else "0020001010000069")
    acq_id = data.get("acq_id") or ("800024" if ch == "ATM" else "622018")

    is_reversal = (mti == "0420") or ("reversal" in tx_key.lower())
    custom_params = {"pan": pan, "account": account, "acq_id": acq_id, "rrn": rrn, "stan": stan, "proc_code": proc_code}
    common = {"status": "success", "is_reversal": is_reversal, "pan": pan, "account": account,
              "acq_id": acq_id, "proc_code": proc_code, "rrn": rrn, "stan": stan}

    try:
        if is_reversal:
            base_key = tx_info.get("base_tx")
            base_tx = sample_requests.get(base_key) if base_key else None
            base_des = (base_tx.get("req_des_present") if base_tx else None) or \
                [2, 3, 4, 7, 11, 12, 13, 15, 17, 18, 22, 32, 37, 41, 42, 43, 48, 49, 60, 102]
            base_proc = (base_tx.get("proc_code") if base_tx else None) or proc_code

            raw_iso_0200, f0200 = assemble_iso_from_numericals("0200", base_proc, base_des, custom_params, ch)

            rev_params = dict(custom_params)
            rev_params["de90"] = build_de90("0200", f0200)
            rev_params["de39"] = "E2"
            raw_iso_0420, _ = assemble_iso_from_numericals("0420", proc_code, req_des, rev_params, ch)

            common.update({"raw_iso": raw_iso_0200, "raw_iso_0200": raw_iso_0200, "raw_iso_0420": raw_iso_0420})
        else:
            raw_iso, _ = assemble_iso_from_numericals(mti, proc_code, req_des, custom_params, ch)
            common.update({"raw_iso": raw_iso, "raw_iso_0200": raw_iso, "raw_iso_0420": ""})
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400

    return jsonify(common)


@app.route("/api/send", methods=["POST"])
def api_send():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    try:
        t = _target_from(data)
    except (TypeError, ValueError) as e:
        return jsonify({"status": "error", "message": f"Invalid target settings: {e}"}), 400
    tx_key = data.get("tx_key")
    iso_req = str(data.get("iso_request", "")).strip()
    force_timeout = bool(data.get("force_timeout", False))

    if not t["ip"] or not t["port"]:
        return jsonify({"status": "error", "message": "Target IP and Port are required."}), 400
    if not iso_req:
        return jsonify({"status": "error", "message": "Request payload cannot be empty."}), 400

    cfg = load_config(ch)
    samples = cfg.get("sample_requests", {})
    tx_info = samples.get(tx_key, {})
    req_mti, _ = parse_raw_iso_dict(iso_req, ch)

    # For a reversal-type tx, leg 1 is the base 0200 -> validate against the base tx schema
    expected_resp_des = tx_info.get("resp_des_present")
    if req_mti and tx_info.get("mti") and req_mti != tx_info.get("mti") and tx_info.get("base_tx") in samples:
        expected_resp_des = samples[tx_info["base_tx"]].get("resp_des_present")

    write_partitioned_log(ch.lower(), f"REQUEST [{tx_key}]: {iso_req}")

    if force_timeout:
        return jsonify({
            "status": "success",
            "iso_response": "[SIMULATED TIMEOUT / LATE RESPONSE 68]",
            "latency_ms": int(t["timeout_sec"] * 1000),
            "timed_out": True,
            "parsed_response": {
                "mti": None, "fields": [{"de": 39, "name": "Response Code", "len": 2, "val": "68"}],
                "de39": describe_rc("68"), "validation": None, "complete": True,
                "parse_error": None, "mti_ok": None
            }
        })

    try:
        payload = pack_payload(iso_req, framing=t["framing"], bitmap_fmt=t["bitmap_fmt"], charset=t["charset"], tpdu=t["tpdu"])
    except ValueError as e:
        return jsonify({"status": "error", "message": f"Cannot encode request: {e}"}), 400

    t0 = time.time()
    try:
        raw_resp = tcp_transact(t["ip"], t["port"], payload, timeout=t["timeout_sec"], framing=t["framing"])
        latency_ms = int((time.time() - t0) * 1000)
        resp_iso = unpack_response(raw_resp)
        write_partitioned_log(ch.lower(), f"RESPONSE ({latency_ms}ms): {resp_iso}")
        parsed = parse_iso_details(resp_iso, expected_resp_des, channel=ch, req_mti=req_mti)
        return jsonify({"status": "success", "iso_response": resp_iso, "latency_ms": latency_ms,
                        "parsed_response": parsed, "timed_out": False})
    except socket.timeout:
        latency_ms = int((time.time() - t0) * 1000)
        write_partitioned_log(ch.lower(), f"TIMEOUT ({latency_ms}ms) exceeding {t['timeout_sec']}s")
        return jsonify({
            "status": "success",
            "iso_response": "[SOCKET TIMEOUT - NO RESPONSE FROM SWITCH]",
            "latency_ms": latency_ms,
            "timed_out": True,
            "parsed_response": {
                "mti": None, "fields": [{"de": 39, "name": "Response Code", "len": 2, "val": "68"}],
                "de39": describe_rc("68"), "validation": None, "complete": True,
                "parse_error": None, "mti_ok": None
            }
        })
    except Exception as e:
        write_partitioned_log(ch.lower(), f"TRANSACTION ERROR: {e}")
        return jsonify({"status": "error", "message": f"{type(e).__name__}: {e}"})


@app.route("/api/execute_linked_0420", methods=["POST"])
def api_execute_linked_0420():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    try:
        t = _target_from(data)
    except (TypeError, ValueError) as e:
        return jsonify({"status": "error", "message": f"Invalid target settings: {e}"}), 400
    orig_req_iso = str(data.get("orig_req_iso", "")).strip()
    reason_code = str(data.get("reason_code", "68")).zfill(2)

    orig_mti, orig_fields = parse_raw_iso_dict(orig_req_iso, channel=ch)
    if not orig_mti:
        return jsonify({"status": "error", "message": "Failed to parse original request."}), 400

    de90 = build_de90(orig_mti, orig_fields)
    rev_fields = {k: v for k, v in orig_fields.items() if k not in (14, 35, 52, 55)}
    rev_fields[38] = orig_fields.get(38, "244729")
    rev_fields[39] = reason_code
    rev_fields[90] = de90

    try:
        rev_req_iso = format_iso_dict("0420", rev_fields, channel=ch)
        payload = pack_payload(rev_req_iso, framing=t["framing"], bitmap_fmt=t["bitmap_fmt"], charset=t["charset"], tpdu=t["tpdu"])
    except ValueError as e:
        return jsonify({"status": "error", "message": f"Cannot build reversal: {e}"}), 400

    write_partitioned_log(ch.lower(), f"AUTO-REVERSAL 0420 REQ: {rev_req_iso}")

    t0 = time.time()
    try:
        raw_resp = tcp_transact(t["ip"], t["port"], payload, timeout=t["timeout_sec"], framing=t["framing"])
        latency_ms = int((time.time() - t0) * 1000)
        rev_resp_iso = unpack_response(raw_resp)
        write_partitioned_log(ch.lower(), f"AUTO-REVERSAL 0430 RESP ({latency_ms}ms): {rev_resp_iso}")
        parsed = parse_iso_details(rev_resp_iso, channel=ch, req_mti="0420")
        return jsonify({"status": "success", "de90": de90, "rev_req_iso": rev_req_iso,
                        "rev_resp_iso": rev_resp_iso, "latency_ms": latency_ms, "parsed_response": parsed})
    except socket.timeout:
        write_partitioned_log(ch.lower(), "AUTO-REVERSAL TIMEOUT")
        return jsonify({"status": "error", "message": f"Reversal timed out after {t['timeout_sec']}s (no 0430)."}), 504
    except Exception as e:
        write_partitioned_log(ch.lower(), f"AUTO-REVERSAL ERROR: {e}")
        return jsonify({"status": "error", "message": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/parse_raw", methods=["POST"])
def api_parse_raw():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    details = parse_iso_details(data.get("raw_iso", ""), channel=ch)
    if not details.get("mti"):
        return jsonify({"status": "error", "message": details.get("error") or "Failed to parse raw ISO payload."}), 400
    return jsonify({"status": "success", "mti": details["mti"], "fields": details["fields"],
                    "de39": details["de39"], "complete": details["complete"], "parse_error": details["parse_error"]})


@app.route("/api/rebuild_from_fields", methods=["POST"])
def api_rebuild_from_fields():
    data = request.get_json(force=True) or {}
    mti = str(data.get("mti") or "0200").strip()
    if not (len(mti) == 4 and mti.isdigit()):
        return jsonify({"status": "error", "message": f"Invalid MTI '{mti}'."}), 400
    ch = norm_channel(data.get("channel"))
    try:
        fields = {int(k): v for k, v in (data.get("fields") or {}).items()}
        return jsonify({"status": "success", "raw_iso": format_iso_dict(mti, fields, channel=ch)})
    except (TypeError, ValueError) as e:
        return jsonify({"status": "error", "message": str(e)}), 400


@app.route("/api/transaction/save", methods=["POST"])
def api_transaction_save():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    key = str(data.get("key", "")).strip().lower().replace(" ", "_")
    label = str(data.get("label", "")).strip()
    mti = str(data.get("mti", "0200")).strip()
    proc_code = str(data.get("proc_code", "000000")).strip()
    raw_req = str(data.get("raw_req", "")).strip()
    req_des = [int(x) for x in data.get("req_des_present", []) if str(x).isdigit()]
    resp_des = [int(x) for x in data.get("resp_des_present", []) if str(x).isdigit()]

    if not key or not label:
        return jsonify({"status": "error", "message": "Key and label are required."}), 400

    cfg = load_config(ch)
    samples = cfg.setdefault("sample_requests", {})

    if raw_req:
        parsed_mti, parsed_fields = parse_raw_iso_dict(raw_req, channel=ch)
        if parsed_mti:
            mti = parsed_mti
            req_des = sorted(parsed_fields.keys())
            if 3 in parsed_fields:
                proc_code = parsed_fields[3]

    entry = samples.get(key, {})
    entry.update({"label": label, "mti": mti, "proc_code": proc_code,
                  "req_des_present": sorted(set(req_des)), "resp_des_present": sorted(set(resp_des))})
    samples[key] = entry  # keeps base_tx if the transaction already had one

    save_config(cfg, ch)
    return jsonify({"status": "success", "message": f"Transaction '{label}' saved to {ch}."})


@app.route("/api/transaction/delete", methods=["POST"])
def api_transaction_delete():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    key = str(data.get("key", "")).strip()

    cfg = load_config(ch)
    samples = cfg.get("sample_requests", {})
    if key in samples:
        del samples[key]
        save_config(cfg, ch)
        return jsonify({"status": "success", "message": f"Transaction '{key}' deleted from {ch}."})
    return jsonify({"status": "error", "message": f"Transaction '{key}' not found in {ch}."}), 404


# ==============================================================
# END-TO-END TEST SUITE ROUTES (per-channel catalogs)
# ==============================================================

def _catalog_response(ch):
    cat = load_catalog(BASE_DIR, ch)
    return {"status": "success", "catalog": cat, "categories": CATEGORIES,
            "file": os.path.basename(catalog_path(BASE_DIR, ch))}


@app.route("/api/suite/catalog", methods=["GET"])
def api_suite_catalog():
    try:
        return jsonify(_catalog_response(norm_channel(request.args.get("channel"))))
    except Exception as e:
        return jsonify({"status": "error", "message": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/suite/testcase/save", methods=["POST"])
def api_suite_testcase_save():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    tc = data.get("testcase")
    original_id = data.get("original_id")
    cat = load_catalog(BASE_DIR, ch)

    errors = validate_testcase(tc, cat.get("profiles"))
    if not errors:
        tc["id"] = str(tc["id"]).strip()
        for st in tc.get("steps", []):
            if st.get("tx") and resolve_tx(st["tx"], load_config(ch), CHANNEL_DEFAULT_CONFIGS[ch]) is None:
                errors.append(f"transaction '{st['tx']}' does not exist in the {ch} config.")
        clash = [t for t in cat["testcases"] if t.get("id") == tc["id"] and t.get("id") != original_id]
        if clash:
            errors.append(f"id '{tc['id']}' is already used by another test case.")
    if errors:
        return jsonify({"status": "error", "message": "Validation failed", "errors": errors}), 400

    replaced = False
    if original_id:
        for i, t in enumerate(cat["testcases"]):
            if t.get("id") == original_id:
                cat["testcases"][i] = tc
                replaced = True
                break
    if not replaced:
        cat["testcases"].append(tc)
    save_catalog(BASE_DIR, ch, cat)
    return jsonify({"status": "success", "message": f"Test case {tc['id']} saved to {ch}."})


@app.route("/api/suite/testcase/delete", methods=["POST"])
def api_suite_testcase_delete():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    tc_id = str(data.get("id", ""))
    cat = load_catalog(BASE_DIR, ch)
    before = len(cat["testcases"])
    cat["testcases"] = [t for t in cat["testcases"] if t.get("id") != tc_id]
    if len(cat["testcases"]) == before:
        return jsonify({"status": "error", "message": f"Test case {tc_id} not found in {ch}."}), 404
    save_catalog(BASE_DIR, ch, cat)
    return jsonify({"status": "success", "message": f"Test case {tc_id} deleted."})


@app.route("/api/suite/profiles/save", methods=["POST"])
def api_suite_profiles_save():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    profiles = data.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        return jsonify({"status": "error", "message": "profiles must be a non-empty object."}), 400
    for k, p in profiles.items():
        if not isinstance(p, dict) or "account" not in p or "card" not in p:
            return jsonify({"status": "error", "message": f"profile '{k}' needs 'account' and 'card'."}), 400
        exp = str(p.get("expiry", "") or "")
        if exp and (len(exp) != 4 or not exp.isdigit()):
            return jsonify({"status": "error", "message": f"profile '{k}': expiry must be YYMM (4 digits)."}), 400
    cat = load_catalog(BASE_DIR, ch)
    cat["profiles"] = profiles
    save_catalog(BASE_DIR, ch, cat)
    return jsonify({"status": "success"})


@app.route("/api/suite/settings/save", methods=["POST"])
def api_suite_settings_save():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    settings = data.get("settings")
    errors = []
    if not isinstance(settings, dict):
        errors.append("settings must be a JSON object.")
    else:
        rule = settings.get("direction_rule")
        if rule is not None and not isinstance(rule, dict):
            errors.append("direction_rule must be an object.")
        elif rule and rule.get("enabled"):
            try:
                de = int(rule.get("de"))
                if not get_field_def(de, get_field_defs(ch)):
                    errors.append(f"direction_rule.de {de} has no field definition.")
            except (TypeError, ValueError):
                errors.append("direction_rule.de must be a DE number.")
        echo = settings.get("default_echo_des", [])
        if not isinstance(echo, list) or not all(str(x).isdigit() for x in echo):
            errors.append("default_echo_des must be a list of DE numbers.")
        if settings.get("des_check", "strict") not in ("strict", "info"):
            errors.append("des_check must be 'strict' or 'info'.")
        try:
            int(settings.get("step_delay_ms", 0) or 0)
        except (TypeError, ValueError):
            errors.append("step_delay_ms must be a number.")
    if errors:
        return jsonify({"status": "error", "message": "Validation failed", "errors": errors}), 400
    cat = load_catalog(BASE_DIR, ch)
    cat["settings"] = settings
    save_catalog(BASE_DIR, ch, cat)
    return jsonify({"status": "success"})


@app.route("/api/suite/reset", methods=["POST"])
def api_suite_reset():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    mode = data.get("mode", "merge")
    if mode == "reset":
        save_catalog(BASE_DIR, ch, default_catalog(ch))
        return jsonify({"status": "success", "message": f"{ch} catalog reset to defaults."})
    added = merge_defaults(BASE_DIR, ch)
    return jsonify({"status": "success", "message": f"{added} missing default test case(s) added to {ch}."})


@app.route("/api/suite/run_case", methods=["POST"])
def api_suite_run_case():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    try:
        t = _target_from(data)
    except (TypeError, ValueError) as e:
        return jsonify({"status": "error", "message": f"Invalid target settings: {e}"}), 400
    if not t["ip"] or not t["port"]:
        return jsonify({"status": "error", "message": "Target IP and Port are required."}), 400

    cat = load_catalog(BASE_DIR, ch)
    if isinstance(data.get("profiles"), dict) and data["profiles"]:
        cat["profiles"] = data["profiles"]       # unsaved edits from the screen
    tc = next((x for x in cat["testcases"] if x.get("id") == data.get("id")), None)
    if tc is None:
        return jsonify({"status": "error", "message": f"Test case {data.get('id')} not found in {ch}."}), 404

    try:
        result = run_testcase(tc, ch, t, cat, load_config(ch), CHANNEL_DEFAULT_CONFIGS[ch], get_field_defs(ch),
                              log_fn=lambda entry: write_partitioned_log(ch.lower(), entry))
    except Exception as e:
        write_partitioned_log(ch.lower(), f"SUITE {tc.get('id')} ERROR: {e}")
        return jsonify({"status": "error", "message": f"{type(e).__name__}: {e}"}), 500
    write_partitioned_log(ch.lower(), f"SUITE {tc.get('id')} VERDICT: {result['verdict']} ({result['pass_steps']}/{result['total_steps']})")
    return jsonify({"status": "success", "result": result})


@app.route("/api/suite/reset_mock", methods=["POST"])
def api_suite_reset_mock():
    data = request.get_json(force=True) or {}
    ch = norm_channel(data.get("channel"))
    try:
        t = _target_from(data)
        iso = format_iso_dict("0800", {7: datetime.now().strftime("%m%d%H%M%S"), 11: f"{random.randint(0, 999999):06d}", 70: "999"}, ch)
        payload = pack_payload(iso, framing=t["framing"], bitmap_fmt=t["bitmap_fmt"], charset=t["charset"], tpdu=t["tpdu"])
        raw = tcp_transact(t["ip"], t["port"], payload, timeout=t["timeout_sec"], framing=t["framing"])
        r = parse_iso_ex(unpack_response(raw))
        rc = r["fields"].get(39)
        if rc != "00":
            return jsonify({"status": "error", "message": f"Target answered RC {rc} - it is probably not the mock CBS."})
        return jsonify({"status": "success", "message": "Mock CBS state reset."})
    except Exception as e:
        return jsonify({"status": "error", "message": f"{type(e).__name__}: {e}"})


if __name__ == "__main__":
    segregate_and_sync_all_configs()
    app.run(host="0.0.0.0", port=5000, debug=False)
