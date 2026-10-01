"""
testcase_catalog.py - End-to-end (Switch <-> CBS) test case catalogs per channel
===============================================================================
Each channel keeps its own catalog file next to the app:
    atm_testcases.json   (ATM issuer + POS + E-Commerce)
    upi_testcases.json
    imps_testcases.json

A catalog file contains:
    settings   - channel-level behaviour (credit/debit tag, default echo DEs, DE check mode)
    profiles   - test accounts / cards (DE 2, DE 102, card expiry)
    testcases  - list of multi-step test cases

Test case schema (all keys optional unless marked *):
{
  "id"*: "ATM_POS_001", "category"*: "Positive", "priority": "P1", "enabled": true,
  "name"*: "...", "description": "...", "expected_result": "...",
  "profile": "standard",
  "steps"*: [
    {
      "label": "Cash withdrawal",
      "tx": "issuer_cash_withdrawal",        # transaction key in the channel config
      "mti": "0200", "proc_code": "011000",  # override / or define a step without tx
      "des": [7, 11, 70],                    # explicit DE list when no tx is used
      "amount": "500.00",                    # rupees (dot) or raw n12
      "profile": "closed",                   # per-step profile override
      "direction": "DR" | "CR",              # adds the credit/debit tag from settings
      "set": {"18": "5411"},                 # DE value overrides; tokens: {step1.37} {step1.resp.38}
      "add": [46], "remove": [4],            # add / remove DEs from the list
      "link": {"type": "reversal" | "repeat_reversal" | "duplicate" | "same_rrn",
               "step": 2, "reason": "68", "amount": "600.00", "partial_amount": "200.00"},
      "tamper": [{"op": "llvar_len", "de": 2, "value": "99"},
                 {"op": "truncate", "chars": 20}, {"op": "append", "value": "XYZ"},
                 {"op": "bitmap_set", "de": 5}, {"op": "bitmap_clear", "de": 4},
                 {"op": "replace", "value": "<raw iso>"}],
      "timeout_sec": 2, "wait_ms": 0,
      "expect": {
        "rc": ["00"],                 # accepted DE 39 values
        "mti": "0210" | null,         # default = request MTI + 10; null = don't check
        "timeout": true,              # expect NO response (switch-side timeout)
        "allow_no_response": true,    # PASS if nothing comes back
        "des": [..], "present": [..], "absent": [..],
        "echo": [2, 3, 4, 11, 37],    # DEs that must come back unchanged
        "regex": {"54": "^...$"},
        "balance": {"from_step": 1, "delta": "-500.00"}   # DE 54 available balance movement
      }
    }
  ]
}
"""

import copy
import json
import os

CATEGORIES = [
    "Network Management",
    "Positive",
    "Negative - Account",
    "Negative - Card",
    "Boundary",
    "Reversal",
    "Duplicate",
    "Security / Format",
    "Timeout / Fault",
]

LINK_TYPES = ("reversal", "repeat_reversal", "duplicate", "same_rrn")
TAMPER_OPS = ("llvar_len", "truncate", "append", "bitmap_set", "bitmap_clear", "replace")

# Response-code groups (ISO codes as mapped in NFS Response Code_Banks.pdf)
OK = ["00"]
INVALID_ACC = ["52", "53", "39", "42", "14"]        # NFS 12 / 09 - invalid account
FREEZE = ["62", "57", "05"]                          # restricted / not permitted / do not honour
DORMANT = ["57", "62", "05"]
NSF = ["51"]                                         # NFS 24
LIMIT = ["61"]                                       # NFS 14
FREQ = ["65", "61"]                                  # NFS 15
INV_AMT = ["13"]                                     # NFS 06
FORMAT = ["30"]                                      # NFS 18
INV_TXN = ["12", "40"]                               # NFS 01 / 13
DUP = ["94"]                                         # NFS 38
BAL54 = r"^(\d{2}\d{2}\d{3}[CD]\d{12})+$"


def S(**kw):
    """Step builder - drops None values."""
    return {k: v for k, v in kw.items() if v is not None}


def E(rc=None, **kw):
    d = {"rc": list(rc) if rc is not None else None}
    d.update(kw)
    return {k: v for k, v in d.items() if v is not None}


def TC(id, category, name, steps, profile="standard", priority="P1", description="", expected_result="", enabled=True):
    return {"id": id, "category": category, "priority": priority, "enabled": enabled, "name": name,
            "description": description, "expected_result": expected_result, "profile": profile, "steps": steps}


def bal_step(tx, label="Balance enquiry", profile=None, **expect):
    return S(label=label, tx=tx, profile=profile, expect=E(OK, present=[54], **expect))


def rev_step(of, label="Reversal 0420", reason="68", amount=None, partial=None, rc=OK, mti_type="reversal", **expect):
    link = {"type": mti_type, "step": of, "reason": reason}
    if amount:
        link["amount"] = amount
    if partial:
        link["partial_amount"] = partial
    return S(label=label, link=link, expect=E(rc, **expect))


def network_cases(prefix):
    nw = "Network Management"
    def nstep(code, rc=OK):
        return [S(label=f"0800 DE70={code}", mti="0800", des=[7, 11, 70], set={"70": code},
                  expect=E(rc, echo=[7, 11, 70]))]
    return [
        TC(f"{prefix}_NW_001", nw, "Sign-On (0800 / DE 70 = 001)", nstep("001"), priority="P1",
           description="Switch signs on to CBS.", expected_result="0810 with DE 39 = 00; DE 7/11/70 echoed."),
        TC(f"{prefix}_NW_002", nw, "Echo Test (0800 / DE 70 = 301)", nstep("301"), priority="P1",
           description="Heartbeat between switch and CBS.", expected_result="0810 with DE 39 = 00."),
        TC(f"{prefix}_NW_003", nw, "Key Exchange (0800 / DE 70 = 101)", nstep("101"), priority="P2",
           description="Working-key exchange request.", expected_result="0810 with DE 39 = 00."),
        TC(f"{prefix}_NW_004", nw, "Cut-Over (0800 / DE 70 = 201)", nstep("201"), priority="P2",
           description="Business-day cut-over notification.", expected_result="0810 with DE 39 = 00."),
        TC(f"{prefix}_NW_005", nw, "Sign-Off (0800 / DE 70 = 002)", nstep("002"), priority="P2",
           description="Switch signs off from CBS.", expected_result="0810 with DE 39 = 00."),
        TC(f"{prefix}_NW_006", nw, "Invalid Network Code (DE 70 = 555)", nstep("555", ["12", "30"]), priority="P3",
           description="Unsupported network management code.", expected_result="0810 declined with 12 / 30."),
    ]


# ============================================================================
# ATM (Issuer ATM + POS + E-Commerce)
# ============================================================================
ATM_PROFILES = {
    "standard": {"title": "Active / Funded Account", "card": "6072930130054479", "account": "101303130001356", "expiry": "2907",
                 "desc": "Active savings account with ample balance."},
    "closed": {"title": "Closed Account", "card": "6072930130011800", "account": "0020001010011800", "expiry": "2907",
               "desc": "Account closed in CBS."},
    "total_freeze": {"title": "Total Freeze Account", "card": "6072930130011663", "account": "0020001010011663", "expiry": "2907",
                     "desc": "Debit and credit freeze."},
    "debit_freeze": {"title": "Debit Freeze Account", "card": "6072930130011664", "account": "0020001010011664", "expiry": "2907",
                     "desc": "Debits blocked, credits allowed."},
    "dormant": {"title": "Dormant / Inoperative Account", "card": "6072930130011700", "account": "0020001010011700", "expiry": "2907",
                "desc": "No customer-induced debit permitted."},
    "min_balance": {"title": "Min Balance Account (bal 1500, min 1000)", "card": "6072930130010463", "account": "0020001010010463", "expiry": "2907",
                    "desc": "Only 500.00 withdrawable above the minimum balance."},
    "low_funds": {"title": "Low Funds Account (bal 100.00)", "card": "6072930130010999", "account": "0020001010010999", "expiry": "2907",
                  "desc": "Insufficient for normal withdrawals."},
    "frequency": {"title": "Frequency Limit Account (3/day)", "card": "6072930130012000", "account": "0020001010012000", "expiry": "2907",
                  "desc": "Daily withdrawal count limit = 3."},
    "not_found": {"title": "Account Not in CBS", "card": "6072930130000000", "account": "0020009999999999", "expiry": "2907",
                  "desc": "Card linked to an account that does not exist."},
    "expired_card": {"title": "Expired Card", "card": "6072930130099990", "account": "101303130001356", "expiry": "2201",
                     "desc": "Card expiry (Track 2 / DE 14) in the past."},
    "lost_card": {"title": "Lost Card", "card": "6072930130041000", "account": "101303130001356", "expiry": "2907",
                  "desc": "Card hot-listed as lost."},
    "stolen_card": {"title": "Stolen Card", "card": "6072930130043000", "account": "101303130001356", "expiry": "2907",
                    "desc": "Card hot-listed as stolen."},
    "restricted_card": {"title": "Restricted / Hotlisted Card", "card": "6072930130062000", "account": "101303130001356", "expiry": "2907",
                        "desc": "Card blocked by bank."},
    "unknown_card": {"title": "Unknown Card (valid BIN)", "card": "6072930199999999", "account": "101303130001356", "expiry": "2907",
                     "desc": "BIN is ours but card is not issued."},
    "invalid_bin": {"title": "Invalid / Unallocated BIN", "card": "9999990000000001", "account": "101303130001356", "expiry": "2907",
                    "desc": "BIN not issued by the bank."},
    "mismatch": {"title": "Card / Account Mismatch (Tampering)", "card": "6072930130054479", "account": "0020001010000069", "expiry": "2907",
                 "desc": "Valid card but DE 102 belongs to another customer."},
    "sql_injection": {"title": "Injection String in DE 102", "card": "6072930130054479", "account": "101303130001356' OR '1'='1", "expiry": "2907",
                      "desc": "Malicious characters in account field."},
}


def atm_cases():
    CW, BE, MS, POS, ECOM = "issuer_cash_withdrawal", "balance_inquiry", "mini_statement", "pos_purchase", "ecom_purchase"
    POS_SET = {"18": "5411", "41": "EP025109"}
    ECOM_SET = {"18": "5814", "41": "70016942"}
    P, NA, NC, BD, RV, DP, SC, TF = ("Positive", "Negative - Account", "Negative - Card", "Boundary",
                                     "Reversal", "Duplicate", "Security / Format", "Timeout / Fault")
    cases = network_cases("ATM")

    def cw(amount="500.00", rc=OK, label="Cash withdrawal", profile=None, **ex):
        return S(label=label, tx=CW, amount=amount, profile=profile, expect=E(rc, **ex))

    # ---------------- Positive ----------------
    cases += [
        TC("ATM_POS_001", P, "Cash Withdrawal - Approved with Balance Debit Verification", [
            bal_step(BE, "Opening balance"),
            cw("500.00", balance={"from_step": 1, "delta": "-500.00"}),
            rev_step(2, "Cleanup reversal", balance={"from_step": 1, "delta": "0.00"}),
        ], description="Withdraw 500.00 and verify the account is debited by exactly 500.00 in DE 54.",
           expected_result="0210 RC 00; available balance reduced by 500.00; DE 2/3/4/11/37/102 echoed."),
        TC("ATM_POS_002", P, "Balance Enquiry - Approved with DE 54", [
            S(label="Balance enquiry", tx=BE, amount="0.00", expect=E(OK, present=[54], absent=[48], regex={"54": BAL54})),
        ], description="Balance enquiry returns ledger and available balances.",
           expected_result="0210 RC 00; DE 54 well-formed (ledger 01 + available 02)."),
        TC("ATM_POS_003", P, "Mini Statement - Approved with DE 63", [
            S(label="Mini statement", tx=MS, amount="0.00", expect=E(OK, present=[54, 63], absent=[48])),
        ], description="Mini statement returns statement lines in DE 63.",
           expected_result="0210 RC 00; DE 63 statement + DE 54 balances."),
        TC("ATM_POS_004", P, "POS Purchase - Approved with Balance Debit", [
            bal_step(BE, "Opening balance"),
            S(label="POS purchase", tx=POS, amount="2500.00", set=POS_SET,
              expect=E(OK, present=[48, 54], balance={"from_step": 1, "delta": "-2500.00"})),
            rev_step(2, "Cleanup POS reversal", balance={"from_step": 1, "delta": "0.00"}),
        ], description="Card-present POS purchase debits the account.",
           expected_result="0210 RC 00; DE 48 retained; balance reduced by 2500.00."),
        TC("ATM_POS_005", P, "E-Commerce Purchase - Approved with Balance Debit", [
            bal_step(BE, "Opening balance"),
            S(label="E-com purchase", tx=ECOM, amount="1500.00", set=ECOM_SET,
              expect=E(OK, present=[14, 54], balance={"from_step": 1, "delta": "-1500.00"})),
            rev_step(2, "Cleanup e-com reversal", rc=["00", "09"], balance={"from_step": 1, "delta": "0.00"}),
        ], description="Card-not-present purchase (DE 22 = 810, DE 25 = 59).",
           expected_result="0210 RC 00; balance reduced by 1500.00; reversal 00 / 09 (in progress)."),
        TC("ATM_POS_006", P, "Cash Withdrawal with Fee in DE 46 (Over Quota)", [
            bal_step(BE, "Opening balance"),
            S(label="Cash withdrawal with DE 46", tx=CW, amount="500.00", set={"46": "ICH356D000000002100"},
              expect=E(OK, present=[46, 54], balance={"from_step": 1, "delta": "-500.00"})),
            rev_step(2, "Cleanup reversal", balance={"from_step": 1, "delta": "0.00"}),
        ], priority="P2", description="Interchange fee carried in DE 46 is passed through to CBS.",
           expected_result="0210 RC 00; DE 46 echoed unchanged."),
    ]

    # ---------------- Negative - Account ----------------
    cases += [
        TC("ATM_NA_001", NA, "Closed Account - Cash Withdrawal", [cw(rc=INVALID_ACC)], profile="closed",
           expected_result="Declined with invalid-account code (52/53/39/42/14)."),
        TC("ATM_NA_002", NA, "Closed Account - Balance Enquiry",
           [S(label="Balance enquiry", tx=BE, amount="0.00", expect=E(INVALID_ACC))], profile="closed",
           expected_result="Declined with invalid-account code."),
        TC("ATM_NA_003", NA, "Closed Account - Mini Statement",
           [S(label="Mini statement", tx=MS, amount="0.00", expect=E(INVALID_ACC, absent=[63]))], profile="closed",
           expected_result="Declined; no statement lines (DE 63) returned."),
        TC("ATM_NA_004", NA, "Closed Account - POS Purchase",
           [S(label="POS purchase", tx=POS, amount="2500.00", set=POS_SET, expect=E(INVALID_ACC))], profile="closed",
           expected_result="Declined with invalid-account code."),
        TC("ATM_NA_005", NA, "Total Freeze Account - Cash Withdrawal", [cw(rc=FREEZE)], profile="total_freeze",
           expected_result="Declined 62 / 57 / 05."),
        TC("ATM_NA_006", NA, "Debit Freeze Account - Cash Withdrawal", [cw(rc=FREEZE)], profile="debit_freeze",
           expected_result="Declined 62 / 57 / 05."),
        TC("ATM_NA_007", NA, "Dormant Account - Cash Withdrawal", [cw(rc=DORMANT)], profile="dormant",
           expected_result="Declined 57 / 62 / 05."),
        TC("ATM_NA_008", NA, "Insufficient Funds - No Debit Posted", [
            bal_step(BE, "Opening balance"),
            cw("500.00", rc=NSF),
            bal_step(BE, "Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], profile="low_funds", expected_result="Declined 51; balance unchanged."),
        TC("ATM_NA_009", NA, "Minimum Balance Breach", [
            bal_step(BE, "Opening balance"),
            cw("600.00", rc=NSF),
            bal_step(BE, "Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], profile="min_balance", expected_result="Declined 51 (would breach min balance 1000); balance unchanged."),
        TC("ATM_NA_010", NA, "Account Not Found in CBS", [cw(rc=INVALID_ACC)], profile="not_found",
           expected_result="Declined with invalid-account code."),
    ]

    # ---------------- Negative - Card ----------------
    cases += [
        TC("ATM_NC_001", NC, "Invalid / Unallocated BIN", [cw(rc=["15", "92", "14"])], profile="invalid_bin",
           expected_result="Declined 15 / 92 / 14."),
        TC("ATM_NC_002", NC, "Unknown Card Number (valid BIN)", [cw(rc=["14"])], profile="unknown_card",
           expected_result="Declined 14 (no such card)."),
        TC("ATM_NC_003", NC, "Expired Card - Cash Withdrawal", [cw(rc=["54", "33"])], profile="expired_card",
           expected_result="Declined 54 / 33."),
        TC("ATM_NC_004", NC, "Lost Card", [cw(rc=["41"])], profile="lost_card", expected_result="Declined 41."),
        TC("ATM_NC_005", NC, "Stolen Card", [cw(rc=["43"])], profile="stolen_card", expected_result="Declined 43."),
        TC("ATM_NC_006", NC, "Restricted / Hotlisted Card", [cw(rc=["62", "36"])], profile="restricted_card",
           expected_result="Declined 62 / 36."),
        TC("ATM_NC_007", NC, "Expired Card - E-Commerce (DE 14)",
           [S(label="E-com purchase", tx=ECOM, amount="1500.00", set=ECOM_SET, expect=E(["54", "33"]))],
           profile="expired_card", expected_result="Declined 54 / 33."),
    ]

    # ---------------- Boundary ----------------
    cases += [
        TC("ATM_BD_001", BD, "Zero Amount Withdrawal", [cw("0.00", rc=INV_AMT)], expected_result="Declined 13."),
        TC("ATM_BD_002", BD, "Withdrawal = Per-Transaction Limit (25,000.00)", [
            cw("25000.00"), rev_step(1, "Cleanup reversal"),
        ], expected_result="Approved 00 at the exact limit."),
        TC("ATM_BD_003", BD, "Withdrawal = Limit + 0.01", [cw("25000.01", rc=LIMIT)], expected_result="Declined 61."),
        TC("ATM_BD_004", BD, "Minimum Withdrawal (100.00)", [cw("100.00"), rev_step(1, "Cleanup reversal")],
           priority="P2", expected_result="Approved 00."),
        TC("ATM_BD_005", BD, "Withdraw Exactly Down to Minimum Balance", [
            bal_step(BE, "Opening balance"),
            cw("500.00", balance={"from_step": 1, "delta": "-500.00"}),
            rev_step(2, "Cleanup reversal", balance={"from_step": 1, "delta": "0.00"}),
        ], profile="min_balance", expected_result="Approved 00 (balance lands exactly on 1000.00)."),
        TC("ATM_BD_006", BD, "Withdraw 0.01 Below Minimum Balance", [cw("500.01", rc=NSF)], profile="min_balance",
           expected_result="Declined 51."),
        TC("ATM_BD_007", BD, "Maximum Field Value (9,999,999,999.99)", [cw("9999999999.99", rc=["61", "13"])],
           priority="P2", expected_result="Declined 61 / 13."),
        TC("ATM_BD_008", BD, "Daily Frequency Limit (4th Withdrawal)", [
            cw("100.00", label="Withdrawal 1"), cw("100.00", label="Withdrawal 2"), cw("100.00", label="Withdrawal 3"),
            cw("100.00", rc=FREQ, label="Withdrawal 4 (over limit)"),
            rev_step(1, "Cleanup reversal 1"), rev_step(2, "Cleanup reversal 2"), rev_step(3, "Cleanup reversal 3"),
        ], profile="frequency", expected_result="First three approved; fourth declined 65."),
        TC("ATM_BD_009", BD, "Non-Numeric Amount (DE 4)", [cw("00000000ABCD", rc=["13", "30"])],
           expected_result="Declined 13 / 30."),
    ]

    # ---------------- Reversal ----------------
    cases += [
        TC("ATM_RV_001", RV, "Full Reversal (Timeout, Reason 68) Restores Balance", [
            bal_step(BE, "Opening balance"),
            cw("1000.00", balance={"from_step": 1, "delta": "-1000.00"}),
            rev_step(2, reason="68", balance={"from_step": 1, "delta": "0.00"}, present=[90]),
        ], expected_result="0430 RC 00; DE 90 echoed; balance fully restored."),
        TC("ATM_RV_002", RV, "Partial Reversal (DE 95: 200.00 dispensed of 500.00)", [
            bal_step(BE, "Opening balance"),
            cw("500.00", balance={"from_step": 1, "delta": "-500.00"}),
            rev_step(2, "Partial reversal", reason="32", partial="200.00", rc=["00", "32"]),
            bal_step(BE, "Closing balance", balance={"from_step": 1, "delta": "-200.00"}),
        ], description="Note: 200.00 stays debited (dispensed).", expected_result="0430 RC 00 / 32; net debit 200.00."),
        TC("ATM_RV_003", RV, "Reversal Without Original Transaction", [
            bal_step(BE, "Opening balance"),
            S(label="Unmatched 0420", tx="issuer_reversal", amount="500.00", expect=E(["25", "21", "00"])),
            bal_step(BE, "Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], expected_result="Acknowledged / declined (25 / 21 / 00) with NO credit to the account."),
        TC("ATM_RV_004", RV, "Duplicate Reversal (Same 0420 Twice)", [
            bal_step(BE, "Opening balance"),
            cw("500.00"),
            rev_step(2, "First reversal"),
            S(label="Duplicate 0420", link={"type": "duplicate", "step": 3}, expect=E(["94", "00"])),
            bal_step(BE, "Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], expected_result="Second reversal 94 / 00; account credited only once."),
        TC("ATM_RV_005", RV, "Repeat Reversal Advice (0421)", [
            bal_step(BE, "Opening balance"),
            cw("500.00"),
            rev_step(2, "Original reversal 0420"),
            rev_step(2, "Repeat reversal 0421", mti_type="repeat_reversal"),
            bal_step(BE, "Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], expected_result="0421 acknowledged 00; no double credit."),
        TC("ATM_RV_006", RV, "Reversal Amount Mismatch", [
            bal_step(BE, "Opening balance"),
            cw("500.00"),
            rev_step(2, "Reversal with wrong amount 600.00", amount="600.00", rc=["13", "12", "30"]),
            bal_step(BE, "Balance after bad reversal", balance={"from_step": 1, "delta": "-500.00"}),
            rev_step(2, "Cleanup reversal (correct amount)", balance={"from_step": 1, "delta": "0.00"}),
        ], expected_result="Mismatched reversal rejected; no credit until the correct reversal."),
        TC("ATM_RV_007", RV, "Reversal of a Declined Transaction", [
            bal_step(BE, "Opening balance"),
            cw("500.00", rc=NSF),
            rev_step(2, "Reversal of declined txn", rc=["21", "00", "25"]),
            bal_step(BE, "Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], profile="low_funds", expected_result="21 / 00 / 25 with NO credit to the account."),
        TC("ATM_RV_008", RV, "POS Reversal Restores Balance", [
            bal_step(BE, "Opening balance"),
            S(label="POS purchase", tx=POS, amount="750.00", set=POS_SET, expect=E(OK)),
            rev_step(2, "POS reversal", reason="68", balance={"from_step": 1, "delta": "0.00"}),
        ], expected_result="0430 RC 00; balance restored."),
    ]

    # ---------------- Duplicate ----------------
    cases += [
        TC("ATM_DP_001", DP, "Duplicate 0200 (Identical Resend)", [
            bal_step(BE, "Opening balance"),
            cw("500.00"),
            S(label="Identical resend", link={"type": "duplicate", "step": 2}, expect=E(DUP)),
            bal_step(BE, "Balance after duplicate", balance={"from_step": 1, "delta": "-500.00"}),
            rev_step(2, "Cleanup reversal"),
        ], expected_result="Resend declined 94; account debited only once."),
        TC("ATM_DP_002", DP, "Same RRN, Different Amount", [
            bal_step(BE, "Opening balance"),
            cw("500.00"),
            S(label="Same RRN, amount 700.00", tx=CW, amount="700.00", link={"type": "same_rrn", "step": 2}, expect=E(DUP)),
            bal_step(BE, "Balance after duplicate", balance={"from_step": 1, "delta": "-500.00"}),
            rev_step(2, "Cleanup reversal"),
        ], expected_result="Declined 94; no second debit."),
    ]

    # ---------------- Security / Format ----------------
    cases += [
        TC("ATM_SC_001", SC, "Missing Mandatory DE 4 (Amount)", [S(label="CW without DE 4", tx=CW, remove=[4], expect=E(["30", "12", "13"]))],
           expected_result="Declined 30 / 12 / 13."),
        TC("ATM_SC_002", SC, "Missing Mandatory DE 37 (RRN)", [S(label="CW without DE 37", tx=CW, remove=[37], expect=E(["30", "12"]))],
           expected_result="Declined 30 / 12."),
        TC("ATM_SC_003", SC, "Missing Mandatory DE 2 (PAN)", [S(label="CW without DE 2", tx=CW, remove=[2], expect=E(["30", "14", "12"]))],
           expected_result="Declined 30 / 14 / 12."),
        TC("ATM_SC_004", SC, "LLVAR Length Tampered (DE 2 prefix = 25)", [
            S(label="Tampered DE 2 length", tx=CW, tamper=[{"op": "llvar_len", "de": 2, "value": "25"}], expect=E(FORMAT, mti=None, allow_no_response=True))],
           expected_result="Format error 30 (or connection dropped) - never approved."),
        TC("ATM_SC_005", SC, "Truncated Message (last 20 chars cut)", [
            S(label="Truncated message", tx=CW, tamper=[{"op": "truncate", "chars": 20}], expect=E(FORMAT, mti=None, allow_no_response=True))],
           expected_result="Format error 30 - never approved."),
        TC("ATM_SC_006", SC, "Bitmap Bit Set Without Data (DE 5)", [
            S(label="Extra bitmap bit", tx=CW, tamper=[{"op": "bitmap_set", "de": 5}], expect=E(FORMAT, mti=None, allow_no_response=True))],
           expected_result="Format error 30."),
        TC("ATM_SC_007", SC, "Trailing Garbage After Last DE", [
            S(label="Trailing bytes", tx=CW, tamper=[{"op": "append", "value": "GARBAGE123"}], expect=E(FORMAT, mti=None, allow_no_response=True))],
           expected_result="Format error 30."),
        TC("ATM_SC_008", SC, "Card / Account Mismatch (Parameter Tampering)", [cw(rc=["57", "14", "12", "05", "52"])], profile="mismatch",
           description="DE 2 belongs to customer A but DE 102 is customer B's account.",
           expected_result="Declined - must never debit another customer's account."),
        TC("ATM_SC_009", SC, "Injection String in DE 102", [cw(rc=["57", "14", "52", "53", "30", "12"])], profile="sql_injection",
           expected_result="Declined safely; CBS stays up."),
        TC("ATM_SC_010", SC, "Non-Numeric Processing Code (DE 3)", [S(label="DE 3 = 01A000", tx=CW, proc_code="01A000", expect=E(["12", "30"]))],
           expected_result="Declined 12 / 30."),
        TC("ATM_SC_011", SC, "Unsupported Processing Code (990000)", [S(label="DE 3 = 990000", tx=CW, proc_code="990000", expect=E(INV_TXN))],
           expected_result="Declined 12 / 40."),
        TC("ATM_SC_012", SC, "Foreign Currency (DE 49 = 840)", [S(label="DE 49 = 840", tx=CW, set={"49": "840"}, expect=E(["12", "30", "57"]))],
           expected_result="Declined 12 / 30 / 57."),
        TC("ATM_SC_013", SC, "Unsupported MTI (0300)", [S(label="MTI 0300", tx=CW, mti="0300", expect=E(["12", "30"], mti=None, allow_no_response=True))],
           priority="P2", expected_result="Rejected (12 / 30) or ignored - never approved."),
        TC("ATM_SC_014", SC, "Negative / Signed Amount", [cw("-00000050000", rc=["13", "30"])], expected_result="Declined 13 / 30."),
    ]

    # ---------------- Timeout / Fault ----------------
    cases += [
        TC("ATM_TF_001", TF, "CBS Late Response -> Switch Timeout -> Auto Reversal", [
            bal_step(BE, "Opening balance"),
            S(label="CW (CBS answers late)", tx=CW, amount="68.00", timeout_sec=2, expect=E(None, timeout=True)),
            rev_step(2, "Timeout reversal (68)", reason="68", rc=["00", "21", "25"]),
            bal_step(BE, "Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], description="Mock CBS: amount 68.00 posts then answers after 5 s. Real CBS: needs delay injection.",
           expected_result="Switch times out, reverses; account not debited in the end."),
        TC("ATM_TF_002", TF, "CBS Drops Connection -> Reversal", [
            bal_step(BE, "Opening balance"),
            S(label="CW (CBS drops)", tx=CW, amount="91.00", timeout_sec=3, expect=E(None, timeout=True)),
            rev_step(2, "Reversal after no response", reason="68", rc=["00", "21", "25"]),
            bal_step(BE, "Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], description="Mock CBS: amount 91.00 posts then closes the socket.",
           expected_result="No response; reversal restores the account."),
        TC("ATM_TF_003", TF, "CBS System Malfunction (96) -> Reversal", [
            bal_step(BE, "Opening balance"),
            S(label="CW (CBS returns 96)", tx=CW, amount="96.00", expect=E(["96", "91"])),
            rev_step(2, "Reversal after 96", reason="68", rc=["21", "00", "25"]),
            bal_step(BE, "Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], description="Mock CBS: amount 96.00 returns 96 without posting.",
           expected_result="96 / 91 then reversal; balance unchanged."),
    ]
    return cases


# ============================================================================
# UPI / IMPS (shared flow, channel-specific keys and limits)
# ============================================================================
def account_profiles(pan):
    def p(title, account, desc):
        return {"title": title, "card": pan, "account": account, "expiry": "2907", "desc": desc}
    return {
        "standard": p("Active / Funded Account", "0020001010000069", "Active savings account with ample balance."),
        "closed": p("Closed Account", "0020001010011800", "Account closed in CBS."),
        "total_freeze": p("Total Freeze Account", "0020001010011663", "Debit and credit freeze."),
        "debit_freeze": p("Debit Freeze Account", "0020001010011664", "Debits blocked, credits allowed."),
        "credit_freeze": p("Credit Freeze Account", "0020001010011665", "Credits blocked, debits allowed."),
        "dormant": p("Dormant / Inoperative Account", "0020001010011700", "No customer-induced debit permitted."),
        "low_funds": p("Low Funds Account (bal 100.00)", "0020001010010999", "Insufficient for normal debits."),
        "frequency": p("Frequency Limit Account (3/day)", "0020001010012000", "Daily debit count limit = 3."),
        "not_found": p("Account Not in CBS", "0020009999999999", "Account does not exist."),
        "sql_injection": p("Injection String in DE 102", "0020001010000069' OR '1'='1", "Malicious characters in account field."),
    }


def payment_cases(ch, limit, keys):
    LIST, BE, IN, OUT, REV = keys["list"], keys["bal"], keys["inward"], keys["outward"], keys["reversal"]
    P, NA, BD, RV, DP, SC, TF = ("Positive", "Negative - Account", "Boundary", "Reversal", "Duplicate",
                                 "Security / Format", "Timeout / Fault")
    over = f"{float(limit) + 0.01:.2f}"
    cases = network_cases(ch)

    def out(amount="1000.00", rc=OK, label="Outward debit", profile=None, **ex):
        return S(label=label, tx=OUT, amount=amount, direction="DR", profile=profile, expect=E(rc, **ex))

    def inw(amount="1000.00", rc=OK, label="Inward credit", profile=None, **ex):
        return S(label=label, tx=IN, amount=amount, direction="CR", profile=profile, expect=E(rc, **ex))

    def bal(label="Balance enquiry", **ex):
        return S(label=label, tx=BE, amount="0.00", expect=E(OK, present=[54], **ex))

    n = ch
    cases += [
        TC(f"{n}_POS_001", P, f"{n} List Account / Account Verification", [
            S(label="List account", tx=LIST, expect=E(OK, present=[102]))],
           expected_result="0210 RC 00; DE 102 echoed."),
        TC(f"{n}_POS_002", P, f"{n} Balance Enquiry with DE 54", [bal(regex={"54": BAL54})],
           expected_result="0210 RC 00; DE 54 well-formed."),
        TC(f"{n}_POS_003", P, f"{n} Outward Pay (Debit) - Balance Debited", [
            bal("Opening balance"),
            out("1000.00", balance={"from_step": 1, "delta": "-1000.00"}),
            rev_step(2, "Cleanup reversal", balance={"from_step": 1, "delta": "0.00"}),
        ], expected_result="0210 RC 00; balance reduced by 1000.00."),
        TC(f"{n}_POS_004", P, f"{n} Inward Pay (Credit) - Balance Credited", [
            bal("Opening balance"),
            inw("1000.00", balance={"from_step": 1, "delta": "1000.00"}),
            rev_step(2, "Cleanup reversal (credit)", balance={"from_step": 1, "delta": "0.00"}),
        ], expected_result="0210 RC 00; balance increased by 1000.00."),
        TC(f"{n}_POS_005", P, f"{n} Outward then Inward (Round Trip)", [
            bal("Opening balance"),
            out("250.00"),
            inw("250.00", balance={"from_step": 1, "delta": "0.00"}),
        ], priority="P2", expected_result="Both approved; net balance unchanged."),
    ]

    cases += [
        TC(f"{n}_NA_001", NA, "Closed Account - List Account", [S(label="List account", tx=LIST, expect=E(INVALID_ACC))],
           profile="closed", expected_result="Declined with invalid-account code."),
        TC(f"{n}_NA_002", NA, "Closed Account - Outward Debit", [out(rc=INVALID_ACC)], profile="closed",
           expected_result="Declined with invalid-account code."),
        TC(f"{n}_NA_003", NA, "Closed Account - Inward Credit", [inw(rc=INVALID_ACC)], profile="closed",
           expected_result="Credit to closed account rejected."),
        TC(f"{n}_NA_004", NA, "Account Not Found - Outward Debit", [out(rc=INVALID_ACC)], profile="not_found",
           expected_result="Declined with invalid-account code."),
        TC(f"{n}_NA_005", NA, "Beneficiary Not Found - Inward Credit", [inw(rc=INVALID_ACC)], profile="not_found",
           expected_result="Declined with invalid-account code."),
        TC(f"{n}_NA_006", NA, "Total Freeze - Outward Debit", [out(rc=FREEZE)], profile="total_freeze",
           expected_result="Declined 62 / 57 / 05."),
        TC(f"{n}_NA_007", NA, "Total Freeze - Inward Credit", [inw(rc=FREEZE)], profile="total_freeze",
           expected_result="Declined 62 / 57 / 05."),
        TC(f"{n}_NA_008", NA, "Debit Freeze - Outward Debit Blocked", [out(rc=FREEZE)], profile="debit_freeze",
           expected_result="Declined 62 / 57 / 05."),
        TC(f"{n}_NA_009", NA, "Debit Freeze - Inward Credit Allowed", [inw("100.00"), rev_step(1, "Cleanup reversal")],
           profile="debit_freeze", expected_result="Credit approved 00."),
        TC(f"{n}_NA_010", NA, "Credit Freeze - Inward Credit Blocked", [inw(rc=FREEZE)], profile="credit_freeze",
           expected_result="Declined 62 / 57 / 05."),
        TC(f"{n}_NA_011", NA, "Credit Freeze - Outward Debit Allowed", [out("100.00"), rev_step(1, "Cleanup reversal")],
           profile="credit_freeze", expected_result="Debit approved 00."),
        TC(f"{n}_NA_012", NA, "Dormant Account - Outward Debit", [out(rc=DORMANT)], profile="dormant",
           expected_result="Declined 57 / 62 / 05."),
        TC(f"{n}_NA_013", NA, "Insufficient Funds - No Debit Posted", [
            bal("Opening balance"), out("500.00", rc=NSF), bal("Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], profile="low_funds", expected_result="Declined 51; balance unchanged."),
    ]

    cases += [
        TC(f"{n}_BD_001", BD, "Zero Amount Debit", [out("0.00", rc=INV_AMT)], expected_result="Declined 13."),
        TC(f"{n}_BD_002", BD, f"Debit = Per-Transaction Limit ({limit})", [out(limit), rev_step(1, "Cleanup reversal")],
           expected_result="Approved 00 at the exact limit."),
        TC(f"{n}_BD_003", BD, f"Debit = Limit + 0.01 ({over})", [out(over, rc=LIMIT)], expected_result="Declined 61."),
        TC(f"{n}_BD_004", BD, "Minimum Debit (1.00)", [out("1.00"), rev_step(1, "Cleanup reversal")], priority="P2",
           expected_result="Approved 00."),
        TC(f"{n}_BD_005", BD, f"Credit = Per-Transaction Limit ({limit})", [inw(limit), rev_step(1, "Cleanup reversal")],
           priority="P2", expected_result="Approved 00."),
        TC(f"{n}_BD_006", BD, "Daily Frequency Limit (4th Debit)", [
            out("100.00", label="Debit 1"), out("100.00", label="Debit 2"), out("100.00", label="Debit 3"),
            out("100.00", rc=FREQ, label="Debit 4 (over limit)"),
            rev_step(1, "Cleanup reversal 1"), rev_step(2, "Cleanup reversal 2"), rev_step(3, "Cleanup reversal 3"),
        ], profile="frequency", expected_result="First three approved; fourth declined 65."),
        TC(f"{n}_BD_007", BD, "Non-Numeric Amount (DE 4)", [out("00000000ABCD", rc=["13", "30"])],
           expected_result="Declined 13 / 30."),
    ]

    cases += [
        TC(f"{n}_RV_001", RV, "Outward Reversal (Timeout 68) Restores Balance", [
            bal("Opening balance"),
            out("1000.00", balance={"from_step": 1, "delta": "-1000.00"}),
            rev_step(2, reason="68", present=[90], balance={"from_step": 1, "delta": "0.00"}),
        ], expected_result="0430 RC 00; balance fully restored."),
        TC(f"{n}_RV_002", RV, "Reversal Without Original Transaction", [
            bal("Opening balance"),
            S(label="Unmatched 0420", tx=REV, amount="500.00", expect=E(["25", "21", "00"])),
            bal("Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], expected_result="25 / 21 / 00 with NO credit."),
        TC(f"{n}_RV_003", RV, "Duplicate Reversal (Same 0420 Twice)", [
            bal("Opening balance"), out("500.00"), rev_step(2, "First reversal"),
            S(label="Duplicate 0420", link={"type": "duplicate", "step": 3}, expect=E(["94", "00"])),
            bal("Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], expected_result="Second reversal 94 / 00; credited once."),
        TC(f"{n}_RV_004", RV, "Repeat Reversal Advice (0421)", [
            bal("Opening balance"), out("500.00"), rev_step(2, "Original reversal 0420"),
            rev_step(2, "Repeat reversal 0421", mti_type="repeat_reversal"),
            bal("Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], expected_result="0421 acknowledged 00; no double credit."),
        TC(f"{n}_RV_005", RV, "Reversal Amount Mismatch", [
            bal("Opening balance"), out("500.00"),
            rev_step(2, "Reversal with wrong amount 600.00", amount="600.00", rc=["13", "12", "30"]),
            bal("Balance after bad reversal", balance={"from_step": 1, "delta": "-500.00"}),
            rev_step(2, "Cleanup reversal", balance={"from_step": 1, "delta": "0.00"}),
        ], expected_result="Mismatched reversal rejected."),
        TC(f"{n}_RV_006", RV, "Reversal of a Declined Transaction", [
            bal("Opening balance"), out("500.00", rc=NSF),
            rev_step(2, "Reversal of declined txn", rc=["21", "00", "25"]),
            bal("Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], profile="low_funds", expected_result="No credit to the account."),
        TC(f"{n}_RV_007", RV, "Inward Credit Reversal Debits Back", [
            bal("Opening balance"), inw("300.00", balance={"from_step": 1, "delta": "300.00"}),
            rev_step(2, "Credit reversal", balance={"from_step": 1, "delta": "0.00"}),
        ], expected_result="Credit reversed; balance back to opening."),
    ]

    cases += [
        TC(f"{n}_DP_001", DP, "Duplicate Debit (Identical Resend)", [
            bal("Opening balance"), out("500.00"),
            S(label="Identical resend", link={"type": "duplicate", "step": 2}, expect=E(DUP)),
            bal("Balance after duplicate", balance={"from_step": 1, "delta": "-500.00"}),
            rev_step(2, "Cleanup reversal"),
        ], expected_result="94; debited only once."),
        TC(f"{n}_DP_002", DP, "Same RRN, Different Amount", [
            bal("Opening balance"), out("500.00"),
            S(label="Same RRN, amount 700.00", tx=OUT, amount="700.00", direction="DR",
              link={"type": "same_rrn", "step": 2}, expect=E(DUP)),
            bal("Balance after duplicate", balance={"from_step": 1, "delta": "-500.00"}),
            rev_step(2, "Cleanup reversal"),
        ], expected_result="94; no second debit."),
        TC(f"{n}_DP_003", DP, "Duplicate Credit (Identical Resend)", [
            bal("Opening balance"), inw("400.00"),
            S(label="Identical resend", link={"type": "duplicate", "step": 2}, expect=E(DUP)),
            bal("Balance after duplicate", balance={"from_step": 1, "delta": "400.00"}),
            rev_step(2, "Cleanup reversal"),
        ], expected_result="94; credited only once."),
    ]

    cases += [
        TC(f"{n}_SC_001", SC, "Missing DE 102 (Account)", [S(label="Debit without DE 102", tx=OUT, amount="100.00", direction="DR",
           remove=[102], expect=E(["30", "12", "14"]))], expected_result="Declined 30 / 12 / 14."),
        TC(f"{n}_SC_002", SC, "Missing DE 4 (Amount)", [S(label="Debit without DE 4", tx=OUT, direction="DR",
           remove=[4], expect=E(["30", "12", "13"]))], expected_result="Declined 30 / 12 / 13."),
        TC(f"{n}_SC_003", SC, "LLVAR Length Tampered (DE 102 prefix = 40)", [S(label="Tampered DE 102 length", tx=OUT, amount="100.00",
           direction="DR", tamper=[{"op": "llvar_len", "de": 102, "value": "40"}], expect=E(FORMAT, mti=None, allow_no_response=True))],
           expected_result="Format error 30 - never approved."),
        TC(f"{n}_SC_004", SC, "Truncated Message", [S(label="Truncated", tx=OUT, amount="100.00", direction="DR",
           tamper=[{"op": "truncate", "chars": 15}], expect=E(FORMAT, mti=None, allow_no_response=True))],
           expected_result="Format error 30."),
        TC(f"{n}_SC_005", SC, "Trailing Garbage After Last DE", [S(label="Trailing bytes", tx=OUT, amount="100.00", direction="DR",
           tamper=[{"op": "append", "value": "XYZ999"}], expect=E(FORMAT, mti=None, allow_no_response=True))],
           expected_result="Format error 30."),
        TC(f"{n}_SC_006", SC, "Bitmap Bit Set Without Data (DE 5)", [S(label="Extra bitmap bit", tx=OUT, amount="100.00", direction="DR",
           tamper=[{"op": "bitmap_set", "de": 5}], expect=E(FORMAT, mti=None, allow_no_response=True))],
           expected_result="Format error 30."),
        TC(f"{n}_SC_007", SC, "Injection String in DE 102", [out("100.00", rc=["14", "52", "53", "30", "12"])], profile="sql_injection",
           expected_result="Declined safely; CBS stays up."),
        TC(f"{n}_SC_008", SC, "Unsupported Processing Code (990000)", [S(label="DE 3 = 990000", tx=OUT, amount="100.00",
           proc_code="990000", expect=E(INV_TXN))], expected_result="Declined 12 / 40."),
        TC(f"{n}_SC_009", SC, "Non-Numeric Processing Code", [S(label="DE 3 = 00A000", tx=OUT, amount="100.00",
           proc_code="00A000", expect=E(["12", "30"]))], expected_result="Declined 12 / 30."),
        TC(f"{n}_SC_010", SC, "Foreign Currency (DE 49 = 840)", [S(label="DE 49 = 840", tx=OUT, amount="100.00", direction="DR",
           set={"49": "840"}, expect=E(["12", "30", "57"]))], expected_result="Declined 12 / 30 / 57."),
        TC(f"{n}_SC_011", SC, "Negative / Signed Amount", [out("-00000010000", rc=["13", "30"])], expected_result="Declined 13 / 30."),
    ]

    cases += [
        TC(f"{n}_TF_001", TF, "CBS Late Response -> Switch Timeout -> Reversal", [
            bal("Opening balance"),
            S(label="Debit (CBS answers late)", tx=OUT, amount="68.00", direction="DR", timeout_sec=2, expect=E(None, timeout=True)),
            rev_step(2, "Timeout reversal (68)", reason="68", rc=["00", "21", "25"]),
            bal("Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], description="Mock CBS: amount 68.00 posts then answers after 5 s.",
           expected_result="Switch times out and reverses; account not debited in the end."),
        TC(f"{n}_TF_002", TF, "CBS Drops Connection -> Reversal", [
            bal("Opening balance"),
            S(label="Debit (CBS drops)", tx=OUT, amount="91.00", direction="DR", timeout_sec=3, expect=E(None, timeout=True)),
            rev_step(2, "Reversal after no response", reason="68", rc=["00", "21", "25"]),
            bal("Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], description="Mock CBS: amount 91.00 posts then closes the socket.",
           expected_result="No response; reversal restores the account."),
        TC(f"{n}_TF_003", TF, "CBS System Malfunction (96) -> Reversal", [
            bal("Opening balance"),
            S(label="Debit (CBS returns 96)", tx=OUT, amount="96.00", direction="DR", expect=E(["96", "91"])),
            rev_step(2, "Reversal after 96", reason="68", rc=["21", "00", "25"]),
            bal("Closing balance", balance={"from_step": 1, "delta": "0.00"}),
        ], description="Mock CBS: amount 96.00 returns 96 without posting.",
           expected_result="96 / 91 then reversal; balance unchanged."),
    ]
    return cases


def default_settings(ch):
    if ch == "ATM":
        rule = {"enabled": False, "de": 124, "debit_value": "", "credit_value": ""}
    else:
        rule = {"enabled": True, "de": 124,
                "debit_value": f"{ch}|000000|DEBIT|9024655944-2@ybl|9024655944-2@ybl|{ch}",
                "credit_value": f"{ch}|000000|CREDIT|9024655944-2@ybl|9024655944-2@ybl|{ch}"}
    return {
        "direction_rule": rule,
        "default_echo_des": [2, 3, 4, 11, 37, 49, 102],
        "des_check": "strict",
        "step_delay_ms": 0,
    }


def default_catalog(ch):
    ch = (ch or "ATM").upper()
    if ch == "UPI":
        profiles = account_profiles("8180073930053234")
        cases = payment_cases("UPI", "100000.00", {"list": "upi_list_account", "bal": "upi_balance_enquiry",
                                                     "inward": "upi_inward", "outward": "upi_outward",
                                                     "reversal": "upi_outward_reversal"})
    elif ch == "IMPS":
        profiles = account_profiles("8180073930053234")
        cases = payment_cases("IMPS", "500000.00", {"list": "imps_list_account", "bal": "imps_balance_enquiry",
                                                      "inward": "imps_inward", "outward": "imps_outward",
                                                      "reversal": "imps_outward_reversal"})
    else:
        ch = "ATM"
        profiles = ATM_PROFILES
        cases = atm_cases()
    return {"channel": ch, "version": 1, "settings": default_settings(ch),
            "profiles": copy.deepcopy(profiles), "testcases": copy.deepcopy(cases)}


# ============================================================================
# Persistence + validation
# ============================================================================
def catalog_path(base_dir, ch):
    return os.path.join(base_dir, f"{(ch or 'ATM').lower()}_testcases.json")


def save_catalog(base_dir, ch, catalog):
    with open(catalog_path(base_dir, ch), "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)


def load_catalog(base_dir, ch):
    ch = (ch or "ATM").upper()
    path = catalog_path(base_dir, ch)
    default = default_catalog(ch)
    if not os.path.exists(path):
        save_catalog(base_dir, ch, default)
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            cat = json.load(f)
    except Exception:
        backup = path + ".corrupt"
        try:
            os.replace(path, backup)
        except OSError:
            pass
        save_catalog(base_dir, ch, default)
        return default
    changed = False
    for key in ("settings", "profiles"):
        if not isinstance(cat.get(key), dict):
            cat[key] = default[key]
            changed = True
    for k, v in default["settings"].items():
        if k not in cat["settings"]:
            cat["settings"][k] = v
            changed = True
    if not isinstance(cat.get("testcases"), list):
        cat["testcases"] = default["testcases"]
        changed = True
    cat["channel"] = ch
    if changed:
        save_catalog(base_dir, ch, cat)
    return cat


def merge_defaults(base_dir, ch):
    """Add default test cases / profiles that are missing, keep user edits."""
    cat = load_catalog(base_dir, ch)
    default = default_catalog(ch)
    have = {t.get("id") for t in cat["testcases"]}
    added = [t for t in default["testcases"] if t["id"] not in have]
    cat["testcases"].extend(added)
    for k, v in default["profiles"].items():
        cat["profiles"].setdefault(k, v)
    save_catalog(base_dir, ch, cat)
    return len(added)


def validate_testcase(tc, profiles=None):
    errors = []
    if not isinstance(tc, dict):
        return ["Test case must be a JSON object."]
    if not str(tc.get("id", "")).strip():
        errors.append("'id' is required.")
    if not str(tc.get("name", "")).strip():
        errors.append("'name' is required.")
    if not str(tc.get("category", "")).strip():
        errors.append("'category' is required.")
    steps = tc.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("'steps' must be a non-empty list.")
        return errors
    if profiles is not None and tc.get("profile") and tc["profile"] not in profiles:
        errors.append(f"profile '{tc['profile']}' is not defined.")
    for i, st in enumerate(steps, start=1):
        if not isinstance(st, dict):
            errors.append(f"step {i}: must be an object.")
            continue
        link = st.get("link")
        if link:
            if link.get("type") not in LINK_TYPES:
                errors.append(f"step {i}: link.type must be one of {LINK_TYPES}.")
            ref = link.get("step")
            if not isinstance(ref, int) or not (1 <= ref < i):
                errors.append(f"step {i}: link.step must point to an earlier step (1..{i - 1}).")
            if link.get("type") == "same_rrn" and not (st.get("tx") or st.get("mti")):
                errors.append(f"step {i}: same_rrn needs 'tx' or 'mti'.")
        elif not st.get("tx") and not (st.get("mti") and st.get("des")):
            errors.append(f"step {i}: needs 'tx', or 'mti' + 'des', or a 'link'.")
        if profiles is not None and st.get("profile") and st["profile"] not in profiles:
            errors.append(f"step {i}: profile '{st['profile']}' is not defined.")
        exp = st.get("expect")
        if not isinstance(exp, dict):
            errors.append(f"step {i}: 'expect' object is required.")
            continue
        if not exp.get("timeout") and not exp.get("rc"):
            errors.append(f"step {i}: expect.rc (list) is required unless expect.timeout is true.")
        if exp.get("rc") is not None and not isinstance(exp.get("rc"), list):
            errors.append(f"step {i}: expect.rc must be a list, e.g. [\"00\"].")
        bal = exp.get("balance")
        if bal:
            ref = bal.get("from_step")
            if not isinstance(ref, int) or not (1 <= ref < i):
                errors.append(f"step {i}: expect.balance.from_step must be an earlier step.")
        for t in st.get("tamper") or []:
            if t.get("op") not in TAMPER_OPS:
                errors.append(f"step {i}: tamper op must be one of {TAMPER_OPS}.")
    return errors
