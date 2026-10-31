"""Build model-verified banks for all scenarios in ONE process (model loaded
once). Each bank is RAW_COLUMNS rows the model classifies as that class, used by
inject_testcase.py when the Simulation Lab buttons fire.

Usage: python build_banks.py [rows_per_bank]
"""
import os
import sys
import csv

import gen_testcase as g
from schema import RAW_COLUMNS

ROWS = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
BANK_DIR = os.path.join(g.HERE, "banks")
SCENARIOS = ["benign", "iotdos", "iotddos", "iotslowloris", "iotbruteforce",
             "iotmitm", "iotevasion", "iotc2beac", "iotexfil", "iottlsssl"]

os.makedirs(BANK_DIR, exist_ok=True)
model, le = g.load_model()
for s in SCENARIOS:
    prof = g.load_profile(s)
    x, got = g.sample_target(prof, ROWS, model, le, max_batches=200)
    rows = g.to_raw_rows(x, prof)
    out = os.path.join(BANK_DIR, s + ".csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(RAW_COLUMNS)
        w.writerows(rows)
    print("bank %-14s label=%-12s rows=%d" % (s, prof["label"], got))
