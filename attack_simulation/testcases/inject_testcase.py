"""Inject synthetic test-case flows into the Simulation Lab test lane.

Runs as the process the Simulation Lab "Start" button launches for IoT scenarios
(see ids_backend/api/simulation.py). Stdlib ONLY -- no numpy/sklearn -- so it
runs in whatever Python the Django backend uses. It samples rows from a
pre-built, model-verified bank (attack_simulation/testcases/banks/<scenario>.csv)
and drips timestamped CSV files into flows_iot_test for `duration` seconds, so it
behaves like a running attack (the producer picks each file up; Stop kills this
process and purges the lane).

Usage:
  python inject_testcase.py <scenario> <count> <duration> <flows_dir> <bank_dir>
"""
import os
import sys
import csv
import time
import random
from datetime import datetime

INTERVAL = 6  # seconds between dripped batches


def read_bank(path):
    with open(path, "r", newline="", encoding="utf-8") as f:
        r = csv.reader(f)
        header = next(r, None)
        rows = [row for row in r if row]
    return header, rows


def pick(rows, count):
    if count >= len(rows):
        return [list(x) for x in rows] + random.choices(rows, k=count - len(rows))
    return random.sample(rows, count)


def main():
    if len(sys.argv) < 6:
        print("usage: inject_testcase.py <scenario> <count> <duration> <flows_dir> <bank_dir>")
        return 2
    scenario = sys.argv[1].lower()
    count = max(1, int(sys.argv[2]))
    duration = max(1, int(sys.argv[3]))
    flows_dir = sys.argv[4]
    bank_dir = sys.argv[5]

    bank_path = os.path.join(bank_dir, scenario + ".csv")
    if not os.path.isfile(bank_path):
        print("ERROR: no bank for scenario '%s' at %s" % (scenario, bank_path))
        return 1
    header, rows = read_bank(bank_path)
    if not rows:
        print("ERROR: bank is empty: %s" % bank_path)
        return 1

    # Label column (for a readable filename); falls back to the scenario name.
    try:
        label = rows[0][header.index("Label")]
    except Exception:
        label = scenario
    safe = "".join(c for c in label if c.isalnum()) or "case"

    os.makedirs(flows_dir, exist_ok=True)
    print("[INJECT] scenario=%s label=%s count/batch=%d duration=%ds interval=%ds bank=%d rows"
          % (scenario, label, count, duration, INTERVAL, len(rows)))

    # Drip a SMALL batch every INTERVAL seconds for the whole duration so the
    # attack shows continuously across the dashboard window (every per-minute
    # bucket), while staying light enough that the consumer never backs up.
    end = time.time() + duration
    batch = 0
    while time.time() < end:
        sample = pick(rows, count)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        out = os.path.join(flows_dir, "testcase_%s_%s.csv" % (safe, ts))
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if header:
                w.writerow(header)
            w.writerows(sample)
        batch += 1
        print("[INJECT] batch %d -> %s (%d flows)" % (batch, os.path.basename(out), len(sample)))
        remaining = end - time.time()
        if remaining <= 0:
            break
        time.sleep(min(INTERVAL, remaining))
    print("[INJECT] done (%d batches)" % batch)
    return 0


if __name__ == "__main__":
    sys.exit(main())
