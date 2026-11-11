"""Inject synthetic, training-pattern attack flows aimed at the REGISTERED camera.

Separate from the Simulation-tab injector (attack_simulation/testcases/inject_testcase.py),
which is left untouched. This one reuses the SAME model-verified banks
(attack_simulation/testcases/banks/<scenario>.csv) but stamps each flow's "Dst IP"
(and rebuilds "Flow ID") with the camera's registered IP, then drips the rows into the
HOME-NETWORK lane (flows_iot) so the model's live predictions appear on the dashboard
for the camera device.

The target IP is NOT hardcoded: it is looked up from the backend's registered devices
(GET /api/devices/), i.e. whatever camera IP you registered in the UI (Sources). IP
columns are metadata only -- NOT model features -- so the prediction is unchanged; only
the displayed target changes.

Stdlib ONLY (runs in whatever Python the backend uses).

Usage:
  python inject_camera.py <scenario> [count] [duration] [backend_url] [flows_dir] [bank_dir]

Defaults: count=25, duration=60, backend_url=http://localhost:8000,
          flows_dir=<repo>/flows_iot, bank_dir=<repo>/attack_simulation/testcases/banks
Env overrides: NEXA_DEVICE_NAME (pick a specific registered device by name),
               NEXA_CAMERA_IP (skip the lookup and use this IP directly).
"""
import os
import sys
import csv
import time
import json
import random
import urllib.request
from datetime import datetime

INTERVAL = 6  # seconds between dripped batches

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.abspath(os.path.join(_HERE, "..", ".."))            # repo root
DEFAULT_BANK_DIR = os.path.join(_REPO, "attack_simulation", "testcases", "banks")
DEFAULT_FLOWS_DIR = os.path.join(_REPO, "flows_iot")                # real home-network lane
DEFAULT_BACKEND = "http://localhost:8000"


def resolve_camera_ip(backend_url):
    """Return the registered camera IP from the UI (GET /api/devices/).

    Preference: env NEXA_CAMERA_IP > a device whose name matches NEXA_DEVICE_NAME >
    an active device_type == 'camera' > the first active device. Raises on none.
    """
    env_ip = os.environ.get("NEXA_CAMERA_IP")
    if env_ip:
        return env_ip, "env NEXA_CAMERA_IP"

    url = backend_url.rstrip("/") + "/api/devices/"
    with urllib.request.urlopen(url, timeout=8) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    devices = data.get("results", data) if isinstance(data, dict) else data
    devices = [d for d in devices if isinstance(d, dict) and d.get("ip_address")]
    if not devices:
        raise RuntimeError(
            "No registered devices found at %s. Register the camera in the UI (Sources) first." % url)

    want_name = os.environ.get("NEXA_DEVICE_NAME")
    active = [d for d in devices if d.get("is_active", True)]
    pool = active or devices

    if want_name:
        for d in pool:
            if str(d.get("name", "")).strip().lower() == want_name.strip().lower():
                return d["ip_address"], "device name '%s'" % want_name
        raise RuntimeError("No registered device named '%s'. Found: %s"
                           % (want_name, ", ".join(repr(d.get("name")) for d in pool)))

    for d in pool:
        if str(d.get("device_type", "")).lower() == "camera":
            return d["ip_address"], "device_type 'camera' (%s)" % d.get("name")
    d = pool[0]
    return d["ip_address"], "first active device (%s)" % d.get("name")


def read_bank(path):
    with open(path, "r", newline="", encoding="utf-8") as f:
        r = csv.reader(f)
        header = next(r, None)
        rows = [row for row in r if row]
    return header, rows


def pick(rows, count):
    if count >= len(rows):
        return [list(x) for x in rows] + [list(x) for x in random.choices(rows, k=count - len(rows))]
    return [list(x) for x in random.sample(rows, count)]


def _col(header, name):
    try:
        return header.index(name)
    except (ValueError, AttributeError):
        return None


def stamp_target(sample, header, target_ip):
    """Set Dst IP = target_ip on each (copied) row, and rebuild Flow ID to match."""
    dst_i = _col(header, "Dst IP")
    src_i = _col(header, "Src IP")
    sp_i = _col(header, "Src Port")
    dp_i = _col(header, "Dst Port")
    pr_i = _col(header, "Protocol")
    fid_i = _col(header, "Flow ID")
    for row in sample:
        if dst_i is not None and dst_i < len(row):
            row[dst_i] = target_ip
        if fid_i is not None and fid_i < len(row):
            parts = [
                row[src_i] if src_i is not None and src_i < len(row) else "",
                target_ip,
                row[sp_i] if sp_i is not None and sp_i < len(row) else "",
                row[dp_i] if dp_i is not None and dp_i < len(row) else "",
                row[pr_i] if pr_i is not None and pr_i < len(row) else "",
            ]
            row[fid_i] = "-".join(str(p) for p in parts)
    return sample


def main():
    if len(sys.argv) < 2:
        print("usage: inject_camera.py <scenario> [count] [duration] [backend_url] [flows_dir] [bank_dir]")
        return 2
    scenario = sys.argv[1].lower()
    count = max(1, int(sys.argv[2])) if len(sys.argv) > 2 else 25
    duration = max(1, int(sys.argv[3])) if len(sys.argv) > 3 else 60
    backend_url = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else DEFAULT_BACKEND
    flows_dir = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else DEFAULT_FLOWS_DIR
    bank_dir = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] else DEFAULT_BANK_DIR

    try:
        target_ip, how = resolve_camera_ip(backend_url)
    except Exception as e:
        print("ERROR: could not resolve camera IP: %s" % e)
        return 1
    print("[CAM-INJECT] target camera IP = %s (via %s)" % (target_ip, how))

    bank_path = os.path.join(bank_dir, scenario + ".csv")
    if not os.path.isfile(bank_path):
        print("ERROR: no bank for scenario '%s' at %s" % (scenario, bank_path))
        return 1
    header, rows = read_bank(bank_path)
    if not rows:
        print("ERROR: bank is empty: %s" % bank_path)
        return 1

    try:
        label = rows[0][header.index("Label")]
    except Exception:
        label = scenario
    safe = "".join(c for c in label if c.isalnum()) or "case"

    os.makedirs(flows_dir, exist_ok=True)
    print("[CAM-INJECT] scenario=%s label=%s target=%s count/batch=%d duration=%ds interval=%ds bank=%d rows -> %s"
          % (scenario, label, target_ip, count, duration, INTERVAL, len(rows), flows_dir))

    end = time.time() + duration
    batch = 0
    while time.time() < end:
        sample = stamp_target(pick(rows, count), header, target_ip)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        out = os.path.join(flows_dir, "camcase_%s_%s.csv" % (safe, ts))
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if header:
                w.writerow(header)
            w.writerows(sample)
        batch += 1
        print("[CAM-INJECT] batch %d -> %s (%d flows)" % (batch, os.path.basename(out), len(sample)))
        remaining = end - time.time()
        if remaining <= 0:
            break
        time.sleep(min(INTERVAL, remaining))
    print("[CAM-INJECT] done (%d batches)" % batch)
    return 0


if __name__ == "__main__":
    sys.exit(main())
