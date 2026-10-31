"""Generate synthetic flow test cases that follow a TRUSTLab attack class's
pattern and inject them into the Simulation Lab (flows_iot_test), OR score them
against the model offline.

The rows are SYNTHESIZED from each class's statistical profile (mean/cov/range,
built by build_profiles.py) -- novel samples, not copied training rows -- and
written in the exact CSV shape the kafka producer + ml_consumer expect, so they
reach the model in the training representation (no capture, no CICFlowMeter, no
domain shift). The model then classifies each test case as its intended class.

Usage:
  python gen_testcase.py <scenario> [count] [--score]
    <scenario>  one of: iotdos iotddos iotslowloris iotbruteforce iotmitm
                        iotevasion iotc2beac iotexfil iottlsssl benign
    [count]     number of synthetic flows (default 150)
    --score     do NOT write to the pipeline; load the model and print
                predicted-class distribution (offline validation)
"""
import os
import sys
import json
import csv
import time
import random
from datetime import datetime, timezone

import numpy as np

from schema import (RAW_COLUMNS, IOT_FEATURE_COLS, TONIOT_TO_CICFLOW,
                    METADATA_COLS, _PROJECT)

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILE_DIR = os.path.join(HERE, "profiles")
FLOWS_TEST_DIR = os.path.join(_PROJECT, "flows_iot_test")
MODELS_DIR = r"D:\VS JAVA\NEXA-FYP2\Models"

SRC_IP_POOL = ["172.20.0.240", "172.20.0.241", "172.20.0.242", "172.20.0.243",
               "172.20.0.244", "172.20.0.245"]
VICTIM_IP = "172.20.0.50"


def load_profile(scenario):
    path = os.path.join(PROFILE_DIR, scenario + ".json")
    if not os.path.isfile(path):
        raise SystemExit("no profile for scenario '%s' (run build_profiles.py). "
                         "available: %s" % (
                             scenario,
                             ", ".join(sorted(f[:-5] for f in os.listdir(PROFILE_DIR)
                                              if f.endswith(".json")))))
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def sample_rows(prof, n, seed=None):
    """Return an (n x 73) array of synthetic feature vectors in IOT_FEATURE_COLS
    order, sampled from the class's Gaussian Mixture (fit in standardized space),
    inverse-standardized, clamped to the observed [min,max], integer-rounded where
    the feature is integral, non-negative, with Flow Duration > 0."""
    import joblib
    gmm_path = os.path.join(PROFILE_DIR, prof["scenario"] + ".gmm.pkl")
    gmm = joblib.load(gmm_path)
    mu = np.asarray(prof["mu"], dtype="float64")
    sd = np.asarray(prof["sd"], dtype="float64")
    lo = np.asarray(prof["min"], dtype="float64")
    hi = np.asarray(prof["max"], dtype="float64")
    is_int = prof["is_int"]

    if seed is not None:
        gmm.random_state = seed
    z, _ = gmm.sample(n)
    rng = np.random.default_rng(seed)
    rng.shuffle(z)                       # gmm.sample returns rows grouped by comp
    x = z * sd + mu
    x = np.clip(x, lo, hi)
    for j in range(len(mu)):
        if is_int[j]:
            x[:, j] = np.round(x[:, j])
    x[x < 0] = 0.0
    if "Flow Duration" in IOT_FEATURE_COLS:
        fd = IOT_FEATURE_COLS.index("Flow Duration")
        x[:, fd] = np.maximum(x[:, fd], 1.0)
    return x


def fmt(v):
    f = float(v)
    if f == int(f):
        return str(int(f))
    return repr(round(f, 6))


def to_raw_rows(x, prof):
    """Map each synthetic feature vector into a full RAW_COLUMNS row."""
    feat_idx = {feat: j for j, feat in enumerate(IOT_FEATURE_COLS)}
    # RAW_COLUMNS name -> model-feature index (via V4->TON inverse)
    raw_to_featidx = {}
    for raw in RAW_COLUMNS:
        ton = _v4_to_ton(raw)
        if ton in feat_idx:
            raw_to_featidx[raw] = feat_idx[ton]

    dst_ports = prof.get("dst_ports") or [80]
    src_ports = prof.get("src_ports") or [44444]
    now_iso = datetime.now(timezone.utc).isoformat()
    label = prof.get("label", "Attack")

    rows = []
    for i in range(x.shape[0]):
        src_ip = random.choice(SRC_IP_POOL)
        dport = random.choice(dst_ports)
        sport = random.choice(src_ports)
        row = []
        for raw in RAW_COLUMNS:
            if raw in raw_to_featidx:
                row.append(fmt(x[i, raw_to_featidx[raw]]))
            elif raw == "Flow ID":
                row.append("%s-%s-%d-%d-6" % (src_ip, VICTIM_IP, sport, dport))
            elif raw == "Src IP":
                row.append(src_ip)
            elif raw == "Dst IP":
                row.append(VICTIM_IP)
            elif raw == "Src Port":
                row.append(str(int(sport)))
            elif raw == "Dst Port":
                row.append(str(int(dport)))
            elif raw == "Timestamp":
                row.append(now_iso)
            elif raw == "Label":
                row.append(label)
            else:
                # non-model V4 cols with no TRUSTLab source (Fwd/Bwd Pkts/s,
                # Fwd Act Data Pkts, Fwd Seg Size Min) -> 0, unused by the model
                row.append("0")
        rows.append(row)
    return rows


# CICFLOW_TO_TONIOT maps V4 -> TON; we need V4 -> TON for RAW_COLUMNS names.
from schema import CICFLOW_TO_TONIOT
def _v4_to_ton(raw):
    return CICFLOW_TO_TONIOT.get(raw)


def write_pipeline(rows, label):
    os.makedirs(FLOWS_TEST_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = "".join(c for c in label if c.isalnum()) or "case"
    out = os.path.join(FLOWS_TEST_DIR, "testcase_%s_%s.csv" % (safe, ts))
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(RAW_COLUMNS)          # header (producer skips it)
        w.writerows(rows)
    return out


def load_model():
    import joblib
    model = joblib.load(os.path.join(MODELS_DIR, "multiclass_xgb_model.pkl"))
    le = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
    return model, le


def sample_target(prof, n, model, le, min_conf=0.0, max_batches=60):
    """Rejection sampling: draw from the GMM and keep only rows the model
    classifies as this scenario's label (optionally above min_conf), until we
    have n (or run out of batches). Guarantees the injected test case predicts
    the intended class. Returns the kept (<=n x 73) array and how many we got."""
    import pandas as pd
    order = list(model.feature_names_in_)
    label = prof["label"]
    kept = []
    got = 0
    for _ in range(max_batches):
        x = sample_rows(prof, max(n * 2, 256))
        df = pd.DataFrame(x, columns=IOT_FEATURE_COLS)
        pred = le.inverse_transform(model.predict(df[order]))
        conf = model.predict_proba(df[order]).max(axis=1)
        mask = (pred == label) & (conf >= min_conf)
        if mask.any():
            kept.append(x[mask])
            got += int(mask.sum())
        if got >= n:
            break
    if not kept:
        return np.empty((0, len(IOT_FEATURE_COLS))), 0
    out = np.vstack(kept)[:n]
    return out, out.shape[0]


def score(x, prof):
    import joblib
    import pandas as pd
    model = joblib.load(os.path.join(MODELS_DIR, "multiclass_xgb_model.pkl"))
    le = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
    df = pd.DataFrame(x, columns=IOT_FEATURE_COLS)
    pred = le.inverse_transform(model.predict(df[list(model.feature_names_in_)]))
    proba = model.predict_proba(df[list(model.feature_names_in_)])
    conf = proba.max(axis=1)
    import collections
    label = prof.get("label")
    dist = collections.Counter(pred)
    hit = dist.get(label, 0)
    print("expected: %s   n=%d   predicted-as-expected: %d (%.1f%%)   mean_conf=%.3f"
          % (label, len(pred), hit, 100.0 * hit / len(pred), conf.mean()))
    for k, v in dist.most_common():
        print("    %-14s %5d (%.1f%%)" % (k, v, 100.0 * v / len(pred)))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    if not args:
        raise SystemExit(__doc__)
    scenario = args[0].lower()
    count = int(args[1]) if len(args) > 1 else 150
    prof = load_profile(scenario)

    if "--score" in flags:
        score(sample_rows(prof, count), prof)
        return

    if "--bank" in flags:
        # Pre-generate a validated bank of RAW_COLUMNS rows (model-verified to
        # predict this class) for the Simulation-Lab button wiring to sample from.
        model, le = load_model()
        x, got = sample_target(prof, count, model, le, max_batches=200)
        rows = to_raw_rows(x, prof)
        bank_dir = os.path.join(HERE, "banks")
        os.makedirs(bank_dir, exist_ok=True)
        out = os.path.join(bank_dir, scenario + ".csv")
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(RAW_COLUMNS)            # header kept; injector re-emits it
            w.writerows(rows)
        print("bank: wrote %d verified '%s' rows -> %s" % (got, prof.get("label"), out))
        return

    # Injection: by default, rejection-sample so every written flow is one the
    # model actually classifies as the target class. --raw skips the filter.
    if "--raw" in flags:
        x = sample_rows(prof, count)
    else:
        model, le = load_model()
        x, got = sample_target(prof, count, model, le)
        if got == 0:
            print("WARNING: the model classified none of the synthesized '%s' flows "
                  "as that class; writing raw samples instead." % prof.get("label"))
            x = sample_rows(prof, count)
        elif got < count:
            print("note: kept %d/%d flows that the model labels '%s'." %
                  (got, count, prof.get("label")))

    rows = to_raw_rows(x, prof)
    out = write_pipeline(rows, prof.get("label", scenario))
    print("wrote %d synthetic '%s' flows -> %s" % (len(rows), prof.get("label"), out))
    print("the producer will ship them to topic flows_iot_test; watch the Simulation Lab.")


if __name__ == "__main__":
    main()
