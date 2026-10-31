"""Offline: learn each TRUSTLab class's statistical pattern as a per-class
Gaussian Mixture (aggregate stats only -- NO raw training rows) used by
gen_testcase.py to synthesize novel, on-manifold flows.

For each class: read the per-class CSV, select the 73 model features (alias
'CWE Flag Count' <- 'CWR Flag Cnt'), standardize, fit a GaussianMixture, and save
    profiles/<scenario>.gmm.pkl   (mixture: means/covariances/weights)
    profiles/<scenario>.json      (standardizer mean/std, min, max, int-ness,
                                    common Dst/Src ports, label)

Usage:  python build_profiles.py [datasets_dir] [rows_per_class] [n_components]
"""
import os
import sys
import json
import numpy as np
import pandas as pd
import joblib
from sklearn.mixture import GaussianMixture

from schema import IOT_FEATURE_COLS, DATASET_ALIASES

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILE_DIR = os.path.join(HERE, "profiles")
DEFAULT_DATASETS = r"D:\COMSATS\FYP\XGBModel\datasets"

CLASS_FILES = {
    "Benign.csv":       ("benign",       "Benign"),
    "Bruteforce.csv":   ("iotbruteforce", "Bruteforce"),
    "C2Beaconing.csv":  ("iotc2beac",    "C2Beac"),
    "DDoS.csv":         ("iotddos",      "ddos"),
    "DoS.csv":          ("iotdos",       "dos"),
    "Evasion.csv":      ("iotevasion",   "Evasion"),
    "Exfiltration.csv": ("iotexfil",     "Exfiltracion"),
    "MITM.csv":         ("iotmitm",      "MITM"),
    "Slowloris.csv":    ("iotslowloris", "slowloris"),
    "TLSSSL.csv":       ("iottlsssl",    "TLSSSL"),
}


def load_matrix(path, rows):
    wanted = set(IOT_FEATURE_COLS) | set(DATASET_ALIASES.values()) | {"Dst Port", "Src Port"}
    wanted = {w.strip() for w in wanted}
    df = pd.read_csv(path, low_memory=True, nrows=rows,
                     usecols=lambda c: c.strip() in wanted, on_bad_lines="skip")
    df.columns = df.columns.str.strip()

    mat = np.zeros((len(df), len(IOT_FEATURE_COLS)), dtype="float64")
    is_int = []
    for j, feat in enumerate(IOT_FEATURE_COLS):
        src = feat if feat in df.columns else DATASET_ALIASES.get(feat)
        if src and src in df.columns:
            col = pd.to_numeric(df[src], errors="coerce").replace(
                [np.inf, -np.inf], np.nan).fillna(0.0).to_numpy()
        else:
            col = np.zeros(len(df))
        mat[:, j] = col
        fin = col[np.isfinite(col)]
        is_int.append(bool(len(fin)) and bool(np.all(np.equal(np.mod(fin, 1), 0))))

    def common(name, default):
        if name in df.columns:
            vc = pd.to_numeric(df[name], errors="coerce").dropna()
            if len(vc):
                return [int(x) for x in vc.astype(int).value_counts().head(6).index.tolist()]
        return [default]

    return mat, is_int, common("Dst Port", 80), common("Src Port", 44444)


def build_one(path, rows, ncomp):
    mat, is_int, dports, sports = load_matrix(path, rows)
    mu = mat.mean(axis=0)
    sd = mat.std(axis=0)
    sd[sd == 0] = 1.0                      # constant features stay at mean
    z = (mat - mu) / sd
    k = min(ncomp, max(1, len(mat) // 50))
    gmm = GaussianMixture(n_components=k, covariance_type="full",
                          reg_covar=1e-3, random_state=42, max_iter=200)
    gmm.fit(z)
    meta = {
        "features": IOT_FEATURE_COLS,
        "mu": mu.tolist(), "sd": sd.tolist(),
        "min": mat.min(axis=0).tolist(), "max": mat.max(axis=0).tolist(),
        "is_int": is_int, "dst_ports": dports, "src_ports": sports,
        "n_rows_seen": int(len(mat)), "n_components": int(k),
    }
    return gmm, meta


def main():
    datasets = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DATASETS
    rows = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
    ncomp = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    os.makedirs(PROFILE_DIR, exist_ok=True)
    for fname, (scenario, label) in CLASS_FILES.items():
        path = os.path.join(datasets, fname)
        if not os.path.isfile(path):
            print("SKIP (missing):", path)
            continue
        gmm, meta = build_one(path, rows, ncomp)
        meta["scenario"] = scenario
        meta["label"] = label
        joblib.dump(gmm, os.path.join(PROFILE_DIR, scenario + ".gmm.pkl"))
        with open(os.path.join(PROFILE_DIR, scenario + ".json"), "w", encoding="utf-8") as f:
            json.dump(meta, f)
        print("wrote %-14s label=%-12s rows=%d comps=%d" % (
            scenario, label, meta["n_rows_seen"], meta["n_components"]))


if __name__ == "__main__":
    main()
