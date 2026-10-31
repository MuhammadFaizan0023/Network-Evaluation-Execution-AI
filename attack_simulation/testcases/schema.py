"""Shared schema for the synthetic test-case generator.

Extracts RAW_COLUMNS, IOT_FEATURE_COLS and CICFLOW_TO_TONIOT directly from the
live ml_consumer/consumer.py so the generator can never drift out of sync with
what the consumer actually expects. consumer.py imports tensorflow at module
load, so we do NOT import it; we regex out the three pure-literal assignments
and exec just those.
"""
import os
import re

_HERE = os.path.dirname(os.path.abspath(__file__))
# attack_simulation/testcases/ -> project root is two levels up
_PROJECT = os.path.abspath(os.path.join(_HERE, "..", ".."))
CONSUMER_PY = os.path.join(_PROJECT, "ml_consumer", "consumer.py")


def _extract(src, name, open_ch, close_ch):
    # match:  NAME = <open_ch> .... <close_ch>  (first close_ch at column 0)
    pat = re.compile(
        r"^%s\s*=\s*%s.*?^%s" % (re.escape(name), re.escape(open_ch), re.escape(close_ch)),
        re.DOTALL | re.MULTILINE,
    )
    m = pat.search(src)
    if not m:
        raise RuntimeError("could not extract %s from consumer.py" % name)
    ns = {}
    exec(m.group(0), ns)          # pure literal, safe
    return ns[name]


with open(CONSUMER_PY, "r", encoding="utf-8") as f:
    _SRC = f.read()

RAW_COLUMNS = _extract(_SRC, "RAW_COLUMNS", "[", "]")
IOT_FEATURE_COLS = _extract(_SRC, "IOT_FEATURE_COLS", "[", "]")
CICFLOW_TO_TONIOT = _extract(_SRC, "CICFLOW_TO_TONIOT", "{", "}")

# inverse: TON-IoT model/feature name -> CICFlowMeter V4 (RAW_COLUMNS) name
TONIOT_TO_CICFLOW = {v: k for k, v in CICFLOW_TO_TONIOT.items()}

# The per-class TRUSTLab CSVs use 'CWR Flag Cnt'; the model feature is
# 'CWE Flag Count' (fed from V4 'CWR Flag Count'). Alias when reading the dataset.
DATASET_ALIASES = {
    "CWE Flag Count": "CWR Flag Cnt",
}

# RAW_COLUMNS metadata columns that are NOT model features and have no TRUSTLab
# source column; synthesized/zeroed by the generator.
METADATA_COLS = {
    "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol",
    "Timestamp", "Label",
}

if __name__ == "__main__":
    print("RAW_COLUMNS:", len(RAW_COLUMNS))
    print("IOT_FEATURE_COLS:", len(IOT_FEATURE_COLS))
    print("CICFLOW_TO_TONIOT:", len(CICFLOW_TO_TONIOT))
    missing = [c for c in IOT_FEATURE_COLS if c not in TONIOT_TO_CICFLOW]
    print("model features with no V4 source:", missing)
