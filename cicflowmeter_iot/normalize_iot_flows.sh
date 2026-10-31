#!/bin/sh
# Normalize a CICFlowMeter-4.0 IoT flow CSV in place so its feature VALUES match
# the representation of the new model's training dataset (which was built with a
# different flow extractor). Column names/order stay V4 (84 cols, RAW_COLUMNS
# order) so ml_consumer's existing CICFLOW_TO_TONIOT rename still applies.
#
# Audited mismatches (dataset vs live CICFlowMeter-4.0):
#   - Active/Idle Mean & Max: live is microseconds, dataset is SECONDS  -> divide by 1e6
#   - Active/Idle Std & Min : dataset always emits integer 0            -> force 0
# V4 column positions (1-indexed): 76 Active Mean, 77 Active Std, 78 Active Max,
# 79 Active Min, 80 Idle Mean, 81 Idle Std, 82 Idle Max, 83 Idle Min.
# Everything else already matches the dataset's units/definitions.

f="$1"
[ -f "$f" ] || exit 0
tmp="${f}.norm.tmp"

awk -F',' 'BEGIN { OFS=","; CONVFMT="%.12g"; OFMT="%.12g" }
NR==1 { print; next }                       # keep header row untouched
{
    if (NF >= 83) {
        $76 = $76 / 1000000; $77 = 0;        # Active Mean (us->s), Active Std -> 0
        $78 = $78 / 1000000; $79 = 0;        # Active Max  (us->s), Active Min -> 0
        $80 = $80 / 1000000; $81 = 0;        # Idle Mean   (us->s), Idle Std  -> 0
        $82 = $82 / 1000000; $83 = 0;        # Idle Max    (us->s), Idle Min  -> 0
    }
    print
}' "$f" > "$tmp" && mv "$tmp" "$f"
