#!/bin/sh
# IoT Benign traffic — generates normal home-device network activity (web polls,
# pings, DNS lookups) so the IDS can be evaluated on a "normal" baseline class.
echo "[IOT-BENIGN] Starting..."
TARGET="${TARGET_HOST:-172.20.0.10}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
END=$(($(date +%s) + DURATION))

# Intensity -> pause between normal requests (seconds)
case "$INTENSITY" in
    low)    SLEEP_MAX=8 ;;
    high)   SLEEP_MAX=2 ;;
    *)      SLEEP_MAX=5 ;;  # medium
esac

while [ $(date +%s) -lt $END ]; do
    # Routine web poll (e.g. status/telemetry page)
    curl -s "http://$TARGET/" > /dev/null 2>&1
    sleep $((RANDOM % SLEEP_MAX + 1))
    # Keep-alive ping
    ping -c 2 "$TARGET" > /dev/null 2>&1
    sleep $((RANDOM % SLEEP_MAX + 1))
    # Routine DNS lookup
    nslookup "$TARGET" > /dev/null 2>&1
    sleep $((RANDOM % SLEEP_MAX + 1))
done
echo "[IOT-BENIGN] Done."
