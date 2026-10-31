#!/bin/sh
# NEXA test-attack: C2 Beaconing — regular, fixed-interval small callbacks to the
# victim (command-and-control check-in signature). Traffic-pattern only: no shell,
# no remote control (iot_test lane).
echo "[C2BEAC] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
BEACON_PORT="${BEACON_PORT:-80}"
END=$(($(date +%s) + DURATION))

# Intensity -> beacon interval (seconds); lower = chattier C2 channel.
# A regular cadence of small identical flows is the hallmark of beaconing.
case "$INTENSITY" in
    low)    INTERVAL=10 ;;
    high)   INTERVAL=2 ;;
    *)      INTERVAL=5 ;;  # medium
esac

while [ "$(date +%s)" -lt "$END" ]; do
    # Small fixed-size check-in to the victim's open port (connection forms a flow)
    printf 'BEACON id=%s ts=%s\n' "$$" "$(date +%s)" \
        | nc -w 2 "$TARGET" "$BEACON_PORT" 2>/dev/null
    sleep "$INTERVAL"
done
echo "[C2BEAC] Done."
