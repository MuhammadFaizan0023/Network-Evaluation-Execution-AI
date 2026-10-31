#!/bin/sh
# NEXA test-attack: Evasion — stealth/evasive scanning (packet fragmentation, decoy
# source IPs, slow timing, payload padding) to probe the victim while dodging naive
# detection (iot_test lane).
echo "[EVASION] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
END=$(($(date +%s) + DURATION))

# Intensity -> nmap timing / decoy count / port breadth / pause.
# Port breadth is capped so a scan yields a few hundred flows (fast CICFlowMeter).
case "$INTENSITY" in
    low)    TIMING=1; DECOYS=5;  PORTS="1-512";  SLEEP_MAX=6 ;;
    high)   TIMING=2; DECOYS=15; PORTS="1-1024"; SLEEP_MAX=2 ;;
    *)      TIMING=1; DECOYS=10; PORTS="1-1024"; SLEEP_MAX=4 ;;  # medium
esac

while [ "$(date +%s)" -lt "$END" ]; do
    # -sS SYN scan, -f fragment packets, -D RND decoys, -T slow timing,
    # --data-length pads packets, --scan-delay spreads probes out (evasion).
    nmap -sS -f -D "RND:$DECOYS" -T$TIMING \
        --data-length 48 --scan-delay 50ms \
        -p "$PORTS" "$TARGET" 2>/dev/null
    sleep $((RANDOM % SLEEP_MAX + 1))
done
echo "[EVASION] Done."
