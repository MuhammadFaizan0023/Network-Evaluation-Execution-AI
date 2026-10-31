#!/bin/sh
# evasion_attack.sh  ->  intended model class: "Evasion"
#
# Dataset Evasion has a VERY high forward byte-bulk (Fwd Byts/b Avg ~1.4e4) with
# small packets (Pkt Len ~54) and 1 fwd/1 bwd — i.e. dense small forward data
# bursts. We drive many rapid small POST bodies back-to-back (tight forward data
# packets) plus fragmented nmap probes for the stealth/evasion flavor.

echo "[EVASION] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
END=$(($(date +%s) + DURATION))

rnd() { awk "BEGIN{srand();print int(rand()*$1)+1}"; }

case "$INTENSITY" in
    low)    REPS=20;  TIMING=3; SLEEP_MAX=4 ;;
    high)   REPS=80;  TIMING=5; SLEEP_MAX=1 ;;
    *)      REPS=40;  TIMING=4; SLEEP_MAX=2 ;;  # medium
esac

# small (~256B) body sent many times -> dense small forward data packets
head -c 256 /dev/urandom > /tmp/ev_body.bin 2>/dev/null

while [ "$(date +%s)" -lt "$END" ]; do
    k=0
    while [ "$k" -lt "$REPS" ]; do
        curl -s -o /dev/null -m 3 -X POST --data-binary @/tmp/ev_body.bin \
            "http://$TARGET/x" 2>/dev/null
        k=$((k + 1))
    done
    # fragmented, decoyed stealth scan (the "evasion" technique flavor)
    nmap -sS -f -D "RND:10" -T$TIMING --data-length 48 -p 1-1024 -Pn "$TARGET" 2>/dev/null
    sleep "$(rnd "$SLEEP_MAX")"
done
rm -f /tmp/ev_body.bin
echo "[EVASION] Done."
