#!/bin/sh
# c2beac_attack.sh  ->  intended model class: "C2Beac"
#
# Short periodic beacons that UPLOAD a small payload and read the reply, so each
# beacon flow has a forward data burst (Fwd bulk nonzero) at a steady cadence
# (dataset: 6/7 pkts, Pkt Len ~83, Fwd Byts/b Avg ~15). We POST a small beacon
# body (id + base64 chunk) to :80 on a tight interval, rotating user-agents.

echo "[C2BEAC] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
PORT="${BEACON_PORT:-80}"
END=$(($(date +%s) + DURATION))

case "$INTENSITY" in
    low)    INTERVAL=0.5 ;;
    high)   INTERVAL=0.1 ;;
    *)      INTERVAL=0.25 ;;  # medium
esac

UAS="Mozilla/5.0 python-requests/2.25.1 curl/7.68.0 Go-http-client/1.1 Apache-HttpClient/4.5.13"

while [ "$(date +%s)" -lt "$END" ]; do
    for ua in $UAS; do
        [ "$(date +%s)" -lt "$END" ] || break
        # small beacon payload uploaded each cycle -> forward burst + reply
        body="id=$$-$(date +%s%N);data=$(head -c 96 /dev/urandom | od -An -tx1 | tr -d ' \n')"
        printf '%s' "$body" > /tmp/c2_body.txt
        curl -s -o /dev/null -A "$ua" -m 3 \
            -X POST --data-binary @/tmp/c2_body.txt \
            "http://$TARGET:$PORT/beacon" 2>/dev/null
        sleep "$INTERVAL"
    done
done
echo "[C2BEAC] Done."
