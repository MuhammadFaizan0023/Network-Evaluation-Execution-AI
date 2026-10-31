#!/bin/sh
# exfiltration_attack.sh  ->  intended model class: "Exfiltracion"
#
# The model flags an attack when the FORWARD (attacker->victim) direction carries
# a sustained data burst, which populates CICFlowMeter's Fwd Bytes/Bulk Avg (0 for
# benign/floods). Exfiltration IS a forward upload, so we push large, slow POST
# bodies: many back-to-back forward data packets -> nonzero fwd bulk, upload-skewed
# Down/Up, larger packets (dataset Exfil Pkt Len ~135). Victim httpd:80 accepts the
# body; we also tunnel an upload over TLS to :443.

echo "[EXFIL] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
PORT="${EXFIL_PORT:-80}"
END=$(($(date +%s) + DURATION))

rnd() { awk "BEGIN{srand();print int(rand()*$1)+1}"; }

case "$INTENSITY" in
    low)    CHUNK=131072;  RATE=64k;  SLEEP_MAX=4 ;;
    high)   CHUNK=1048576; RATE=256k; SLEEP_MAX=1 ;;
    *)      CHUNK=524288;  RATE=128k; SLEEP_MAX=2 ;;  # medium
esac

TMP=/tmp/exfil_payload.bin
head -c "$CHUNK" /dev/urandom > "$TMP" 2>/dev/null

while [ "$(date +%s)" -lt "$END" ]; do
    # Slow large forward upload -> many forward data packets = forward bulk.
    curl -s -o /dev/null --limit-rate "$RATE" -m 20 \
        -X POST --data-binary @"$TMP" "http://$TARGET:$PORT/upload" 2>/dev/null
    # TLS-tunnelled upload to the victim's openssl s_server on :443.
    cat "$TMP" | timeout 10 openssl s_client -quiet -connect "$TARGET:443" >/dev/null 2>&1
    sleep "$(rnd "$SLEEP_MAX")"
done
rm -f "$TMP"
echo "[EXFIL] Done."
