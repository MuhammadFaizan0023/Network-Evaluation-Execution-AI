#!/bin/sh
# tlsssl_attack.sh  ->  intended model class: "TLSSSL"
#
# TLS sessions where the CLIENT also uploads bulk (not just downloads), so the
# forward direction carries a data burst (Fwd bulk nonzero) with large TLS-record
# packets (dataset: Pkt Len ~275, ACK ~9, 5/6 pkts, Fwd Byts/b Avg ~100). The
# victim's openssl s_server:443 completes real handshakes; we feed bulk stdin into
# s_client and also POST a payload over https so forward bytes are substantial.

echo "[TLSSSL] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
PORT="${TLS_PORT:-443}"
END=$(($(date +%s) + DURATION))

rnd() { awk "BEGIN{srand();print int(rand()*$1)+1}"; }

case "$INTENSITY" in
    low)    BURST=3;  SLEEP_MAX=4 ;;
    high)   BURST=12; SLEEP_MAX=1 ;;
    *)      BURST=6;  SLEEP_MAX=2 ;;  # medium
esac

# ~8 KB upload body -> forward TLS records (client-side bulk)
head -c 8192 /dev/urandom > /tmp/tls_body.bin 2>/dev/null

while [ "$(date +%s)" -lt "$END" ]; do
    i=0
    while [ "$i" -lt "$BURST" ]; do
        # HTTPS POST: TLS handshake + forward application-data burst
        curl -sk -o /dev/null -m 6 -X POST --data-binary @/tmp/tls_body.bin \
            "https://$TARGET:$PORT/upload" 2>/dev/null
        i=$((i + 1))
    done
    # raw TLS session fed bulk stdin (client sends encrypted app-data forward)
    cat /tmp/tls_body.bin | timeout 6 openssl s_client -quiet -connect "$TARGET:$PORT" >/dev/null 2>&1
    sleep "$(rnd "$SLEEP_MAX")"
done
rm -f /tmp/tls_body.bin
echo "[TLSSSL] Done."
