#!/bin/sh
# NEXA test-attack: TLS/SSL — repeated TLS handshakes + encrypted sessions against
# the victim's TLS listener (:443), producing an SSL/TLS traffic signature on the
# victim's wire (iot_test lane). Requires the iot-victim TLS listener (openssl
# s_server on :443, added in iot_victim/entrypoint.sh).
echo "[TLSSSL] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
TLS_PORT="${TLS_PORT:-443}"
END=$(($(date +%s) + DURATION))

# Intensity -> requests per burst / pause between bursts.
case "$INTENSITY" in
    low)    BURST=5;  SLEEP_MAX=5 ;;
    high)   BURST=25; SLEEP_MAX=1 ;;
    *)      BURST=12; SLEEP_MAX=3 ;;  # medium
esac

while [ "$(date +%s)" -lt "$END" ]; do
    i=0
    while [ "$i" -lt "$BURST" ]; do
        # Full HTTPS request (handshake + encrypted GET); -k accepts self-signed cert
        curl -sk -m 5 "https://$TARGET:$TLS_PORT/" >/dev/null 2>&1
        i=$((i + 1))
    done
    # A couple of raw TLS handshakes to vary the SSL/TLS signature
    echo "Q" | openssl s_client -connect "$TARGET:$TLS_PORT" >/dev/null 2>&1
    sleep $((RANDOM % SLEEP_MAX + 1))
done
echo "[TLSSSL] Done."
