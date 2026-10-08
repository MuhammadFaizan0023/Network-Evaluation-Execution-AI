#!/bin/sh
# NEXA IoT test victim device: expose a few device-like services and
# self-capture this container's traffic into the ISOLATED test folder.
set -e

CAP_DIR="/pcaps_iot_test"
mkdir -p "$CAP_DIR"

echo "[iot-victim] starting services..."

# HTTP (busybox httpd) on :80
httpd -h /www -p 0.0.0.0:80 || echo "[iot-victim] httpd failed to start"

# Telnet (busybox telnetd) on :23 — gives a login service to scan/brute
telnetd -l /bin/sh -p 23 || echo "[iot-victim] telnetd failed to start"

# SSH (dropbear) on :22 — generate host keys on first boot
mkdir -p /etc/dropbear
dropbear -R -p 22 || echo "[iot-victim] dropbear failed to start"

# Self-capture on eth0 (Ethernet link-layer). NOTE: do NOT use `-i any` here —
# it yields Linux "cooked"/SLL captures that CICFlowMeter cannot parse into flows.
# Rotate every 5s; exclude Kafka/management ports to keep the test captures clean.
echo "[iot-victim] starting tcpdump capture on eth0 -> $CAP_DIR"
exec tcpdump -i eth0 \
    'not port 29092 and not port 9092 and not port 9093 and not port 8000 and not port 3000 and not port 3306' \
    -w "$CAP_DIR/capture_%Y%m%d_%H%M%S.pcap" -G 5
