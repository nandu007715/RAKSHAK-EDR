"""
detector.py
Real lightweight IDS engine for RAKSHAK-EDR
"""

import threading
import datetime
from collections import defaultdict

packet_count = 0
threat_count = 0
sniff_running = False

_lock = threading.Lock()

recent_ips = defaultdict(int)
recent_ports = defaultdict(set)

latest_alerts = []

try:
    from scapy.all import sniff, ARP, IP, TCP, ICMP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


def _log_alert(attack, ip, severity):
    global threat_count

    with _lock:
        threat_count += 1

        latest_alerts.append({
            "attack": attack,
            "ip": ip,
            "severity": severity,
            "status": "Detected",
            "time": datetime.datetime.now().strftime("%H:%M:%S")
        })

        if len(latest_alerts) > 100:
            latest_alerts.pop(0)

    print(f"[RAKSHAK] {attack} | {ip} | {severity}")


def _detect(pkt):
    global packet_count

    with _lock:
        packet_count += 1

    src_ip = "Unknown"

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        recent_ips[src_ip] += 1

    # ARP spoof
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        _log_alert("ARP Spoofing", src_ip, "HIGH")

    # ICMP flood
    if pkt.haslayer(ICMP):
        if recent_ips[src_ip] > 25:
            _log_alert("ICMP Flood", src_ip, "CRITICAL")

    # Port scan / brute force
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        dport = pkt[TCP].dport
        recent_ports[src_ip].add(dport)

        if len(recent_ports[src_ip]) > 15:
            _log_alert("Port Scan", src_ip, "HIGH")

        if recent_ips[src_ip] > 40:
            _log_alert("Brute Force Pattern", src_ip, "CRITICAL")


def start_sniffing(iface=None):
    global sniff_running

    if not SCAPY_AVAILABLE:
        print("[RAKSHAK] Scapy unavailable - simulation mode active.")
        return

    if sniff_running:
        return

    sniff_running = True

    def _run():
        try:
            kwargs = {
                "prn": _detect,
                "store": False
            }

            if iface:
                kwargs["iface"] = iface

            sniff(**kwargs)

        except Exception as e:
            print("[RAKSHAK] Sniff error:", e)

    threading.Thread(target=_run, daemon=True).start()
    print("[RAKSHAK] Live detector started")


def stop_sniffing():
    global sniff_running
    sniff_running = False


def get_status():
    return {
        "packet_count": packet_count,
        "threat_count": threat_count,
        "latest_alerts": latest_alerts[-30:],
        "scapy_available": SCAPY_AVAILABLE,
        "sniff_running": sniff_running,
        "last_check": datetime.datetime.now().strftime("%H:%M:%S")
    }