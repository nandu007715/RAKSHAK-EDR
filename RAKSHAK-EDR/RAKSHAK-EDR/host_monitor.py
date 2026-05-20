"""
host_monitor.py
System / Host information for RAKSHAK-EDR
"""

import os
import time
import uuid
import socket
import platform
import psutil

BOOT_TIME = time.time()


def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_mac():
    mac = uuid.getnode()
    return ":".join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))


def get_uptime():
    seconds = int(time.time() - BOOT_TIME)

    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    sec = seconds % 60

    return f"{hours}h {minutes}m {sec}s"


def get_host_info():
    try:
        return {
            "hostname": socket.gethostname(),
            "ip": get_local_ip(),
            "mac": get_mac(),
            "os": f"{platform.system()} {platform.release()}",
            "cpu": psutil.cpu_percent(interval=0.3),
            "ram": psutil.virtual_memory().percent,
            "disk": psutil.disk_usage(os.sep).percent,
            "uptime": get_uptime()
        }

    except Exception as e:
        return {
            "hostname": "Unknown",
            "ip": "Unknown",
            "mac": "Unknown",
            "os": "Unknown",
            "cpu": 0,
            "ram": 0,
            "disk": 0,
            "uptime": "Unknown",
            "error": str(e)
        }