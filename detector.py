# detector.py
from collections import defaultdict
import time

SYN_FLOOD_THRESHOLD = 50
PORT_SCAN_THRESHOLD = 20
TIME_WINDOW = 5

syn_counter = defaultdict(list)
port_scan_tracker = defaultdict(set)

def detect_packet(pkt):
    src = pkt.get("src_addr")
    dst_port = pkt.get("dst_port")
    src_port = pkt.get("src_port")
    payload = pkt.get("payload", "").lower()
    flags = pkt.get("tcp_flags", {})
    now = time.time()

    # ---------------- SYN Flood ----------------
    if flags.get("SYN") and not flags.get("ACK"):
        syn_counter[src].append(now)
        syn_counter[src] = [
            t for t in syn_counter[src] if now - t <= TIME_WINDOW
        ]
        if len(syn_counter[src]) > SYN_FLOOD_THRESHOLD:
            return "SYN Flood Attack"

    # ---------------- Port Scan ----------------
    if flags.get("SYN") and dst_port:
        port_scan_tracker[src].add(dst_port)
        if len(port_scan_tracker[src]) > PORT_SCAN_THRESHOLD:
            return "Port Scanning"

    #  Ignore ALL HTTPS traffic (both directions)
    if dst_port == 443 or src_port == 443:
        return None

    # --------------- SQL Injection ----------------
    sql_patterns = [
        "select ", "union ", " or 1=1",
        "' or '1'='1", "\" or \"1\"=\"1",
        "drop table", "--", ";--"
    ]

    for pattern in sql_patterns:
        if pattern in payload:
            return "SQL Injection"

    # ---------------- XSS ----------------
    xss_patterns = [
        "<script", "javascript:",
        "onerror=", "onload=",
        "alert(", "document.cookie"
    ]

    for pattern in xss_patterns:
        if pattern in payload:
            return "Cross-Site Scripting (XSS)"

    return None
