import pydivert
from scapy.all import IP, TCP
from detector import detect_packet
from firewall import drop_packet_info
import threading

running = threading.Event()

def _extract_packet_info(divert_packet):
    try:
        raw = bytes(divert_packet.payload)
    except Exception:
        raw = b""

    info = {
        "src_addr": divert_packet.src_addr,
        "dst_addr": divert_packet.dst_addr,
        "src_port": getattr(divert_packet, "src_port", None),
        "dst_port": getattr(divert_packet, "dst_port", None),
        "tcp_flags": {},
        "payload": ""
    }

    try:
        pkt = IP(raw)
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            info["tcp_flags"] = {
                "SYN": bool(tcp.flags & 0x02),
                "ACK": bool(tcp.flags & 0x10),
                "RST": bool(tcp.flags & 0x04),
                "FIN": bool(tcp.flags & 0x01),
            }
            info["payload"] = bytes(tcp.payload).decode(errors="ignore")
        else:
            info["payload"] = raw.decode(errors="ignore")
    except Exception:
        pass

    return info


def start_sniffing(callback=None, divert_filter="ip"):
    """
    TRUE IPS:
    - Malicious packets → dropped
    - Normal packets → re-injected
    """
    running.set()
    with pydivert.WinDivert(divert_filter) as w:
        for pkt in w:
            if not running.is_set():
                break

            pkt_info = _extract_packet_info(pkt)
            alert = detect_packet(pkt_info)
            pkt_info["alert"] = alert

            if alert:
                # 🚫 DROP malicious packet
                drop_packet_info(pkt_info)
                if callback:
                    callback(pkt_info)
                continue  # DO NOT re-inject

            # ✅ Allow normal traffic
            w.send(pkt)


def stop_sniffing():
    running.clear()

