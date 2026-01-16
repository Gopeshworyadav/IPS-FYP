# firewall.py
from datetime import datetime

def drop_packet_info(packet_info):
    print(
        f"[IPS DROP] {datetime.now()} | "
        f"{packet_info['src_addr']}:{packet_info['src_port']} → "
        f"{packet_info['dst_addr']}:{packet_info['dst_port']} | "
        f"Attack: {packet_info['alert']}"
    )


        ______________________________________________________
