
from flask import Flask, jsonify, render_template
from threading import Thread
import packet_sniffer as sniffer

app = Flask(__name__)
alerts = []

def _callback(pkt_info):
    alerts.append({
        "src": pkt_info.get("src_addr"),
        "dst": pkt_info.get("dst_addr"),
        "src_port": pkt_info.get("src_port"),
        "dst_port": pkt_info.get("dst_port"),
        "alert": pkt_info.get("alert"),
        "payload_preview": (pkt_info.get("payload") or "")[:200]
    })

sniffer_thread = None

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/start", methods=["POST","GET"])
def start():
    global sniffer_thread
    if sniffer_thread and sniffer_thread.is_alive():
        return jsonify({"status":"already running"})
    sniffer_thread = Thread(target=sniffer.start_sniffing, args=(_callback,))
    sniffer_thread.daemon = True
    sniffer_thread.start()
    return jsonify({"status":"started"})

@app.route("/stop", methods=["POST","GET"])
def stop():
    sniffer.stop_sniffing()
    return jsonify({"status":"stopped"})

@app.route("/alerts")
def get_alerts():
    return jsonify(alerts[-100:])  # latest 100

if __name__ == "__main__":
    app.run(debug=True)
