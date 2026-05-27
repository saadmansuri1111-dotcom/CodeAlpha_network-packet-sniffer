"""
╔══════════════════════════════════════════════════════════════════╗
║          🌐 Network Packet Sniffer - Web Dashboard               ║
║       Real-time packet visualization in your browser             ║
╚══════════════════════════════════════════════════════════════════╝

A Flask-based web dashboard that provides real-time visualization
of captured network packets with interactive charts, protocol
breakdown, and live packet feed.

Usage:
    Run as Administrator/root:
        python web_dashboard.py [--port 5000] [--filter "tcp"] [--iface eth0]

    Then open http://localhost:5000 in your browser.
"""

import sys
import json
import time
import threading
import argparse
from datetime import datetime
from collections import Counter
from typing import Optional

try:
    from flask import Flask, render_template_string, jsonify
    from flask_socketio import SocketIO, emit
except ImportError:
    print("❌ Flask/Flask-SocketIO not installed. Run: pip install flask flask-socketio")
    sys.exit(1)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, Ether, Raw, get_if_list
except ImportError:
    print("❌ scapy is not installed. Run: pip install scapy")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────
# Flask App Setup
# ─────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config['SECRET_KEY'] = 'packet-sniffer-secret'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global state
packets_data = []
MAX_PACKETS = 500
capture_active = False
capture_thread = None

stats = {
    "total": 0,
    "protocols": Counter(),
    "src_ips": Counter(),
    "dst_ips": Counter(),
    "packet_sizes": [],
    "dns_queries": [],
    "start_time": None,
    "packets_per_second": [],
}

# Protocol & service maps
PROTOCOL_MAP = {
    1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP",
    41: "IPv6", 47: "GRE", 89: "OSPF",
}

PORT_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


# ─────────────────────────────────────────────────────────────────
# Packet Analysis
# ─────────────────────────────────────────────────────────────────

def analyze_packet(packet) -> Optional[dict]:
    """Analyze a packet and return structured data."""
    info = {
        "id": stats["total"] + 1,
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "src_ip": "N/A",
        "dst_ip": "N/A",
        "src_port": "",
        "dst_port": "",
        "protocol": "OTHER",
        "service": "",
        "size": len(packet),
        "ttl": "",
        "flags": "",
        "info": "",
        "payload_preview": "",
    }

    stats["total"] += 1
    stats["packet_sizes"].append(len(packet))

    # ARP
    if packet.haslayer(ARP):
        arp = packet[ARP]
        info["protocol"] = "ARP"
        info["src_ip"] = arp.psrc
        info["dst_ip"] = arp.pdst
        op = "Request" if arp.op == 1 else "Reply"
        info["info"] = f"ARP {op}: Who has {arp.pdst}? Tell {arp.psrc}"
        stats["protocols"]["ARP"] += 1
        return info

    if not packet.haslayer(IP):
        info["protocol"] = "Non-IP"
        stats["protocols"]["Other"] += 1
        return info

    ip = packet[IP]
    info["src_ip"] = ip.src
    info["dst_ip"] = ip.dst
    info["ttl"] = str(ip.ttl)
    info["protocol"] = PROTOCOL_MAP.get(ip.proto, f"Proto({ip.proto})")

    stats["src_ips"][ip.src] += 1
    stats["dst_ips"][ip.dst] += 1

    # TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        info["src_port"] = str(tcp.sport)
        info["dst_port"] = str(tcp.dport)
        info["protocol"] = "TCP"

        flags = str(tcp.flags)
        flag_map = {'S': 'SYN', 'A': 'ACK', 'F': 'FIN', 'R': 'RST', 'P': 'PSH'}
        flag_names = [name for char, name in flag_map.items() if char in flags]
        info["flags"] = "|".join(flag_names)
        info["info"] = f"[{info['flags']}]"

        service = PORT_SERVICES.get(tcp.dport, PORT_SERVICES.get(tcp.sport, ""))
        info["service"] = service

    # UDP
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        info["src_port"] = str(udp.sport)
        info["dst_port"] = str(udp.dport)
        info["protocol"] = "UDP"
        service = PORT_SERVICES.get(udp.dport, PORT_SERVICES.get(udp.sport, ""))
        info["service"] = service

    # ICMP
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        info["protocol"] = "ICMP"
        types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable", 11: "Time Exceeded"}
        info["info"] = types.get(icmp.type, f"Type {icmp.type}")

    # DNS
    if packet.haslayer(DNS):
        dns = packet[DNS]
        info["protocol"] = "DNS"
        try:
            if dns.qr == 0 and dns.qd:
                query = dns.qd.qname.decode()
                info["info"] = f"Query: {query}"
                stats["dns_queries"].append(query)
            elif dns.qd:
                query = dns.qd.qname.decode()
                info["info"] = f"Response: {query} ({dns.ancount} answers)"
        except Exception:
            info["info"] = "DNS packet"

    stats["protocols"][info["protocol"]] += 1

    # Payload preview
    if packet.haslayer(Raw):
        try:
            payload = bytes(packet[Raw].load)
            text = payload.decode('utf-8', errors='replace')[:80]
            info["payload_preview"] = ''.join(c if c.isprintable() else '.' for c in text)
        except Exception:
            info["payload_preview"] = ""

    return info


# ─────────────────────────────────────────────────────────────────
# Capture Thread
# ─────────────────────────────────────────────────────────────────

def capture_packets(bpf_filter=None, iface=None):
    """Background thread for packet capture."""
    global capture_active
    stats["start_time"] = time.time()
    capture_active = True

    def callback(pkt):
        if not capture_active:
            return

        info = analyze_packet(pkt)
        if info:
            packets_data.append(info)
            if len(packets_data) > MAX_PACKETS:
                packets_data.pop(0)

            # Emit to connected clients
            socketio.emit('new_packet', info)

            # Send stats update every 5 packets
            if stats["total"] % 5 == 0:
                socketio.emit('stats_update', get_stats_data())

    sniff_kwargs = {
        "prn": callback,
        "store": False,
        "stop_filter": lambda x: not capture_active,
    }
    if bpf_filter:
        sniff_kwargs["filter"] = bpf_filter
    if iface:
        sniff_kwargs["iface"] = iface

    try:
        sniff(**sniff_kwargs)
    except Exception as e:
        print(f"Capture error: {e}")
        capture_active = False


def get_stats_data() -> dict:
    """Get current statistics as dictionary."""
    elapsed = time.time() - stats["start_time"] if stats["start_time"] else 0
    avg_size = sum(stats["packet_sizes"][-100:]) / max(len(stats["packet_sizes"][-100:]), 1)

    return {
        "total": stats["total"],
        "elapsed": round(elapsed, 1),
        "pps": round(stats["total"] / max(elapsed, 1), 1),
        "avg_size": round(avg_size),
        "protocols": dict(stats["protocols"].most_common(10)),
        "top_src": dict(stats["src_ips"].most_common(8)),
        "top_dst": dict(stats["dst_ips"].most_common(8)),
        "dns_queries": list(set(stats["dns_queries"][-20:])),
    }


# ─────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/packets')
def api_packets():
    return jsonify(packets_data[-100:])


@app.route('/api/stats')
def api_stats():
    return jsonify(get_stats_data())


@app.route('/api/interfaces')
def api_interfaces():
    return jsonify(get_if_list())


@socketio.on('connect')
def handle_connect():
    emit('stats_update', get_stats_data())
    emit('initial_packets', packets_data[-50:])


@socketio.on('start_capture')
def handle_start(data):
    global capture_thread, capture_active
    if capture_active:
        return

    bpf_filter = data.get('filter', None)
    iface = data.get('iface', None)

    capture_thread = threading.Thread(
        target=capture_packets,
        args=(bpf_filter, iface),
        daemon=True
    )
    capture_thread.start()
    emit('capture_status', {'active': True})


@socketio.on('stop_capture')
def handle_stop():
    global capture_active
    capture_active = False
    emit('capture_status', {'active': False})


# ─────────────────────────────────────────────────────────────────
# HTML Dashboard Template
# ─────────────────────────────────────────────────────────────────

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔍 Network Packet Sniffer Dashboard</title>
    <meta name="description" content="Real-time network packet capture and analysis dashboard">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.5/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #1a1f35;
            --bg-card-hover: #222845;
            --border: #2a3050;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #22d3ee;
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-orange: #f59e0b;
            --accent-pink: #ec4899;
            --gradient-1: linear-gradient(135deg, #22d3ee, #3b82f6);
            --gradient-2: linear-gradient(135deg, #8b5cf6, #ec4899);
            --gradient-3: linear-gradient(135deg, #10b981, #22d3ee);
            --shadow: 0 4px 24px rgba(0, 0, 0, 0.4);
            --shadow-glow: 0 0 30px rgba(34, 211, 238, 0.1);
            --radius: 12px;
            --radius-sm: 8px;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* ── Animated Background ── */
        body::before {
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background:
                radial-gradient(ellipse at 20% 20%, rgba(34, 211, 238, 0.05) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 80%, rgba(139, 92, 246, 0.05) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 50%, rgba(59, 130, 246, 0.03) 0%, transparent 70%);
            pointer-events: none;
            z-index: 0;
        }

        /* ── Header ── */
        .header {
            position: sticky;
            top: 0;
            z-index: 100;
            background: rgba(10, 14, 23, 0.85);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border);
            padding: 16px 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .header-left {
            display: flex;
            align-items: center;
            gap: 16px;
        }

        .logo {
            font-size: 24px;
            font-weight: 700;
            background: var(--gradient-1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.5px;
        }

        .logo-icon {
            font-size: 28px;
            filter: drop-shadow(0 0 8px rgba(34, 211, 238, 0.5));
        }

        .status-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 500;
            border: 1px solid;
        }

        .status-badge.active {
            color: var(--accent-green);
            border-color: rgba(16, 185, 129, 0.3);
            background: rgba(16, 185, 129, 0.1);
        }

        .status-badge.inactive {
            color: var(--text-muted);
            border-color: var(--border);
            background: rgba(100, 116, 139, 0.1);
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: currentColor;
        }

        .status-badge.active .status-dot {
            animation: pulse 1.5s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.5); }
            50% { opacity: 0.7; box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
        }

        .header-right {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        /* ── Controls ── */
        .controls {
            position: relative;
            z-index: 1;
            padding: 20px 32px;
            display: flex;
            gap: 12px;
            align-items: center;
            flex-wrap: wrap;
        }

        .control-input {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius-sm);
            color: var(--text-primary);
            padding: 10px 16px;
            font-size: 14px;
            font-family: 'JetBrains Mono', monospace;
            outline: none;
            transition: all 0.2s;
        }

        .control-input:focus {
            border-color: var(--accent-cyan);
            box-shadow: 0 0 0 3px rgba(34, 211, 238, 0.15);
        }

        .control-input::placeholder {
            color: var(--text-muted);
        }

        #filterInput { width: 280px; }
        #ifaceInput { width: 180px; }

        .btn {
            padding: 10px 24px;
            border: none;
            border-radius: var(--radius-sm);
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            font-family: 'Inter', sans-serif;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .btn-start {
            background: var(--gradient-3);
            color: #0a0e17;
        }

        .btn-start:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 16px rgba(16, 185, 129, 0.3);
        }

        .btn-stop {
            background: linear-gradient(135deg, var(--accent-red), #dc2626);
            color: white;
        }

        .btn-stop:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 16px rgba(239, 68, 68, 0.3);
        }

        .btn-clear {
            background: var(--bg-card);
            color: var(--text-secondary);
            border: 1px solid var(--border);
        }

        .btn-clear:hover {
            background: var(--bg-card-hover);
            color: var(--text-primary);
        }

        /* ── Stats Grid ── */
        .stats-grid {
            position: relative;
            z-index: 1;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            padding: 0 32px 20px;
        }

        .stat-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 20px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s;
        }

        .stat-card:hover {
            transform: translateY(-2px);
            box-shadow: var(--shadow-glow);
            border-color: rgba(34, 211, 238, 0.2);
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
        }

        .stat-card:nth-child(1)::before { background: var(--gradient-1); }
        .stat-card:nth-child(2)::before { background: var(--gradient-2); }
        .stat-card:nth-child(3)::before { background: var(--gradient-3); }
        .stat-card:nth-child(4)::before { background: linear-gradient(135deg, var(--accent-orange), var(--accent-red)); }

        .stat-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-muted);
            margin-bottom: 8px;
        }

        .stat-value {
            font-size: 32px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            background: var(--gradient-1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .stat-card:nth-child(2) .stat-value {
            background: var(--gradient-2);
            -webkit-background-clip: text;
            background-clip: text;
        }

        .stat-card:nth-child(3) .stat-value {
            background: var(--gradient-3);
            -webkit-background-clip: text;
            background-clip: text;
        }

        .stat-card:nth-child(4) .stat-value {
            background: linear-gradient(135deg, var(--accent-orange), var(--accent-red));
            -webkit-background-clip: text;
            background-clip: text;
        }

        .stat-sub {
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 4px;
        }

        /* ── Main Layout ── */
        .main-content {
            position: relative;
            z-index: 1;
            display: grid;
            grid-template-columns: 1fr 360px;
            gap: 20px;
            padding: 0 32px 32px;
            min-height: 500px;
        }

        @media (max-width: 1200px) {
            .main-content {
                grid-template-columns: 1fr;
            }
        }

        /* ── Packet Table ── */
        .packet-panel {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            overflow: hidden;
            display: flex;
            flex-direction: column;
            max-height: 600px;
        }

        .panel-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-shrink: 0;
        }

        .panel-title {
            font-size: 16px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .packet-count {
            font-size: 12px;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }

        .packet-table-wrapper {
            overflow-y: auto;
            flex: 1;
        }

        .packet-table-wrapper::-webkit-scrollbar {
            width: 6px;
        }

        .packet-table-wrapper::-webkit-scrollbar-track {
            background: transparent;
        }

        .packet-table-wrapper::-webkit-scrollbar-thumb {
            background: var(--border);
            border-radius: 3px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            font-family: 'JetBrains Mono', monospace;
        }

        thead {
            position: sticky;
            top: 0;
            z-index: 10;
        }

        thead th {
            background: var(--bg-secondary);
            padding: 10px 12px;
            text-align: left;
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border);
        }

        tbody tr {
            border-bottom: 1px solid rgba(42, 48, 80, 0.5);
            transition: background 0.15s;
            animation: fadeIn 0.3s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-4px); }
            to { opacity: 1; transform: translateY(0); }
        }

        tbody tr:hover {
            background: rgba(34, 211, 238, 0.05);
        }

        tbody td {
            padding: 8px 12px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 200px;
        }

        /* Protocol colors */
        .proto-tcp { color: var(--accent-cyan); }
        .proto-udp { color: var(--accent-green); }
        .proto-icmp { color: var(--accent-orange); }
        .proto-dns { color: var(--accent-purple); }
        .proto-arp { color: var(--accent-red); }
        .proto-http { color: var(--accent-blue); }
        .proto-https { color: var(--accent-green); }

        .proto-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .proto-badge.tcp { background: rgba(34, 211, 238, 0.15); color: var(--accent-cyan); }
        .proto-badge.udp { background: rgba(16, 185, 129, 0.15); color: var(--accent-green); }
        .proto-badge.icmp { background: rgba(245, 158, 11, 0.15); color: var(--accent-orange); }
        .proto-badge.dns { background: rgba(139, 92, 246, 0.15); color: var(--accent-purple); }
        .proto-badge.arp { background: rgba(239, 68, 68, 0.15); color: var(--accent-red); }
        .proto-badge.other { background: rgba(100, 116, 139, 0.15); color: var(--text-muted); }

        /* ── Sidebar ── */
        .sidebar {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

        .sidebar-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            overflow: hidden;
        }

        .chart-container {
            padding: 16px;
            height: 220px;
            position: relative;
        }

        .top-list {
            list-style: none;
            padding: 0 16px 16px;
        }

        .top-list li {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid rgba(42, 48, 80, 0.3);
            font-size: 13px;
        }

        .top-list li:last-child { border-bottom: none; }

        .top-list .ip {
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-primary);
        }

        .top-list .count {
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent-cyan);
            font-weight: 600;
        }

        .dns-list {
            padding: 0 16px 16px;
            max-height: 200px;
            overflow-y: auto;
        }

        .dns-item {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: var(--text-secondary);
            padding: 4px 0;
            border-bottom: 1px solid rgba(42, 48, 80, 0.2);
            word-break: break-all;
        }

        /* ── Footer ── */
        .footer {
            position: relative;
            z-index: 1;
            text-align: center;
            padding: 20px;
            color: var(--text-muted);
            font-size: 12px;
            border-top: 1px solid var(--border);
        }

        /* ── Animations ── */
        @keyframes slideIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .stat-card, .packet-panel, .sidebar-card {
            animation: slideIn 0.4s ease;
        }

        .stat-card:nth-child(2) { animation-delay: 0.05s; }
        .stat-card:nth-child(3) { animation-delay: 0.1s; }
        .stat-card:nth-child(4) { animation-delay: 0.15s; }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header" id="main-header">
        <div class="header-left">
            <span class="logo-icon">🔍</span>
            <span class="logo">PacketSniffer</span>
            <div class="status-badge inactive" id="statusBadge">
                <span class="status-dot"></span>
                <span id="statusText">Idle</span>
            </div>
        </div>
        <div class="header-right">
            <span style="font-size: 13px; color: var(--text-muted);" id="clockDisplay"></span>
        </div>
    </header>

    <!-- Controls -->
    <div class="controls" id="capture-controls">
        <input type="text" class="control-input" id="filterInput"
               placeholder='BPF Filter (e.g., "tcp port 80")'>
        <input type="text" class="control-input" id="ifaceInput"
               placeholder="Interface (optional)">
        <button class="btn btn-start" id="startBtn" onclick="startCapture()">
            ▶ Start Capture
        </button>
        <button class="btn btn-stop" id="stopBtn" onclick="stopCapture()" style="display:none;">
            ⏹ Stop Capture
        </button>
        <button class="btn btn-clear" id="clearBtn" onclick="clearPackets()">
            🗑 Clear
        </button>
    </div>

    <!-- Stats Cards -->
    <div class="stats-grid" id="stats-section">
        <div class="stat-card" id="stat-total">
            <div class="stat-label">Total Packets</div>
            <div class="stat-value" id="statTotal">0</div>
            <div class="stat-sub" id="statPps">0 pkt/s</div>
        </div>
        <div class="stat-card" id="stat-elapsed">
            <div class="stat-label">Elapsed Time</div>
            <div class="stat-value" id="statElapsed">0s</div>
            <div class="stat-sub">capture duration</div>
        </div>
        <div class="stat-card" id="stat-avg-size">
            <div class="stat-label">Avg Packet Size</div>
            <div class="stat-value" id="statAvgSize">0B</div>
            <div class="stat-sub">bytes per packet</div>
        </div>
        <div class="stat-card" id="stat-protocols">
            <div class="stat-label">Unique Protocols</div>
            <div class="stat-value" id="statProtoCount">0</div>
            <div class="stat-sub">detected so far</div>
        </div>
    </div>

    <!-- Main Content -->
    <div class="main-content">
        <!-- Packet Table -->
        <div class="packet-panel" id="packet-panel">
            <div class="panel-header">
                <span class="panel-title">📡 Live Packet Feed</span>
                <span class="packet-count" id="packetCount">0 packets</span>
            </div>
            <div class="packet-table-wrapper" id="packetTableWrapper">
                <table>
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>Time</th>
                            <th>Protocol</th>
                            <th>Source</th>
                            <th>Destination</th>
                            <th>Size</th>
                            <th>Info</th>
                        </tr>
                    </thead>
                    <tbody id="packetBody"></tbody>
                </table>
            </div>
        </div>

        <!-- Sidebar -->
        <div class="sidebar">
            <!-- Protocol Chart -->
            <div class="sidebar-card" id="protocol-chart-card">
                <div class="panel-header">
                    <span class="panel-title">🌐 Protocols</span>
                </div>
                <div class="chart-container">
                    <canvas id="protoChart"></canvas>
                </div>
            </div>

            <!-- Top Sources -->
            <div class="sidebar-card" id="top-sources-card">
                <div class="panel-header">
                    <span class="panel-title">📤 Top Sources</span>
                </div>
                <ul class="top-list" id="topSources">
                    <li style="color: var(--text-muted);">No data yet</li>
                </ul>
            </div>

            <!-- DNS Queries -->
            <div class="sidebar-card" id="dns-queries-card">
                <div class="panel-header">
                    <span class="panel-title">🔎 DNS Queries</span>
                </div>
                <div class="dns-list" id="dnsQueries">
                    <div class="dns-item" style="color: var(--text-muted);">No queries captured</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="footer">
        Network Packet Sniffer & Analyzer — Educational Tool — Powered by Scapy + Flask
    </footer>

    <script>
        // ── Socket.IO Connection ──
        const socket = io();
        let autoScroll = true;
        let packetCount = 0;
        const MAX_TABLE_ROWS = 200;

        // ── Protocol Chart ──
        const chartCtx = document.getElementById('protoChart').getContext('2d');
        const protoChart = new Chart(chartCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#22d3ee', '#10b981', '#8b5cf6', '#f59e0b',
                        '#ef4444', '#3b82f6', '#ec4899', '#64748b'
                    ],
                    borderColor: '#1a1f35',
                    borderWidth: 2,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#94a3b8',
                            font: { family: 'Inter', size: 11 },
                            padding: 12,
                            usePointStyle: true,
                            pointStyleWidth: 8,
                        }
                    }
                },
                cutout: '60%',
            }
        });

        // ── Clock ──
        function updateClock() {
            const now = new Date();
            document.getElementById('clockDisplay').textContent = now.toLocaleTimeString();
        }
        setInterval(updateClock, 1000);
        updateClock();

        // ── Control Functions ──
        function startCapture() {
            const filter = document.getElementById('filterInput').value || null;
            const iface = document.getElementById('ifaceInput').value || null;
            socket.emit('start_capture', { filter, iface });
            document.getElementById('startBtn').style.display = 'none';
            document.getElementById('stopBtn').style.display = 'flex';
            updateStatus(true);
        }

        function stopCapture() {
            socket.emit('stop_capture');
            document.getElementById('startBtn').style.display = 'flex';
            document.getElementById('stopBtn').style.display = 'none';
            updateStatus(false);
        }

        function clearPackets() {
            document.getElementById('packetBody').innerHTML = '';
            packetCount = 0;
            document.getElementById('packetCount').textContent = '0 packets';
        }

        function updateStatus(active) {
            const badge = document.getElementById('statusBadge');
            const text = document.getElementById('statusText');
            if (active) {
                badge.className = 'status-badge active';
                text.textContent = 'Capturing';
            } else {
                badge.className = 'status-badge inactive';
                text.textContent = 'Idle';
            }
        }

        // ── Packet Display ──
        function getProtoBadgeClass(proto) {
            const p = proto.toLowerCase();
            if (p === 'tcp') return 'tcp';
            if (p === 'udp') return 'udp';
            if (p === 'icmp') return 'icmp';
            if (p === 'dns') return 'dns';
            if (p === 'arp') return 'arp';
            return 'other';
        }

        function addPacketRow(pkt) {
            const tbody = document.getElementById('packetBody');
            const row = document.createElement('tr');
            const cls = getProtoBadgeClass(pkt.protocol);

            const src = pkt.src_port ? `${pkt.src_ip}:${pkt.src_port}` : pkt.src_ip;
            const dst = pkt.dst_port ? `${pkt.dst_ip}:${pkt.dst_port}` : pkt.dst_ip;
            const info = pkt.service ? `[${pkt.service}] ${pkt.info}` : pkt.info;

            row.innerHTML = `
                <td style="color: var(--text-muted);">${pkt.id}</td>
                <td style="color: var(--text-muted);">${pkt.timestamp}</td>
                <td><span class="proto-badge ${cls}">${pkt.protocol}</span></td>
                <td>${src}</td>
                <td>${dst}</td>
                <td style="color: var(--text-muted);">${pkt.size}B</td>
                <td style="color: var(--text-secondary); max-width: 250px;">${info || ''}</td>
            `;

            tbody.appendChild(row);
            packetCount++;

            // Remove old rows if too many
            while (tbody.children.length > MAX_TABLE_ROWS) {
                tbody.removeChild(tbody.firstChild);
            }

            // Auto-scroll
            if (autoScroll) {
                const wrapper = document.getElementById('packetTableWrapper');
                wrapper.scrollTop = wrapper.scrollHeight;
            }

            document.getElementById('packetCount').textContent = `${packetCount} packets`;
        }

        // ── Stats Update ──
        function updateStats(data) {
            document.getElementById('statTotal').textContent = data.total.toLocaleString();
            document.getElementById('statPps').textContent = `${data.pps} pkt/s`;
            document.getElementById('statElapsed').textContent = `${data.elapsed}s`;
            document.getElementById('statAvgSize').textContent = `${data.avg_size}B`;
            document.getElementById('statProtoCount').textContent = Object.keys(data.protocols).length;

            // Update protocol chart
            const labels = Object.keys(data.protocols);
            const values = Object.values(data.protocols);
            protoChart.data.labels = labels;
            protoChart.data.datasets[0].data = values;
            protoChart.update('none');

            // Update top sources
            const srcList = document.getElementById('topSources');
            srcList.innerHTML = '';
            const srcEntries = Object.entries(data.top_src).slice(0, 6);
            if (srcEntries.length === 0) {
                srcList.innerHTML = '<li style="color: var(--text-muted);">No data yet</li>';
            } else {
                srcEntries.forEach(([ip, count]) => {
                    const li = document.createElement('li');
                    li.innerHTML = `<span class="ip">${ip}</span><span class="count">${count}</span>`;
                    srcList.appendChild(li);
                });
            }

            // Update DNS queries
            const dnsList = document.getElementById('dnsQueries');
            dnsList.innerHTML = '';
            if (data.dns_queries.length === 0) {
                dnsList.innerHTML = '<div class="dns-item" style="color: var(--text-muted);">No queries captured</div>';
            } else {
                data.dns_queries.forEach(q => {
                    const div = document.createElement('div');
                    div.className = 'dns-item';
                    div.textContent = q;
                    dnsList.appendChild(div);
                });
            }
        }

        // ── Socket Events ──
        socket.on('new_packet', (pkt) => {
            addPacketRow(pkt);
        });

        socket.on('initial_packets', (packets) => {
            packets.forEach(pkt => addPacketRow(pkt));
        });

        socket.on('stats_update', (data) => {
            updateStats(data);
        });

        socket.on('capture_status', (data) => {
            updateStatus(data.active);
            if (data.active) {
                document.getElementById('startBtn').style.display = 'none';
                document.getElementById('stopBtn').style.display = 'flex';
            } else {
                document.getElementById('startBtn').style.display = 'flex';
                document.getElementById('stopBtn').style.display = 'none';
            }
        });

        // Detect scroll to disable auto-scroll
        document.getElementById('packetTableWrapper').addEventListener('scroll', function() {
            const el = this;
            autoScroll = (el.scrollTop + el.clientHeight >= el.scrollHeight - 50);
        });
    </script>
</body>
</html>
"""


# ─────────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🌐 Network Packet Sniffer - Web Dashboard"
    )
    parser.add_argument("--port", "-p", type=int, default=5000,
                        help="Port to run the web dashboard on (default: 5000)")
    parser.add_argument("--filter", "-f", type=str, default=None,
                        help="Auto-start with BPF filter")
    parser.add_argument("--iface", "-i", type=str, default=None,
                        help="Auto-start with interface")
    parser.add_argument("--auto-start", action="store_true",
                        help="Automatically start capturing on launch")

    args = parser.parse_args()

    print(f"""
+------------------------------------------------------------------+
|          Network Packet Sniffer - Web Dashboard                  |
+------------------------------------------------------------------+

    Dashboard URL:  http://localhost:{args.port}
    Filter:         {args.filter or 'None'}
    Interface:      {args.iface or 'Default'}
    Auto-start:     {args.auto_start}

    WARNING: Run as Administrator for packet capture!
""")

    if args.auto_start:
        thread = threading.Thread(
            target=capture_packets,
            args=(args.filter, args.iface),
            daemon=True
        )
        thread.start()

    socketio.run(app, host='0.0.0.0', port=args.port, debug=False, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
