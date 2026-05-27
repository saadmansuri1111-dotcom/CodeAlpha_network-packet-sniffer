# 🔍 Network Packet Sniffer & Analyzer

A comprehensive Python tool for capturing, analyzing, and visualizing network traffic packets. Built for learning about network protocols and understanding how data flows through a network.

## Features

### 📡 Terminal Sniffer (`packet_sniffer.py`)
- **Real-time packet capture** using Scapy
- **Rich terminal UI** with color-coded protocols
- **Protocol analysis**: TCP, UDP, ICMP, DNS, ARP, and more
- **Detailed statistics**: protocol distribution, top talkers, port analysis, DNS queries
- **BPF filtering**: capture specific traffic types
- **PCAP export**: save captures for analysis in Wireshark
- **Educational guide**: built-in protocol reference and OSI model overview

### 🌐 Web Dashboard (`web_dashboard.py`)
- **Real-time web interface** with live packet feed
- **Interactive protocol chart** (doughnut visualization)
- **Top sources/destinations** auto-updating list
- **DNS query tracker** showing resolved domains
- **Start/Stop capture** from the browser
- **Beautiful dark theme** with glassmorphism design

---

## Prerequisites

### Windows
1. **Python 3.8+** — [Download](https://www.python.org/downloads/)
2. **Npcap** — Required for packet capture on Windows
   - Download from: https://npcap.com/#download
   - During installation, check **"WinPcap API-compatible Mode"**

### Linux/macOS
- Python 3.8+
- Run with `sudo` for packet capture privileges

---

## Installation

```bash
# Navigate to the project directory
cd network-packet-sniffer

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Terminal Sniffer

```bash
# Basic capture (50 packets on default interface)
python packet_sniffer.py

# Capture 100 packets with verbose output
python packet_sniffer.py --count 100 --verbose

# Filter HTTP traffic only
python packet_sniffer.py --filter "tcp port 80"

# Capture DNS queries
python packet_sniffer.py --filter "udp port 53" --verbose

# Save capture to file
python packet_sniffer.py --save my_capture.pcap

# Show protocol educational guide
python packet_sniffer.py --guide

# List available network interfaces
python packet_sniffer.py --interfaces

# Capture unlimited packets (Ctrl+C to stop)
python packet_sniffer.py --count 0
```

### Web Dashboard

```bash
# Start the web dashboard
python web_dashboard.py

# Custom port
python web_dashboard.py --port 8080

# Auto-start capture with a filter
python web_dashboard.py --auto-start --filter "tcp"
```

Then open **http://localhost:5000** in your browser.

> ⚠️ **Important**: Both tools require **Administrator/root privileges** for packet capture.

---

## Understanding the Output

### Protocol Color Coding
| Color | Protocol | Description |
|-------|----------|-------------|
| 🔵 Cyan | TCP | Transmission Control Protocol (reliable) |
| 🟢 Green | UDP | User Datagram Protocol (fast, unreliable) |
| 🟡 Yellow | ICMP | Internet Control Message Protocol (ping) |
| 🟣 Purple | DNS | Domain Name System (name resolution) |
| 🔴 Red | ARP | Address Resolution Protocol (MAC lookup) |

### Packet Information
- **Source/Destination IP**: Where the packet came from and where it's going
- **Ports**: Source and destination port numbers (identify services)
- **TTL**: Time To Live — how many network hops remain
- **Flags**: TCP control flags (SYN, ACK, FIN, RST, PSH)
- **Payload**: The actual data being transmitted

### Common BPF Filters
```
tcp                    → TCP packets only
udp                    → UDP packets only
icmp                   → ICMP (ping) packets
port 80                → HTTP traffic
port 443               → HTTPS traffic
host 192.168.1.1       → Traffic to/from specific host
src host 10.0.0.1      → From specific source
dst port 53            → To DNS port
tcp and port 22        → SSH traffic
not arp                → Exclude ARP packets
```

---

## Project Structure

```
network-packet-sniffer/
├── packet_sniffer.py    # Terminal-based packet sniffer
├── web_dashboard.py     # Web-based dashboard with real-time UI
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

---

## How Network Packets Work

### OSI Model (7 Layers)
```
Layer 7: Application    → HTTP, DNS, SMTP, FTP
Layer 6: Presentation   → SSL/TLS, encoding
Layer 5: Session        → Session management
Layer 4: Transport      → TCP (reliable), UDP (fast)
Layer 3: Network        → IP addressing, routing
Layer 2: Data Link      → MAC addresses, Ethernet
Layer 1: Physical       → Cables, signals, bits
```

### TCP 3-Way Handshake
```
Client  ──── SYN ────→  Server     (Hey, let's connect!)
Client  ←── SYN|ACK ──  Server     (Sure, I'm ready!)
Client  ──── ACK ────→  Server     (Great, connected!)
```

### Packet Structure
```
┌──────────────────────────────────────────────┐
│ Ethernet Header (MAC addresses, 14 bytes)    │
├──────────────────────────────────────────────┤
│ IP Header (Source/Dest IP, TTL, 20+ bytes)   │
├──────────────────────────────────────────────┤
│ TCP/UDP Header (Ports, Flags, 8-20+ bytes)   │
├──────────────────────────────────────────────┤
│ Payload / Application Data                   │
└──────────────────────────────────────────────┘
```

---

## License

This project is for educational purposes only. Use responsibly and only monitor networks you have permission to analyze.
