"""
╔══════════════════════════════════════════════════════════════════╗
║              🔍 Network Packet Sniffer & Analyzer               ║
║         Capture, analyze, and understand network traffic         ║
╚══════════════════════════════════════════════════════════════════╝

A comprehensive Python packet sniffer that captures network packets,
analyzes their structure, and displays detailed information about
source/destination IPs, protocols, and payloads.

Usage:
    Run as Administrator/root:
        python packet_sniffer.py [options]

    Options:
        --count N       Number of packets to capture (default: 50)
        --filter EXPR   BPF filter expression (e.g., "tcp port 80")
        --iface NAME    Network interface to sniff on
        --save FILE     Save captured packets to a .pcap file
        --verbose       Show full payload data
        --stats-only    Show only statistics summary

Author: Network Packet Sniffer Educational Tool
"""

import argparse
import sys
import time
import signal
from datetime import datetime
from collections import Counter, defaultdict
from typing import Optional

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, DNS, ARP, Ether, Raw,
        wrpcap, conf, get_if_list, hexdump
    )
except ImportError:
    print("❌ scapy is not installed. Run: pip install scapy")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    from rich.columns import Columns
    from rich.align import Align
except ImportError:
    print("❌ rich is not installed. Run: pip install rich")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────────
# Global State
# ─────────────────────────────────────────────────────────────────

console = Console()
captured_packets = []
stop_sniffing = False

# Statistics counters
stats = {
    "total": 0,
    "protocols": Counter(),
    "src_ips": Counter(),
    "dst_ips": Counter(),
    "src_ports": Counter(),
    "dst_ports": Counter(),
    "packet_sizes": [],
    "dns_queries": [],
    "tcp_flags": Counter(),
    "start_time": None,
    "arp_count": 0,
}

# Protocol number to name mapping
PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    2: "IGMP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

# Well-known port to service mapping
PORT_SERVICES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP-S", 68: "DHCP-C",
    80: "HTTP", 110: "POP3", 119: "NNTP", 123: "NTP",
    143: "IMAP", 161: "SNMP", 194: "IRC", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP-TLS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Color coding for protocols
PROTOCOL_COLORS = {
    "TCP": "cyan",
    "UDP": "green",
    "ICMP": "yellow",
    "DNS": "magenta",
    "ARP": "red",
    "HTTP": "bright_blue",
    "HTTPS": "bright_green",
    "SSH": "bright_yellow",
    "OTHER": "white",
}


def get_protocol_color(protocol: str) -> str:
    """Get the color for a given protocol."""
    return PROTOCOL_COLORS.get(protocol.upper(), PROTOCOL_COLORS["OTHER"])


def get_service_name(port: int) -> str:
    """Get the service name for a well-known port."""
    return PORT_SERVICES.get(port, str(port))


def format_tcp_flags(flags) -> str:
    """Format TCP flags into readable string."""
    flag_names = []
    flag_map = {
        'S': 'SYN', 'A': 'ACK', 'F': 'FIN',
        'R': 'RST', 'P': 'PSH', 'U': 'URG',
        'E': 'ECE', 'C': 'CWR',
    }
    flags_str = str(flags)
    for char, name in flag_map.items():
        if char in flags_str:
            flag_names.append(name)
    return "|".join(flag_names) if flag_names else str(flags)


def format_payload(payload: bytes, max_length: int = 100) -> str:
    """Format raw payload data for display."""
    if not payload:
        return "[dim]No payload[/dim]"

    try:
        # Try to decode as ASCII/UTF-8 text
        text = payload.decode('utf-8', errors='replace')
        # Clean up non-printable characters
        cleaned = ''.join(c if c.isprintable() or c in '\n\r\t' else '.' for c in text)
        if len(cleaned) > max_length:
            cleaned = cleaned[:max_length] + "..."
        return f"[dim]{cleaned}[/dim]"
    except Exception:
        # Show hex representation
        hex_str = payload.hex()
        if len(hex_str) > max_length:
            hex_str = hex_str[:max_length] + "..."
        return f"[dim]0x{hex_str}[/dim]"


def get_packet_layers(packet) -> list:
    """Extract all protocol layers from a packet."""
    layers = []
    counter = 0
    while True:
        layer = packet.getlayer(counter)
        if layer is None:
            break
        layers.append(layer.__class__.__name__)
        counter += 1
    return layers


# ─────────────────────────────────────────────────────────────────
# Packet Analysis Engine
# ─────────────────────────────────────────────────────────────────

def analyze_packet(packet, verbose: bool = False) -> Optional[dict]:
    """
    Analyze a captured packet and extract all relevant information.

    Returns a dictionary containing:
        - timestamp: When the packet was captured
        - src_ip / dst_ip: Source and destination IP addresses
        - src_port / dst_port: Source and destination ports
        - protocol: Protocol name (TCP, UDP, ICMP, etc.)
        - service: Service name if using well-known port
        - size: Packet size in bytes
        - ttl: Time to live
        - flags: TCP flags (if applicable)
        - payload: Raw payload data
        - layers: All protocol layers in the packet
        - info: Additional protocol-specific information
    """
    info = {
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
        "payload": b"",
        "layers": get_packet_layers(packet),
        "info": "",
        "src_mac": "",
        "dst_mac": "",
    }

    stats["total"] += 1
    stats["packet_sizes"].append(len(packet))

    # ── Ethernet Layer ──
    if packet.haslayer(Ether):
        info["src_mac"] = packet[Ether].src
        info["dst_mac"] = packet[Ether].dst

    # ── ARP Layer ──
    if packet.haslayer(ARP):
        arp = packet[ARP]
        info["protocol"] = "ARP"
        info["src_ip"] = arp.psrc
        info["dst_ip"] = arp.pdst
        op_name = "Request" if arp.op == 1 else "Reply"
        info["info"] = f"ARP {op_name}: Who has {arp.pdst}? Tell {arp.psrc}"
        stats["arp_count"] += 1
        stats["protocols"]["ARP"] += 1
        return info

    # ── IP Layer ──
    if not packet.haslayer(IP):
        return info

    ip_layer = packet[IP]
    info["src_ip"] = ip_layer.src
    info["dst_ip"] = ip_layer.dst
    info["ttl"] = str(ip_layer.ttl)

    proto_num = ip_layer.proto
    info["protocol"] = PROTOCOL_MAP.get(proto_num, f"Proto({proto_num})")

    stats["src_ips"][ip_layer.src] += 1
    stats["dst_ips"][ip_layer.dst] += 1

    # ── TCP Layer ──
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        info["src_port"] = str(tcp.sport)
        info["dst_port"] = str(tcp.dport)
        info["flags"] = format_tcp_flags(tcp.flags)
        info["protocol"] = "TCP"

        # Determine service
        service = get_service_name(tcp.dport)
        if service == str(tcp.dport):
            service = get_service_name(tcp.sport)
        info["service"] = service if service != str(tcp.sport) else ""

        stats["src_ports"][tcp.sport] += 1
        stats["dst_ports"][tcp.dport] += 1
        stats["tcp_flags"][info["flags"]] += 1

        # Build info string
        flag_str = info["flags"]
        seq_info = f"Seq={tcp.seq} Ack={tcp.ack}" if verbose else ""
        win_info = f"Win={tcp.window}" if verbose else ""
        info["info"] = f"[{flag_str}] {seq_info} {win_info}".strip()

    # ── UDP Layer ──
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        info["src_port"] = str(udp.sport)
        info["dst_port"] = str(udp.dport)
        info["protocol"] = "UDP"

        service = get_service_name(udp.dport)
        if service == str(udp.dport):
            service = get_service_name(udp.sport)
        info["service"] = service if service != str(udp.sport) else ""

        stats["src_ports"][udp.sport] += 1
        stats["dst_ports"][udp.dport] += 1

    # ── ICMP Layer ──
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        info["protocol"] = "ICMP"
        icmp_types = {
            0: "Echo Reply", 3: "Dest Unreachable", 4: "Source Quench",
            5: "Redirect", 8: "Echo Request", 11: "Time Exceeded",
            13: "Timestamp Request", 14: "Timestamp Reply",
        }
        type_name = icmp_types.get(icmp.type, f"Type {icmp.type}")
        info["info"] = f"{type_name} (code={icmp.code})"

    # ── DNS Layer ──
    if packet.haslayer(DNS):
        dns = packet[DNS]
        info["protocol"] = "DNS"
        try:
            if dns.qr == 0:  # Query
                query_name = dns.qd.qname.decode() if dns.qd else "N/A"
                info["info"] = f"Query: {query_name}"
                stats["dns_queries"].append(query_name)
            else:  # Response
                query_name = dns.qd.qname.decode() if dns.qd else "N/A"
                ans_count = dns.ancount
                info["info"] = f"Response: {query_name} ({ans_count} answers)"
        except Exception:
            info["info"] = "DNS packet"

    stats["protocols"][info["protocol"]] += 1

    # ── Extract Payload ──
    if packet.haslayer(Raw):
        info["payload"] = bytes(packet[Raw].load)

    return info


# ─────────────────────────────────────────────────────────────────
# Display Functions
# ─────────────────────────────────────────────────────────────────

def display_banner():
    """Display the application banner."""
    banner = """
[bold bright_cyan]╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗              ║
║   ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝              ║
║   ██████╔╝███████║██║     █████╔╝ █████╗     ██║                 ║
║   ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║                 ║
║   ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║                 ║
║   ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝                 ║
║                                                                  ║
║   ███████╗███╗   ██╗██╗███████╗███████╗███████╗██████╗           ║
║   ██╔════╝████╗  ██║██║██╔════╝██╔════╝██╔════╝██╔══██╗          ║
║   ███████╗██╔██╗ ██║██║█████╗  █████╗  █████╗  ██████╔╝          ║
║   ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██╗          ║
║   ███████║██║ ╚████║██║██║     ██║     ███████╗██║  ██║          ║
║   ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝          ║
║                                                                  ║
║          🔍 Network Packet Sniffer & Analyzer v1.0               ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝[/bold bright_cyan]
"""
    console.print(banner)


def display_packet(info: dict, packet_num: int, verbose: bool = False):
    """Display a single analyzed packet with rich formatting."""
    protocol = info["protocol"]
    color = get_protocol_color(protocol)

    # Build the main packet line
    src = f"{info['src_ip']}"
    dst = f"{info['dst_ip']}"
    if info["src_port"]:
        src += f":{info['src_port']}"
    if info["dst_port"]:
        dst += f":{info['dst_port']}"

    service_tag = f" [{info['service']}]" if info['service'] else ""

    # Packet header
    console.print(
        f"  [{color}]#{packet_num:<5}[/{color}] "
        f"[dim]{info['timestamp']}[/dim]  "
        f"[bold {color}]{protocol:<6}[/bold {color}]{service_tag:<12} "
        f"[white]{src:<24}[/white] → [white]{dst:<24}[/white]  "
        f"[dim]{info['size']:>5}B[/dim]  "
        f"{'TTL=' + info['ttl'] + '  ' if info['ttl'] else ''}"
        f"{info['info']}"
    )

    # Show payload if verbose
    if verbose and info["payload"]:
        payload_str = format_payload(info["payload"], max_length=200)
        console.print(f"         └─ Payload: {payload_str}")

    # Show layers if verbose
    if verbose and len(info["layers"]) > 1:
        layers_str = " → ".join(info["layers"])
        console.print(f"         └─ Layers: [dim]{layers_str}[/dim]")


def display_separator():
    """Display a visual separator."""
    console.print("[dim]" + "─" * 120 + "[/dim]")


def display_statistics():
    """Display comprehensive capture statistics."""
    if stats["total"] == 0:
        console.print("\n[yellow]No packets captured.[/yellow]")
        return

    elapsed = time.time() - stats["start_time"] if stats["start_time"] else 0
    avg_size = sum(stats["packet_sizes"]) / len(stats["packet_sizes"]) if stats["packet_sizes"] else 0
    pps = stats["total"] / elapsed if elapsed > 0 else 0

    console.print("\n")
    display_separator()

    # ── Summary Panel ──
    summary_text = (
        f"[bold]Total Packets:[/bold] {stats['total']}  │  "
        f"[bold]Duration:[/bold] {elapsed:.1f}s  │  "
        f"[bold]Rate:[/bold] {pps:.1f} pkt/s  │  "
        f"[bold]Avg Size:[/bold] {avg_size:.0f}B  │  "
        f"[bold]Min/Max Size:[/bold] {min(stats['packet_sizes'])}B / {max(stats['packet_sizes'])}B"
    )
    console.print(Panel(
        Align.center(summary_text),
        title="[bold bright_cyan]📊 Capture Summary[/bold bright_cyan]",
        border_style="bright_cyan",
        box=box.DOUBLE,
    ))

    # ── Protocol Distribution ──
    if stats["protocols"]:
        proto_table = Table(
            title="🌐 Protocol Distribution",
            box=box.ROUNDED,
            border_style="cyan",
            show_lines=True,
            title_style="bold bright_cyan",
        )
        proto_table.add_column("Protocol", style="bold", justify="center", min_width=12)
        proto_table.add_column("Count", justify="center", min_width=8)
        proto_table.add_column("Percentage", justify="center", min_width=12)
        proto_table.add_column("Bar", min_width=30)

        for proto, count in stats["protocols"].most_common(10):
            pct = (count / stats["total"]) * 100
            bar_len = int(pct / 100 * 25)
            bar = "█" * bar_len + "░" * (25 - bar_len)
            color = get_protocol_color(proto)
            proto_table.add_row(
                f"[{color}]{proto}[/{color}]",
                str(count),
                f"{pct:.1f}%",
                f"[{color}]{bar}[/{color}]"
            )
        console.print(proto_table)

    # ── Top Talkers ──
    tables = []

    if stats["src_ips"]:
        src_table = Table(
            title="📤 Top Source IPs",
            box=box.ROUNDED,
            border_style="green",
            title_style="bold green",
        )
        src_table.add_column("IP Address", style="bold white", min_width=18)
        src_table.add_column("Packets", justify="center", min_width=8)
        for ip, count in stats["src_ips"].most_common(8):
            src_table.add_row(ip, str(count))
        tables.append(src_table)

    if stats["dst_ips"]:
        dst_table = Table(
            title="📥 Top Destination IPs",
            box=box.ROUNDED,
            border_style="red",
            title_style="bold red",
        )
        dst_table.add_column("IP Address", style="bold white", min_width=18)
        dst_table.add_column("Packets", justify="center", min_width=8)
        for ip, count in stats["dst_ips"].most_common(8):
            dst_table.add_row(ip, str(count))
        tables.append(dst_table)

    if tables:
        console.print(Columns(tables, padding=(1, 4)))

    # ── Port Analysis ──
    port_tables = []

    if stats["dst_ports"]:
        port_table = Table(
            title="🔌 Top Destination Ports",
            box=box.ROUNDED,
            border_style="magenta",
            title_style="bold magenta",
        )
        port_table.add_column("Port", justify="center", min_width=8)
        port_table.add_column("Service", style="bold", min_width=12)
        port_table.add_column("Packets", justify="center", min_width=8)
        for port, count in stats["dst_ports"].most_common(8):
            service = get_service_name(port)
            port_table.add_row(str(port), service, str(count))
        port_tables.append(port_table)

    if stats["tcp_flags"]:
        flags_table = Table(
            title="🚩 TCP Flags Distribution",
            box=box.ROUNDED,
            border_style="yellow",
            title_style="bold yellow",
        )
        flags_table.add_column("Flags", style="bold", min_width=20)
        flags_table.add_column("Count", justify="center", min_width=8)
        for flags, count in stats["tcp_flags"].most_common(8):
            flags_table.add_row(flags, str(count))
        port_tables.append(flags_table)

    if port_tables:
        console.print(Columns(port_tables, padding=(1, 4)))

    # ── DNS Queries ──
    if stats["dns_queries"]:
        dns_table = Table(
            title="🔎 DNS Queries Captured",
            box=box.ROUNDED,
            border_style="bright_magenta",
            title_style="bold bright_magenta",
        )
        dns_table.add_column("#", justify="center", min_width=4)
        dns_table.add_column("Domain", style="bold white", min_width=40)

        # Show unique queries
        seen = set()
        idx = 0
        for query in stats["dns_queries"]:
            if query not in seen and idx < 15:
                seen.add(query)
                idx += 1
                dns_table.add_row(str(idx), query)

        console.print(dns_table)

    display_separator()


# ─────────────────────────────────────────────────────────────────
# Packet Capture Engine
# ─────────────────────────────────────────────────────────────────

def packet_callback(packet, verbose: bool = False):
    """Callback function invoked for each captured packet."""
    global captured_packets

    info = analyze_packet(packet, verbose=verbose)
    if info:
        captured_packets.append(info)
        display_packet(info, stats["total"], verbose=verbose)


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    global stop_sniffing
    stop_sniffing = True
    console.print("\n\n[bold yellow]⚠ Capture interrupted by user (Ctrl+C)[/bold yellow]")


def list_interfaces():
    """List available network interfaces."""
    console.print("\n[bold bright_cyan]📡 Available Network Interfaces:[/bold bright_cyan]\n")
    interfaces = get_if_list()
    iface_table = Table(box=box.ROUNDED, border_style="cyan")
    iface_table.add_column("#", justify="center", min_width=4)
    iface_table.add_column("Interface Name", style="bold white", min_width=30)

    for i, iface in enumerate(interfaces, 1):
        iface_table.add_row(str(i), iface)

    console.print(iface_table)
    return interfaces


def start_capture(count: int = 50, bpf_filter: str = None,
                  iface: str = None, save_file: str = None,
                  verbose: bool = False):
    """
    Start capturing network packets.

    Args:
        count: Number of packets to capture (0 = unlimited)
        bpf_filter: BPF filter expression (e.g., "tcp port 80")
        iface: Network interface to sniff on
        save_file: Path to save captured packets (.pcap)
        verbose: Show detailed packet information
    """
    global stop_sniffing
    stats["start_time"] = time.time()

    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    # Display capture configuration
    config_text = []
    config_text.append(f"[bold]Interface:[/bold]  {iface or 'Default'}")
    config_text.append(f"[bold]Filter:[/bold]     {bpf_filter or 'None (all traffic)'}")
    config_text.append(f"[bold]Max Packets:[/bold] {count if count > 0 else 'Unlimited'}")
    config_text.append(f"[bold]Verbose:[/bold]    {'Yes' if verbose else 'No'}")
    if save_file:
        config_text.append(f"[bold]Save to:[/bold]   {save_file}")

    console.print(Panel(
        "\n".join(config_text),
        title="[bold green]⚙ Capture Configuration[/bold green]",
        border_style="green",
        box=box.ROUNDED,
    ))

    console.print("\n[bold bright_green]▶ Starting packet capture...[/bold bright_green]")
    console.print("[dim]Press Ctrl+C to stop capturing\n[/dim]")

    # Table header
    header = (
        f"  [bold]{'#':<6} {'Time':<13} {'Proto':<18} "
        f"{'Source':<24} {'→':^3} {'Destination':<24} "
        f"{'Size':>6}  {'Info'}[/bold]"
    )
    console.print(header)
    display_separator()

    # Capture packets
    raw_packets = []

    def _callback(pkt):
        raw_packets.append(pkt)
        packet_callback(pkt, verbose=verbose)

    try:
        sniff_kwargs = {
            "prn": _callback,
            "store": False,
            "stop_filter": lambda x: stop_sniffing,
        }
        if count > 0:
            sniff_kwargs["count"] = count
        if bpf_filter:
            sniff_kwargs["filter"] = bpf_filter
        if iface:
            sniff_kwargs["iface"] = iface

        sniff(**sniff_kwargs)

    except PermissionError:
        console.print(
            "\n[bold red]❌ Permission denied![/bold red]\n"
            "[yellow]Packet sniffing requires administrator/root privileges.\n"
            "  • Windows: Run as Administrator\n"
            "  • Linux/Mac: Run with sudo[/yellow]"
        )
        return
    except OSError as e:
        if "Npcap" in str(e) or "winpcap" in str(e).lower() or "pcap" in str(e).lower():
            console.print(
                "\n[bold red]❌ Npcap/WinPcap not found![/bold red]\n"
                "[yellow]Scapy requires Npcap for Windows packet capture.\n"
                "  Download from: https://npcap.com/#download\n"
                "  Install with 'WinPcap API-compatible Mode' checked.[/yellow]"
            )
        else:
            console.print(f"\n[bold red]❌ OS Error: {e}[/bold red]")
        return
    except Exception as e:
        console.print(f"\n[bold red]❌ Error during capture: {e}[/bold red]")
        return

    # Save packets if requested
    if save_file and raw_packets:
        try:
            wrpcap(save_file, raw_packets)
            console.print(f"\n[bold green]💾 Saved {len(raw_packets)} packets to {save_file}[/bold green]")
        except Exception as e:
            console.print(f"\n[bold red]❌ Error saving packets: {e}[/bold red]")

    # Display statistics
    display_statistics()


# ─────────────────────────────────────────────────────────────────
# Educational Information
# ─────────────────────────────────────────────────────────────────

def show_protocol_guide():
    """Display educational information about network protocols."""
    console.print("\n")

    # OSI Model
    osi_table = Table(
        title="📚 OSI Model - Network Layers",
        box=box.DOUBLE,
        border_style="bright_cyan",
        title_style="bold bright_cyan",
        show_lines=True,
    )
    osi_table.add_column("Layer", justify="center", style="bold", min_width=8)
    osi_table.add_column("Name", style="bold white", min_width=16)
    osi_table.add_column("Protocols", min_width=25)
    osi_table.add_column("Description", min_width=40)

    osi_data = [
        ("7", "Application", "HTTP, DNS, SMTP, FTP", "End-user services & interfaces"),
        ("6", "Presentation", "SSL/TLS, JPEG, ASCII", "Data formatting & encryption"),
        ("5", "Session", "NetBIOS, RPC", "Session management & control"),
        ("4", "Transport", "TCP, UDP", "End-to-end delivery & reliability"),
        ("3", "Network", "IP, ICMP, ARP", "Logical addressing & routing"),
        ("2", "Data Link", "Ethernet, Wi-Fi", "Physical addressing (MAC)"),
        ("1", "Physical", "Cables, Signals", "Raw bit transmission"),
    ]

    for layer, name, protocols, desc in osi_data:
        osi_table.add_row(layer, name, protocols, desc)

    console.print(osi_table)

    # Common protocols
    proto_panel = Panel(
        "[bold cyan]TCP[/bold cyan] - Transmission Control Protocol\n"
        "  → Connection-oriented, reliable delivery with 3-way handshake (SYN → SYN-ACK → ACK)\n"
        "  → Used by: HTTP, HTTPS, SSH, FTP, SMTP\n\n"
        "[bold green]UDP[/bold green] - User Datagram Protocol\n"
        "  → Connectionless, fast but unreliable (no delivery guarantee)\n"
        "  → Used by: DNS, DHCP, VoIP, streaming, gaming\n\n"
        "[bold yellow]ICMP[/bold yellow] - Internet Control Message Protocol\n"
        "  → Network diagnostics and error reporting\n"
        "  → Used by: ping, traceroute\n\n"
        "[bold magenta]DNS[/bold magenta] - Domain Name System\n"
        "  → Translates domain names to IP addresses\n"
        "  → Usually uses UDP port 53\n\n"
        "[bold red]ARP[/bold red] - Address Resolution Protocol\n"
        "  → Maps IP addresses to MAC addresses on local network\n"
        "  → Works at Layer 2 (Data Link)",
        title="[bold bright_cyan]📖 Protocol Reference Guide[/bold bright_cyan]",
        border_style="bright_cyan",
        box=box.DOUBLE,
    )
    console.print(proto_panel)

    # Filter examples
    filter_panel = Panel(
        "[bold]Common BPF Filter Expressions:[/bold]\n\n"
        '  [cyan]"tcp"[/cyan]                  → Capture only TCP packets\n'
        '  [cyan]"udp"[/cyan]                  → Capture only UDP packets\n'
        '  [cyan]"icmp"[/cyan]                 → Capture only ICMP (ping) packets\n'
        '  [cyan]"port 80"[/cyan]              → Capture HTTP traffic\n'
        '  [cyan]"port 443"[/cyan]             → Capture HTTPS traffic\n'
        '  [cyan]"tcp port 80"[/cyan]          → Capture TCP traffic on port 80\n'
        '  [cyan]"host 192.168.1.1"[/cyan]     → Capture traffic to/from specific host\n'
        '  [cyan]"src host 10.0.0.1"[/cyan]    → Capture traffic from specific source\n'
        '  [cyan]"dst port 53"[/cyan]          → Capture traffic to DNS port\n'
        '  [cyan]"tcp and port 22"[/cyan]      → Capture SSH traffic\n'
        '  [cyan]"not arp"[/cyan]              → Exclude ARP packets\n'
        '  [cyan]"len > 100"[/cyan]            → Packets larger than 100 bytes',
        title="[bold green]🔧 BPF Filter Examples[/bold green]",
        border_style="green",
        box=box.ROUNDED,
    )
    console.print(filter_panel)


# ─────────────────────────────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🔍 Network Packet Sniffer & Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python packet_sniffer.py                       # Capture 50 packets on default interface
  python packet_sniffer.py --count 100           # Capture 100 packets
  python packet_sniffer.py --filter "tcp port 80" # Capture only HTTP traffic
  python packet_sniffer.py --verbose             # Show payload and layer details
  python packet_sniffer.py --save capture.pcap   # Save to pcap file
  python packet_sniffer.py --guide               # Show protocol educational guide
  python packet_sniffer.py --interfaces          # List available interfaces
        """
    )

    parser.add_argument("--count", "-c", type=int, default=50,
                        help="Number of packets to capture (0 = unlimited, default: 50)")
    parser.add_argument("--filter", "-f", type=str, default=None,
                        help='BPF filter expression (e.g., "tcp port 80")')
    parser.add_argument("--iface", "-i", type=str, default=None,
                        help="Network interface to sniff on")
    parser.add_argument("--save", "-s", type=str, default=None,
                        help="Save captured packets to a .pcap file")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed packet information (payload, layers)")
    parser.add_argument("--guide", "-g", action="store_true",
                        help="Show protocol educational guide")
    parser.add_argument("--interfaces", action="store_true",
                        help="List available network interfaces")

    args = parser.parse_args()

    display_banner()

    if args.guide:
        show_protocol_guide()
        return

    if args.interfaces:
        list_interfaces()
        return

    start_capture(
        count=args.count,
        bpf_filter=args.filter,
        iface=args.iface,
        save_file=args.save,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
