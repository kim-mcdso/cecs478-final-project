#!/usr/bin/env python3
"""
OSI Encapsulation Explorer

Commands to run
  Visualize encapsulation:
    python cecs478-final-project.py simulate --payload "Hello, OSI!"
  Visualize decapsulation:
    python cecs478-final-project.py simulate --payload "Hello" --direction up
  Generate basic PCAP:
    python cecs478-final-project.py pcap --payload "PCAP demo" --out demo.pcap
  Generate advanced PCAP:
    python cecs478-final-project.py pcap --payload "Advanced PCAP" --out advanced.pcap --advanced --proto tcp --src-ip 10.0.0.1 --dst-ip 10.0.0.2 --src-port 12345 --dst-port 80
  OSI vs TCP/IP comparison:
    python cecs478-final-project.py compare
"""

import argparse
import sys
import textwrap
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

# Scapy import (only needed for advanced mode PCAP generation)
try:
    from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


# OSI and TCP layers

OSI_LAYERS = [
    "7 Application",
    "6 Presentation",
    "5 Session",
    "4 Transport",
    "3 Network",
    "2 Data Link",
    "1 Physical",
]

TCPIP_STACK = [
    "Application",
    "Transport",
    "Internet (Network)",
    "Link (Network Access)",
]


@dataclass
class Header:
    name: str
    fields: Dict[str, Any] = field(default_factory=dict)

    def render(self) -> str:
        if not self.fields:
            return f"{self.name} Header"
        kv = ", ".join([f"{k}={v}" for k, v in self.fields.items()])
        return f"{self.name} Header ({kv})"


@dataclass
class PDU:
    headers: List[Header] = field(default_factory=list)
    payload: bytes = b""

    def add_header(self, header: Header):
        self.headers.insert(0, header)  # Add at the 'front' to show outermost first

    def remove_header(self) -> Optional[Header]:
        return self.headers.pop(0) if self.headers else None

    def render_stack(self) -> str:
        lines = []
        for h in self.headers:
            lines.append(f"[{h.render()}]")
        lines.append(f"Payload: {self.payload.decode(errors='replace')}")
        return "\n".join(lines)


# layer visualization
# show how encapsulation and decapsulation happen

def ascii_box(title: str, content: str) -> str:
    border = "-" * 70
    t = f"== {title} =="
    lines = [border, t, border]
    lines.extend(content.splitlines())
    lines.append(border)
    return "\n".join(lines)

# 7 layers in order from 7 to 1 adding each applicable header
def visualize_encapsulation(payload: str) -> str:
    pdu = PDU(payload=payload.encode())
    steps = []

    # Layer 7: Application
    pdu.add_header(Header("Application", {"data_format": "text"}))
    steps.append(step_block("Layer 7", "Application", pdu))

    # Layer 6: Presentation
    pdu.add_header(Header("Presentation", {"encoding": "UTF-8"}))
    steps.append(step_block("Layer 6", "Presentation", pdu))

    # Layer 5: Session
    pdu.add_header(Header("Session", {"session_id": "SYNTH-001"}))
    steps.append(step_block("Layer 5", "Session", pdu))

    # Layer 4: Transport
    pdu.add_header(Header("Transport", {"type": "TCP/UDP (generic)"}))
    steps.append(step_block("Layer 4", "Transport", pdu))

    # Layer 3: Network
    pdu.add_header(Header("Network", {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}))
    steps.append(step_block("Layer 3", "Network", pdu))

    # Layer 2: Data Link
    pdu.add_header(Header("Data Link", {"src_mac": "aa:bb:cc:dd:ee:ff", "dst_mac": "11:22:33:44:55:66"}))
    steps.append(step_block("Layer 2", "Data Link", pdu))

    # Layer 1: Physical
    pdu.add_header(Header("Physical", {"medium": "copper"}))
    steps.append(step_block("Layer 1", "Physical", pdu))

    return "\n\n".join(steps)

# 7 layers in order from 1 to 7 removing each applicable header
def visualize_decapsulation(payload: str) -> str:
    # build as in encapsulation
    pdu = PDU(payload=payload.encode())
    pdu.add_header(Header("Application", {"data_format": "text"}))
    pdu.add_header(Header("Presentation", {"encoding": "UTF-8"}))
    pdu.add_header(Header("Session", {"session_id": "SYNTH-001"}))
    pdu.add_header(Header("Transport", {"type": "TCP/UDP (generic)"}))
    pdu.add_header(Header("Network", {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}))
    pdu.add_header(Header("Data Link", {"src_mac": "aa:bb:cc:dd:ee:ff", "dst_mac": "11:22:33:44:55:66"}))
    pdu.add_header(Header("Physical", {"medium": "copper"}))

    steps = []
    # Starting at Layer 1
    steps.append(step_block("Layer 1", "Physical (receive bits)", pdu))

    # Move upward removing headers
    for layer, name in [
        ("Layer 2", "Data Link"),
        ("Layer 3", "Network"),
        ("Layer 4", "Transport"),
        ("Layer 5", "Session"),
        ("Layer 6", "Presentation"),
        ("Layer 7", "Application"),
    ]:
        removed = pdu.remove_header()
        steps.append(step_block(layer, f"Decapsulate {removed.name}", pdu))

    return "\n\n".join(steps)


def step_block(layer_label: str, layer_name: str, pdu: PDU) -> str:
    content = []
    content.append(f"Layer: {layer_label} - {layer_name}")
    content.append("")
    content.append("Current PDU stack:")
    content.append(pdu.render_stack())
    return ascii_box(f"{layer_label} {layer_name}", "\n".join(content))


# OSI vs. TCP/IP comparisons

def comparison_table() -> str:
    table = textwrap.dedent("""
    +----------------------+-----------------------+
    |        OSI           |        TCP/IP         |
    +----------------------+-----------------------+
    | 7 Application        | Application           |
    | 6 Presentation       | (Merged in App)       |
    | 5 Session            | (Merged in App)       |
    | 4 Transport          | Transport             |
    | 3 Network            | Internet              |
    | 2 Data Link          | Link (Network Access) |
    | 1 Physical           | Link (Network Access) |
    +----------------------+-----------------------+

    Notes:
    - TCP/IP collapses Presentation and Session into the Application layer.
    - Internet layer in TCP/IP aligns with OSI Network layer.
    - Link/Network Access in TCP/IP spans OSI Layers 1–2.
    """).strip("\n")
    return ascii_box("OSI vs TCP/IP comparison", table)


# generating pcap files
# basic pcap file
def generate_basic_pcap(payload: str, out_path: str):
    if not SCAPY_AVAILABLE:
        print("Scapy is not available. Install with 'pip install scapy' to generate PCAPs.")
        sys.exit(1)

    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5555, dport=6666) / Raw(load=payload.encode())
    wrpcap(out_path, [pkt])
    print(f"PCAP written to {out_path} (basic synthetic headers).")

# more advanced pcap file
def generate_advanced_pcap(payload: str, out_path: str, proto: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
    if not SCAPY_AVAILABLE:
        print("Scapy is not available. Install with 'pip install scapy' to generate PCAPs.")
        sys.exit(1)

    eth = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
    ip = IP(src=src_ip, dst=dst_ip)
    if proto.lower() == "tcp":
        l4 = TCP(sport=src_port, dport=dst_port, seq=1000, ack=0, flags="S")
    elif proto.lower() == "udp":
        l4 = UDP(sport=src_port, dport=dst_port)
    else:
        print("Unsupported proto. Use 'tcp' or 'udp'.")
        sys.exit(1)

    pkt = eth / ip / l4 / Raw(load=payload.encode())
    wrpcap(out_path, [pkt])
    print(f"PCAP written to {out_path} (advanced {proto.upper()} with real headers).")


# settings to allow commands to run
def parse_args():
    parser = argparse.ArgumentParser(
        prog="cecs478-final-project",
        description="OSI Encapsulation Explorer - educational visualization and PCAP generation (offline only).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # simulate
    sim = sub.add_parser("simulate", help="Visualize encapsulation or decapsulation.")
    sim.add_argument("--payload", required=True, help="Application data to encapsulate.")
    sim.add_argument("--direction", choices=["down", "up"], default="down", help="down=encapsulation, up=decapsulation.")

    # pcap
    pcap = sub.add_parser("pcap", help="Generate an offline PCAP using synthetic or advanced headers.")
    pcap.add_argument("--payload", required=True, help="Payload to include in the packet.")
    pcap.add_argument("--out", required=True, help="Output .pcap path.")
    pcap.add_argument("--advanced", action="store_true", help="Use realistic headers (Ethernet/IP/TCP/UDP).")
    pcap.add_argument("--proto", choices=["tcp", "udp"], default="udp", help="Transport protocol (advanced mode).")
    pcap.add_argument("--src-ip", default="10.0.0.1", help="Source IP (advanced mode).")
    pcap.add_argument("--dst-ip", default="10.0.0.2", help="Destination IP (advanced mode).")
    pcap.add_argument("--src-port", type=int, default=12345, help="Source port (advanced mode).")
    pcap.add_argument("--dst-port", type=int, default=80, help="Destination port (advanced mode).")

    # compare
    sub.add_parser("compare", help="Show OSI vs TCP/IP side-by-side comparison.")

    return parser.parse_args()


def main():
    args = parse_args()

    if args.command == "simulate":
        if args.direction == "down":
            print(visualize_encapsulation(args.payload))
        else:
            print(visualize_decapsulation(args.payload))

    elif args.command == "pcap":
        if args.advanced:
            generate_advanced_pcap(
                payload=args.payload,
                out_path=args.out,
                proto=args.proto,
                src_ip=args.src_ip,
                dst_ip=args.dst_ip,
                src_port=args.src_port,
                dst_port=args.dst_port,
            )
        else:
            generate_basic_pcap(
                payload=args.payload,
                out_path=args.out,
            )

    elif args.command == "compare":
        print(comparison_table())

    else:
        print("Unknown command.")
        sys.exit(1)


if __name__ == "__main__":
    main()