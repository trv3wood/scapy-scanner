# Scapy Scanner

A powerful network scanner built with Python and Scapy that supports multiple scanning techniques.

## Features

- **ARP Scanning**: Discover hosts on local network using ARP requests
- **ICMP Scanning**: Ping sweep to identify active hosts
- **TCP SYN Scanning**: Stealthy TCP port scanning
- **TCP Connect Scanning**: Full TCP connection port scanning
- **TCP XMAS Scanning**: XMAS tree scan (FIN, PSH, URG flags)
- **TCP FIN Scanning**: FIN scan for firewall evasion
- **TCP NULL Scanning**: NULL scan (no flags set)
- **TCP ACK Scanning**: ACK scan for firewall rule detection
- **UDP Scanning**: UDP port scanning

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd scapy-scanner
```

2. Create a virtual environment (recommended):
```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # Linux/Mac
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

```bash
python src/main.py [OPTIONS] TARGET
```

### Examples

```bash
# ARP scan for single host
python src/main.py 192.168.1.1 -s arp

# ARP scan for network range
python src/main.py 192.168.1.0/24 -s arp

# ICMP ping sweep
python src/main.py example.com -s icmp

# TCP SYN scan on ports 1-1000
python src/main.py 192.168.1.1 -s syn -p 1-1000

# TCP Connect scan on specific ports
python src/main.py 192.168.1.1 -s connect -p 80,443

# TCP XMAS scan
python src/main.py 192.168.1.1 -s xmas -p 1-100

# TCP FIN scan
python src/main.py 192.168.1.1 -s fin -p 1-100

# TCP NULL scan
python src/main.py 192.168.1.1 -s null -p 1-100

# TCP ACK scan
python src/main.py 192.168.1.1 -s ack -p 1-100

# UDP scan on DNS/DHCP ports
python src/main.py 192.168.1.1 -s udp -p 53,67,68
```

### Command Line Options

- `TARGET`: Target IP address, IP range, or hostname (e.g., 192.168.1.1, 192.168.1.0/24, example.com)
- `-s, --scan-type`: Scan type (arp, icmp, syn, connect, xmas, fin, null, ack, udp) - default: syn
- `-p, --ports`: Port range to scan (e.g., 80, 1-100, 22,80,443, 1-65535) - default: 1-1000

## Project Structure

```
scapy-scanner/
├── src/
│   ├── main.py          # Main entry point
│   ├── arg.py           # Command line argument parser
│   ├── scanner.py       # Scanner implementation
│   ├── test_parser.py   # Parser testing
│   └── test_ip_parsing.py # IP parsing testing
├── requirements.txt     # Python dependencies
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

## Requirements

- Python 3.6+
- Scapy 2.4.5+

## Legal Notice

This tool is intended for educational purposes and authorized security testing only. Ensure you have proper authorization before scanning any network or system. Unauthorized scanning may be illegal in your jurisdiction.

## License

This project is for educational purposes.
