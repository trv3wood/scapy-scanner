import argparse
import logging

class Parser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description="simple scanner based on scapy", 
            usage="python main.py [OPTIONS] TARGET"
        )
        self._setup_arguments()
    
    def _setup_arguments(self):
        # Required arguments
        self.parser.add_argument(
            "target",
            help="Target IP address, IP range, or hostname (e.g., 192.168.1.1, 192.168.1.0/24, example.com)",
        )
        
        # Scan type selection
        self.parser.add_argument(
            "-s", "--scan-type",
            choices=["arp", "icmp", "syn", "tcp", "xmas", "fin", "null", "ack", "udp"],
            default="syn",
            help="Scan type: arp, icmp, syn, connect, xmas, fin, null, ack, udp (default: syn)"
        )
        
        # Port options
        self.parser.add_argument(
            "-p", "--ports",
            default="1-1000",
            help="Port range to scan (e.g., 80, 1-100, 22,80,443, 1-65535) (default: 1-1000)"
        )
        
        """
        # Timing options
        self.parser.add_argument(
            "-t", "--timeout",
            type=float,
            default=1.0,
            help="Timeout in seconds for each probe (default: 1.0)"
        )
        
        self.parser.add_argument(
            "-d", "--delay",
            type=float,
            default=0.1,
            help="Delay between probes in seconds (default: 0.1)"
        )
        
        # Output options
        self.parser.add_argument(
            "-v", "--verbose",
            action="store_true",
            help="Enable verbose output"
        )
        
        self.parser.add_argument(
            "-o", "--output",
            help="Output file to save results"
        )
        
        # Advanced options
        self.parser.add_argument(
            "--threads",
            type=int,
            default=10,
            help="Number of threads for parallel scanning (default: 10)"
        )
        
        self.parser.add_argument(
            "--retries",
            type=int,
            default=2,
            help="Number of retries for failed probes (default: 2)"
        )
        
        # Interface selection
        self.parser.add_argument(
            "-i", "--interface",
            help="Network interface to use for scanning"
        )
        
        # Source IP/Port options
        self.parser.add_argument(
            "--source-ip",
            help="Source IP address to use for scanning"
        )
        
        self.parser.add_argument(
            "--source-port",
            type=int,
            help="Source port to use for scanning"
        )
        
        # TCP specific options
        self.parser.add_argument(
            "--tcp-flags",
            help="Custom TCP flags (for advanced users)"
        )
        
        # UDP specific options
        self.parser.add_argument(
            "--udp-payload",
            help="Custom UDP payload to send"
        )
    """
    
    def parse_args(self):
        """Parse command line arguments and return the parsed arguments"""
        args = self.parser.parse_args()
        # Process the target argument using our custom parsing
        if hasattr(args, 'target'):
            args.targets = self._setup_target(args.target)
        return args
    
    def print_help(self):
        """Print help message"""
        self.parser.print_help()
    
    def get_usage_examples(self):
        """Return usage examples for different scan types"""
        examples = [
            "Examples:",
            "  python main.py 192.168.1.1 -s arp                    # ARP scan for single host",
            "  python main.py 192.168.1.0/24 -s arp                 # ARP scan for network range",
            "  python main.py example.com -s icmp                   # ICMP ping sweep",
            "  python main.py 192.168.1.1 -s syn -p 1-1000          # TCP SYN scan on ports 1-1000",
            "  python main.py 192.168.1.1 -s connect -p 80,443      # TCP Connect scan on specific ports",
            "  python main.py 192.168.1.1 -s xmas -p 1-100          # TCP XMAS scan",
            "  python main.py 192.168.1.1 -s fin -p 1-100           # TCP FIN scan",
            "  python main.py 192.168.1.1 -s null -p 1-100          # TCP NULL scan",
            "  python main.py 192.168.1.1 -s ack -p 1-100           # TCP ACK scan",
            "  python main.py 192.168.1.1 -s udp -p 53,67,68        # UDP scan on DNS/DHCP ports",
            # "  python main.py 192.168.1.1 -s syn -p 1-1000 -v -o results.txt  # Verbose with output file",
            # "  python main.py 192.168.1.1 -s syn -t 2.0 -d 0.05 --threads 20   # Custom timing and threads",
        ]
        return "\n".join(examples)

    def _setup_target(self, target_list: str) -> list[str]:
        """
        Set up the target list.

        :param target_list: A string containing the target list.
        :return: A list of targets.
        """
        elements = target_list.split(',')
        result = []
        
        try:
            for e in elements:
                e = e.strip()  # Remove any whitespace
                if '/' in e:
                    # Handle CIDR notation
                    result.extend(self._cidr_to_ip_list(e))
                elif '-' in e:
                    # Handle IP range notation
                    result.extend(self._range_to_ip_list(e))
                else:
                    # Single IP or hostname
                    result.append(e)
            return result
        except Exception as ex:
            logging.error(f"Error parsing target list: {ex}")
            logging.error(self.get_usage_examples())

    def _cidr_to_ip_list(self, cidr: str) -> list[str]:
        """
        Convert a CIDR notation to a list of IP addresses.

        :param cidr: A string in CIDR notation.
        :return: A list of IP addresses.
        """
        try:
            import ipaddress
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except (ValueError, ImportError):
            # Fallback if ipaddress module is not available
            return self._cidr_to_ip_list_fallback(cidr)

    def _cidr_to_ip_list_fallback(self, cidr: str) -> list[str]:
        """
        Fallback method to convert CIDR notation to IP list without ipaddress module.
        
        :param cidr: A string in CIDR notation.
        :return: A list of IP addresses.
        """
        try:
            ip_str, prefix_str = cidr.split('/')
            prefix = int(prefix_str)
            
            # Convert IP to integer
            ip_parts = list(map(int, ip_str.split('.')))
            ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
            
            # Calculate network mask and broadcast address
            mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
            network_addr = ip_int & mask
            broadcast_addr = network_addr | (~mask & 0xFFFFFFFF)
            
            # Generate all IP addresses in the range (excluding network and broadcast)
            result = []
            for ip in range(network_addr + 1, broadcast_addr):
                # Convert integer back to IP string
                ip_str = ".".join(str((ip >> shift) & 0xFF) for shift in (24, 16, 8, 0))
                result.append(ip_str)
            
            return result
        except (ValueError, IndexError):
            raise ValueError(f"Invalid CIDR format: {cidr}")

    def _range_to_ip_list(self, range_str: str) -> list[str]:
        """
        Convert a range notation to a list of IP addresses.

        :param range_str: A string in range notation (e.g., "192.168.1.1-192.168.1.10").
        :return: A list of IP addresses.
        """
        try:
            start_ip, end_ip = range_str.split('-')
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            # Convert IPs to integers
            start_parts = list(map(int, start_ip.split('.')))
            end_parts = list(map(int, end_ip.split('.')))
            
            start_int = (start_parts[0] << 24) + (start_parts[1] << 16) + (start_parts[2] << 8) + start_parts[3]
            end_int = (end_parts[0] << 24) + (end_parts[1] << 16) + (end_parts[2] << 8) + end_parts[3]
            
            # Generate all IP addresses in the range
            result = []
            for ip_int in range(start_int, end_int + 1):
                ip_str = ".".join(str((ip_int >> shift) & 0xFF) for shift in (24, 16, 8, 0))
                result.append(ip_str)
            
            return result
        except (ValueError, IndexError):
            raise ValueError(f"Invalid IP range format: {range_str}")