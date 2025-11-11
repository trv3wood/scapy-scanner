import argparse
from scapy.layers.inet import IP, TCP, ICMP
from scapy.all import sr1, Packet
from scapy.layers.l2 import Ether, ARP
class Scanner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
    def run(self):
        if not self.args.targets:
            raise ValueError("No target specified for scanning")
        match self.args.scan_type:
            case 'arp':
                self.arp_scan()
            case 'icmp':
                self.icmp_scan()
            case 'syn':
                self.syn_scan()
            case 'tcp':
                self.tcp_connect_scan()
            case 'xmas':
                self.tcp_xmas_scan()
            case 'fin':
                self.tcp_fin_scan()
            case 'null':
                self.tcp_null_scan()
            case 'ack':
                self.tcp_ack_scan()
            case 'udp':
                self.udp_scan()
                
    def _send_packet(self, request, dst_attr: str='dst'):
        for dst_addr in self.args.targets:
            setattr(request, dst_attr, dst_addr)
            # request.show()
            ans = sr1(request, timeout=1, verbose=1)
            if ans:
                ans.show()
            
    def arp_scan(self):
        self._send_packet(Ether()/ARP(), dst_attr='pdst')
            
    def syn_scan(self):
        pass
        
    def icmp_scan(self):
        self._send_packet(IP()/ICMP())
        
    def tcp_connect_scan(self):
        pass
    def tcp_xmas_scan(self):
        pass
    def tcp_fin_scan(self):
        pass
    def tcp_null_scan(self):
        pass
    def tcp_ack_scan(self):
        pass
    def udp_scan(self):
        pass