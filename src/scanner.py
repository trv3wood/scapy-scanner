import scapy
class Scanner:
    def __init__(self, args):
        self.args = args
    def send(self):
        if not self.args.target:
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
    def arp_scan():
        pass
    def syn_scan():
        pass
    def icmp_scan():
        pass
    def tcp_connect_scan():
        pass
    def tcp_xmas_scan():
        pass
    def tcp_fin_scan():
        pass
    def tcp_null_scan():
        pass
    def tcp_ack_scan():
        pass
    def udp_scan():
        pass