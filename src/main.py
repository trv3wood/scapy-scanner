
"""
 ARP 扫描
 ICMP 扫描
 TCP SYN 扫描
 TCP Connect 扫描
 TCP XMAS 扫描
 TCP FIN 扫描
 TCP NULL 扫描
 TCP ACK 扫描
 UDP 扫描
"""
import arg
def main():
    parser = arg.Parser()
    args = parser.parse_args()
    print(args)

if __name__ == '__main__':
    main()