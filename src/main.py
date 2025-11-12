
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
import asyncio
import arg
import scanner
async def main():
    parser = arg.Parser()
    args = parser.parse_args()
    scan = scanner.Scanner(args)
    result = await scan.run()
    # print(result)
    match args.scan_type:
        case 'icmp' | 'arp':
            for ip, status in result.items():
                print(f"{ip} - {status}")
        case _:
            for target, port_info in result.items():
                for port, status in port_info.items():
                    if status != 'closed':
                        print(f"{target}:{port} - {status}")
                    elif args.verbose:
                        print(f"{target}:{port} - {status}")

if __name__ == '__main__':
    asyncio.run(main())