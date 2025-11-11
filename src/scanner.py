import argparse
from concurrent.futures import ThreadPoolExecutor
from socket import timeout
from scapy.layers.inet import IP, TCP, ICMP
from scapy.all import srp1
from scapy.layers.l2 import ARP
import asyncio

class Scanner:
    def __init__(self, args: argparse.Namespace):
        self.targets = args.targets
        self.scan_type = args.scan_type
        self.timeout = args.timeout or 1
        self.max_workers = args.join_threads
        self.executor = ThreadPoolExecutor(max_workers=args.join_threads)
        self.loop = asyncio.get_event_loop()
    async def run(self):
        if not self.targets:
            raise ValueError("No target specified for scanning")
        match self.scan_type:
            case 'arp':
                await self.arp_scan()
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

    async def _parallel_scan_async(self, coroutines):
        """异步并行扫描"""
        results = {}
        for coro in asyncio.as_completed(coroutines):
            try:
                target, result = await coro
                if result:
                    results[target] = result
                    print(f"收到 {target} 的回复:")
                    result.show()
            except Exception as e:
                print(f"扫描 {target} 时出错: {e}")
        
        return results
            
    async def arp_scan(self):
        async def scan(target):
            print(f"开始扫描 {target}")
            # 使用线程池执行阻塞的scapy操作 - 使用srp1进行层2扫描
            loop = asyncio.get_event_loop()
            try:
                ans = await loop.run_in_executor(
                    self.executor, 
                    srp1, 
                    ARP(pdst=target),
                )
                return target, ans
            except Exception as e:
                print(f"扫描 {target} 时出错: {e}")
                return target, None
        
        # 创建协程列表而不是立即执行
        coroutines = [
            scan(target) for target in self.targets
        ]
        await self._parallel_scan_async(coroutines)

    def syn_scan(self):
        pass
        
    def icmp_scan(self):
        pass
        
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
