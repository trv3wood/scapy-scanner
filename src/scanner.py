import argparse
from concurrent.futures import ThreadPoolExecutor
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.all import srp1, sr1
from scapy.layers.l2 import ARP, Ether
import asyncio
import socket

class Scanner:
    def __init__(self, args: argparse.Namespace):
        self.targets = args.targets
        self.scan_type = args.scan_type
        self.timeout = args.timeout or 1
        self.max_workers = args.join_threads
        self.verbose = args.verbose | False
        self.ports = args.ports
        self.executor = ThreadPoolExecutor(max_workers=args.join_threads)
        self.loop = asyncio.get_event_loop()
        
    async def run(self):
        if not self.targets:
            raise ValueError("No target specified for scanning")
        match self.scan_type:
            case 'arp':
                return await self.arp_scan()
            case 'icmp':
                return await self.icmp_scan()
            case 'syn':
                return await self.syn_scan()
            case 'tcp':
                return await self.tcp_connect_scan()
            case 'xmas':
                return await self.tcp_xmas_scan()
            case 'fin':
                return await self.tcp_fin_scan()
            case 'null':
                return await self.tcp_null_scan()
            case 'ack':
                return await self.tcp_ack_scan()
            case 'udp':
                return await self.udp_scan()

    # buggy!!!
    async def arp_scan(self):
        """ARP扫描 - 使用ARP协议发现局域网内的主机"""
        async def scan(target):
            loop = asyncio.get_event_loop()
            try:
                # 创建ARP请求包
                arp_packet = ARP(pdst=target)
                # 创建以太网帧
                ether_packet = Ether(dst="ff:ff:ff:ff:ff:ff")
                # 组合包
                packet = ether_packet/arp_packet
                # packet = arp_packet
                
                # 发送ARP请求并等待响应
                response = await loop.run_in_executor(
                    self.executor,
                    lambda: srp1(packet, timeout=self.timeout, verbose=self.verbose)
                )
                
                # print(response)
                if response is None:
                    return target, "offline"  # 无响应，主机离线
                elif response.haslayer(ARP):
                    # 获取MAC地址
                    mac_address = response[ARP].hwsrc
                    return target, f"online (MAC: {mac_address})"
                return target, "offline"
            except Exception as e:
                print(f"ARP扫描 {target} 时出错: {e}")
                return target, "error"
        
        coroutines = [scan(target) for target in self.targets]
        results = {}
        
        for coro in asyncio.as_completed(coroutines):
            target, status = await coro
            results[target] = status
        
        return results

    async def syn_scan(self):
        """SYN扫描 - 半开放扫描，发送SYN包，根据响应判断端口状态"""
        async def scan_port(target, port):
            loop = asyncio.get_event_loop()
            try:
                # 创建SYN包
                syn_packet = IP(dst=target)/TCP(dport=port, flags="S")
                # 发送SYN包并等待响应
                response = await loop.run_in_executor(
                    self.executor,
                    lambda: sr1(syn_packet, timeout=self.timeout, verbose=self.verbose)
                )
                
                if response is None:
                    return target, port, "filtered"  # 无响应，可能被过滤
                elif response.haslayer(TCP):
                    if response[TCP].flags == "SA":  # SYN-ACK
                        # 发送RST包关闭连接
                        rst_packet = IP(dst=target)/TCP(dport=port, flags="R")
                        await loop.run_in_executor(
                            self.executor,
                            lambda: sr1(rst_packet, timeout=self.timeout, verbose=False)
                        )
                        return target, port, "open"
                    elif response[TCP].flags == "RA":  # RST-ACK
                        return target, port, "closed"
                return target, port, "filtered"
            except Exception as e:
                print(f"SYN扫描 {target}:{port} 时出错: {e}")
                return target, port, "error"
        
        # 解析端口范围
        coroutines = []
        
        for target in self.targets:
            for port in self.ports:
                coroutines.append(scan_port(target, port))
        
        results = {}
        for coro in asyncio.as_completed(coroutines):
            target, port, status = await coro
            if target not in results:
                results[target] = {}
            results[target][port] = status
 
        return results
    
    async def icmp_scan(self):
        """ICMP扫描 - 使用ping检测主机是否在线"""
        async def scan(target):
            loop = asyncio.get_event_loop()
            try:
                # 创建ICMP Echo请求包
                icmp_packet = IP(dst=target)/ICMP()
                # 发送ICMP包并等待响应
                response = await loop.run_in_executor(
                    self.executor,
                    lambda: sr1(icmp_packet, timeout=self.timeout, verbose=self.verbose)
                )
                
                if response is None:
                    return target, "offline"
                elif response.haslayer(ICMP):
                    if response[ICMP].type == 0:  # Echo Reply
                        return target, "online"
                return target, "offline"
            except Exception as e:
                print(f"ICMP扫描 {target} 时出错: {e}")
                return target, "error"
        
        coroutines = [scan(target) for target in self.targets]
        results = {}
        
        for coro in asyncio.as_completed(coroutines):
            target, status = await coro
            results[target] = status
        
        return results
        
    async def tcp_connect_scan(self):
        """TCP连接扫描 - 完整的三次握手连接扫描"""
        async def scan_port(target, port):
            loop = asyncio.get_event_loop()
            try:
                # 使用socket进行TCP连接
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                # 尝试连接
                result = await loop.run_in_executor(
                    self.executor,
                    lambda: sock.connect_ex((target, port))
                )
                sock.close()
                
                if result == 0:
                    return target, port, "open"
                else:
                    return target, port, "closed"
            except Exception as e:
                print(f"TCP连接扫描 {target}:{port} 时出错: {e}")
                return target, port, "error"
        
        # 解析端口范围
        coroutines = []
        
        for target in self.targets:
            for port in self.ports:
                coroutines.append(scan_port(target, port))
        
        results = {}
        for coro in asyncio.as_completed(coroutines):
            target, port, status = await coro
            if target not in results:
                results[target] = {}
            results[target][port] = status

        return results
    async def tcp_xmas_scan(self):
        """XMAS扫描 - 发送FIN, URG, PUSH标志的包，根据响应判断端口状态"""
        async def scan_port(target, port):
            loop = asyncio.get_event_loop()
            try:
                # 创建XMAS包 (FIN, URG, PUSH)
                xmas_packet = IP(dst=target)/TCP(dport=port, flags="FPU")
                # 发送XMAS包并等待响应
                response = await loop.run_in_executor(
                    self.executor,
                    lambda: sr1(xmas_packet, timeout=self.timeout, verbose=self.verbose)
                )
                
                if response is None:
                    return target, port, "open|filtered"  # 无响应，可能开放或被过滤
                elif response.haslayer(TCP):
                    if response[TCP].flags == 0x14:  # RST-ACK
                        return target, port, "closed"
                return target, port, "filtered"
            except Exception as e:
                print(f"XMAS扫描 {target}:{port} 时出错: {e}")
                return target, port, "error"
        
        # 解析端口范围
        coroutines = []
        
        for target in self.targets:
            for port in self.ports:
                coroutines.append(scan_port(target, port))
        
        results = {}
        for coro in asyncio.as_completed(coroutines):
            target, port, status = await coro
            if target not in results:
                results[target] = {}
            results[target][port] = status
            
        return results
    async def tcp_fin_scan(self):
        """FIN扫描 - 发送FIN包，根据响应判断端口状态"""
        async def scan_port(target, port):
            loop = asyncio.get_event_loop()
            try:
                # 创建FIN包
                fin_packet = IP(dst=target)/TCP(dport=port, flags="F")
                # 发送FIN包并等待响应
                response = await loop.run_in_executor(
                    self.executor,
                    lambda: sr1(fin_packet, timeout=self.timeout, verbose=self.verbose)
                )
                
                if response is None:
                    return target, port, "open|filtered"  # 无响应，可能开放或被过滤
                elif response.haslayer(TCP):
                    if response[TCP].flags == 0x14:  # RST-ACK
                        return target, port, "closed"
                return target, port, "filtered"
            except Exception as e:
                print(f"FIN扫描 {target}:{port} 时出错: {e}")
                return target, port, "error"
        
        # 解析端口范围
        coroutines = []
        
        for target in self.targets:
            for port in self.ports:
                coroutines.append(scan_port(target, port))
        
        results = {}
        for coro in asyncio.as_completed(coroutines):
            target, port, status = await coro
            if target not in results:
                results[target] = {}
            results[target][port] = status
        return results
    async def tcp_null_scan(self):
        """NULL扫描 - 发送无标志的TCP包，根据响应判断端口状态"""
        async def scan_port(target, port):
            loop = asyncio.get_event_loop()
            try:
                # 创建NULL包 (无标志)
                null_packet = IP(dst=target)/TCP(dport=port, flags="")
                # 发送NULL包并等待响应
                response = await loop.run_in_executor(
                    self.executor,
                    lambda: sr1(null_packet, timeout=self.timeout, verbose=self.verbose)
                )
                
                if response is None:
                    return target, port, "open|filtered"  # 无响应，可能开放或被过滤
                elif response.haslayer(TCP):
                    if response[TCP].flags == 0x14:  # RST-ACK
                        return target, port, "closed"
                return target, port, "filtered"
            except Exception as e:
                print(f"NULL扫描 {target}:{port} 时出错: {e}")
                return target, port, "error"
        
        # 解析端口范围
        coroutines = []
        
        for target in self.targets:
            for port in self.ports:
                coroutines.append(scan_port(target, port))
        
        results = {}
        for coro in asyncio.as_completed(coroutines):
            target, port, status = await coro
            if target not in results:
                results[target] = {}
            results[target][port] = status

        return results
    async def tcp_ack_scan(self):
        """ACK扫描 - 发送ACK包，用于检测防火墙规则"""
        async def scan_port(target, port):
            loop = asyncio.get_event_loop()
            try:
                # 创建ACK包
                ack_packet = IP(dst=target)/TCP(dport=port, flags="A")
                # 发送ACK包并等待响应
                response = await loop.run_in_executor(
                    self.executor,
                    lambda: sr1(ack_packet, timeout=self.timeout, verbose=self.verbose)
                )
                
                if response is None:
                    return target, port, "filtered"  # 无响应，被过滤
                elif response.haslayer(TCP):
                    if response[TCP].flags == "R":  # RST
                        return target, port, "unfiltered"  # 未过滤
                return target, port, "filtered"
            except Exception as e:
                print(f"ACK扫描 {target}:{port} 时出错: {e}")
                return target, port, "error"
        
        # 解析端口范围
        coroutines = []
        
        for target in self.targets:
            for port in self.ports:
                coroutines.append(scan_port(target, port))
        
        results = {}
        for coro in asyncio.as_completed(coroutines):
            target, port, status = await coro
            if target not in results:
                results[target] = {}
            results[target][port] = status

        return results
    async def udp_scan(self):
        """UDP扫描 - 发送UDP包，根据响应判断端口状态"""
        async def scan_port(target, port):
            loop = asyncio.get_event_loop()
            try:
                # 创建UDP包
                udp_packet = IP(dst=target)/UDP(dport=port)
                # 发送UDP包并等待响应
                response = await loop.run_in_executor(
                    self.executor,
                    lambda: sr1(udp_packet, timeout=self.timeout, verbose=self.verbose)
                )
                
                if response is None:
                    # 无响应，可能开放或被过滤
                    # 尝试发送ICMP端口不可达包来确认
                    icmp_packet = IP(dst=target)/ICMP(type=3, code=3)
                    icmp_response = await loop.run_in_executor(
                        self.executor,
                        lambda: sr1(icmp_packet, timeout=self.timeout, verbose=False)
                    )
                    
                    if icmp_response is not None and icmp_response.haslayer(ICMP):
                        return target, port, "closed"
                    else:
                        return target, port, "open|filtered"
                elif response.haslayer(UDP):
                    return target, port, "open"
                elif response.haslayer(ICMP):
                    if response[ICMP].type == 3 and response[ICMP].code == 3:  # 端口不可达
                        return target, port, "closed"
                return target, port, "filtered"
            except Exception as e:
                print(f"UDP扫描 {target}:{port} 时出错: {e}")
                return target, port, "error"
        
        # 解析端口范围
        coroutines = []
        
        for target in self.targets:
            for port in self.ports:
                coroutines.append(scan_port(target, port))
        
        results = {}
        for coro in asyncio.as_completed(coroutines):
            target, port, status = await coro
            if target not in results:
                results[target] = {}
            results[target][port] = status
 
        return results
