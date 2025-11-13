#!/usr/bin/env python3
"""
测试异步扫描修复
"""
import asyncio
import sys
import os

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from scanner import Scanner
import argparse

async def test_async_scan():
    """测试异步扫描功能"""
    print("测试异步扫描修复...")
    
    # 创建模拟参数
    args = argparse.Namespace()
    args.targets = ['127.0.0.1', 'localhost']  # 测试本地地址
    args.scan_type = 'arp'
    args.timeout = 1
    args.join_threads = 4
    
    # 创建扫描器实例
    scanner = Scanner(args)
    
    try:
        # 测试异步扫描
        print("开始异步ARP扫描...")
        results = await scanner.arp_scan()
        print(f"扫描完成，结果数量: {len(results)}")
        
        # 显示结果
        for target, result in results.items():
            if result:
                print(f"{target}: 在线")
            else:
                print(f"{target}: 离线或超时")
                
    except Exception as e:
        print(f"测试过程中出错: {e}")
        return False
    
    return True

if __name__ == "__main__":
    # 运行测试
    success = asyncio.run(test_async_scan())
    if success:
        print("异步扫描修复测试通过！")
    else:
        print("异步扫描修复测试失败！")
