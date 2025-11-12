#!/usr/bin/env python3
"""
Test script for the Parser class
"""

import sys
import os

# Add current directory to path to import arg module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from arg import Parser

def test_parser():
    """Test the parser with various command line arguments"""
    
    # Test 1: Basic help
    print("=== Test 1: Help message ===")
    parser = Parser()
    try:
        # Simulate help command
        sys.argv = ['test_parser.py', '--help']
        args = parser.parse_args()
    except SystemExit:
        print("Help message displayed successfully")
    
    # Test 2: Basic scan
    print("\n=== Test 2: Basic SYN scan ===")
    sys.argv = ['test_parser.py', '192.168.1.1', '-s', 'syn', '-p', '1-100,200']
    args = parser.parse_args()
    print(f"Target: {args.target}")
    print(f"Scan type: {args.scan_type}")
    print(f"Ports: {args.ports}")
    print(f"Timeout: {args.timeout}")
    
    # Test 3: ARP scan
    print("\n=== Test 3: ARP scan ===")
    sys.argv = ['test_parser.py', '192.168.1.0/24', '-s', 'arp']
    args = parser.parse_args()
    print(f"Target: {args.target}")
    print(f"Scan type: {args.scan_type}")
    
    """
    # Test 4: UDP scan with custom options
    print("\n=== Test 4: UDP scan with custom options ===")
    sys.argv = ['test_parser.py', 'example.com', '-s', 'udp', '-p', '53,67,68', '-t', '2.0', '-d', '0.05', '--threads', '5']
    args = parser.parse_args()
    print(f"Target: {args.target}")
    print(f"Scan type: {args.scan_type}")
    print(f"Ports: {args.ports}")
    print(f"Timeout: {args.timeout}")
    print(f"Delay: {args.delay}")
    print(f"Threads: {args.threads}")
    """
    
    # Test 5: Usage examples
    print("\n=== Test 5: Usage examples ===")
    print(parser.get_usage_examples())
    
    print("\n=== All tests completed successfully! ===")

if __name__ == '__main__':
    test_parser()
