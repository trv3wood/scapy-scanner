#!/usr/bin/env python3
"""
Test script for IP address parsing functionality
"""

import sys
import os

# Add the current directory to Python path so we can import arg
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from arg import Parser

def test_ip_parsing():
    """Test the IP address parsing functionality"""
    parser = Parser()
    
    # Test cases
    test_cases = [
        # Single IP
        "192.168.1.1",
        # CIDR notation
        "192.168.1.0/30",  # Small range for testing
        # IP range
        "192.168.1.1-192.168.1.3",
        # Multiple targets
        "192.168.1.1,192.168.1.0/30,192.168.1.1-192.168.1.3,example.com",
        # Edge cases
        "10.0.0.1/32",  # Single IP in CIDR
        "192.168.1.1-192.168.1.1",  # Single IP in range
    ]
    
    print("Testing IP address parsing functionality...")
    print("=" * 60)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test_case}")
        print("-" * 40)
        
        try:
            result = parser._setup_target(test_case)
            print(f"Result: {result}")
            print(f"Number of targets: {len(result)}")
        except Exception as e:
            print(f"Error: {e}")

def test_individual_methods():
    """Test individual parsing methods"""
    parser = Parser()
    
    print("\n\nTesting individual methods...")
    print("=" * 60)
    
    # Test CIDR parsing
    print("\nCIDR parsing:")
    cidr_tests = ["192.168.1.0/30", "10.0.0.0/29", "172.16.0.0/28"]
    for cidr in cidr_tests:
        result = parser._cidr_to_ip_list(cidr)
        print(f"{cidr} -> {len(result)} IPs: {result}")
    
    # Test range parsing
    print("\nRange parsing:")
    range_tests = ["192.168.1.1-192.168.1.3", "10.0.0.1-10.0.0.5"]
    for range_str in range_tests:
        result = parser._range_to_ip_list(range_str)
        print(f"{range_str} -> {len(result)} IPs: {result}")

if __name__ == "__main__":
    test_ip_parsing()
    test_individual_methods()
