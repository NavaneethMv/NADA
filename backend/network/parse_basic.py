#!/home/nav/main_project/anomalyX/.env/bin/python
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP

def capture_traffic():
    capture = scapy.sniff(count=5, prn=extract_features, iface="wlan0")
    print(capture.summary())

def extract_features(packet):
    extract_basic_features(packet)

def extract_basic_features(packet):
    # protocol_type, service, src_bytes, dst_bytes, flag
    features = {}
    
    # Set default values
    features['protocol_type'] = 'other'
    features['service'] = 'other'
    features['src_bytes'] = 0
    features['dst_bytes'] = 0
    features['flag'] = ''

    # Protocol type
    if TCP in packet:
        features['protocol_type'] = "tcp"
    elif UDP in packet:
        features['protocol_type'] = "udp"
    elif ICMP in packet:
        features['protocol_type'] = 'icmp'

    # Service identification
    try:
        if TCP in packet:
            dport = packet[TCP].dport
        elif UDP in packet:
            dport = packet[UDP].dport
        else:
            dport = 0

        common_ports = {
            80: 'http',
            443: 'https',
            22: 'ssh',
            21: 'ftp',
            23: 'telnet',
            25: 'smtp',
            53: 'domain',
            3306: 'mysql',
            5432: 'postgresql'
        }
        features['service'] = common_ports.get(dport, 'other')
    except Exception as e:
        features['service'] = 'other'
        print(f"Error determining service: {e}")

    # Bytes
    if IP in packet:
        features['src_bytes'] = len(packet)
        features['dst_bytes'] = 0

    # Flags
    if TCP in packet:
        flags = [] # SFR
        if packet[TCP].flags.S: flags.append('S')
        if packet[TCP].flags.A: flags.append('A')
        if packet[TCP].flags.F: flags.append('F')
        if packet[TCP].flags.R: flags.append('R')
        if packet[TCP].flags.P: flags.append('P')
        features['flag'] = ''.join(flags)

    print(features)
    return features

if __name__ == "__main__":
    try:
        capture_traffic()
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    except Exception as e:
        print(f"Error during capture: {e}")
