#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import defaultdict, deque
import time
import numpy as np
import pandas as pd
import logging
from typing import Dict, List, Set, Tuple, Optional, Any

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('NetworkFeatureExtractor')

class NetworkFeatureExtractor:
    """Extract NSL-KDD features from live network traffic using Scapy."""
    
    def __init__(self, time_window: int = 2, max_connections: int = 1000):
        """
        Initialize the feature extractor.
        
        Args:
            time_window: Time window in seconds for connection tracking
            max_connections: Maximum number of connections to track in history
        """
        self.time_window = time_window
        self.max_connections = max_connections
        
        # Connection tracking
        self.connections: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'start_time': None,
            'src_bytes': 0,
            'dst_bytes': 0,
            'count': 0,
            'srv_count': 0,
            'packets': [],
            'flags': set(),
            'service': 'other'  
        })
        
        # Session tracking
        self.logged_in_sessions: Dict[str, bool] = {}
        self.failed_logins: Dict[str, int] = defaultdict(int)
        
        # History tracking with efficient data structures
        self.conn_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.service_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Service mapping
        self.common_ports = {
            80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp', 23: 'telnet',
            25: 'smtp', 53: 'domain', 3306: 'mysql', 5432: 'postgresql',
            110: 'pop3', 143: 'imap', 20: 'ftp-data', 123: 'ntp', 
            161: 'snmp', 179: 'bgp', 67: 'dhcp', 68: 'dhcp'
        }
        
        # Keywords for content-based features
        self.suspicious_keywords = [
            'login', 'pass', 'password', 'cmd', 'root', 'admin', 'exec', 
            'shell', 'ftp', 'telnet', 'sudo', 'su'
        ]
        
        self.compromise_keywords = [
            "root", "su ", "sudo", "passwd", "shadow", "nmap", "exploit", "malware",
            "shell", "cmd.exe", "bash", "exec", "sh ", "net user", "admin",
            "meterpreter", "payload", "privilege escalation", "nc -e", "hacked",
            "backdoor", "bind shell", "system(", "fork(", "eval(", "execve("
        ]
        
        self.root_shell_commands = [
            "sudo su", "su root", "sudo -i", "sudo bash", "sudo sh",
            "chmod 777", "chown root", "passwd root", "shadow", 
            "visudo", "echo 'root::0:0'", "nc -e /bin/sh", 
            "netcat -e", "perl -e 'exec'", "python -c 'import pty'"
        ]
        
        self.last_cleanup = time.time()
        self.cleanup_interval = 10  # seconds

    def get_connection_key(self, packet) -> Optional[str]:
        """
        Generate a unique key for a connection based on protocol, IPs, and ports.
        
        Args:
            packet: Scapy packet
            
        Returns:
            Connection key or None if not a supported packet type
        """
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    proto = 'tcp'
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    proto = 'udp'
                elif ICMP in packet:
                    # For ICMP, use types as "ports"
                    src_port = packet[ICMP].type
                    dst_port = 0
                    proto = 'icmp'
                else:
                    return None
                    
                return f"{proto}_{src_ip}:{src_port}_{dst_ip}:{dst_port}"
        except Exception as e:
            logger.error(f"Error generating connection key: {e}")
        return None

    def get_service(self, packet) -> str:
        """
        Determine the service type based on the destination port.
        
        Args:
            packet: Scapy packet
            
        Returns:
            Service name string
        """
        try:
            if TCP in packet:
                dport = packet[TCP].dport
            elif UDP in packet:
                dport = packet[UDP].dport
            else:
                return 'other'
                
            return self.common_ports.get(dport, 'other')
        except Exception as e:
            logger.error(f"Error determining service: {e}")
            return 'other'

    def get_flag(self, packet) -> str:
        """
        Extract TCP flags from a packet.
        
        Args:
            packet: Scapy packet
            
        Returns:
            String representation of flags
        """
        try:
            if TCP in packet:
                flags = []
                if packet[TCP].flags.S: flags.append('S')
                if packet[TCP].flags.A: flags.append('A')
                if packet[TCP].flags.F: flags.append('F')
                if packet[TCP].flags.R: flags.append('R')
                if packet[TCP].flags.P: flags.append('P')
                if packet[TCP].flags.U: flags.append('U')
                return ''.join(flags)
        except Exception as e:
            logger.error(f"Error getting flags: {e}")
        return ''

    def extract_basic_features(self, packet) -> Dict[str, Any]:
        """
        Extract basic features from a packet similar to those in NSL-KDD.
        
        Args:
            packet: Scapy packet
            
        Returns:
            Dictionary of features
        """
        features = {
            'duration': 0,
            'protocol_type': 'other',
            'service': 'other',
            'flag': '',
            'src_bytes': 0,
            'dst_bytes': 0,
            'hot': 0,
            'logged_in': 0,
            'num_failed_logins': 0
        }
        
        try:
            # Protocol type
            if TCP in packet:
                features['protocol_type'] = 'tcp'
            elif UDP in packet:
                features['protocol_type'] = 'udp'
            elif ICMP in packet:
                features['protocol_type'] = 'icmp'
                
            # Service and flag
            features['service'] = self.get_service(packet)
            features['flag'] = self.get_flag(packet)
            
            # Source bytes
            if IP in packet:
                features['src_bytes'] = len(packet)

            # Hot indicators from payload content
            if TCP in packet and scapy.Raw in packet:
                try:
                    payload = packet[scapy.Raw].load.decode(errors='ignore').lower()
                    features['hot'] = sum(1 for word in self.suspicious_keywords if word in payload)
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"Error extracting basic features: {e}")
            
        return features

    def extract_traffic_features(self, connection_key: str, current_time: float) -> Dict[str, Any]:
        """
        Extract traffic-based features from connection history.
        
        Args:
            connection_key: Connection identifier
            current_time: Current timestamp
            
        Returns:
            Dictionary of traffic features
        """
        features = {
            'count': 0, 
            'srv_count': 0, 
            'same_src_bytes_avg': 0, 
            'same_src_bytes_var': 0,
            'error_rate': 0,
            'same_srv_rate': 0,
            'diff_srv_rate': 0,
        }
        
        try:
            conn_data = self.connections[connection_key]
            service = conn_data.get('service', 'other')
            
            # Count connections in time window
            same_host_connections = [t for t in self.conn_history[connection_key] 
                                    if current_time - t <= self.time_window]
            features['count'] = len(same_host_connections)
            
            # Count same service connections
            same_srv_connections = [t for t in self.service_history[service] 
                                    if current_time - t <= self.time_window]
            features['srv_count'] = len(same_srv_connections)
            
            # Byte statistics
            if same_host_connections:
                # Only consider connections with same source IP
                conn_prefix = connection_key.split('_')[1].split(':')[0]  # Source IP
                byte_sizes = []
                
                for key in self.conn_history.keys():
                    if key.split('_')[1].split(':')[0] == conn_prefix:
                        if 'src_bytes' in self.connections[key]:
                            byte_sizes.append(self.connections[key]['src_bytes'])
                
                if byte_sizes:
                    features['same_src_bytes_avg'] = np.mean(byte_sizes)
                    features['same_src_bytes_var'] = np.var(byte_sizes)
            
            # Error rate calculation
            total_packets = len(conn_data['packets'])
            if total_packets > 0:
                error_flags = ('R', 'S')  # Reset and SYN without ACK
                error_packets = sum(1 for p in conn_data['packets'] 
                                   if any(flag in self.get_flag(p) for flag in error_flags))
                features['error_rate'] = error_packets / total_packets
            
            # Service rate calculations
            dst_ip = connection_key.split('_')[2].split(':')[0]
            current_service = conn_data.get('service', 'other')
            
            # Find connections to same host
            same_host_connections = []
            for conn_key in self.conn_history.keys():
                conn_parts = conn_key.split('_')
                if len(conn_parts) >= 3 and conn_parts[2].split(':')[0] == dst_ip:
                    same_host_connections.append(conn_key)
            
            total_same_host = len(same_host_connections)
            if total_same_host > 0:
                diff_srv_count = sum(1 for key in same_host_connections 
                                    if self.connections[key].get('service', 'other') != current_service)
                
                features['same_srv_rate'] = (total_same_host - diff_srv_count) / total_same_host
                features['diff_srv_rate'] = diff_srv_count / total_same_host
                
        except Exception as e:
            logger.error(f"Error extracting traffic features: {e}")
        
        return features

    def extract_error_rate_features(self, connection_key: str, current_time: float) -> Dict[str, float]:
        """
        Extract error-rate features similar to those in NSL-KDD.
        
        Args:
            connection_key: Connection identifier
            current_time: Current timestamp
            
        Returns:
            Dictionary of error rate features
        """
        features = {
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0
        }
        
        try:
            # Parse connection key
            parts = connection_key.split('_')
            if len(parts) < 3:
                return features
                
            dst_ip = parts[2].split(':')[0]
            service = self.connections[connection_key].get('service', 'other')
            
            # Counters
            syn_error_count = 0
            srv_syn_error_count = 0
            rej_error_count = 0
            srv_rej_error_count = 0
            same_host_count = 0
            same_srv_count = 0
            
            # Analyze recent connections
            for conn_key, conn_times in self.conn_history.items():
                recent_conn_times = [t for t in conn_times if current_time - t <= self.time_window]
                if not recent_conn_times:
                    continue
                    
                conn_parts = conn_key.split('_')
                if len(conn_parts) < 3:
                    continue
                    
                conn_dst_ip = conn_parts[2].split(':')[0]
                conn_service = self.connections[conn_key].get('service', 'other')
                
                is_same_host = (conn_dst_ip == dst_ip)
                is_same_service = (conn_service == service)
                
                if is_same_host:
                    same_host_count += len(recent_conn_times)
                    
                    # Check for SYN errors (S flag only)
                    for flag in self.connections[conn_key]['flags']:
                        if 'S' in flag and 'A' not in flag:
                            syn_error_count += 1
                    
                    # Check for REJ errors (RST flag)
                    for flag in self.connections[conn_key]['flags']:
                        if 'R' in flag:
                            rej_error_count += 1
                
                if is_same_service:
                    same_srv_count += len(recent_conn_times)
                    
                    # Check for SYN errors for same service
                    for flag in self.connections[conn_key]['flags']:
                        if 'S' in flag and 'A' not in flag:
                            srv_syn_error_count += 1
                    
                    # Check for REJ errors for same service
                    for flag in self.connections[conn_key]['flags']:
                        if 'R' in flag:
                            srv_rej_error_count += 1
            
            # Calculate error rates
            if same_host_count > 0:
                features['serror_rate'] = syn_error_count / same_host_count
                features['rerror_rate'] = rej_error_count / same_host_count
            
            if same_srv_count > 0:
                features['srv_serror_rate'] = srv_syn_error_count / same_srv_count
                features['srv_rerror_rate'] = srv_rej_error_count / same_srv_count
                
        except Exception as e:
            logger.error(f"Error extracting error rate features: {e}")
        
        return features

    def extract_host_based_features(self, connection_key: str, current_time: float) -> Dict[str, Any]:
        """
        Extract host-based features from connection history.
        
        Args:
            connection_key: Connection identifier
            current_time: Current timestamp
            
        Returns:
            Dictionary of host-based features
        """
        features = {
            'dst_host_count': 0,
            'dst_host_srv_count': 0,
            'dst_host_same_srv_rate': 0.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }
        
        try:
            # Parse connection key
            parts = connection_key.split('_')
            if len(parts) < 3:
                return features
                
            dst_ip = parts[2].split(':')[0]
            service = self.connections[connection_key].get('service', 'other')
            
            # Counters
            dst_host_connections = []
            dst_host_services = defaultdict(int)
            dst_host_serrors = 0
            dst_host_rerrors = 0
            dst_host_srv_serrors = 0
            dst_host_srv_rerrors = 0
            
            # Analyze connections
            for conn_key, conn_times in self.conn_history.items():
                conn_parts = conn_key.split('_')
                if len(conn_parts) < 3:
                    continue
                    
                conn_dst_ip = conn_parts[2].split(':')[0]
                
                if conn_dst_ip == dst_ip:
                    dst_host_connections.append(conn_key)
                    conn_service = self.connections[conn_key].get('service', 'other')
                    dst_host_services[conn_service] += 1
                    
                    # Check for SYN errors
                    for flag in self.connections[conn_key]['flags']:
                        if 'S' in flag and 'A' not in flag:
                            dst_host_serrors += 1
                            if conn_service == service:
                                dst_host_srv_serrors += 1
                    
                    # Check for REJ errors
                    for flag in self.connections[conn_key]['flags']:
                        if 'R' in flag:
                            dst_host_rerrors += 1
                            if conn_service == service:
                                dst_host_srv_rerrors += 1
            
            # Calculate features
            dst_host_count = len(dst_host_connections)
            features['dst_host_count'] = dst_host_count
            
            dst_host_srv_count = dst_host_services.get(service, 0)
            features['dst_host_srv_count'] = dst_host_srv_count
            
            if dst_host_count > 0:
                features['dst_host_same_srv_rate'] = dst_host_srv_count / dst_host_count
                features['dst_host_diff_srv_rate'] = (dst_host_count - dst_host_srv_count) / dst_host_count
                features['dst_host_serror_rate'] = dst_host_serrors / dst_host_count
                features['dst_host_rerror_rate'] = dst_host_rerrors / dst_host_count
            
            if dst_host_srv_count > 0:
                features['dst_host_srv_serror_rate'] = dst_host_srv_serrors / dst_host_srv_count
                features['dst_host_srv_rerror_rate'] = dst_host_srv_rerrors / dst_host_srv_count
            
        except Exception as e:
            logger.error(f"Error extracting host-based features: {e}")
        
        return features

    def extract_content_features(self, packet) -> Dict[str, int]:
        """
        Extract content-based features from packet payload.
        
        Args:
            packet: Scapy packet
            
        Returns:
            Dictionary of content features
        """
        features = {
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_access_files': 0
        }
        
        try:
            if not packet.haslayer(scapy.Raw):
                return features
                
            payload = packet[scapy.Raw].load.decode(errors='ignore').lower()
            
            # Compromised features
            features['num_compromised'] = sum(1 for keyword in self.compromise_keywords if keyword in payload)
            
            # Root shell detection
            features['root_shell'] = 1 if any(cmd in payload for cmd in self.root_shell_commands) else 0
            
            # SU attempted
            su_attempt_commands = ["su root", "su -", "sudo su", "sudo -i"]
            features['su_attempted'] = 1 if any(cmd in payload for cmd in su_attempt_commands) else 0
            
            # Number of root accesses
            root_commands = ["su root", "sudo", "chmod 777", "chown root"]
            features['num_root'] = sum(payload.count(cmd) for cmd in root_commands)
            
            # File creation commands
            file_creation_commands = ["touch ", "echo ", "cat > ", "vi ", "nano ", "cp ", "wget ", "curl "]
            features['num_file_creations'] = sum(payload.count(cmd) for cmd in file_creation_commands)
            
            # File access commands
            file_access_commands = ["cat ", "less ", "more ", "ls ", "grep ", "find "]
            features['num_access_files'] = sum(payload.count(cmd) for cmd in file_access_commands)
            
        except Exception as e:
            logger.error(f"Error extracting content features: {e}")
            
        return features

    def update_login_status(self, packet) -> Dict[str, int]:
        """
        Track login status and failed login attempts.
        
        Args:
            packet: Scapy packet
            
        Returns:
            Dictionary with login status features
        """
        features = {
            'num_failed_logins': 0,
            'logged_in': 0
        }
        
        try:
            if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(scapy.Raw)):
                return features
                
            raw_data = packet[scapy.Raw].load.decode(errors='ignore').lower()
            src_ip = packet[IP].src
            
            # Track failed logins
            failed_keywords = ["login incorrect", "authentication failed", "invalid password", "access denied"]
            if any(keyword in raw_data for keyword in failed_keywords):
                self.failed_logins[src_ip] += 1
            
            # Track successful logins
            success_keywords = ["login successful", "authenticated", "session opened", "ssh-2.0", "http/1.1 200 ok"]
            if any(keyword in raw_data for keyword in success_keywords):
                self.logged_in_sessions[src_ip] = True
                # Reset failed logins on successful login
                self.failed_logins[src_ip] = 0
            
            # Track logouts
            logout_keywords = ["logout", "disconnected", "session closed"]
            if any(keyword in raw_data for keyword in logout_keywords):
                self.logged_in_sessions.pop(src_ip, None)
            
            features['num_failed_logins'] = self.failed_logins[src_ip]
            features['logged_in'] = 1 if self.logged_in_sessions.get(src_ip, False) else 0
            
        except Exception as e:
            logger.error(f"Error updating login status: {e}")
            
        return features

    def extract_features(self, packet) -> Optional[pd.Series]:
        """
        Extract all features from a packet.
        
        Args:
            packet: Scapy packet
            
        Returns:
            Pandas Series containing all features or None if error
        """
        try:
            current_time = time.time()
            connection_key = self.get_connection_key(packet)
            
            if connection_key is None:
                return None
            
            # Periodic cleanup of old connections
            if current_time - self.last_cleanup > self.cleanup_interval:
                self.clean_old_history(current_time)
                self.last_cleanup = current_time
                
            # Initialize feature groups
            basic_features = self.extract_basic_features(packet)
            content_features = self.extract_content_features(packet)
            login_features = self.update_login_status(packet)
            
            # Merge feature dictionaries
            features = {**basic_features, **content_features, **login_features}
            
            # Update connection data
            conn_data = self.connections[connection_key]
            
            # Set start time for first packet of connection
            if connection_key not in self.conn_history or not self.conn_history[connection_key]:
                conn_data['start_time'] = current_time
            # Ensure valid start_time
            if not conn_data['start_time']:
                conn_data['start_time'] = current_time
            
            # Update connection properties
            conn_data['service'] = features['service']
            
            # Store packet reference (limit to last 10 packets to save memory)
            conn_data['packets'].append(packet)
            if len(conn_data['packets']) > 10:
                conn_data['packets'] = conn_data['packets'][-10:]
            
            # Update TCP flags
            if TCP in packet:
                conn_data['flags'].add(self.get_flag(packet))
            
            # Update byte counts
            if IP in packet:
                conn_data['src_bytes'] += len(packet)
                
                # Handle reverse flow
                if TCP in packet:
                    reverse_key = f"tcp_{packet[IP].dst}:{packet[TCP].dport}_{packet[IP].src}:{packet[TCP].sport}"
                elif UDP in packet:
                    reverse_key = f"udp_{packet[IP].dst}:{packet[UDP].dport}_{packet[IP].src}:{packet[UDP].sport}"
                else:
                    reverse_key = None
                
                if reverse_key:
                    # Initialize reverse connection if it doesn't exist
                    if reverse_key not in self.connections:
                        self.connections[reverse_key] = {
                            'start_time': None,
                            'src_bytes': 0,
                            'dst_bytes': 0,
                            'count': 0,
                            'srv_count': 0,
                            'packets': [],
                            'flags': set(),
                            'service': 'other'
                        }
                    
                    self.connections[reverse_key]['dst_bytes'] += len(packet)
            
            # Update features from connection data
            features['dst_bytes'] = conn_data['dst_bytes']
            
            # Calculate duration properly
            features['duration'] = current_time - conn_data['start_time'] if conn_data['start_time'] else 0
            if features['duration'] < 0:
                logger.warning(f"Negative duration detected ({features['duration']}). Setting to 0.")
                features['duration'] = 0
            
            # Extract additional feature groups
            traffic_features = self.extract_traffic_features(connection_key, current_time)
            error_rate_features = self.extract_error_rate_features(connection_key, current_time)
            host_based_features = self.extract_host_based_features(connection_key, current_time)
            
            # Merge all feature groups
            features.update(traffic_features)
            features.update(error_rate_features)
            features.update(host_based_features)
            
            # Update connection history
            self.conn_history[connection_key].append(current_time)
            self.service_history[features['service']].append(current_time)
            
            # Convert to pandas Series
            return pd.Series(features)
            
        except Exception as e:
            logger.error(f"Error in feature extraction: {e}", exc_info=True)
            return None

    def clean_old_history(self, current_time: float) -> None:
        """
        Clean up old connection history to prevent memory leaks.
        
        Args:
            current_time: Current timestamp
        """
        try:
            # Remove connections older than time window
            threshold = current_time - self.time_window
            
            # Clean connection history
            for key in list(self.conn_history.keys()):
                self.conn_history[key] = deque([t for t in self.conn_history[key] if t > threshold], 
                                            maxlen=self.max_connections)
                if not self.conn_history[key]:
                    del self.conn_history[key]
                    if key in self.connections:
                        del self.connections[key]
            
            # Clean service history
            for key in list(self.service_history.keys()):
                self.service_history[key] = deque([t for t in self.service_history[key] if t > threshold], 
                                                maxlen=self.max_connections)
                if not self.service_history[key]:
                    del self.service_history[key]
            
            # Clean old login sessions (older than 1 hour)
            long_session_threshold = current_time - 3600
            for key in list(self.logged_in_sessions.keys()):
                if any(conn_key.split('_')[1].split(':')[0] == key for conn_key in self.conn_history):
                    # Keep if there's recent activity
                    pass
                else:
                    # Remove if no recent activity
                    del self.logged_in_sessions[key]
                    
        except Exception as e:
            logger.error(f"Error cleaning history: {e}")

    def start_capture(self, interface: str = "eth0", packet_count: int = 100, 
                    timeout: int = 300, pcap_file: str = None) -> pd.DataFrame:
        """
        Start packet capture and feature extraction.
        
        Args:
            interface: Network interface to capture from
            packet_count: Number of packets to capture
            timeout: Maximum capture time in seconds
            pcap_file: Optional pcap file to read instead of live capture
            
        Returns:
            DataFrame with extracted features
        """
        logger.info(f"Starting packet capture: interface={interface}, count={packet_count}, timeout={timeout}")
        features_list = []
        start_time = time.time()
        
        def packet_callback(packet):
            try:
                if len(features_list) >= packet_count:
                    return "Stop capture"  # Signal to stop capture
                
                if time.time() - start_time > timeout:
                    logger.info(f"Capture timeout after {timeout} seconds")
                    return "Stop capture"  # Signal to stop capture
                
                features = self.extract_features(packet)
                if features is not None:
                    features_list.append(features)
                    if len(features_list) % 10 == 0:
                        logger.info(f"Processed {len(features_list)}/{packet_count} packets")
                
            except Exception as e:
                logger.error(f"Error in packet callback: {e}")
                
            return None  # Continue capturing
        
        try:
            if pcap_file:
                logger.info(f"Reading packets from file: {pcap_file}")
                scapy.sniff(offline=pcap_file, prn=packet_callback, store=False, stop_filter=lambda x: packet_callback(x) == "Stop capture")
            else:
                logger.info(f"Capturing packets from interface: {interface}")
                scapy.sniff(iface=interface, prn=packet_callback, store=False, 
                          count=packet_count, timeout=timeout, 
                          stop_filter=lambda x: packet_callback(x) == "Stop capture")
                
        except KeyboardInterrupt:
            logger.info("