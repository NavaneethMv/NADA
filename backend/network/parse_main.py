#!/home/nav/main_project/anomalyX/.env/bin/python

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from collections import defaultdict
import time
import numpy as np
import pandas as pd
import queue
import threading
from datetime import datetime

class NetworkFeatureExtractor:
    def __init__(self, time_window=2, batch_size=10):
        self.time_window = time_window
        self.connections = defaultdict(lambda: {
            'start_time': None,
            'src_bytes': 0,
            'dst_bytes': 0,
            'count': 0,
            'srv_count': 0,
            'packets': [],
            'flags': set(),
            'service': 'other'  
        })
        self.logged_in_sessions = {}
        self.failed_logins = defaultdict(int)
        self.conn_history = defaultdict(list)
        self.service_history = defaultdict(list)
        
        self.batch_size = batch_size
        self.feature_queue = queue.Queue(maxsize=100)  # Buffer for processed features
        self.stop_capture = False  # Flag to control capture loop
        self.last_batch_time = time.time()
        
    def get_connection_key(self, packet):
        try:
            if IP in packet and (TCP in packet or UDP in packet):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    proto = 'tcp'
                else:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    proto = 'udp'
                return f"{proto}_{src_ip}:{src_port}_{dst_ip}:{dst_port}"
        except Exception as e:
            print(f"Error generating connection key: {e}")
        return None

    def get_service(self, packet):
        try:
            if TCP in packet:
                dport = packet[TCP].dport
            elif UDP in packet:
                dport = packet[UDP].dport
            else:
                return 'other'
                
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
            return common_ports.get(dport, 'other')
        except Exception as e:
            print(f"Error determining service: {e}")
            return 'other'

    def get_flag(self, packet):
        try:
            if TCP in packet:
                flags = []
                if packet[TCP].flags.S: flags.append('S')
                if packet[TCP].flags.A: flags.append('A')
                if packet[TCP].flags.F: flags.append('F')
                if packet[TCP].flags.R: flags.append('R')
                if packet[TCP].flags.P: flags.append('P')
                return ''.join(flags)
        except Exception as e:
            print(f"Error getting flags: {e}")
        return ''

    def extract_basic_features(self, packet):
        features = {
            'duration': 0,
            'protocol_type': 'other',
            'service': 'other',
            'flag': '',
            'src_bytes': 0,
            'dst_bytes': 0
        }
        
        try:
            
            if TCP in packet:
                features['protocol_type'] = 'tcp'
            elif UDP in packet:
                features['protocol_type'] = 'udp'
            elif ICMP in packet:
                features['protocol_type'] = 'icmp'
                
            
            features['service'] = self.get_service(packet)
            
            
            features['flag'] = self.get_flag(packet)
            
            
            if IP in packet:
                features['src_bytes'] = len(packet)

            if TCP in packet and scapy.Raw in packet:
                payload = packet[scapy.Raw].load.decode(errors='ignore').lower()
                suspicious_keywords = ['login', 'pass', 'cmd', 'root', 'admin', 'exec', 'shell', 'ftp', 'telnet']
                val = int(sum(1 for word in suspicious_keywords if word in payload))
                features['hot'] = val


        except Exception as e:
            print(f"Error extracting basic features: {e}")
            
        return features


    def extract_traffic_features(self, connection_key, current_time):
        features = {
            "count": 0,
            "srv_count": 0,
            "same_srv_rate": 0,
            "diff_srv_rate": 0,
        }

        try:
            conn_data = self.connections[connection_key]

            same_host_connections = [
                t
                for t in self.conn_history[connection_key]
                if current_time - t <= self.time_window
            ]
            features["count"] = len(same_host_connections)

            service = conn_data.get("service", "other")
            same_srv_connections = [
                t
                for t in self.service_history[service]
                if current_time - t <= self.time_window
            ]
            features["srv_count"] = len(same_srv_connections)

            total_connections = len(self.conn_history)
            unique_services = len(
                set(self.connections[key]["service"] for key in self.conn_history)
            )

            dst_ip = connection_key.split("_")[2].split(":")[0]
            current_service = conn_data.get("service", "other")

            same_host_connections = []
            for conn_key in self.conn_history.keys():
                conn_parts = conn_key.split("_")
                if len(conn_parts) >= 3 and conn_parts[2].split(":")[0] == dst_ip:
                    conn_times = [
                        t
                        for t in self.conn_history[conn_key]
                        if current_time - t <= self.time_window
                    ]
                    if conn_times:
                        same_host_connections.append(conn_key)

            total_same_host = len(same_host_connections)
            if total_same_host > 0:
                diff_srv_count = sum(
                    1
                    for key in same_host_connections
                    if self.connections[key].get("service", "other") != current_service
                )

                features["same_srv_rate"] = (
                    total_same_host - diff_srv_count
                ) / total_same_host
                features["diff_srv_rate"] = diff_srv_count / total_same_host

        except Exception as e:
            print(f"Error extracting traffic features: {e}")

        return features


    def extract_error_rate_features(self, connection_key, current_time):
        features = {
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0
        }
        
        try:
            # Get current connection data
            conn_data = self.connections[connection_key]
            
            # Extract service and IPs from connection key
            parts = connection_key.split('_')
            if len(parts) >= 2:
                src_ip = parts[1].split(':')[0]
                dst_ip = parts[2].split(':')[0]
                service = conn_data.get('service', 'other')
                
                # Count connections with SYN errors (S flag without ACK)
                syn_error_count = 0
                srv_syn_error_count = 0
                
                # Count connections with REJ errors (RST flag)
                rej_error_count = 0
                srv_rej_error_count = 0
                
                # Total connections to same host and same service
                same_host_count = 0
                same_srv_count = 0
                
                # Analyze recent connections within time window
                for conn_key, conn_times in self.conn_history.items():
                    recent_conn_times = [t for t in conn_times if current_time - t <= self.time_window]
                    if not recent_conn_times:
                        continue
                        
                    # Extract connection details
                    conn_parts = conn_key.split('_')
                    if len(conn_parts) < 3:
                        continue
                        
                    conn_src_ip = conn_parts[1].split(':')[0]
                    conn_dst_ip = conn_parts[2].split(':')[0]
                    conn_service = self.connections[conn_key].get('service', 'other')
                    
                    # Check if connection is to same destination host
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
            print(f"Error extracting error rate features: {e}")
        
        return features

    def extract_host_based_features(self, connection_key, current_time):
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
            # Parse connection key to get destination IP and service
            parts = connection_key.split('_')
            if len(parts) < 3:
                return features
                
            dst_ip = parts[2].split(':')[0]
            service = self.connections[connection_key].get('service', 'other')
            
            # Counters for destination host
            dst_host_connections = []
            dst_host_services = defaultdict(int)
            
            # Counters for SYN and REJ errors
            dst_host_serrors = 0
            dst_host_rerrors = 0
            
            # Counters for service-specific errors
            dst_host_srv_serrors = 0
            dst_host_srv_rerrors = 0
            
            # Analyze all connections in history
            for conn_key, conn_times in self.conn_history.items():
                # Check connections within a longer window (100 connections)
                # NSL-KDD typically uses last 100 connections for host-based features
                
                conn_parts = conn_key.split('_')
                if len(conn_parts) < 3:
                    continue
                    
                conn_dst_ip = conn_parts[2].split(':')[0]
                
                # Check if connection is to the same destination host
                if conn_dst_ip == dst_ip:
                    dst_host_connections.append(conn_key)
                    conn_service = self.connections[conn_key].get('service', 'other')
                    dst_host_services[conn_service] += 1
                    
                    # Check for SYN errors (S flag only)
                    for flag in self.connections[conn_key]['flags']:
                        if 'S' in flag and 'A' not in flag:
                            dst_host_serrors += 1
                            if conn_service == service:
                                dst_host_srv_serrors += 1
                    
                    # Check for REJ errors (RST flag)
                    for flag in self.connections[conn_key]['flags']:
                        if 'R' in flag:
                            dst_host_rerrors += 1
                            if conn_service == service:
                                dst_host_srv_rerrors += 1
            
            # Calculate host-based features
            dst_host_count = len(dst_host_connections)
            features['dst_host_count'] = dst_host_count
            
            # Count connections with same service
            dst_host_srv_count = dst_host_services.get(service, 0)
            features['dst_host_srv_count'] = dst_host_srv_count
            
            # Calculate service rate features
            if dst_host_count > 0:
                features['dst_host_same_srv_rate'] = dst_host_srv_count / dst_host_count
                features['dst_host_diff_srv_rate'] = (dst_host_count - dst_host_srv_count) / dst_host_count
                features['dst_host_serror_rate'] = dst_host_serrors / dst_host_count
                features['dst_host_rerror_rate'] = dst_host_rerrors / dst_host_count
            
            # Calculate service-specific error rates
            if dst_host_srv_count > 0:
                features['dst_host_srv_serror_rate'] = dst_host_srv_serrors / dst_host_srv_count
                features['dst_host_srv_rerror_rate'] = dst_host_srv_rerrors / dst_host_srv_count
            
        except Exception as e:
            print(f"Error extracting host-based features: {e}")
        
        return features

    def extract_compromised_features(self, packet):
        num_compromised = 0

        try:
            compromise_keywords = [
                "root", "su ", "sudo", "passwd", "shadow", "nmap", "exploit", "malware",
                "shell", "cmd.exe", "bash", "exec", "sh ", "net user", "admin",
                "meterpreter", "payload", "privilege escalation", "nc -e", "hacked",
                "backdoor", "bind shell", "system(", "fork(", "eval(", "execve("
            ]

            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load.decode(errors='ignore').lower()

                num_compromised = sum(1 for keywords in compromise_keywords if keywords in payload)

        except Exception as e:
            print(f"Error extracting num_compromised: {e}")

        return num_compromised

    def extract_root_shell(self, packet):
        root_shell_commands = [
            "sudo su", "su root", "sudo -i", "sudo bash", "sudo sh",
            "chmod 777", "chown root", "passwd root", "shadow", 
            "visudo", "echo 'root::0:0'", "nc -e /bin/sh", 
            "netcat -e", "perl -e 'exec'", "python -c 'import pty'"
        ]

        try:
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load.decode(errors='ignore').lower()

                for cmd in root_shell_commands:
                    if cmd in payload:
                        return 1
        except Exception as e:
            print(f"Error extracting root_shell: {e}")
        
        return 0


    def extract_su_attempted(self, packet):
        su_attempt_commands = [
            "su root", "su -", "su -l", "sudo su", "sudo -i", "sudo bash",
            "sudo sh", "echo root::0:0", "perl -e 'exec(\"/bin/sh\")'",
            "python -c 'import pty; pty.spawn(\"/bin/sh\")'"
        ]

        try:
            if packet.haslayer(scapy.Raw):  
                payload = packet[scapy.Raw].load.decode(errors='ignore').lower()

                for cmd in su_attempt_commands:
                    if cmd in payload:
                        return 1  

        except Exception as e:
            print(f"Error extracting su_attempted: {e}")

        return 0 
    

    def extract_num_root(self, packet):
        num_root = 0
        root_commands = [
            "su root", "sudo", "chmod 777", "chown root:root", "tar --checkpoint",
            "perl -e 'exec(\"/bin/sh\")'", "python -c 'import pty; pty.spawn(\"/bin/sh\")'",
            "nc -e /bin/sh", "bash -p", "echo root::0:0", "cp /bin/sh /tmp/sh && chmod +s /tmp/sh"
        ]


        try:
            if packet.haslayer(scapy.Raw):  
                payload = packet[scapy.Raw].load.decode(errors='ignore').lower()

                for cmd in root_commands:
                    num_root += payload.count(cmd)

        except Exception as e:
            print(f"Error extracting num_root: {e}")

        return num_root


    def extract_num_file_creations(self, packet):
        num_file_creations = 0
        file_creation_commands = [
            "touch ", "echo ", "cat > ", "vi ", "nano ", "cp ", "wget ", "curl ", "scp "
        ]


        try:
            if packet.haslayer(scapy.Raw):  
                payload = packet[scapy.Raw].load.decode(errors='ignore').lower()

                for cmd in file_creation_commands:
                    num_file_creations += payload.count(cmd)

        except Exception as e:
            print(f"Error extracting num_file_creations: {e}")

        return num_file_creations


    def extract_num_access_files(self, packet):
        num_access_files = 0

        file_access_commands = [
            "cat ", "less ", "more ", "ls ", "stat ", "grep ", "find ", "vim ", "nano ", "cp ", "mv "
        ]

        try:
            if packet.haslayer(scapy.Raw):  
                payload = packet[scapy.Raw].load.decode(errors='ignore').lower()

                for cmd in file_access_commands:
                    num_access_files += payload.count(cmd)

        except Exception as e:
            print(f"Error extracting num_access_files: {e}")

        return num_access_files


    def extract_features(self, packet):
        try:
            current_time = time.time()
            connection_key = self.get_connection_key(packet)
            
            if connection_key is None:
                return None
                
            # Extract basic features
            features = self.extract_basic_features(packet)
            features['num_compromised'] = self.extract_compromised_features(packet)
            features['root_shell'] = self.extract_root_shell(packet)
            features['su_attempted'] = self.extract_su_attempted(packet)
            features['num_root'] = self.extract_num_root(packet)
            features['num_file_creations'] = self.extract_num_file_creations(packet)
            features['num_access_files'] = self.extract_num_access_files(packet)
            
            # Update connection data
            conn_data = self.connections[connection_key]
            
            # Improved duration handling - only set start time for first packet of connection
            if connection_key not in self.conn_history or not self.conn_history[connection_key]:
                conn_data['start_time'] = current_time
            # Make sure we always have a valid start_time
            if not conn_data['start_time']:
                conn_data['start_time'] = current_time
            
            conn_data['service'] = features['service']
            conn_data['packets'].append(packet)
            
            if TCP in packet:
                conn_data['flags'].add(self.get_flag(packet))
            
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
                    
            # Update dst_bytes and duration
            features['dst_bytes'] = conn_data['dst_bytes']
            features['duration'] = current_time - conn_data['start_time'] if conn_data['start_time'] else 0
            
            # Check for negative duration and fix it
            if features['duration'] < 0:
                print(f"Warning: Negative duration detected ({features['duration']}). Setting to 0.")
                features['duration'] = 0

            # Extract login information
            if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(scapy.Raw):
                raw_data = packet[scapy.Raw].load.decode(errors='ignore')
                src_ip = packet[IP].src

                failed_keywords = ["login incorrect", "authentication failed", "invalid password"]
                if any(keyword in raw_data.lower() for keyword in failed_keywords):
                    self.failed_logins[src_ip] += 1

                success_keywords = ["230 login successful", "ssh-2.0", "http/1.1 200 ok"]
                if any(keyword in raw_data.lower() for keyword in success_keywords):
                    self.failed_logins[src_ip] = 0
                
                features['num_failed_logins'] = self.failed_logins[src_ip]

                if "230 Login successful" in raw_data or "SSH-2.0" in raw_data or "HTTP/1.1 200 OK" in raw_data:
                    self.logged_in_sessions[src_ip] = True

                if "logout" in raw_data or "disconnected" in raw_data:
                    self.logged_in_sessions.pop(src_ip, None)

                features['logged_in'] = 1 if self.logged_in_sessions.get(src_ip, False) else 0
            
            # Extract additional features
            traffic_features = self.extract_traffic_features(connection_key, current_time)
            features.update(traffic_features)
            
            # Extract new error rate features
            error_rate_features = self.extract_error_rate_features(connection_key, current_time)
            features.update(error_rate_features)
            
            # Extract new host-based features
            host_based_features = self.extract_host_based_features(connection_key, current_time)
            features.update(host_based_features)
            
            # Update connection history
            self.conn_history[connection_key].append(current_time)
            self.service_history[features['service']].append(current_time)
            
            # Clean old history data periodically
            self.clean_old_history(current_time)
            
            return pd.Series(features)
            
        except Exception as e:
            print(f"Error in feature extraction: {e}")
            return None

    def clean_old_history(self, current_time):
        try:
            threshold = current_time - self.time_window
            
            for key in list(self.conn_history.keys()):
                self.conn_history[key] = [t for t in self.conn_history[key] if t > threshold]
                if not self.conn_history[key]:
                    del self.conn_history[key]
                    
            for key in list(self.service_history.keys()):
                self.service_history[key] = [t for t in self.service_history[key] if t > threshold]
                if not self.service_history[key]:
                    del self.service_history[key]
                    
        except Exception as e:
            print(f"Error cleaning history: {e}")

    def start_capture(self, interface="s1-eth3", continuous=True):
        """
        Start capturing packets and extracting features
        
        Args:
            interface: Network interface to capture from
            continuous: If True, run in continuous mode, otherwise use packet_count
        
        Returns:
            In non-continuous mode: DataFrame of features
            In continuous mode: Doesn't return (runs until stopped)
        """
        print(f"Starting packet capture on interface {interface}")
        features_batch = []
        self.stop_capture = False
        
        def packet_callback(packet):
            if self.stop_capture:
                return
            
            try:
                features = self.extract_features(packet)
                if features is not None:
                    features_batch.append(features)
                    
                    # When batch is ready, process it
                    if len(features_batch) >= self.batch_size:
                        self._process_batch(features_batch.copy())
                        features_batch.clear()
                        
                    # Also check time-based batching (process at least every second)
                    current_time = time.time()
                    if features_batch and current_time - self.last_batch_time >= 1.0:
                        self._process_batch(features_batch.copy())
                        features_batch.clear()
                        self.last_batch_time = current_time
                        
            except Exception as e:
                print(f"Error in packet callback: {e}")
        
        # Start capturing in a separate thread if in continuous mode
        if continuous:
            capture_thread = threading.Thread(
                target=lambda: scapy.sniff(iface=interface, prn=packet_callback, store=0),
                daemon=True
            )
            capture_thread.start()
            return None
        else:
            # Original behavior for non-continuous mode
            features_list = []
            try:
                scapy.sniff(iface=interface, prn=lambda pkt: self._non_continuous_callback(pkt, features_list), count=100)
            except Exception as e:
                print(f"Error during packet capture: {e}")
                
            if features_list:
                return self._create_dataframe(features_list)
            return pd.DataFrame()
    
    def _non_continuous_callback(self, packet, features_list):
        """Helper for non-continuous mode"""
        try:
            features = self.extract_features(packet)
            if features is not None:
                features_list.append(features)
                print(f"Processed packet {len(features_list)}", end='\r')
        except Exception as e:
            print(f"Error in packet callback: {e}")
    
    def _process_batch(self, batch):
        """Process a batch of features and put in queue"""
        if not batch:
            return
            
        df = self._create_dataframe(batch)
        
        # Add timestamp column for tracking
        # df['capture_timestamp'] = datetime.now().isoformat()
        
        try:
            # Non-blocking put with timeout
            self.feature_queue.put(df, timeout=0.5)
            print(f"✓ Processed batch of {len(batch)} packets at {time.strftime('%H:%M:%S')}")
        except queue.Full:
            print("⚠ Queue full, dropping batch")
    
    def _create_dataframe(self, features_list):
        """Create and clean DataFrame from feature list"""
        df = pd.DataFrame(features_list)
        
        columns_to_fill = [
            'hot', 'logged_in', 'num_failed_logins',
            # Error rate features
            'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
            # Host-based features
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate', 
            'dst_host_diff_srv_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
            # Added compromised features columns that might be missing
            'num_compromised', 'root_shell', 'su_attempted', 'num_root',
            'num_file_creations', 'num_access_files'
        ]
        
        for col in columns_to_fill:
            if col in df.columns:
                df[col].fillna(0, inplace=True)
                if col in ['hot', 'logged_in', 'num_failed_logins', 'dst_host_count', 
                        'dst_host_srv_count', 'num_compromised', 'root_shell', 
                        'su_attempted', 'num_root', 'num_file_creations', 'num_access_files']:
                    df[col] = df[col].astype(int)
        
        return df
    
    def get_features_batch(self, timeout=1.0):
        """
        Get the next batch of features from the queue
        
        Args:
            timeout: How long to wait for data (seconds)
            
        Returns:
            DataFrame with features or None if timeout
        """
        try:
            return self.feature_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    def stop(self):
        """Stop the capturing process"""
        self.stop_capture = True