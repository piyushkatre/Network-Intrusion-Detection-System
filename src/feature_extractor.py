"""
Feature extraction from live network packets.
Extracts the same 82 features expected by the trained ML model.
"""

import numpy as np
from collections import defaultdict
from datetime import datetime
import time

# Lazy scapy imports to avoid Windows hang during interface enumeration
_scapy_mods = None

def _get_scapy():
    """Lazy-load scapy classes. Returns a namespace object with IP, TCP, UDP, ICMP, Raw."""
    global _scapy_mods
    if _scapy_mods is not None:
        return _scapy_mods
    from scapy.all import IP, TCP, UDP, ICMP, Raw
    class _ScapyMods:
        pass
    _scapy_mods = _ScapyMods()
    _scapy_mods.IP = IP
    _scapy_mods.TCP = TCP
    _scapy_mods.UDP = UDP
    _scapy_mods.ICMP = ICMP
    _scapy_mods.Raw = Raw
    return _scapy_mods


class FlowTracker:
    """Track network flows to compute flow-based features"""
    def __init__(self, timeout=60):
        self.flows = {}  # (src_ip, dst_ip, src_port, dst_port, protocol) -> flow_data
        self.timeout = timeout
        
    def get_flow_key(self, packet):
        """Generate unique flow identifier"""
        s = _get_scapy()
        if s.IP not in packet:
            return None
            
        src_ip = packet[s.IP].src
        dst_ip = packet[s.IP].dst
        protocol = packet[s.IP].proto
        
        src_port = packet[s.TCP].sport if s.TCP in packet else (packet[s.UDP].sport if s.UDP in packet else 0)
        dst_port = packet[s.TCP].dport if s.TCP in packet else (packet[s.UDP].dport if s.UDP in packet else 0)
        
        return (src_ip, dst_ip, src_port, dst_port, protocol)
    
    def update_flow(self, packet):
        """Update flow statistics with new packet"""
        s = _get_scapy()
        flow_key = self.get_flow_key(packet)
        if not flow_key:
            return None
            
        current_time = time.time()
        
        # Clean old flows
        self._cleanup_old_flows(current_time)
        
        # Check if this packet is a reply (reverse flow)
        reverse_key = (flow_key[1], flow_key[0], flow_key[3], flow_key[2], flow_key[4])
        is_backward = reverse_key in self.flows and flow_key not in self.flows
        
        active_key = reverse_key if is_backward else flow_key
        
        if active_key not in self.flows:
            self.flows[active_key] = {
                'start_time': current_time,
                'last_time': current_time,
                'fwd_packets': 0,
                'bwd_packets': 0,
                'fwd_bytes': 0,
                'bwd_bytes': 0,
                'fwd_packet_lengths': [],
                'bwd_packet_lengths': [],
                'packet_times': [],
                'flags': []
            }
        
        flow = self.flows[active_key]
        packet_len = len(packet)
        
        # Update flow data
        flow['last_time'] = current_time
        flow['packet_times'].append(current_time)
        
        if is_backward:
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += packet_len
            flow['bwd_packet_lengths'].append(packet_len)
        else:
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += packet_len
            flow['fwd_packet_lengths'].append(packet_len)
        
        if s.TCP in packet:
            flags = packet[s.TCP].flags
            flow['flags'].append(str(flags))
        
        return flow
    
    def _cleanup_old_flows(self, current_time):
        """Remove flows older than timeout"""
        to_remove = []
        for key, flow in self.flows.items():
            if current_time - flow['last_time'] > self.timeout:
                to_remove.append(key)
        for key in to_remove:
            del self.flows[key]


class FeatureExtractor:
    """Extract 82 features from network packets"""
    
    def __init__(self, feature_columns_path):
        """Initialize with feature column names from training"""
        self.feature_columns = np.load(feature_columns_path, allow_pickle=True).tolist()
        self.flow_tracker = FlowTracker()
        
    def extract(self, packet):
        """Extract all 82 features from a packet"""
        s = _get_scapy()
        features = {}
        
        # Update flow tracking
        flow = self.flow_tracker.update_flow(packet)
        
        if s.IP not in packet:
            # Return zero features for non-IP packets
            return np.zeros(len(self.feature_columns))
        
        # Basic packet information
        packet_len = len(packet)
        ip_layer = packet[s.IP]
        
        # Protocol type
        protocol = ip_layer.proto
        features['protocol'] = protocol
        
        # Packet sizes
        features['total_length'] = packet_len
        features['header_length'] = ip_layer.ihl * 4 if hasattr(ip_layer, 'ihl') else 20
        
        # TCP/UDP features
        if s.TCP in packet:
            tcp = packet[s.TCP]
            features['src_port'] = tcp.sport
            features['dst_port'] = tcp.dport
            features['tcp_flags'] = int(tcp.flags)
            features['tcp_window'] = tcp.window
            features['tcp_urgptr'] = tcp.urgptr if hasattr(tcp, 'urgptr') else 0
        elif s.UDP in packet:
            udp = packet[s.UDP]
            features['src_port'] = udp.sport
            features['dst_port'] = udp.dport
            features['tcp_flags'] = 0
            features['tcp_window'] = 0
            features['tcp_urgptr'] = 0
        else:
            features['src_port'] = 0
            features['dst_port'] = 0
            features['tcp_flags'] = 0
            features['tcp_window'] = 0
            features['tcp_urgptr'] = 0
        
        # Flow-based features (from tracker)
        if flow:
            duration = flow['last_time'] - flow['start_time']
            features['flow_duration'] = duration if duration > 0 else 0.001
            features['fwd_packets'] = flow['fwd_packets']
            features['bwd_packets'] = flow['bwd_packets']
            features['fwd_bytes'] = flow['fwd_bytes']
            features['bwd_bytes'] = flow['bwd_bytes']
            
            # Packet length statistics
            fwd_lengths = flow['fwd_packet_lengths']
            if fwd_lengths:
                features['fwd_packet_length_max'] = max(fwd_lengths)
                features['fwd_packet_length_min'] = min(fwd_lengths)
                features['fwd_packet_length_mean'] = np.mean(fwd_lengths)
                features['fwd_packet_length_std'] = np.std(fwd_lengths)
            else:
                features['fwd_packet_length_max'] = 0
                features['fwd_packet_length_min'] = 0
                features['fwd_packet_length_mean'] = 0
                features['fwd_packet_length_std'] = 0
            
            # Rates
            if duration > 0:
                features['fwd_packets_per_sec'] = flow['fwd_packets'] / duration
                features['bwd_packets_per_sec'] = flow['bwd_packets'] / duration
            else:
                features['fwd_packets_per_sec'] = 0
                features['bwd_packets_per_sec'] = 0
            
            # Inter-arrival times
            packet_times = flow['packet_times']
            if len(packet_times) > 1:
                iat = np.diff(packet_times)
                features['flow_iat_mean'] = np.mean(iat)
                features['flow_iat_std'] = np.std(iat)
                features['flow_iat_max'] = np.max(iat)
                features['flow_iat_min'] = np.min(iat)
            else:
                features['flow_iat_mean'] = 0
                features['flow_iat_std'] = 0
                features['flow_iat_max'] = 0
                features['flow_iat_min'] = 0
        else:
            # Default flow features for first packet
            features['flow_duration'] = 0.001
            features['fwd_packets'] = 1
            features['bwd_packets'] = 0
            features['fwd_bytes'] = packet_len
            features['bwd_bytes'] = 0
            features['fwd_packet_length_max'] = packet_len
            features['fwd_packet_length_min'] = packet_len
            features['fwd_packet_length_mean'] = packet_len
            features['fwd_packet_length_std'] = 0
            features['fwd_packets_per_sec'] = 1000
            features['bwd_packets_per_sec'] = 0
            features['flow_iat_mean'] = 0
            features['flow_iat_std'] = 0
            features['flow_iat_max'] = 0
            features['flow_iat_min'] = 0
        
        # Payload data
        if s.Raw in packet:
            features['payload_bytes'] = len(packet[s.Raw].load)
        else:
            features['payload_bytes'] = 0
        
        # Build feature array in correct order
        # Use exact match first, then fuzzy substring match as fallback
        feature_array = []
        for col in self.feature_columns:
            # Try exact match first
            if col in features:
                feature_array.append(float(features[col]))
                continue
            
            # Fallback: case-insensitive exact match
            col_lower = col.lower()
            matched = False
            for key, val in features.items():
                if key.lower() == col_lower:
                    feature_array.append(float(val))
                    matched = True
                    break
            
            if not matched:
                # Last resort: substring match (less reliable)
                for key, val in features.items():
                    if key.lower() in col_lower or col_lower in key.lower():
                        feature_array.append(float(val))
                        matched = True
                        break
            
            if not matched:
                feature_array.append(0.0)
        
        return np.array(feature_array)
