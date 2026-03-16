"""
Traffic Converter Module
Converts numeric network features to natural language descriptions for LLM analysis.
"""

import numpy as np
from typing import Dict, List, Tuple


class TrafficConverter:
    """Converts network traffic features to human-readable descriptions."""
    
    def __init__(self):
        self.port_names = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 445: "SMB", 3389: "RDP",
            8080: "HTTP-Proxy", 3306: "MySQL", 5432: "PostgreSQL"
        }
        
        self.feature_descriptions = {
            'Destination Port': 'destination port',
            'Flow Duration': 'flow duration (ms)',
            'Total Fwd Packets': 'forward packets',
            'Total Backward Packets': 'backward packets',
            'Flow Bytes/s': 'bytes per second',
            'Flow Packets/s': 'packets per second',
            'Fwd Packet Length Mean': 'average forward packet size',
            'Bwd Packet Length Mean': 'average backward packet size',
            'Flow IAT Mean': 'average inter-arrival time',
            'SYN Flag Count': 'SYN flags',
            'ACK Flag Count': 'ACK flags',
            'PSH Flag Count': 'PSH flags',
            'FIN Flag Count': 'FIN flags',
            'RST Flag Count': 'RST flags'
        }
    
    def features_to_description(self, features: np.ndarray, feature_names: List[str]) -> str:
        """
        Convert numeric features to natural language description.
        
        Args:
            features: Array of numeric feature values
            feature_names: List of feature names
            
        Returns:
            Natural language description of the network traffic
        """
        if len(features) != len(feature_names):
            raise ValueError(f"Features ({len(features)}) and names ({len(feature_names)}) length mismatch")
        
        # Create feature dictionary
        feature_dict = {name: value for name, value in zip(feature_names, features)}
        
        # Build description
        description_parts = []
        
        # Port information
        if 'Destination Port' in feature_dict:
            port = int(feature_dict['Destination Port'])
            port_name = self.port_names.get(port, f"port {port}")
            description_parts.append(f"Network traffic to {port_name}")
        
        # Flow characteristics
        if 'Flow Duration' in feature_dict:
            duration = feature_dict['Flow Duration']
            if duration > 0:
                description_parts.append(f"lasting {duration:.0f}ms")
        
        # Packet counts
        fwd_packets = feature_dict.get('Total Fwd Packets', 0)
        bwd_packets = feature_dict.get('Total Backward Packets', 0)
        if fwd_packets > 0 or bwd_packets > 0:
            description_parts.append(
                f"with {int(fwd_packets)} forward and {int(bwd_packets)} backward packets"
            )
        
        # Data transfer rate
        if 'Flow Bytes/s' in feature_dict:
            bytes_per_sec = feature_dict['Flow Bytes/s']
            if bytes_per_sec > 1000000:
                description_parts.append(f"transferring {bytes_per_sec/1000000:.2f} MB/s")
            elif bytes_per_sec > 1000:
                description_parts.append(f"transferring {bytes_per_sec/1000:.2f} KB/s")
        
        # TCP flags analysis
        flags = self._analyze_tcp_flags(feature_dict)
        if flags:
            description_parts.append(flags)
        
        # Suspicious patterns
        suspicious = self._identify_suspicious_patterns(feature_dict)
        if suspicious:
            description_parts.append(f"Suspicious indicators: {', '.join(suspicious)}")
        
        return ". ".join(description_parts) + "."
    
    def _analyze_tcp_flags(self, feature_dict: Dict[str, float]) -> str:
        """Analyze TCP flags to describe connection behavior."""
        flags = []
        
        syn_count = feature_dict.get('SYN Flag Count', 0)
        ack_count = feature_dict.get('ACK Flag Count', 0)
        fin_count = feature_dict.get('FIN Flag Count', 0)
        rst_count = feature_dict.get('RST Flag Count', 0)
        psh_count = feature_dict.get('PSH Flag Count', 0)
        
        if syn_count > 0 and ack_count == 0:
            flags.append("SYN without ACK (possible scan)")
        elif syn_count > 5:
            flags.append(f"multiple SYN attempts ({int(syn_count)})")
        
        if rst_count > 0:
            flags.append(f"connection reset ({int(rst_count)} times)")
        
        if fin_count > 0:
            flags.append("normal connection termination")
        
        if psh_count > 0:
            flags.append("data push")
        
        return ", ".join(flags) if flags else ""
    
    def _identify_suspicious_patterns(self, feature_dict: Dict[str, float]) -> List[str]:
        """Identify potentially suspicious patterns in the traffic."""
        suspicious = []
        
        # Port scanning indicators
        if feature_dict.get('Total Fwd Packets', 0) > 0 and feature_dict.get('Total Backward Packets', 0) == 0:
            suspicious.append("one-way traffic (possible scan)")
        
        # High packet rate
        packets_per_sec = feature_dict.get('Flow Packets/s', 0)
        if packets_per_sec > 1000:
            suspicious.append(f"high packet rate ({packets_per_sec:.0f} pkt/s)")
        
        # Very short or very long flows
        duration = feature_dict.get('Flow Duration', 0)
        if duration < 10 and duration > 0:
            suspicious.append("very short connection")
        elif duration > 1000000:  # > 1000 seconds
            suspicious.append("unusually long connection")
        
        # Unusual packet sizes
        fwd_mean = feature_dict.get('Fwd Packet Length Mean', 0)
        if fwd_mean > 1400:
            suspicious.append("large packet sizes")
        elif fwd_mean < 40 and fwd_mean > 0:
            suspicious.append("very small packets")
        
        # High SYN count (port scan)
        syn_count = feature_dict.get('SYN Flag Count', 0)
        if syn_count > 10:
            suspicious.append("excessive SYN flags")
        
        return suspicious
    
    def generate_traffic_summary(self, features: np.ndarray, feature_names: List[str]) -> str:
        """
        Generate a concise summary of traffic for LLM analysis.
        
        Args:
            features: Array of numeric feature values
            feature_names: List of feature names
            
        Returns:
            Concise traffic summary
        """
        feature_dict = {name: value for name, value in zip(feature_names, features)}
        
        summary = []
        
        # Basic info
        port = int(feature_dict.get('Destination Port', 0))
        port_name = self.port_names.get(port, f"port {port}")
        summary.append(f"Traffic to {port_name}")
        
        # Volume
        fwd = int(feature_dict.get('Total Fwd Packets', 0))
        bwd = int(feature_dict.get('Total Backward Packets', 0))
        summary.append(f"({fwd}→, {bwd}←)")
        
        # Duration
        duration = feature_dict.get('Flow Duration', 0)
        if duration > 0:
            summary.append(f"{duration:.0f}ms")
        
        # Flags
        flags = []
        if feature_dict.get('SYN Flag Count', 0) > 0:
            flags.append("SYN")
        if feature_dict.get('ACK Flag Count', 0) > 0:
            flags.append("ACK")
        if feature_dict.get('FIN Flag Count', 0) > 0:
            flags.append("FIN")
        if feature_dict.get('RST Flag Count', 0) > 0:
            flags.append("RST")
        
        if flags:
            summary.append(f"[{','.join(flags)}]")
        
        return " ".join(summary)
    
    def interpret_feature(self, feature_name: str, value: float) -> str:
        """
        Interpret a single feature value.
        
        Args:
            feature_name: Name of the feature
            value: Feature value
            
        Returns:
            Human-readable interpretation
        """
        if feature_name in self.feature_descriptions:
            desc = self.feature_descriptions[feature_name]
            return f"{desc}: {value:.2f}"
        
        return f"{feature_name}: {value:.2f}"
