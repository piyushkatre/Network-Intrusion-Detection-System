"""
Real-time network packet capture and analysis.
Captures live network traffic and sends to prediction API.
"""

# NOTE: We do NOT import scapy.all at module level because on Windows
# it can hang for minutes while enumerating network interfaces.
# Instead, we use lazy imports inside methods that need scapy.
import requests
import json
import threading
import time
from pathlib import Path
from feature_extractor import FeatureExtractor

# Lazy-loaded scapy references
_scapy_loaded = False
_sniff = None
_IP = None
_TCP = None
_UDP = None
_conf = None


def _ensure_scapy():
    """Lazy-load scapy modules. Called once before first use."""
    global _scapy_loaded, _sniff, _IP, _TCP, _UDP, _conf
    if _scapy_loaded:
        return True
    try:
        from scapy.all import sniff, IP, TCP, UDP, conf
        _sniff = sniff
        _IP = IP
        _TCP = TCP
        _UDP = UDP
        _conf = conf
        _scapy_loaded = True
        print("  ✓ Scapy loaded successfully")
        return True
    except Exception as e:
        print(f"  ✗ Failed to load Scapy: {e}")
        return False


class NetworkCapture:
    """Capture and analyze live network traffic"""
    
    def __init__(self, api_url='http://localhost:5000/api', feature_columns_path=None):
        self.api_url = api_url
        self.is_running = False
        self.packet_count = 0
        self.prediction_count = 0
        self.attack_count = 0
        self.packet_history = []  # Store last 10,000 packets
        self.MAX_HISTORY = 10000
        
        # Initialize feature extractor
        if feature_columns_path is None:
            base_dir = Path(__file__).parent.parent
            feature_columns_path = base_dir / 'data' / 'feature_columns.npy'
        
        self.feature_extractor = FeatureExtractor(str(feature_columns_path))
        
        # Scapy will be configured on first use via _ensure_scapy()
        
    def extract_packet_info(self, packet):
        """Extract basic packet information for display"""
        info = {
            'timestamp': time.time(),
            'protocol': 'Unknown',
            'src': 'N/A',
            'dst': 'N/A',
            'length': len(packet),
            'src_port': 0,
            'dst_port': 0
        }
        
        if _IP in packet:
            info['src'] = packet[_IP].src
            info['dst'] = packet[_IP].dst
            info['protocol'] = packet[_IP].proto
            
            # Protocol name
            if _TCP in packet:
                info['protocol'] = 'TCP'
                info['src_port'] = packet[_TCP].sport
                info['dst_port'] = packet[_TCP].dport
            elif _UDP in packet:
                info['protocol'] = 'UDP'
                info['src_port'] = packet[_UDP].sport
                info['dst_port'] = packet[_UDP].dport
        
        return info
        
    def on_packet_captured(self, packet):
        """Callback for each captured packet"""
        if not self.is_running:
            return
            
        try:
            self.packet_count += 1
            
            # Only process IP packets
            if _IP not in packet:
                return
            
            # Extract features
            features = self.feature_extractor.extract(packet)
            
            # Get packet info for logging
            packet_info = self.extract_packet_info(packet)
            
            # Send for prediction
            result = self.send_for_prediction(features, packet_info)
            
            # Store full packet info with prediction result
            if result:
                packet_record = {
                    **packet_info,
                    'is_attack': result.get('is_attack', False),
                    'confidence': result.get('confidence', 0),
                    'prediction': result.get('prediction', 'Unknown')
                }
                
                # Add to history
                self.packet_history.append(packet_record)
                if len(self.packet_history) > self.MAX_HISTORY:
                    self.packet_history.pop(0)

        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def send_for_prediction(self, features, packet_info):
        """Send packet features to API for prediction"""
        try:
            response = requests.post(
                f'{self.api_url}/predict',
                json={
                    'features': features.tolist(),
                    'packet_info': packet_info  # Include packet info for backend verification
                },
                timeout=2
            )
            
            if response.status_code == 200:
                result = response.json()
                self.prediction_count += 1
                
                is_attack = result.get('is_attack', False)
                if is_attack:
                    self.attack_count += 1
                
                # Log prediction
                status = "⚠️ ATTACK" if is_attack else "✓ BENIGN"
                confidence = result.get('confidence', 0) * 100
                print(f"[{packet_info['protocol']}] {packet_info['src']} -> {packet_info['dst']} | "
                      f"{status} ({confidence:.1f}% confidence)")
                
                return result
                
            else:
                print(f"API error: {response.status_code}")
                return None
                
        except requests.exceptions.Timeout:
            print("Prediction timeout - API slow")
            return None
        except Exception as e:
            print(f"Prediction error: {e}")
            return None

    def start(self, interface=None, packet_filter='ip', count=0):
        """
        Start capturing packets
        
        Args:
            interface: Network interface to capture on (None = auto-detect)
            packet_filter: BPF filter expression (default: 'ip' for IP packets only)
            count: Number of packets to capture (0 = unlimited)
        """
        # Auto-detect best interface if not specified
        if interface is None:
            print("Auto-detecting network interface...")
            try:
                from scapy.all import get_if_list, get_if_addr
                
                # Method 1: Find interface matching common local IPs (192.168.x.x, 10.x.x.x, 172.x.x.x)
                found = False
                for iface in get_if_list():
                    try:
                        ip = get_if_addr(iface)
                        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
                            interface = iface
                            print(f"✓ Auto-selected interface by IP ({ip}): {interface}")
                            found = True
                            break
                    except Exception:
                        continue
                
                # Method 2: Fallback to route if no local IP found
                if not found:
                    print("No local IP interface found, falling back to route...")
                    interface = _conf.route.route("8.8.8.8")[0]
                    print(f"✓ Auto-selected interface by route: {interface}")
                    
            except Exception as e:
                print(f"Warning: Interface auto-detection failed: {e}")
                print("Using default interface.")
        
        self.is_running = True
        self.packet_count = 0
        self.prediction_count = 0
        self.attack_count = 0
        self.packet_history = []  # Reset history on new capture
        
        print("=" * 60)
        print("REAL-TIME NETWORK INTRUSION DETECTION")
        print("=" * 60)
        print(f"Interface: {interface or 'All available interfaces'}")
        print(f"Filter: {packet_filter}")
        print(f"API Endpoint: {self.api_url}")
        print("Press CTRL+C to stop...\n")
        
        try:
            # Start packet capture
            _sniff(
                prn=self.on_packet_captured,
                iface=interface,
                filter=packet_filter,
                store=False,  # Don't store packets in memory
                count=count
            )
        except KeyboardInterrupt:
            print("\n\nCapture stopped by user")
        except PermissionError:
            print("\n❌ ERROR: Permission denied!")
            print("Live packet capture requires administrator/root privileges.")
            print("\nOn Windows:")
            print("1. Make sure Npcap is installed (https://npcap.com/)")
            print("2. Run this script as Administrator")
        except Exception as e:
            print(f"\n❌ Capture error: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop packet capture"""
        self.is_running = False
        print("\n" + "=" * 60)
        print("CAPTURE STATISTICS")
        print("=" * 60)
        print(f"Total packets captured: {self.packet_count}")
        print(f"Packets analyzed: {self.prediction_count}")
        print(f"Attacks detected: {self.attack_count}")
        if self.prediction_count > 0:
            attack_rate = (self.attack_count / self.prediction_count) * 100
            print(f"Attack rate: {attack_rate:.2f}%")
        print("=" * 60)
    
    def get_stats(self):
        """Get current capture statistics and recent packets"""
        # Return last 50 packets for live feed by default
        recent_packets = self.packet_history[-50:] if len(self.packet_history) > 0 else []
        return {
            'running': self.is_running,
            'packet_count': self.packet_count,
            'prediction_count': self.prediction_count,
            'attack_count': self.attack_count,
            'recent_packets': recent_packets
        }
        
    def get_full_history(self):
        """Get full packet history for export"""
        return self.packet_history


def main():
    """Standalone mode - run capture from command line"""
    import sys
    
    # Check if API is running
    api_url = 'http://localhost:5000/api'
    try:
        response = requests.get(f'{api_url}/health', timeout=2)
        if response.status_code != 200:
            print("❌ API not available. Please start the server first:")
            print("   python src/app.py")
            sys.exit(1)
    except Exception:
        print("❌ Cannot connect to API at http://localhost:5000")
        print("Please start the server first: python src/app.py")
        sys.exit(1)
    
    # Start capture
    capture = NetworkCapture(api_url=api_url)
    
    # Get interface from command line args if provided
    interface = sys.argv[1] if len(sys.argv) > 1 else None
    
    capture.start(interface=interface, packet_filter='ip')


if __name__ == '__main__':
    main()
