"""
Safe Attack Simulator for Testing IDS
Generates suspicious network traffic patterns to test detection capabilities.
"""

import sys
import time
import random
import platform

# Check if running on Windows and if admin
def is_admin():
    """Check if script is running with administrator privileges"""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        import os
        return os.geteuid() == 0

def check_scapy():
    """Check if Scapy is available and working"""
    try:
        from scapy.all import IP, TCP, send
        return True
    except ImportError:
        return False
    except Exception as e:
        print(f"Error with Scapy: {e}")
        return False

# Try to import scapy components
try:
    from scapy.all import IP, TCP, UDP, send, RandShort, RandIP, conf, get_if_list, get_if_addr
    SCAPY_AVAILABLE = True
    
    # Auto-configure Scapy interface to match NIDS logic
    try:
        # Find interface with local IP
        target_iface = None
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
                    target_iface = iface
                    break
            except Exception:
                pass
        
        if target_iface:
            conf.iface = target_iface
            print(f"[*] Configured Scapy to send on: {target_iface} ({get_if_addr(target_iface)})")
        else:
            # Fallback
            route = conf.route.route("8.8.8.8")
            conf.iface = route[0]
            print(f"[*] Fallback interface: {conf.iface}")
            
    except Exception as e:
        print(f"Error configuring interface: {e}")

except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy not installed. Install with: pip install scapy")

def scan_attack(target_ip="45.33.32.156", count=50):
    """Simulate a rapid port scan using Scapy TCP SYN packets"""
    if not SCAPY_AVAILABLE:
        print("\n[!] Scapy not available - using socket fallback")
        import socket
        print(f"\n[+] Simulating Port Scan on {target_ip} (Socket Mode)...")
        print(f"    Sending {count} connection attempts rapidly...")
        for i in range(count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                port = 80 + i
                result = s.connect_ex((target_ip, port))
                s.close()
            except Exception:
                pass
            if i % 10 == 0:
                sys.stdout.write(".")
                sys.stdout.flush()
            time.sleep(0.02)
        print("\n[+] Scan simulation complete")
        return True
    
    print(f"\n[+] Simulating Port Scan on {target_ip} (Scapy Mode)...")
    print(f"    Sending {count} TCP SYN packets...")
    
    try:
        for i in range(count):
            # Create TCP SYN packet for port scan
            port = 80 + (i % 100)  # Scan ports 80-179
            packet = IP(dst=target_ip)/TCP(dport=port, flags="S")
            send(packet, verbose=0)
            
            if i % 10 == 0:
                sys.stdout.write(".")
                sys.stdout.flush()
            time.sleep(0.05)  # Slow enough to be captured
        
        print("\n[+] Scan simulation complete")
        return True
    except Exception as e:
        print(f"\nError during scan: {e}")
        return False

def dos_pattern(target_ip="45.33.32.156", count=100):
    """Simulate a SYN Flood pattern (DoS) using Scapy"""
    if not SCAPY_AVAILABLE:
        print("\n[!] Scapy not available - using socket fallback")
        import socket
        print(f"\n[+] Simulating DoS Pattern on {target_ip} (Socket Mode)...")
        print(f"    Sending {count} high-speed requests...")
        packets_sent = 0
        for i in range(count):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.01)
                s.connect_ex((target_ip, 80))
                s.close()
                packets_sent += 1
            except Exception:
                pass
            if i % 10 == 0:
                sys.stdout.write(".")
                sys.stdout.flush()
            time.sleep(0.001)
        print(f"\n[+] DoS simulation complete ({packets_sent} requests sent)")
        return True
    
    print(f"\n[+] Simulating DoS Pattern on {target_ip} (Scapy Mode)...")
    print(f"    Sending {count} rapid TCP SYN packets...")
    
    try:
        packets_sent = 0
        for i in range(count):
            # Create TCP SYN packet targeting port 80
            packet = IP(dst=target_ip)/TCP(dport=80, flags="S", sport=RandShort())
            send(packet, verbose=0)
            packets_sent += 1
            
            if i % 10 == 0:
                sys.stdout.write(".")
                sys.stdout.flush()
            time.sleep(0.01)  # Fast but capturable
            
        print(f"\n[+] DoS simulation complete ({packets_sent} packets sent)")
        return True
    except Exception as e:
        print(f"\n  Error during DoS simulation: {e}")
        return False

def unusual_flags(target_ip="192.168.1.1", count=20):
    """Simulate packets with unusual TCP flags (Xmas scan, Null scan)"""
    if not SCAPY_AVAILABLE:
        print("  Scapy not available. Cannot send packets.")
        return False
        
    print(f"\n[+] Simulating Malformed Packets on {target_ip}...")
    
    try:
        # Xmas Scan (FIN, URG, PSH set) - very suspicious
        print("    Sending Xmas Scan packets...")
        for _ in range(count):
            pkt = IP(dst=target_ip)/TCP(dport=80, flags="FPU")
            send(pkt, verbose=0)
            time.sleep(0.05)
            
        # Null Scan (No flags) - suspicious
        print("    Sending Null Scan packets...")
        for _ in range(count):
            pkt = IP(dst=target_ip)/TCP(dport=80, flags="")
            send(pkt, verbose=0)
            time.sleep(0.05)
            
        print("[+] Malformed packet simulation complete")
        return True
    except Exception as e:
        print(f"\n  Error during malformed packet simulation: {e}")
        return False

def http_based_test():
    """Alternative: Use HTTP requests to generate traffic for testing"""
    import requests # type: ignore
    
    print("\n" + "=" * 60)
    print("HTTP-BASED ATTACK SIMULATION")
    print("=" * 60)
    print("This generates HTTP traffic that can be captured and analyzed.")
    print("Less realistic than raw packets, but works without admin rights.")
    
    try:
        # Rapid requests (simulates scanning)
        print("\n[+] Simulating rapid HTTP requests (scan-like)...")
        for i in range(50):
            try:
                requests.get(f"http://scanme.nmap.org", timeout=1)
                if i % 10 == 0:
                    sys.stdout.write(".")
                    sys.stdout.flush()
            except Exception:
                pass
            time.sleep(0.01)
        
        print("\n[+] HTTP simulation complete")
        print("Check your network capture for this traffic!")
        
    except ImportError:
        print("  'requests' library not installed. Install with: pip install requests")
    except Exception as e:
        print(f"  Error: {e}")

def main():
    print("=" * 60)
    print("IDS ATTACK SIMULATOR")
    print("=" * 60)
    
    # Check prerequisites
    print("\n" + "=" * 60)
    print("SYSTEM CHECK")
    print("=" * 60)
    
    if platform.system() == "Windows":
        if not is_admin():
            print("WARNING: Not running as Administrator!")
            print("Raw packet sending may fail on Windows without admin rights.")
            print("Right-click Python/Terminal and 'Run as Administrator'")
            print("\nAlternative: Use HTTP-based testing (Option 6)")
        else:
            print("Running with Administrator privileges")
    
    if not SCAPY_AVAILABLE:
        print("Scapy not available")
        print("Install with: pip install scapy")
        print("\nYou can still use HTTP-based testing (Option 6)")
    else:
        print("Scapy is available")
    
    print("\nEnsure your 'python src/app.py' server is running!")
    print("Run 'Start Monitoring' in the UI first.")
    
    target = "8.8.8.8"  # Changed to 8.8.8.8 (Confirmed visible in logs)
    print(f"\nTargeting External IP: {target}")
    print("This ensures packets leave the interface and are captured.")

    try:
        while True:
            print("\n" + "=" * 60)
            print("Select simulation type:")
            print("1. Port Scan (Rapid connection attempts)")
            print("2. SYN Flood Pattern (DoS characteristics)")
            print("3. Suspicious Flags (Xmas/Null scans)")
            print("4. CONTINUOUS ATTACK LOOP (Best for testing)")
            print("5. HTTP-Based Testing (No admin required)")
            print("6. Exit")
            
            choice = input("\nEnter choice (1-6): ").strip()
            
            if choice == '1':
                if scan_attack(target):
                    print("\nCheck your Real-Time UI for alerts!")
            elif choice == '2':
                if dos_pattern(target):
                    print("\nCheck your Real-Time UI for alerts!")
            elif choice == '3':
                if unusual_flags(target):
                    print("\nCheck your Real-Time UI for alerts!")
            elif choice == '4':
                print("\n[!] Starting CONTINUOUS ATTACK SIMULATION...")
                print("    Press CTRL+C to stop")
                try:
                    while True:
                        scan_attack(target, count=20)
                        time.sleep(0.5)
                        dos_pattern(target, count=20)
                        time.sleep(0.5)
                        unusual_flags(target, count=10)
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n[!] Stopped continuous simulation")
            elif choice == '5':
                http_based_test()
            elif choice == '6':
                break
            else:
                print("Invalid choice. Please enter 1-6.")
                
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n[!] Stopped.")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
