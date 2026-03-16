"""
Test if Scapy packets sent from this machine are visible to Scapy sniffer.
This helps diagnose why the IDS isn't seeing simulated attacks.
"""

from scapy.all import *
import threading
import time

def packet_sniffer():
    """Sniff packets for 10 seconds"""
    print("\n[SNIFFER] Starting packet capture for 10 seconds...")
    print("[SNIFFER] Looking for packets to 8.8.8.8...")
    
    def packet_callback(pkt):
        if IP in pkt:
            if pkt[IP].dst == "8.8.8.8" or pkt[IP].src == "8.8.8.8":
                proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
                print(f"[SNIFFER] ✓ CAPTURED: {pkt[IP].src} -> {pkt[IP].dst} [{proto}]")
    
    sniff(filter="host 8.8.8.8", prn=packet_callback, timeout=10, store=False)
    print("[SNIFFER] Capture complete\n")

def packet_sender():
    """Send test packets after 2 seconds"""
    time.sleep(2)
    print("\n[SENDER] Sending 5 test TCP SYN packets to 8.8.8.8...")
    
    for i in range(5):
        pkt = IP(dst="8.8.8.8")/TCP(dport=80+i, flags="S")
        send(pkt, verbose=0)
        print(f"[SENDER] Sent packet #{i+1} to port {80+i}")
        time.sleep(0.5)
    
    print("[SENDER] All packets sent\n")

if __name__ == "__main__":
    print("="*60)
    print("PACKET VISIBILITY TEST")
    print("="*60)
    print("\nThis test checks if Scapy can capture packets it sends.")
    print("If you see 'CAPTURED' messages, the IDS should work.")
    print("If not, there's a Windows networking issue.\n")
    
    # Start sniffer in background
    sniffer_thread = threading.Thread(target=packet_sniffer, daemon=True)
    sniffer_thread.start()
    
    # Send packets in main thread
    packet_sender()
    
    # Wait for sniffer to finish
    sniffer_thread.join()
    
    print("="*60)
    print("TEST COMPLETE")
    print("="*60)
    print("\nIf you saw CAPTURED messages above, your setup is working!")
    print("If not, Scapy cannot see its own packets on Windows.")
    print("This is a known limitation on some Windows configurations.")
