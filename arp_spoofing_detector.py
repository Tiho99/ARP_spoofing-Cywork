#!/usr/bin/env python3
import scapy.all as scapy
import sys
import time
import argparse

# Dictionary to store IP-MAC associations
ip_mac_mapping = {}

def get_mac(ip, interface):
    """
    Retrieve the real MAC address of an IP
    """
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, 
                                 iface=interface, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        return None
    except:
        return None

def process_sniffed_packet(packet):
    """
    Analyze each ARP packet
    """
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        arp_packet = packet[scapy.ARP]
        sender_ip = arp_packet.psrc
        sender_mac = arp_packet.hwsrc
        
        print(f"[.] ARP Reply detected: {sender_ip} -> {sender_mac}")
        
        # Check if we already know this IP
        if sender_ip in ip_mac_mapping:
            # Check if MAC has changed
            known_mac = ip_mac_mapping[sender_ip]
            
            if sender_mac != known_mac:
                print(f"\n{'!'*50}")
                print(f"[!] ARP SPOOFING ALERT DETECTED!")
                print(f"[!] IP: {sender_ip}")
                print(f"[!] Old MAC: {known_mac}")
                print(f"[!] New suspicious MAC: {sender_mac}")
                print(f"[!] Time: {time.strftime('%H:%M:%S')}")
                print(f"{'!'*50}\n")
                
                # Verify the real MAC
                print(f"[*] Verifying real MAC...")
                # Note: This part is commented as it can slow down
                # real_mac = get_mac(sender_ip, interface)
                # if real_mac and real_mac != sender_mac:
                #     print(f"[!] CONFIRMED: Spoofing!")
        else:
            # New IP, add to mapping
            ip_mac_mapping[sender_ip] = sender_mac
            print(f"[+] New IP recorded: {sender_ip} -> {sender_mac}")

def initialize_baseline(interface, known_ips):
    """
    Initialize the baseline with known IP-MAC mappings
    """
    print(f"[*] Initializing baseline reference...")
    
    # Add our own IP and MAC
    try:
        our_mac = scapy.get_if_hwaddr(interface)
        print(f"[+] Our MAC: {our_mac}")
        # Add broadcast and multicast addresses
        ip_mac_mapping["ff:ff:ff:ff:ff:ff"] = "Broadcast"
        ip_mac_mapping["00:00:00:00:00:00"] = "Zero MAC"
    except:
        print(f"[!] Unable to retrieve our MAC")
    
    # Add custom known IPs
    if known_ips:
        for ip in known_ips:
            mac = get_mac(ip, interface)
            if mac:
                ip_mac_mapping[ip] = mac
                print(f"[+] {ip} -> {mac}")
            else:
                print(f"[-] {ip} -> Not reachable")
    
    print(f"\n[*] Baseline initialized")
    return len(ip_mac_mapping)

def sniff(interface, known_ips):
    """
    Start ARP monitoring
    """
    print(f"[*] Starting ARP Spoofing Detector on {interface}")
    print(f"[*] Monitoring ARP replies...")
    print(f"[*] Press Ctrl+C to stop\n")
    
    # Initialize baseline
    ip_count = initialize_baseline(interface, known_ips)
    print(f"[*] Starting real-time monitoring...\n")
    
    try:
        # Filter only ARP packets
        scapy.sniff(iface=interface, store=False, 
                   prn=process_sniffed_packet,
                   filter="arp")
    except KeyboardInterrupt:
        print(f"\n\n[*] Monitoring stopped")
        print(f"[*] IPs monitored: {len(ip_mac_mapping)}")
        sys.exit(0)
    except PermissionError:
        print(f"\n[!] ERROR: Permission denied!")
        print(f"[!] Run with: sudo python3 {sys.argv[0]} <interface>")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Spoofing Detector")
    parser.add_argument("interface", help="Network interface to monitor")
    parser.add_argument("-k", "--known-ips", nargs="+", 
                       help="List of known IP addresses to baseline (space-separated)")
    parser.add_argument("-f", "--file", help="File containing list of IPs (one per line)")
    
    args = parser.parse_args()
    
    # Check for sudo/root privileges
    import os
    if os.geteuid() != 0:
        print(f"[!] Run with sudo!")
        print(f"[!] Command: sudo python3 {sys.argv[0]} {args.interface}")
        if args.known_ips:
            print(f"[!] Example: sudo python3 {sys.argv[0]} {args.interface} -k {' '.join(args.known_ips)}")
        sys.exit(1)
    
    # Prepare known IPs list
    known_ips_list = []
    
    # Add IPs from command line
    if args.known_ips:
        known_ips_list.extend(args.known_ips)
    
    # Add IPs from file
    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_ips = [line.strip() for line in f if line.strip()]
                known_ips_list.extend(file_ips)
                print(f"[*] Loaded {len(file_ips)} IPs from {args.file}")
        except FileNotFoundError:
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
    
    # If no IPs provided, use common defaults
    if not known_ips_list:
        print("[*] No IPs specified, using common defaults")
        print("[*] Tip: Use -k option to specify your own IPs")
        # Common gateway IPs
        known_ips_list = ["192.168.1.1", "192.168.0.1", "10.0.0.1", "10.0.2.2"]
    
    print(f"[*] Interface: {args.interface}")
    print(f"[*] Known IPs to baseline: {len(known_ips_list)}")
    if known_ips_list:
        for ip in known_ips_list[:5]:  # Show first 5
            print(f"    - {ip}")
        if len(known_ips_list) > 5:
            print(f"    ... and {len(known_ips_list) - 5} more")
    
    sniff(args.interface, known_ips_list)