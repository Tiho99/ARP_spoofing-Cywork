#!/usr/bin/env python3
import requests
import time

print("[*] Generating HTTP traffic to test the sniffer...")
print("[*] This script visits public HTTP websites")

# List of HTTP sites (not HTTPS)
http_sites = [
    "http://example.com",
    "http://httpforever.com",
    "http://neverssl.com",
    "http://info.cern.ch"
]

for site in http_sites:
    try:
        print(f"[*] Visiting: {site}")
        response = requests.get(site, timeout=5)
        print(f"    Response: {response.status_code}")
        time.sleep(2)
    except:
        print(f"    Failed: {site}")
    
print("[*] Test completed!")