"""
Cisco Device Connection Test
=============================
Run this to verify connection to a real Cisco device.

Usage:
    python test_cisco.py

Make sure your .env has:
    CISCO_HOST=<device IP or hostname>
    CISCO_USERNAME=<username>
    CISCO_PASSWORD=<password>
"""

import os
import sys
import json
from dotenv import load_dotenv

load_dotenv()

CISCO_HOST     = os.getenv("CISCO_HOST",     "sandbox-iosxe-latest-1.cisco.com")
CISCO_USERNAME = os.getenv("CISCO_USERNAME", "developer")
CISCO_PASSWORD = os.getenv("CISCO_PASSWORD", "C1sco12345")
CISCO_PORT     = int(os.getenv("CISCO_PORT", "443"))

print("=" * 55)
print("  Cisco Device Connection Test")
print("=" * 55)
print(f"  Host     : {CISCO_HOST}")
print(f"  Username : {CISCO_USERNAME}")
print(f"  Port     : {CISCO_PORT}")
print("=" * 55)

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "mock"))

from device_collector import CiscoIOSXECollector

collector = CiscoIOSXECollector(CISCO_HOST, CISCO_USERNAME, CISCO_PASSWORD, CISCO_PORT)

# Step 1: Test connection
print("\n[1] Testing connection...")
if collector.test_connection():
    print(f"    [OK] Connected!")

    # Step 2: Get hostname
    hostname = collector.get_hostname()
    print(f"    [OK] Device hostname: {hostname}")

    # Step 3: Get interfaces
    print("\n[2] Fetching interfaces...")
    interfaces = collector.get_interfaces()
    if interfaces:
        print(f"    [OK] Found {len(interfaces)} interfaces:")
        for ev in interfaces:
            status = "UP  " if "up" in ev["message"].lower() else "DOWN"
            print(f"         [{status}] {ev['message']}")
    else:
        print("    [--] No interfaces returned")

    # Step 4: Get ACLs
    print("\n[3] Fetching ACL rules...")
    acls = collector.get_acl_logs()
    if acls:
        print(f"    [OK] Found {len(acls)} ACL entries")
    else:
        print("    [--] No ACL data returned")

    print("\n[OK] All tests passed! Device is ready for SOC dashboard.")
    print("     Start the dashboard with: python main.py")

else:
    print(f"    [ERROR] Cannot connect to {CISCO_HOST}:{CISCO_PORT}")
    print()
    print("  Troubleshooting:")
    print("  1. Check CISCO_HOST in backend/.env")
    print("  2. Make sure RESTCONF is enabled on the device:")
    print("       Router(config)# restconf")
    print("  3. Check firewall allows HTTPS (port 443) from this machine")
    print("  4. Try the DevNet sandbox instead:")
    print("       CISCO_HOST=sandbox-iosxe-latest-1.cisco.com")
    print("       CISCO_USERNAME=developer")
    print("       CISCO_PASSWORD=C1sco12345")
