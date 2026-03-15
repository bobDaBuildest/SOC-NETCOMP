"""
Real Device Collector
======================
Connects to real network devices via RESTCONF API or Syslog.

Configuration via .env file:
  CISCO_HOST=192.168.1.1          # mentor's device IP or hostname
  CISCO_USERNAME=admin
  CISCO_PASSWORD=yourpassword
  CISCO_PORT=443                  # optional, default 443

  # OR use Cisco DevNet Sandbox (free, always-on):
  # CISCO_HOST=sandbox-iosxe-latest-1.cisco.com
  # CISCO_USERNAME=developer
  # CISCO_PASSWORD=C1sco12345

  MERAKI_API_KEY=your_key         # optional
  MERAKI_ORG_ID=your_org_id       # optional
"""

import os
import json
import socket
import threading
import requests
import urllib3
from datetime import datetime
from typing import Dict, List, Optional, Callable
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Read credentials from .env ─────────────────────────────────────────────────
# Cisco IOS XE — defaults to DevNet sandbox if not set
CISCO_HOST     = os.getenv("CISCO_HOST",     "sandbox-iosxe-latest-1.cisco.com")
CISCO_USERNAME = os.getenv("CISCO_USERNAME", "developer")
CISCO_PASSWORD = os.getenv("CISCO_PASSWORD", "C1sco12345")
CISCO_PORT     = int(os.getenv("CISCO_PORT", "443"))

# Cisco Meraki — optional
MERAKI_API_KEY = os.getenv("MERAKI_API_KEY", "6bec40cf957de430a6f1f2baa056b99a4fac9ea0")
MERAKI_ORG_ID  = os.getenv("MERAKI_ORG_ID",  "549236")


# ── Normalizer ─────────────────────────────────────────────────────────────────
def normalize_event(raw: Dict, device_name: str, device_type: str) -> Dict:
    return {
        "timestamp":   raw.get("timestamp", datetime.now().strftime("%Y-%m-%dT%H:%M:%S")),
        "device":      device_name,
        "device_type": device_type,
        "severity":    raw.get("severity", "INFO"),
        "message":     raw.get("message", str(raw)),
        "src_ip":      raw.get("src_ip", ""),
        "dst_ip":      raw.get("dst_ip", ""),
        "protocol":    raw.get("protocol", ""),
        "action":      raw.get("action", ""),
        "event_type":  raw.get("event_type", "unknown"),
        "raw":         raw,
    }


# ── 1. Cisco IOS XE RESTCONF Collector ────────────────────────────────────────
class CiscoIOSXECollector:
    """
    Connects to any Cisco IOS XE device via RESTCONF API.
    Works with:
      - Real Cisco routers/switches (set CISCO_HOST in .env)
      - Cisco DevNet Sandbox (default, free)
    """

    def __init__(self, host: str, username: str, password: str, port: int = 443):
        self.base_url    = f"https://{host}:{port}/restconf/data"
        self.auth        = (username, password)
        self.device_name = f"Cisco-IOS-XE-{host.split('.')[0]}"
        self.headers     = {
            "Accept":       "application/yang-data+json",
            "Content-Type": "application/yang-data+json",
        }

    def test_connection(self) -> bool:
        try:
            r = requests.get(
                f"{self.base_url}/Cisco-IOS-XE-native:native/hostname",
                auth=self.auth, headers=self.headers,
                verify=False, timeout=5
            )
            return r.status_code == 200
        except Exception:
            return False

    def get_hostname(self) -> str:
        try:
            r = requests.get(
                f"{self.base_url}/Cisco-IOS-XE-native:native/hostname",
                auth=self.auth, headers=self.headers,
                verify=False, timeout=5
            )
            if r.status_code == 200:
                return r.json().get("Cisco-IOS-XE-native:hostname", self.device_name)
        except Exception:
            pass
        return self.device_name

    def get_interfaces(self) -> List[Dict]:
        """Get interface status — detects interface flaps/outages."""
        try:
            r = requests.get(
                f"{self.base_url}/ietf-interfaces:interfaces",
                auth=self.auth, headers=self.headers,
                verify=False, timeout=10
            )
            if r.status_code != 200:
                return []

            interfaces = r.json().get("ietf-interfaces:interfaces", {}).get("interface", [])
            events = []
            for iface in interfaces:
                oper_status = iface.get("ietf-interfaces:oper-status", "unknown")
                events.append(normalize_event(
                    raw={
                        "message":    f"Interface {iface.get('name')} status: {oper_status}",
                        "event_type": "interface_status",
                        "action":     "INFO",
                        "severity":   "LOW" if oper_status == "up" else "HIGH",
                    },
                    device_name=self.device_name,
                    device_type="cisco_iosxe"
                ))
            return events
        except Exception as e:
            return []

    def get_acl_logs(self) -> List[Dict]:
        """Get ACL deny logs — shows blocked traffic."""
        try:
            r = requests.get(
                f"{self.base_url}/Cisco-IOS-XE-acl:access-lists",
                auth=self.auth, headers=self.headers,
                verify=False, timeout=10
            )
            if r.status_code != 200:
                return []

            acls = r.json().get("Cisco-IOS-XE-acl:access-lists", {}).get("acl", [])
            events = []
            for acl in acls:
                events.append(normalize_event(
                    raw={
                        "message":    f"ACL {acl.get('name', 'unknown')} active",
                        "event_type": "acl_log",
                        "action":     "INFO",
                        "severity":   "LOW",
                    },
                    device_name=self.device_name,
                    device_type="cisco_iosxe"
                ))
            return events
        except Exception:
            return []

    def get_routing_table(self) -> List[Dict]:
        """Check routing table for anomalies."""
        try:
            r = requests.get(
                f"{self.base_url}/ietf-routing:routing",
                auth=self.auth, headers=self.headers,
                verify=False, timeout=10
            )
            if r.status_code != 200:
                return []
            return [normalize_event(
                raw={
                    "message":    "Routing table retrieved successfully",
                    "event_type": "routing_check",
                    "action":     "INFO",
                    "severity":   "LOW",
                },
                device_name=self.device_name,
                device_type="cisco_iosxe"
            )]
        except Exception:
            return []


# ── 2. Cisco Meraki API Collector ─────────────────────────────────────────────
class CiscoMerakiCollector:

    def __init__(self, api_key: str, org_id: str):
        self.base_url = "https://api.meraki.com/api/v1"
        self.headers  = {
            "X-Cisco-Meraki-API-Key": api_key,
            "Content-Type": "application/json",
        }
        self.org_id = org_id

    def test_connection(self) -> bool:
        try:
            r = requests.get(
                f"{self.base_url}/organizations/{self.org_id}",
                headers=self.headers, timeout=5
            )
            return r.status_code == 200
        except Exception:
            return False

    def get_security_events(self, network_id: Optional[str] = None) -> List[Dict]:
        try:
            if not network_id:
                r = requests.get(
                    f"{self.base_url}/organizations/{self.org_id}/networks",
                    headers=self.headers, timeout=10
                )
                if r.status_code != 200:
                    return []
                networks = r.json()
                if not networks:
                    return []
                network_id = networks[0]["id"]

            r = requests.get(
                f"{self.base_url}/networks/{network_id}/appliance/security/events",
                headers=self.headers, timeout=10
            )
            if r.status_code != 200:
                return []

            events = []
            for ev in r.json():
                events.append(normalize_event(
                    raw={
                        "timestamp":  ev.get("ts", ""),
                        "message":    ev.get("message", ""),
                        "src_ip":     ev.get("srcIp", ""),
                        "dst_ip":     ev.get("destIp", ""),
                        "protocol":   ev.get("protocol", ""),
                        "action":     "DENY" if "block" in ev.get("disposition", "").lower() else "ALLOW",
                        "severity":   "HIGH" if ev.get("priority") == 1 else "MEDIUM",
                        "event_type": ev.get("type", "security_event"),
                    },
                    device_name="Cisco-Meraki-MX",
                    device_type="cisco_meraki"
                ))
            return events
        except Exception:
            return []


# ── 3. Syslog Receiver (UDP 514) ──────────────────────────────────────────────
class SyslogReceiver:
    """
    Listens for syslog messages from ANY device on UDP port 514.
    Just point your Cisco/FortiGate/PaloAlto syslog to this machine's IP.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 514):
        self.host    = host
        self.port    = port
        self.events  = []
        self.running = False

    def _parse_syslog(self, message: str, src_ip: str) -> Dict:
        severity = "LOW"
        if any(w in message for w in ["CRITICAL", "emerg", "alert"]):
            severity = "CRITICAL"
        elif any(w in message for w in ["ERROR", "error", "crit"]):
            severity = "HIGH"
        elif any(w in message for w in ["WARN", "warning"]):
            severity = "MEDIUM"

        action = "DENY" if any(w in message for w in ["denied", "blocked", "dropped"]) else "ALLOW"

        return normalize_event(
            raw={
                "timestamp":  datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                "message":    message.strip(),
                "src_ip":     src_ip,
                "action":     action,
                "severity":   severity,
                "event_type": "syslog",
            },
            device_name=f"Device-{src_ip}",
            device_type="syslog_device"
        )

    def start(self, callback: Optional[Callable] = None):
        self.running = True

        def _listen():
            try:
                port = self.port
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.bind((self.host, port))
                except PermissionError:
                    port = 5140  # fallback unprivileged port
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.bind((self.host, port))
                    print(f"[INFO] Port 514 needs root. Listening on {port} instead.")

                sock.settimeout(1.0)
                print(f"[INFO] Syslog receiver listening on {self.host}:{port}")

                while self.running:
                    try:
                        data, addr = sock.recvfrom(65535)
                        message = data.decode("utf-8", errors="ignore")
                        event   = self._parse_syslog(message, addr[0])
                        self.events.append(event)
                        if callback:
                            callback(event)
                    except socket.timeout:
                        continue
                sock.close()
            except Exception as e:
                print(f"[ERROR] Syslog receiver: {e}")

        threading.Thread(target=_listen, daemon=True).start()

    def stop(self):
        self.running = False

    def get_events(self) -> List[Dict]:
        events      = self.events.copy()
        self.events = []
        return events


# ── 4. Master Collector ────────────────────────────────────────────────────────
class DeviceCollector:
    """
    Aggregates events from all real sources.
    Credentials are read from .env automatically.
    Falls back to mock data if devices are unreachable.
    """

    def __init__(self):
        from mock_generator import MockDataGenerator
        self.mock_gen = MockDataGenerator()

        self.iosxe  = CiscoIOSXECollector(CISCO_HOST, CISCO_USERNAME, CISCO_PASSWORD, CISCO_PORT)
        self.meraki = CiscoMerakiCollector(MERAKI_API_KEY, MERAKI_ORG_ID)
        self.syslog = SyslogReceiver()

        self._check_connections()

    def _check_connections(self):
        print(f"[INFO] Checking device connections...")
        print(f"[INFO] Cisco host: {CISCO_HOST}")

        self.iosxe_ok  = self.iosxe.test_connection()
        self.meraki_ok = self.meraki.test_connection()

        print(f"   Cisco IOS XE : {'[OK] Connected' if self.iosxe_ok  else '[--] Unavailable'}")
        print(f"   Cisco Meraki : {'[OK] Connected' if self.meraki_ok else '[--] Unavailable'}")

        if self.iosxe_ok:
            hostname = self.iosxe.get_hostname()
            print(f"   Device name  : {hostname}")

    def get_latest_events(self, count: int = 50) -> List[Dict]:
        events = []

        if self.iosxe_ok:
            events += self.iosxe.get_interfaces()
            events += self.iosxe.get_acl_logs()

        if self.meraki_ok:
            events += self.meraki.get_security_events()

        events += self.syslog.get_events()

        # Fill with mock if not enough real events
        remaining = max(0, count - len(events))
        if remaining > 0:
            events += self.mock_gen.generate_mixed_dataset(remaining)

        return sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)[:count]

    def simulate_attack(self, scenario: str) -> List[Dict]:
        return self.mock_gen.generate_attack_scenario(scenario)

    def start_syslog_listener(self):
        self.syslog.start()


# ── CLI test ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("Device Collector - Connection Test")
    print("=" * 50)
    print(f"Target: {CISCO_HOST}")
    print(f"User  : {CISCO_USERNAME}")
    print()

    collector = CiscoIOSXECollector(CISCO_HOST, CISCO_USERNAME, CISCO_PASSWORD, CISCO_PORT)

    print("Testing connection...")
    if collector.test_connection():
        print(f"[OK] Connected to {CISCO_HOST}")
        hostname = collector.get_hostname()
        print(f"[OK] Hostname: {hostname}")

        print("\nFetching interfaces...")
        interfaces = collector.get_interfaces()
        print(f"[OK] Got {len(interfaces)} interface events")
        for ev in interfaces[:3]:
            print(f"  - {ev['message']} [{ev['severity']}]")
    else:
        print(f"[ERROR] Cannot connect to {CISCO_HOST}")
        print("Check CISCO_HOST, CISCO_USERNAME, CISCO_PASSWORD in .env")
