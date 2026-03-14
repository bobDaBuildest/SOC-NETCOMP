"""
Real Device Collector
======================
Connects to real (or sandbox) network devices via:
  1. Cisco DevNet Sandbox — free, always-on Cisco devices
  2. SNMP trap receiver
  3. Syslog receiver (UDP 514)
  4. REST API polling

All collectors normalize data to the same format as mock_generator.py
so the chatbot doesn't know the difference.
"""

import json
import socket
import threading
import time
import requests
import urllib3
from datetime import datetime
from typing import Dict, List, Optional, Callable

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Cisco DevNet Sandbox Credentials (Free — always available) ────────────────
# Always-on sandboxes: https://developer.cisco.com/site/sandbox/
CISCO_DEVNET = {
    "iosxe": {
        "host":     "sandbox-iosxe-latest-1.cisco.com",
        "username": "developer",
        "password": "C1sco12345",
        "base_url": "https://sandbox-iosxe-latest-1.cisco.com",
    },
    "meraki": {
        "host":    "api.meraki.com",
        "api_key": "6bec40cf957de430a6f1f2baa056b99a4fac9ea0",  # DevNet demo key
        "org_id":  "549236",
        "base_url": "https://api.meraki.com/api/v1",
    }
}


# ── Normalizer: converts any device output → standard event format ────────────
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


# ── 1. Cisco IOS XE REST API Collector ───────────────────────────────────────
class CiscoIOSXECollector:
    """
    Connects to Cisco IOS XE via RESTCONF API.
    Works with DevNet sandbox OR real devices.
    """

    def __init__(self, host: str, username: str, password: str):
        self.base_url = f"https://{host}/restconf/data"
        self.auth     = (username, password)
        self.headers  = {
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

    def get_interfaces(self) -> List[Dict]:
        """Get interface status — useful for detecting interface flaps."""
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
                status = iface.get("ietf-interfaces:statistics", {})
                events.append(normalize_event(
                    raw={
                        "message":    f"Interface {iface.get('name')} is {iface.get('ietf-interfaces:oper-status', 'unknown')}",
                        "event_type": "interface_status",
                        "action":     "INFO",
                        "severity":   "INFO" if iface.get("ietf-interfaces:oper-status") == "up" else "WARNING",
                    },
                    device_name="Cisco-IOS-XE-Sandbox",
                    device_type="cisco_iosxe"
                ))
            return events
        except Exception as e:
            return [normalize_event(
                {"message": f"Connection error: {e}", "event_type": "collector_error", "severity": "ERROR"},
                "Cisco-IOS-XE-Sandbox", "cisco_iosxe"
            )]

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
            return [normalize_event(
                {"message": "ACL data retrieved", "event_type": "acl_log", "action": "INFO"},
                "Cisco-IOS-XE-Sandbox", "cisco_iosxe"
            )]
        except Exception as e:
            return []


# ── 2. Cisco Meraki API Collector ─────────────────────────────────────────────
class CiscoMerakiCollector:
    """
    Connects to Cisco Meraki dashboard API.
    DevNet demo org is always available for testing.
    """

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
        """Get security events from Meraki MX firewall."""
        try:
            # Get networks if no network_id provided
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

            # Get security events
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
        except Exception as e:
            return []


# ── 3. Syslog Receiver (UDP 514) ──────────────────────────────────────────────
class SyslogReceiver:
    """
    Listens for syslog messages from any device on UDP port 514.
    Devices just need to be configured to send syslog to this IP.
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 514):
        self.host     = host
        self.port     = port
        self.events   = []
        self.running  = False
        self._thread  = None

    def _parse_syslog(self, message: str, src_ip: str) -> Dict:
        severity = "INFO"
        if "CRITICAL" in message or "emerg" in message.lower():
            severity = "CRITICAL"
        elif "ERROR" in message or "alert" in message.lower():
            severity = "HIGH"
        elif "WARN" in message:
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
        """Start listening for syslog messages in background thread."""
        self.running = True

        def _listen():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((self.host, self.port))
                sock.settimeout(1.0)
                print(f"🔊 Syslog receiver listening on {self.host}:{self.port}")
                while self.running:
                    try:
                        data, addr = sock.recvfrom(65535)
                        message    = data.decode("utf-8", errors="ignore")
                        event      = self._parse_syslog(message, addr[0])
                        self.events.append(event)
                        if callback:
                            callback(event)
                    except socket.timeout:
                        continue
                sock.close()
            except PermissionError:
                print("⚠️  Port 514 requires root. Using port 5140 instead.")
                # Retry on unprivileged port
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((self.host, 5140))
                sock.settimeout(1.0)
                print(f"🔊 Syslog receiver listening on {self.host}:5140")
                while self.running:
                    try:
                        data, addr = sock.recvfrom(65535)
                        message    = data.decode("utf-8", errors="ignore")
                        event      = self._parse_syslog(message, addr[0])
                        self.events.append(event)
                        if callback:
                            callback(event)
                    except socket.timeout:
                        continue
                sock.close()

        self._thread = threading.Thread(target=_listen, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def get_events(self) -> List[Dict]:
        events      = self.events.copy()
        self.events = []
        return events


# ── 4. Master Collector: combines all sources ─────────────────────────────────
class DeviceCollector:
    """
    Master collector that aggregates events from all sources.
    Falls back to mock data if real devices are unavailable.
    """

    def __init__(self):
        from mock_generator import MockDataGenerator
        self.mock_gen = MockDataGenerator()

        # Try real devices
        self.iosxe  = CiscoIOSXECollector(
            CISCO_DEVNET["iosxe"]["host"],
            CISCO_DEVNET["iosxe"]["username"],
            CISCO_DEVNET["iosxe"]["password"],
        )
        self.meraki = CiscoMerakiCollector(
            CISCO_DEVNET["meraki"]["api_key"],
            CISCO_DEVNET["meraki"]["org_id"],
        )
        self.syslog = SyslogReceiver()

        self._check_connections()

    def _check_connections(self):
        print("🔍 Checking real device connections...")
        self.iosxe_ok  = self.iosxe.test_connection()
        self.meraki_ok = self.meraki.test_connection()
        print(f"   Cisco IOS XE  : {'✅ Connected' if self.iosxe_ok  else '❌ Unavailable — using mock'}")
        print(f"   Cisco Meraki  : {'✅ Connected' if self.meraki_ok else '❌ Unavailable — using mock'}")

    def get_latest_events(self, count: int = 50) -> List[Dict]:
        """Get latest events from all available sources."""
        events = []

        # Real devices (if available)
        if self.iosxe_ok:
            events += self.iosxe.get_interfaces()
            events += self.iosxe.get_acl_logs()

        if self.meraki_ok:
            events += self.meraki.get_security_events()

        # Syslog buffer
        events += self.syslog.get_events()

        # Fill remaining with mock data
        remaining = max(0, count - len(events))
        if remaining > 0:
            events += self.mock_gen.generate_mixed_dataset(remaining)

        return sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)[:count]

    def simulate_attack(self, scenario: str) -> List[Dict]:
        """Inject a mock attack scenario for demo/testing."""
        return self.mock_gen.generate_attack_scenario(scenario)

    def start_syslog_listener(self):
        self.syslog.start()


# ── CLI test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    collector = DeviceCollector()

    print("\n📊 Fetching latest 20 events...")
    events = collector.get_latest_events(20)
    print(f"✅ Got {len(events)} events\n")

    print("🚨 Simulating brute_force_ssh attack...")
    attack = collector.simulate_attack("brute_force_ssh")
    print(f"✅ Generated {len(attack)} attack events")
    print(json.dumps(attack[0], indent=2))
