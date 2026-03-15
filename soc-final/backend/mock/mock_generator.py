"""
Mock Security Device Data Generator
====================================
Simulates realistic logs from:
  - Cisco Router (syslog)
  - Cisco Firewall (ASA)
  - pfSense Firewall
  - Snort IDS/IPS
  - Windows Security Events

Generates both normal traffic AND attack scenarios for testing.
"""

import random
import json
import time
from datetime import datetime, timedelta
from typing import List, Dict


# ── Realistic IP pools ──────────────────────────────────────────────────
INTERNAL_IPS = ["192.168.1.10", "192.168.1.20", "192.168.1.30",
                "10.0.0.5", "10.0.0.8", "10.0.0.15"]
EXTERNAL_IPS = ["8.8.8.8", "142.250.74.46", "93.184.216.34"]
ATTACKER_IPS = ["185.220.101.5", "45.33.32.156", "104.21.45.12",
                "198.51.100.23", "203.0.113.99"]
PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "SSH", "FTP", "IRC"]
PORTS = [22, 23, 25, 53, 80, 443, 445, 3389, 8080, 4444]


# ── Attack Scenarios ────────────────────────────────────────────────────
ATTACK_SCENARIOS = {
    "port_scan": {
        "description": "Port scanning from attacker",
        "severity": "HIGH",
        "events": 15,
    },
    "brute_force_ssh": {
        "description": "SSH brute force attack",
        "severity": "CRITICAL",
        "events": 20,
    },
    "data_exfiltration": {
        "description": "Large data transfer to external IP",
        "severity": "CRITICAL",
        "events": 5,
    },
    "ddos": {
        "description": "DDoS attack detected",
        "severity": "CRITICAL",
        "events": 30,
    },
    "lateral_movement": {
        "description": "Lateral movement inside network",
        "severity": "HIGH",
        "events": 8,
    },
}


# ── Base event generator ────────────────────────────────────────────────
def _timestamp(offset_seconds: int = 0) -> str:
    t = datetime.now() - timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%S")


def _random_port() -> int:
    return random.choice(PORTS + list(range(1024, 65535, 1000)))


# ── Cisco Router (IOS Syslog) ───────────────────────────────────────────
class CiscoRouterGenerator:
    DEVICE_NAME = "Cisco-IOS-Router-01"

    def normal_event(self) -> Dict:
        src = random.choice(INTERNAL_IPS)
        dst = random.choice(EXTERNAL_IPS)
        return {
            "timestamp": _timestamp(random.randint(0, 300)),
            "device": self.DEVICE_NAME,
            "device_type": "cisco_router",
            "severity": "INFO",
            "facility": "LOCAL7",
            "message": "%LINEPROTO-5-UPDOWN: Interface GigabitEthernet0/0, changed state to up",
            "src_ip": src,
            "dst_ip": dst,
            "protocol": random.choice(["TCP", "UDP"]),
            "bytes": random.randint(100, 5000),
            "action": "ALLOW",
            "event_type": "interface_change",
        }

    def attack_event(self, scenario: str) -> Dict:
        attacker = random.choice(ATTACKER_IPS)
        target = random.choice(INTERNAL_IPS)

        if scenario == "port_scan":
            port = random.randint(1, 1024)
            return {
                "timestamp": _timestamp(random.randint(0, 60)),
                "device": self.DEVICE_NAME,
                "device_type": "cisco_router",
                "severity": "HIGH",
                "facility": "LOCAL7",
                "message": f"%SEC-6-IPACCESSLOGP: list BLOCK denied tcp {attacker}({random.randint(1024, 65535)}) -> {target}({port}), 1 packet",
                "src_ip": attacker,
                "dst_ip": target,
                "dst_port": port,
                "protocol": "TCP",
                "action": "DENY",
                "event_type": "port_scan",
                "attack_scenario": scenario,
            }

        if scenario == "brute_force_ssh":
            return {
                "timestamp": _timestamp(
                    random.randint(
                        0,
                        30)),
                "device": self.DEVICE_NAME,
                "device_type": "cisco_router",
                "severity": "CRITICAL",
                "message": f"%SSH-3-NO_MATCH: No matching kex algorithm for {attacker}",
                "src_ip": attacker,
                "dst_ip": target,
                "dst_port": 22,
                "protocol": "TCP",
                "action": "DENY",
                "event_type": "brute_force",
                "attack_scenario": scenario,
            }

        return self.normal_event()


# ── Cisco ASA Firewall ──────────────────────────────────────────────────
class CiscoASAGenerator:
    DEVICE_NAME = "Cisco-ASA-Firewall-01"

    def normal_event(self) -> Dict:
        src = random.choice(INTERNAL_IPS)
        dst = random.choice(EXTERNAL_IPS)
        return {
            "timestamp": _timestamp(
                random.randint(
                    0,
                    300)),
            "device": self.DEVICE_NAME,
            "device_type": "cisco_asa",
            "severity": "INFO",
            "message": f"%ASA-6-302013: Built outbound TCP connection for {src}/80 to {dst}/443",
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": 443,
            "protocol": "TCP",
            "bytes_sent": random.randint(
                500,
                10000),
            "bytes_recv": random.randint(
                1000,
                50000),
            "action": "ALLOW",
            "event_type": "connection_built",
        }

    def attack_event(self, scenario: str) -> Dict:
        attacker = random.choice(ATTACKER_IPS)
        target = random.choice(INTERNAL_IPS)

        if scenario == "data_exfiltration":
            return {
                "timestamp": _timestamp(
                    random.randint(
                        0,
                        120)),
                "device": self.DEVICE_NAME,
                "device_type": "cisco_asa",
                "severity": "CRITICAL",
                "message": f"%ASA-4-106023: Deny tcp src outside:{attacker}/4521 dst inside:{target}/443 by access-group OUTSIDE_IN",
                "src_ip": attacker,
                "dst_ip": target,
                "dst_port": 443,
                "protocol": "TCP",
                "bytes_sent": random.randint(
                    10_000_000,
                    50_000_000),
                "bytes_recv": random.randint(
                    100,
                    500),
                "action": "DENY",
                "event_type": "data_exfiltration",
                "attack_scenario": scenario,
            }

        if scenario == "ddos":
            return {
                "timestamp": _timestamp(
                    random.randint(
                        0,
                        10)),
                "device": self.DEVICE_NAME,
                "device_type": "cisco_asa",
                "severity": "CRITICAL",
                "message": f"%ASA-1-106021: Deny TCP reverse path check from {attacker} to {target} on interface outside",
                "src_ip": attacker,
                "dst_ip": target,
                "protocol": "TCP",
                "packets_per_sec": random.randint(
                    10000,
                    100000),
                "action": "DENY",
                "event_type": "ddos",
                "attack_scenario": scenario,
            }

        return self.normal_event()


# ── pfSense Firewall ────────────────────────────────────────────────────
class PfSenseGenerator:
    DEVICE_NAME = "pfSense-Firewall-02"

    def normal_event(self) -> Dict:
        src = random.choice(INTERNAL_IPS)
        dst = random.choice(EXTERNAL_IPS)
        return {
            "timestamp": _timestamp(random.randint(0, 300)),
            "device": self.DEVICE_NAME,
            "device_type": "pfsense",
            "severity": "INFO",
            "rule": f"@{random.randint(1, 50)}(1000000103)",
            "action": "pass",
            "direction": "out",
            "protocol": random.choice(["tcp", "udp"]),
            "src_ip": src,
            "src_port": random.randint(1024, 65535),
            "dst_ip": dst,
            "dst_port": random.choice([80, 443, 53]),
            "length": random.randint(40, 1500),
            "event_type": "firewall_pass",
        }

    def attack_event(self, scenario: str) -> Dict:
        attacker = random.choice(ATTACKER_IPS)
        target = random.choice(INTERNAL_IPS)

        if scenario == "lateral_movement":
            src = random.choice(INTERNAL_IPS)
            dst = random.choice([ip for ip in INTERNAL_IPS if ip != src])
            return {
                "timestamp": _timestamp(random.randint(0, 60)),
                "device": self.DEVICE_NAME,
                "device_type": "pfsense",
                "severity": "HIGH",
                "rule": "@BLOCK_LATERAL",
                "action": "block",
                "direction": "in",
                "protocol": "tcp",
                "src_ip": src,
                "src_port": random.randint(1024, 65535),
                "dst_ip": dst,
                "dst_port": random.choice([445, 3389, 22]),
                "length": random.randint(40, 200),
                "event_type": "lateral_movement",
                "attack_scenario": scenario,
                "flags": "S",
            }

        return self.normal_event()


# ── Snort IDS/IPS ───────────────────────────────────────────────────────
class SnortGenerator:
    DEVICE_NAME = "Snort-IDS-01"

    SIGNATURES = [
        {"sid": 1000001, "msg": "ET SCAN Nmap SYN Scan", "category": "port_scan"},
        {"sid": 1000002, "msg": "ET BRUTE SSH Brute Force", "category": "brute_force"},
        {"sid": 1000003, "msg": "ET MALWARE CnC Beacon", "category": "malware"},
        {"sid": 1000004, "msg": "ET EXPLOIT EternalBlue", "category": "exploit"},
        {"sid": 1000005, "msg": "ET DOS ICMP Flood", "category": "ddos"},
        {"sid": 1000006, "msg": "ET POLICY IRC Connection", "category": "policy"},
        {"sid": 1000007, "msg": "ET TROJAN Metasploit Payload", "category": "malware"},
    ]

    def alert_event(self) -> Dict:
        sig = random.choice(self.SIGNATURES)
        attacker = random.choice(ATTACKER_IPS)
        target = random.choice(INTERNAL_IPS)
        return {
            "timestamp": _timestamp(random.randint(0, 300)),
            "device": self.DEVICE_NAME,
            "device_type": "snort_ids",
            "severity": random.choice(["HIGH", "CRITICAL"]),
            "alert": {
                "signature_id": sig["sid"],
                "signature": sig["msg"],
                "category": sig["category"],
                "priority": random.randint(1, 3),
            },
            "src_ip": attacker,
            "src_port": random.randint(1024, 65535),
            "dst_ip": target,
            "dst_port": random.choice(PORTS),
            "protocol": random.choice(["TCP", "UDP"]),
            "action": "ALERT",
            "event_type": "ids_alert",
        }


# ── Main Generator ──────────────────────────────────────────────────────
class MockDataGenerator:
    def __init__(self):
        self.cisco_router = CiscoRouterGenerator()
        self.cisco_asa = CiscoASAGenerator()
        self.pfsense = PfSenseGenerator()
        self.snort = SnortGenerator()

    def generate_normal_traffic(self, count: int = 20) -> List[Dict]:
        events = []
        for _ in range(count):
            generator = random.choice([
                self.cisco_router.normal_event,
                self.cisco_asa.normal_event,
                self.pfsense.normal_event,
            ])
            events.append(generator())
        return sorted(events, key=lambda x: x["timestamp"])

    def generate_attack_scenario(self, scenario: str) -> List[Dict]:
        """Generate a full attack scenario with correlated events across devices."""
        if scenario not in ATTACK_SCENARIOS:
            raise ValueError(
                f"Unknown scenario: {scenario}. Choose from: {
                    list(
                        ATTACK_SCENARIOS.keys())}")

        info = ATTACK_SCENARIOS[scenario]
        events = []
        count = info["events"]

        for i in range(count):
            # Each attack triggers events on multiple devices
            if scenario in ("port_scan", "brute_force_ssh"):
                events.append(self.cisco_router.attack_event(scenario))
                if i % 3 == 0:
                    events.append(self.snort.alert_event())

            elif scenario in ("data_exfiltration", "ddos"):
                events.append(self.cisco_asa.attack_event(scenario))
                if i % 2 == 0:
                    events.append(self.snort.alert_event())

            elif scenario == "lateral_movement":
                events.append(self.pfsense.attack_event(scenario))
                if i % 2 == 0:
                    events.append(
                        self.cisco_asa.attack_event("data_exfiltration"))

        return sorted(events, key=lambda x: x["timestamp"])

    def generate_mixed_dataset(self, normal_count: int = 30) -> List[Dict]:
        """Generate realistic mixed dataset: normal traffic + random attack."""
        scenario = random.choice(list(ATTACK_SCENARIOS.keys()))
        normal = self.generate_normal_traffic(normal_count)
        attacks = self.generate_attack_scenario(scenario)
        mixed = normal + attacks
        return sorted(mixed, key=lambda x: x["timestamp"])

    def generate_all_scenarios(self) -> Dict:
        """Generate all attack scenarios — useful for testing the chatbot."""
        return {
            scenario: self.generate_attack_scenario(scenario)
            for scenario in ATTACK_SCENARIOS
        }


# ── CLI usage ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    gen = MockDataGenerator()

    print("=== Generating mixed dataset (30 normal + random attack) ===\n")
    dataset = gen.generate_mixed_dataset(30)

    # Save to file
    with open("mock_events.json", "w") as f:
        json.dump(dataset, f, indent=2)

    print(f"✅ Generated {len(dataset)} events → mock_events.json")

    # Stats
    attacks = [e for e in dataset if e.get(
        "action") in ("DENY", "block", "ALERT")]
    print(f"   Normal events : {len(dataset) - len(attacks)}")
    print(f"   Attack events : {len(attacks)}")
    print("\n📋 Sample event:")
    print(json.dumps(dataset[0], indent=2))
