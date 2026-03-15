"""
Real Log Parser
================
Parses real FortiGate and PaloAlto firewall logs
and converts them to the SOC dashboard event format.

Usage:
    parser = RealLogParser()
    events = parser.load_all()          # load both log files
    events = parser.load_fortigate()    # FortiGate only
    events = parser.load_paloalto()     # PaloAlto only
"""

import os
import re
from datetime import datetime
from typing import List, Dict


# Ports that are suspicious / worth flagging
SUSPICIOUS_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 5900: "VNC",
    4444: "Metasploit", 6667: "IRC", 31337: "Backdoor"
}

# Apps that are elevated risk
HIGH_RISK_APPS = {"incomplete", "unknown-tcp", "unknown-udp", "unknown-p2p"}


def _severity_from_action(action: str, app: str, dst_port: int) -> str:
    action = action.lower()
    if action in ("deny", "drop", "block", "reset"):
        return "HIGH"
    if app.lower() in HIGH_RISK_APPS:
        return "MEDIUM"
    if dst_port in SUSPICIOUS_PORTS:
        return "MEDIUM"
    return "LOW"


def _message_from_event(device_type: str, action: str, app: str,
                         src_ip: str, dst_ip: str, dst_port: int) -> str:
    port_name = SUSPICIOUS_PORTS.get(dst_port, str(dst_port))
    if action.lower() in ("deny", "drop", "block"):
        return f"{device_type}: Blocked {app} from {src_ip} -> {dst_ip}:{port_name}"
    return f"{device_type}: {app} traffic {src_ip} -> {dst_ip}:{port_name} [{action}]"


class RealLogParser:

    def __init__(self, logs_dir: str = None):
        if logs_dir is None:
            # Default: look next to this file
            logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
        self.logs_dir = logs_dir
        self.fortigate_file = os.path.join(logs_dir, "FortiGate Sample logs.txt")
        self.paloalto_file  = os.path.join(logs_dir, "PaloAlto sample traffic logs.txt")

    # ── FortiGate ──────────────────────────────────────────────────────────────

    def load_fortigate(self) -> List[Dict]:
        if not os.path.exists(self.fortigate_file):
            print(f"[WARN] FortiGate log not found: {self.fortigate_file}")
            return []

        events = []
        with open(self.fortigate_file, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                def get(field):
                    m = re.search(rf'{field}="?([^\s"]+)"?', line)
                    return m.group(1) if m else ""

                date_str = get("date")
                time_str = get("time")
                timestamp = f"{date_str}T{time_str}" if date_str else datetime.now().isoformat()

                src_ip   = get("srcip")
                dst_ip   = get("dstip")
                action   = get("action")
                app      = get("app") or get("service")
                level    = get("level")
                policy   = get("policyname")
                apprisk  = get("apprisk")

                try:
                    dst_port = int(get("dstport"))
                except ValueError:
                    dst_port = 0

                # Map FortiGate level to severity
                level_map = {"emergency": "CRITICAL", "alert": "CRITICAL",
                             "critical": "CRITICAL", "error": "HIGH",
                             "warning": "HIGH", "notice": "MEDIUM",
                             "information": "LOW", "debug": "LOW"}
                severity = level_map.get(level.lower(), "LOW")

                # Elevate if action is deny/drop
                if action.lower() in ("deny", "drop"):
                    severity = "HIGH"
                if apprisk.lower() == "critical":
                    severity = "CRITICAL"

                events.append({
                    "timestamp":   timestamp,
                    "device":      "FortiGate-FW-01",
                    "device_type": "fortigate",
                    "src_ip":      src_ip,
                    "dst_ip":      dst_ip,
                    "dst_port":    dst_port,
                    "action":      action.upper() if action else "ALLOW",
                    "app":         app,
                    "policy":      policy,
                    "severity":    severity,
                    "event_type":  "firewall_traffic",
                    "message":     _message_from_event(
                                       "FortiGate", action, app,
                                       src_ip, dst_ip, dst_port),
                })

        print(f"[OK] FortiGate: loaded {len(events)} events")
        return events

    # ── PaloAlto ───────────────────────────────────────────────────────────────

    def load_paloalto(self) -> List[Dict]:
        if not os.path.exists(self.paloalto_file):
            print(f"[WARN] PaloAlto log not found: {self.paloalto_file}")
            return []

        events = []
        with open(self.paloalto_file, encoding="utf-8", errors="ignore") as f:
            lines = [l.rstrip("\r\n") for l in f.readlines()]

        # PaloAlto format: every 4 lines = 1 event (after the header block)
        i = 0
        while i < len(lines):
            # Skip header / separator
            if lines[i].startswith("===") or lines[i].startswith("Time") \
                    or lines[i].startswith("Rule") or lines[i].startswith("Src User"):
                i += 1
                continue

            # Try to parse a 4-line block
            if i + 3 < len(lines):
                line1 = lines[i].split()      # Time App From SrcPort Source
                line2 = lines[i+1].split()    # Rule Action To DstPort Dest
                # line3 = end reason (skip)
                # line4 = rule uuid (skip)

                try:
                    timestamp_str = f"{line1[0]} {line1[1]}"
                    timestamp = datetime.strptime(
                        timestamp_str, "%Y/%m/%d %H:%M:%S").isoformat()
                    # line1: date time app from_zone src_port src_ip
                    app      = line1[2]
                    src_port = int(line1[4])
                    src_ip   = line1[5]

                    # line2: rule_name action to_zone dst_port dst_ip
                    action   = line2[-4].lower()
                    dst_port = int(line2[-2])
                    dst_ip   = line2[-1]

                    severity = _severity_from_action(action, app, dst_port)
                    if action in ("deny", "drop", "reset"):
                        severity = "HIGH"

                    events.append({
                        "timestamp":   timestamp,
                        "device":      "PaloAlto-FW-01",
                        "device_type": "paloalto",
                        "src_ip":      src_ip,
                        "dst_ip":      dst_ip,
                        "src_port":    src_port,
                        "dst_port":    dst_port,
                        "action":      action.upper(),
                        "app":         app,
                        "policy":      line2[0] if line2 else "",
                        "severity":    severity,
                        "event_type":  "firewall_traffic",
                        "message":     _message_from_event(
                                           "PaloAlto", action, app,
                                           src_ip, dst_ip, dst_port),
                    })
                    i += 4
                    continue

                except (IndexError, ValueError):
                    pass

            i += 1

        print(f"[OK] PaloAlto: loaded {len(events)} events")
        return events

    # ── Combined ───────────────────────────────────────────────────────────────

    def load_all(self) -> List[Dict]:
        events = self.load_fortigate() + self.load_paloalto()
        events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        print(f"[OK] Total real events loaded: {len(events)}")
        return events


# ── Quick test ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json

    # When run directly, look for logs/ folder next to this script
    parser = RealLogParser()
    events = parser.load_all()

    if events:
        print(f"\nSample event:")
        print(json.dumps(events[0], indent=2))

        actions = {}
        for e in events:
            a = e["action"]
            actions[a] = actions.get(a, 0) + 1
        print(f"\nActions: {actions}")

        severities = {}
        for e in events:
            s = e["severity"]
            severities[s] = severities.get(s, 0) + 1
        print(f"Severities: {severities}")
    else:
        print("[ERROR] No events loaded. Make sure logs/ folder exists next to this script.")
        print("Expected files:")
        print("  logs/FortiGate Sample logs.txt")
        print("  logs/PaloAlto sample traffic logs.txt")
