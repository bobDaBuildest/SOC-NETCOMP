"""
Unified Event Stream
=====================
Single entry point for ALL device data (real + mock).
This is what the SOC chatbot calls to get events.

Usage:
    from event_stream import EventStream
    stream = EventStream()
    events = stream.get_events(limit=50)
    attack = stream.inject_attack("brute_force_ssh")
"""

import sys
import os
import io

# Fix Windows Unicode encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# Correct paths: mock/ and real/ are siblings of event_stream.py (inside backend/)
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "mock"))
sys.path.insert(0, os.path.join(_HERE, "real"))

# Also support the sibling Soc-netcomp repo path
sys.path.insert(0, r"C:\Users\zafeiro\Documents\GitHub\Soc-netcomp\backend\devices\mock")
sys.path.insert(0, r"C:\Users\zafeiro\Documents\GitHub\Soc-netcomp\backend\devices\collector")

try:
    from mock_generator import MockDataGenerator, ATTACK_SCENARIOS
except ImportError as e:
    print(f"[ERROR] Could not import mock_generator: {e}")
    print(f"[INFO]  Searched in: {sys.path[:4]}")
    raise


# Try to load real firewall logs
try:
    from real_log_parser import RealLogParser
    _HAS_REAL_LOGS = True
except ImportError:
    _HAS_REAL_LOGS = False
from typing import List, Dict, Optional
from datetime import datetime
import json


class EventStream:
    """
    Unified stream of security events from all devices.
    The chatbot calls this -- it doesn't need to know if data is real or mock.
    """

    def __init__(self):
        self.mock = MockDataGenerator()
        self._event_buffer: List[Dict] = []

        # Try real collector, fall back gracefully
        try:
            from device_collector import DeviceCollector
            self.real = DeviceCollector()
            self.has_real = True
        except Exception:
            self.real = None
            self.has_real = False
            print("[INFO] Running in mock-only mode")

        # Pre-load initial events
        self._load_initial_events()

    def _load_initial_events(self):
        """Pre-load events: real logs first, then fill with mock data."""
        real_events = []
        if _HAS_REAL_LOGS:
            try:
                logs_dir = os.path.join(_HERE, "logs")
                parser = RealLogParser(logs_dir=logs_dir)
                real_events = parser.load_all()
            except Exception as e:
                print(f"[WARN] Could not load real logs: {e}")

        mock_events = self.mock.generate_mixed_dataset(50)
        self._event_buffer = real_events + mock_events
        print(f"[OK] EventStream ready -- {len(self._event_buffer)} events loaded ({len(real_events)} real, {len(mock_events)} mock)")

    def get_events(self, limit: int = 50, severity: Optional[str] = None,
                   device_type: Optional[str] = None) -> List[Dict]:
        """Get latest events, optionally filtered."""
        events = self._event_buffer[-limit:]

        if severity:
            events = [e for e in events if e.get("severity") == severity.upper()]

        if device_type:
            events = [e for e in events if e.get("device_type") == device_type]

        return sorted(events, key=lambda x: x.get("timestamp", ""), reverse=True)

    def get_critical_events(self, limit: int = 20) -> List[Dict]:
        return self.get_events(limit=limit, severity="CRITICAL")

    def get_attack_events(self, limit: int = 30) -> List[Dict]:
        return [e for e in self._event_buffer
                if e.get("action") in ("DENY", "block", "ALERT")][-limit:]

    def inject_attack(self, scenario: str) -> List[Dict]:
        """Inject an attack scenario into the stream (for demo/testing)."""
        if scenario not in ATTACK_SCENARIOS:
            return []
        attack_events = self.mock.generate_attack_scenario(scenario)
        self._event_buffer.extend(attack_events)
        return attack_events

    def get_kpis(self) -> Dict:
        """Calculate KPIs from current event buffer."""
        events = self._event_buffer
        total = len(events)
        attacks = [e for e in events if e.get("action") in ("DENY", "block", "ALERT")]
        critical = [e for e in events if e.get("severity") == "CRITICAL"]
        devices = list(set(e.get("device") for e in events))

        return {
            "total_events": total,
            "attack_events": len(attacks),
            "critical_events": len(critical),
            "anomaly_rate": round(len(attacks) / max(total, 1) * 100, 1),
            "active_devices": len(devices),
            "device_list": devices,
            "mttd_minutes": round(2.3 + len(critical) * 0.1, 1),
            "mttr_minutes": round(4.1 + len(attacks) * 0.05, 1),
            "blocked_attacks": len([e for e in attacks if e.get("action") == "DENY"]),
            "ids_alerts": len([e for e in events if e.get("device_type") == "snort_ids"]),
            "last_updated": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        }

    def get_summary_for_chatbot(self) -> str:
        """
        Returns a text summary of current network state.
        This is injected into every chatbot prompt as context.
        """
        kpis = self.get_kpis()
        attacks = self.get_attack_events(10)
        critical = self.get_critical_events(5)

        summary = f"""
CURRENT NETWORK SECURITY STATUS (as of {kpis['last_updated']}):

KPIs:
- Total events analyzed: {kpis['total_events']}
- Attack events detected: {kpis['attack_events']} ({kpis['anomaly_rate']}% anomaly rate)
- Critical severity events: {kpis['critical_events']}
- Blocked attacks: {kpis['blocked_attacks']}
- Active devices monitored: {kpis['active_devices']}
- Mean Time to Detect (MTTD): {kpis['mttd_minutes']} minutes
- Mean Time to Respond (MTTR): {kpis['mttr_minutes']} minutes

Active Devices: {', '.join(kpis['device_list'])}

Latest Critical Events:
"""
        for ev in critical[:5]:
            summary += f"- [{ev.get('timestamp')}] {ev.get('device')} | {ev.get('message', '')} | Action: {ev.get('action')}\n"

        summary += "\nLatest Attack Events:\n"
        for ev in attacks[:5]:
            summary += f"- [{ev.get('timestamp')}] {ev.get('device')} | SRC: {ev.get('src_ip')} -> DST: {ev.get('dst_ip')} | {ev.get('event_type')} | {ev.get('action')}\n"

        return summary.strip()


if __name__ == "__main__":
    stream = EventStream()

    print("\nKPIs:")
    print(json.dumps(stream.get_kpis(), indent=2))

    print("\nChatbot context summary:")
    print(stream.get_summary_for_chatbot())

    print("\nInjecting port_scan attack...")
    events = stream.inject_attack("port_scan")
    print(f"Injected {len(events)} attack events")
