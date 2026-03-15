"""
SOC Chatbot Assistant
======================
Connects the OpenAI LLM with the EventStream to answer
natural language questions about network security events.

Example questions:
  - "Show me the latest critical events"
  - "Is there an attack taking place?"
  - "Who is behaving unusually on the network?"
  - "Block IP 185.220.101.5"
  - "Correlate events from the last hour"
"""

import os
import re
import json
import sys
from typing import List, Dict

from dotenv import load_dotenv

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../devices/mock"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../devices/real"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../devices/collector"))

from event_stream import EventStream  # noqa: E402

load_dotenv()

# ── System prompt ────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst assistant.
You have access to real-time security event data from network devices including:
- Cisco IOS Routers
- Cisco ASA Firewalls
- pfSense Firewalls
- Snort IDS/IPS

Your job is to:
1. Answer questions about security events in plain language
2. Identify and correlate attack patterns across devices
3. Assess threat severity with a confidence score (0-100%)
4. Recommend specific remediation actions
5. Generate firewall rules when asked to block threats

When analyzing events always:
- Mention which device detected the threat
- Provide a confidence score for your assessment
- Correlate related events across multiple devices
- Suggest concrete next steps

When asked to BLOCK something, respond with:
- The specific firewall rule to apply
- Which device to apply it on
- Confidence score that this is the right action
- Ask for user confirmation before "executing"

Format responses clearly with sections when appropriate.
Keep responses concise but complete."""


class SOCChatbot:
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY", "")
        self.stream = EventStream()
        self.history: List[Dict] = []
        self.blocked_ips: List[str] = []
        self.pending_action = None

        print("[OK] SOC Chatbot initialized")
        print(f"   Groq API: {'[OK] Key found' if self.api_key else '[ERROR] No key - set GROQ_API_KEY'}")
        print(f"   Event stream: [OK] {len(self.stream._event_buffer)} events loaded")

    def _build_context(self) -> str:
        """Build current network context to inject into every prompt."""
        return self.stream.get_summary_for_chatbot()

    def _get_ai_response(self, user_message: str) -> str:
        """Call Groq with full context + conversation history."""
        if not self.api_key:
            return self._mock_response(user_message)

        try:
            from groq import Groq
            client = Groq(api_key=self.api_key)

            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "system", "content": f"CURRENT NETWORK DATA:\n{self._build_context()}"},
            ]
            messages += self.history[-10:]
            messages.append({"role": "user", "content": user_message})

            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                max_tokens=800,
                temperature=0.3,
            )
            return response.choices[0].message.content

        except Exception as e:
            return f"AI unavailable: {str(e)}\n\n{self._mock_response(user_message)}"

    def _mock_response(self, message: str) -> str:
        """Rule-based fallback when no API key is available."""
        msg = message.lower()
        kpis = self.stream.get_kpis()

        if any(w in msg for w in ["critical", "latest"]):
            events = self.stream.get_critical_events(5)
            if not events:
                return "No critical events detected at this time."
            lines = [f"** {len(events)} Critical Events Detected:**\n"]
            for e in events:
                lines.append(
                    f"• [{e['timestamp']}] {e['device']}\n"
                    f"  {e['message']}\n"
                    f"  Action: {e['action']}"
                )
            return "\n".join(lines)

        if any(w in msg for w in ["attack", "unusual"]):
            attacks = self.stream.get_attack_events(10)
            if not attacks:
                return "No active attacks detected."
            src_ips = {}
            for e in attacks:
                ip = e.get("src_ip", "unknown")
                src_ips[ip] = src_ips.get(ip, 0) + 1
            top_ip = max(src_ips, key=src_ips.get)
            lines = [
                "**Attack Analysis** (Confidence: 87%)\n",
                f"Detected {len(attacks)} attack events across {kpis['active_devices']} devices.",
                f"Most active attacker: **{top_ip}** ({src_ips[top_ip]} events)",
                "\nCorrelated patterns:",
            ]
            types = list(set(e.get("event_type") for e in attacks))
            for t in types:
                lines.append(f"  • {t.replace('_', ' ').title()}")
            lines.append(f"\nRecommendation: Investigate {top_ip} immediately.")
            return "\n".join(lines)

        if any(w in msg for w in ["block", "ban"]):
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
            if ips:
                ip = ips[0]
                return (
                    f"**Firewall Rule Generated** (Confidence: 94%)\n\n"
                    f"Target IP: `{ip}`\n"
                    f"Rule: `deny ip host {ip} any`\n"
                    f"Apply on: Cisco-ASA-Firewall-01 + pfSense-Firewall-02\n\n"
                    f"Awaiting confirmation — reply 'confirm block {ip}' to execute."
                )
            return "Please specify an IP address to block. Example: 'block 185.220.101.5'"

        if any(w in msg for w in ["kpi", "stats", "status"]):
            return (
                f"**Network Security KPIs**\n\n"
                f"• Total Events: {kpis['total_events']}\n"
                f"• Attack Events: {kpis['attack_events']} ({kpis['anomaly_rate']}%)\n"
                f"• Critical Events: {kpis['critical_events']}\n"
                f"• Blocked Attacks: {kpis['blocked_attacks']}\n"
                f"• Active Devices: {kpis['active_devices']}\n"
                f"• MTTD: {kpis['mttd_minutes']} min\n"
                f"• MTTR: {kpis['mttr_minutes']} min\n"
                f"• IDS Alerts: {kpis['ids_alerts']}"
            )

        return (
            "I'm your SOC Assistant. I can help you with:\n"
            "• 'Show me critical events'\n"
            "• 'Is there an attack happening?'\n"
            "• 'Show KPIs'\n"
            "• 'Block IP [address]'\n"
            "• 'Correlate events'\n\n"
            "Set GROQ_API_KEY for full AI-powered responses."
        )

    def _handle_confirm_block(self, message: str) -> str:
        """Handle user confirmation to execute a block action."""
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
        if ips:
            ip = ips[0]
            self.blocked_ips.append(ip)
            return (
                f"**Action Executed** — IP {ip} has been blocked\n\n"
                f"Applied rules:\n"
                f"• Cisco-ASA-Firewall-01: `deny ip host {ip} any`\n"
                f"• pfSense-Firewall-02: `block in quick from {ip}`\n\n"
                f"Currently blocked IPs: {', '.join(self.blocked_ips)}\n"
                f"Note: In production this would call the device REST API directly."
            )
        return "Could not find IP to block."

    def chat(self, user_message: str) -> str:
        """Main chat method — call this with user input."""
        if "confirm block" in user_message.lower():
            response = self._handle_confirm_block(user_message)
        elif user_message.lower().startswith("inject "):
            scenario = user_message.split(" ", 1)[1].strip()
            events = self.stream.inject_attack(scenario)
            if events:
                response = f"Injected {len(events)} '{scenario}' attack events into the stream. Ask me to analyze them!"
            else:
                response = (
                    f"Unknown scenario '{scenario}'. "
                    "Available: port_scan, brute_force_ssh, data_exfiltration, ddos, lateral_movement"
                )
        else:
            response = self._get_ai_response(user_message)

        self.history.append({"role": "user", "content": user_message})
        self.history.append({"role": "assistant", "content": response})

        return response


# ── CLI interface for testing ─────────────────────────────────────────────────
if __name__ == "__main__":
    bot = SOCChatbot()
    print("=" * 60)
    print("SOC Assistant — Type 'exit' to quit")
    print("=" * 60)
    print("Try: 'show critical events', 'is there an attack?', 'show kpis'")
    print("-" * 60 + "\n")

    while True:
        try:
            user_input = input("You: ").strip()
            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                break
            response = bot.chat(user_input)
            print(f"\nSOC Assistant:\n{response}\n")
            print("-" * 60)
        except KeyboardInterrupt:
            break

    print("\nGoodbye!")