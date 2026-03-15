import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from the repository root .env (central config)
_root_env = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(_root_env)


class AIAnalyst:
    def __init__(self):
        self.groq_key = os.getenv("GROQ_API_KEY", "")

        # If retrieval dependencies are installed, initialize the playbook
        # retriever.
        self._retriever = None
        try:
            from services.retrieval import MitigationRetriever

            self._retriever = MitigationRetriever.get_instance()
        except Exception:
            self._retriever = None

    async def explain(self, alert_id: str, alert_description: str) -> str:
        # Fallback if no API key
        if not self.groq_key:
            return self._fallback_explanation(alert_id, alert_description)

        mitigation_context = ""
        if self._retriever:
            try:
                matches = self._retriever.query(alert_description, top_k=2)
                if matches:
                    mitigation_context = "\n\nRelevant remediation steps (from playbook):\n"
                    for m in matches:
                        title = m.get("title") or m.get(
                            "pattern") or "Mitigation"
                        desc = m.get("description", "").strip()
                        if desc:
                            mitigation_context += f"- {title}: {desc}\n"
                        else:
                            mitigation_context += f"- {title}\n"
                        for step in m.get("mitigation_steps", []):
                            mitigation_context += f"  • {step}\n"
            except Exception:
                mitigation_context = ""

        try:
            from groq import AsyncGroq
            client = AsyncGroq(api_key=self.groq_key)

            prompt = f"""You are a cybersecurity analyst. Analyze this security alert and provide:
1. A plain language explanation of what happened
2. The potential impact
3. Recommended remediation steps

Alert ID: {alert_id}
Alert Description: {alert_description}{mitigation_context}"""

            response = await client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are an expert SOC analyst. Be concise and actionable."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500
            )
            return response.choices[0].message.content

        except Exception as e:
            return self._fallback_explanation(alert_id, alert_description)

    def _fallback_explanation(self, alert_id: str, description: str) -> str:
        return (
            f"[Static Analysis — Set GROQ_API_KEY for AI-powered explanations]\n\n"
            f"Alert {alert_id}: {description}\n\n"
            "Recommended actions:\n"
            "1. Investigate the source IP in your threat intelligence platform\n"
            "2. Check for related alerts in the last 24 hours\n"
            "3. Isolate affected endpoint if threat is confirmed"
        )
