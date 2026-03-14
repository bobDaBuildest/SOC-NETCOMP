import os
from dotenv import load_dotenv

load_dotenv()


class AIAnalyst:
    def __init__(self):
        self.groq_key = os.getenv("GROQ_API_KEY", "")

    async def explain(self, alert_id: str, alert_description: str) -> str:
        # Fallback if no API key
        if not self.groq_key:
            return self._fallback_explanation(alert_id, alert_description)

        try:
            from groq import AsyncGroq
            client = AsyncGroq(api_key=self.groq_key)

            prompt = f"""You are a cybersecurity analyst. Analyze this security alert and provide:
1. A plain language explanation of what happened
2. The potential impact
3. Recommended remediation steps

Alert ID: {alert_id}
Alert Description: {alert_description}"""

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
