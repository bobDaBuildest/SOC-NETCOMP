"""
Quick test to verify Groq API is working.
Run from the backend/ folder:
    python test_groq.py
"""

import os
import asyncio
from dotenv import load_dotenv

load_dotenv()


async def test_groq():
    api_key = os.getenv("GROQ_API_KEY", "")

    if not api_key:
        print("[ERROR] GROQ_API_KEY not found in .env file!")
        return

    print(f"[OK] Key found: {api_key[:12]}...")

    try:
        from groq import AsyncGroq
        client = AsyncGroq(api_key=api_key)

        print("[INFO] Sending test alert to Groq...")

        response = await client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are an expert SOC analyst. Be concise and actionable."},
                {"role": "user", "content": (
                    "Analyze this security alert:\n"
                    "Alert ID: ALT-001\n"
                    "Description: CRITICAL threat detected. Source: 192.168.1.55 -> 185.220.101.5 "
                    "via ICMP. Bytes sent: 15,000,000. Possible data exfiltration."
                )}
            ],
            max_tokens=300
        )

        answer = response.choices[0].message.content
        print("\n--- Groq Response ---")
        print(answer)
        print("---------------------")
        print("\n[SUCCESS] Groq is working correctly!")

    except Exception as e:
        print(f"[ERROR] {e}")


if __name__ == "__main__":
    asyncio.run(test_groq())
