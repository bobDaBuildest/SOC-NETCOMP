import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "devices/mock"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "devices/real"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "devices/collector"))

from typing import List, Optional
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from ai_analyst import AIAnalyst
from anomaly_detection import AnomalyDetector
from soc_chatbot import SOCChatbot

app = FastAPI(title="AI SOC Dashboard API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

detector = AnomalyDetector()
analyst  = AIAnalyst()
chatbot  = SOCChatbot()


# ── Models ────────────────────────────────────────────────────────────────────

class LogEntry(BaseModel):
    timestamp: str
    source_ip: str
    dest_ip: str
    protocol: str
    bytes_sent: int
    bytes_received: int
    duration: float
    flags: Optional[str] = ""

class AnalyzeRequest(BaseModel):
    alert_id: str
    alert_description: str

class ChatRequest(BaseModel):
    message: str

class InjectRequest(BaseModel):
    scenario: str


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "AI SOC Dashboard v2.0 is running 🚀"}

@app.get("/health")
def health():
    return {"status": "ok"}


# ── Chatbot endpoints ─────────────────────────────────────────────────────────

@app.post("/api/chat")
def chat(req: ChatRequest):
    """Main chatbot endpoint — natural language SOC assistant."""
    response = chatbot.chat(req.message)
    return {
        "message":  req.message,
        "response": response,
        "blocked_ips": chatbot.blocked_ips,
    }

@app.get("/api/events")
def get_events(limit: int = 50, severity: Optional[str] = None):
    """Get latest security events from all devices."""
    events = chatbot.stream.get_events(limit=limit, severity=severity)
    return {"total": len(events), "events": events}

@app.get("/api/events/critical")
def get_critical_events():
    """Get only critical severity events."""
    events = chatbot.stream.get_critical_events(20)
    return {"total": len(events), "events": events}

@app.get("/api/events/attacks")
def get_attack_events():
    """Get only attack/blocked events."""
    events = chatbot.stream.get_attack_events(30)
    return {"total": len(events), "events": events}

@app.post("/api/events/inject")
def inject_attack(req: InjectRequest):
    """Inject a mock attack scenario for demo/testing."""
    events = chatbot.stream.inject_attack(req.scenario)
    if not events:
        return {"error": f"Unknown scenario '{req.scenario}'", "available": [
            "port_scan", "brute_force_ssh", "data_exfiltration", "ddos", "lateral_movement"
        ]}
    return {"injected": len(events), "scenario": req.scenario, "events": events[:3]}

@app.get("/api/kpis")
def get_kpis():
    """Get security KPIs — MTTD, MTTR, anomaly rate, etc."""
    return chatbot.stream.get_kpis()


# ── Legacy endpoints (keep for backwards compatibility) ───────────────────────

@app.post("/api/detect")
def detect_anomaly(log: LogEntry):
    result = detector.predict(log.dict())
    return {
        "is_anomaly":   result["is_anomaly"],
        "confidence":   result["confidence"],
        "threat_level": result["threat_level"],
        "details":      result["details"],
    }

@app.post("/api/detect/batch")
def detect_batch(logs: List[LogEntry]):
    results = []
    for log in logs:
        r = detector.predict(log.dict())
        results.append({"log": log.dict(), **r})
    return {
        "total":     len(results),
        "anomalies": sum(1 for r in results if r["is_anomaly"]),
        "results":   results,
    }

@app.post("/api/analyze")
async def analyze_alert(req: AnalyzeRequest):
    explanation = await analyst.explain(req.alert_id, req.alert_description)
    return {"alert_id": req.alert_id, "explanation": explanation}

@app.get("/api/stats")
def get_stats():
    return detector.get_stats()


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
