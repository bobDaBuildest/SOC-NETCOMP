import os
import sys

# ── Fix import paths — must come before local module imports ───────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)                                      # backend/ itself
sys.path.insert(0, os.path.join(_HERE, "mock"))
sys.path.insert(0, os.path.join(_HERE, "real"))
sys.path.insert(0, os.path.join(_HERE, "devices", "mock"))
sys.path.insert(0, os.path.join(_HERE, "devices", "real"))
sys.path.insert(0, os.path.join(_HERE, "devices", "collector"))

from response_engine import ResponseEngine
from soc_chatbot import SOCChatbot
from anomaly_detection import AnomalyDetector
from ai_analyst import AIAnalyst
import sqlite3
from pydantic import BaseModel
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Depends
import uvicorn
from typing import List, Optional


app = FastAPI(title="AI SOC Dashboard API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

detector = AnomalyDetector()
analyst = AIAnalyst()
chatbot = SOCChatbot()


def get_db():
    conn = sqlite3.connect("soc.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            dest_ip TEXT,
            protocol TEXT,
            bytes_sent INTEGER,
            bytes_received INTEGER,
            duration REAL,
            flags TEXT,
            is_anomaly INTEGER,
            threat_level TEXT
        )
    """)
    # ── Persistent blocked IPs table (single source of truth) ──────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ip        TEXT NOT NULL,
            blocked_at TEXT NOT NULL DEFAULT (datetime('now')),
            blocked_by TEXT NOT NULL DEFAULT 'SOC-Analyst',
            reason    TEXT
        )
    """)
    conn.commit()
    try:
        yield conn
    finally:
        conn.close()


# ── Models ──────────────────────────────────────────────────────────────

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


# ── Serve frontend ───────────────────────────────────────────────────────
_FRONTEND = os.path.abspath(os.path.join(_HERE, "..", "frontend"))

# ── Routes ──────────────────────────────────────────────────────────────

@app.get("/")
def root():
    index = os.path.join(_FRONTEND, "index.html")
    if os.path.exists(index):
        return FileResponse(index)
    return {"status": "AI SOC Dashboard v2.0 is running 🚀"}


@app.get("/health")
def health():
    return {"status": "ok"}


# ── Chatbot endpoints ───────────────────────────────────────────────────

@app.post("/api/chat")
def chat(req: ChatRequest, db: sqlite3.Connection = Depends(get_db)):
    """Main chatbot endpoint — natural language SOC assistant."""
    result = chatbot.chat(req.message)
    response_text = result["response"]
    blocked_ip    = result["blocked_ip"]

    # ── If a block was confirmed, persist it to SQLite ──────────────────────
    if blocked_ip:
        db.execute(
            "INSERT INTO blocked_ips (ip, blocked_at, blocked_by, reason) "
            "VALUES (?, datetime('now'), 'SOC-Analyst', 'Manual block via SOC chat')",
            (blocked_ip,)
        )
        db.commit()

    # ── Return fresh KPIs so frontend updates instantly (no Refresh needed) ─
    kpis = chatbot.stream.get_kpis()
    blocked_count = db.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
    kpis["blocked_attacks"] = blocked_count   # SQLite is source of truth

    return {
        "message":     req.message,
        "response":    response_text,
        "blocked_ips": chatbot.blocked_ips,
        "stats":       kpis,
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
        return {
            "error": f"Unknown scenario '{
                req.scenario}'",
            "available": [
                "port_scan",
                "brute_force_ssh",
                "data_exfiltration",
                "ddos",
                "lateral_movement"]}
    return {"injected": len(events),
            "scenario": req.scenario,
            "events": events[:3]}


@app.get("/api/kpis")
def get_kpis(db: sqlite3.Connection = Depends(get_db)):
    """Get security KPIs — single source of truth: EventStream + SQLite for blocked."""
    kpis = chatbot.stream.get_kpis()
    # Blocked count comes from SQLite (persistent, survives restarts)
    blocked_count = db.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
    kpis["blocked_attacks"] = blocked_count
    return kpis


@app.get("/api/blocked-ips")
def get_blocked_ips(db: sqlite3.Connection = Depends(get_db)):
    """
    Returns all blocked IPs with full audit trail.
    Production use: poll this from SIEM / firewall orchestration layer.
    """
    rows = db.execute(
        "SELECT ip, blocked_at, blocked_by, reason FROM blocked_ips ORDER BY blocked_at DESC"
    ).fetchall()
    entries = [
        {"ip": r[0], "blocked_at": r[1], "blocked_by": r[2], "reason": r[3]}
        for r in rows
    ]
    return {"total": len(entries), "blocked_ips": entries}



@app.post("/api/detect")
def detect_anomaly(log: LogEntry, db: sqlite3.Connection = Depends(get_db)):
    result = detector.predict(log.dict())
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO events (timestamp, source_ip, dest_ip, protocol, bytes_sent, bytes_received, duration, flags, is_anomaly, threat_level)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        log.timestamp, log.source_ip, log.dest_ip, log.protocol,
        log.bytes_sent, log.bytes_received, log.duration, log.flags or "",
        1 if result["is_anomaly"] else 0, result["threat_level"]
    ))
    db.commit()
    return {
        "is_anomaly": result["is_anomaly"],
        "confidence": result["confidence"],
        "threat_level": result["threat_level"],
        "details": result["details"],
    }


@app.post("/api/detect/batch")
def detect_batch(
        logs: List[LogEntry],
        db: sqlite3.Connection = Depends(get_db)):
    results = []
    cursor = db.cursor()
    for log in logs:
        r = detector.predict(log.dict())
        cursor.execute("""
            INSERT INTO events (timestamp, source_ip, dest_ip, protocol, bytes_sent, bytes_received, duration, flags, is_anomaly, threat_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log.timestamp, log.source_ip, log.dest_ip, log.protocol,
            log.bytes_sent, log.bytes_received, log.duration, log.flags or "",
            1 if r["is_anomaly"] else 0, r["threat_level"]
        ))
        results.append({"log": log.dict(), **r})
    db.commit()
    return {
        "total": len(results),
        "anomalies": sum(1 for r in results if r["is_anomaly"]),
        "results": results,
    }


@app.post("/api/analyze")
async def analyze_alert(
        req: AnalyzeRequest,
        db: sqlite3.Connection = Depends(get_db)):
    # 1. AI explanation (natural language)
    explanation = await analyst.explain(req.alert_id, req.alert_description)

    # =============================
    # 2. AUTO-BLOCK LOGIC (HIGH/CRITICAL)
    # =============================
    description = req.alert_description.upper()
    high_threat = ("HIGH" in description or "CRITICAL" in description)
    action_status = ""

    if high_threat:
        try:
            target_ip = req.alert_description.split("Source: ")[
                1].split(" ")[0]
            success = ResponseEngine.block_ip(target_ip)

            if success:
                # Log block event in DB so KPI + AI both match
                cursor = db.cursor()
                cursor.execute("""
                    INSERT INTO events (
                        timestamp, source_ip, dest_ip, protocol,
                        bytes_sent, bytes_received, duration, flags,
                        is_anomaly, threat_level
                    )
                    VALUES (datetime('now'), ?, 'AUTO_BLOCK', 'SYSTEM', 0, 0, 0, 'BLOCKED', 1, 'CRITICAL')
                """, (target_ip,))
                db.commit()

                action_status = f"\n\n[AUTOMATED RESPONSE] IP {target_ip} has been blocked."
            else:
                action_status = f"\n\n[ERROR] Firewall could not block {target_ip}."
        except Exception:
            action_status = "\n\n[ERROR] Could not extract or block IP."

    # =============================
    # 3. FETCH REAL STATS FROM SQLITE
    # =============================
    cursor = db.cursor()

    cursor.execute("SELECT COUNT(*) FROM events")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM events WHERE is_anomaly = 1")
    attack_events = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM events WHERE threat_level IN ('HIGH','CRITICAL')")
    critical_events = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM events WHERE threat_level IN ('HIGH','CRITICAL') AND is_anomaly = 1")
    total_blocked = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM events")
    active_devices = cursor.fetchone()[0]

    anomaly_rate = attack_events / total_events if total_events > 0 else 0.0

    # =============================
    # 4. ADD REAL STATS TO AI MESSAGE
    # =============================
    synced_stats = f"""

🔍 **Real-Time SOC Metrics (Database Verified)**
- Total events: {total_events}
- Attack events: {attack_events}
- Critical/High events: {critical_events}
- Blocked attacks: {total_blocked}
- Active devices: {active_devices}
- Anomaly rate: {(anomaly_rate * 100):.1f}%

"""

    return {
        "alert_id": req.alert_id,
        "explanation": explanation + action_status + synced_stats,
        "stats": {
            "total_events": total_events,
            "attack_events": attack_events,
            "critical_events": critical_events,
            "total_blocked": total_blocked,
            "active_devices": active_devices,
            "anomaly_rate": anomaly_rate,
        }
    }


@app.get("/api/stats")
def get_stats(db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()

    cursor.execute("SELECT COUNT(*) FROM events")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM events WHERE is_anomaly = 1")
    attack_events = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM events WHERE threat_level IN ('HIGH','CRITICAL')")
    critical_events = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM events WHERE threat_level IN ('HIGH','CRITICAL') AND is_anomaly = 1")
    total_blocked = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(DISTINCT source_ip) FROM events")
    active_devices = cursor.fetchone()[0]

    anomaly_rate = attack_events / total_events if total_events > 0 else 0.0

    return {
        "total_events": total_events,
        "attack_events": attack_events,
        "anomaly_rate": anomaly_rate,
        "critical_events": critical_events,
        "total_blocked": total_blocked,
        "active_devices": active_devices
    }


@app.get("/api/firewalls")
def get_firewalls():
    from response_engine import ResponseEngine
    return ResponseEngine.get_status()


# ── Device connection endpoints ──────────────────────────────────────────────

class DeviceConnectRequest(BaseModel):
    host: str
    username: str
    password: str
    port: int = 443
    device_type: str = "cisco_iosxe"

# In-memory list of connected devices (persists while server runs)
_connected_devices = []

@app.post("/api/device/connect")
def device_connect(req: DeviceConnectRequest):
    """Connect to a network device via RESTCONF and store it."""
    try:
        import requests as req_lib
        import urllib3
        urllib3.disable_warnings()

        base_url = f"https://{req.host}:{req.port}/restconf/data"
        r = req_lib.get(
            f"{base_url}/Cisco-IOS-XE-native:native/hostname",
            auth=(req.username, req.password),
            headers={"Accept": "application/yang-data+json"},
            verify=False,
            timeout=8,
        )

        if r.status_code == 200:
            hostname = r.json().get("Cisco-IOS-XE-native:hostname", req.host)
            # Avoid duplicates
            existing = [d for d in _connected_devices if d["host"] == req.host]
            if not existing:
                _connected_devices.append({
                    "host": req.host,
                    "hostname": hostname,
                    "device_type": req.device_type,
                    "status": "connected",
                })
            return {"status": "connected", "hostname": hostname, "host": req.host}
        else:
            return {"status": "error", "detail": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


@app.get("/api/devices")
def get_devices():
    """Return list of all connected devices."""
    return {"devices": _connected_devices}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)