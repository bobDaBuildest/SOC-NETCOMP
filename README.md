# 🛡️ AI SOC Dashboard
### Netcompany Hackathon Thessaloniki 2026

An AI-powered Security Operations Center (SOC) dashboard that detects network anomalies in real-time and explains threats using natural language AI.

---

## 🚀 Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/ai-soc-dashboard.git
cd ai-soc-dashboard
```

### 2. Backend setup
```bash
cd backend
pip install -r requirements.txt

# Optional: add your free Groq API key for AI explanations
export GROQ_API_KEY=your_key_here  # Get free at console.groq.com

python main.py
# API runs at http://localhost:8000
```

### 3. Frontend
```bash
# Just open frontend/index.html in your browser
# or serve it:
cd frontend && python -m http.server 3000
```

---

## 🧪 Running Tests

```bash
pytest tests/ -v
```

Tests run automatically on every push via GitHub Actions ✅

---

## 🏗️ Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Frontend      │────▶│   FastAPI        │────▶│ AnomalyDetector │
│ (HTML/JS/CSS)   │     │   Backend        │     │ (Rule-based/ML) │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │   AIAnalyst      │
                         │  (Groq / Gemini) │
                         └──────────────────┘
```

## 📁 Project Structure

```
ai-soc-dashboard/
├── backend/
│   ├── main.py              # FastAPI server & routes
│   ├── anomaly_detection.py # Threat detection engine
│   ├── ai_analyst.py        # AI explanation via Groq
│   └── requirements.txt
├── frontend/
│   ├── index.html           # Dashboard UI
│   ├── dashboard.js         # API calls & chart rendering
│   └── style.css
├── tests/
│   └── test_backend.py      # Automated pytest suite
├── datasets/
│   └── sample_logs.csv      # Sample network logs
└── .github/workflows/
    └── ci.yml               # Auto-run tests on push
```

## 🔑 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/detect` | Analyze single log entry |
| POST | `/api/detect/batch` | Analyze multiple logs |
| POST | `/api/analyze` | AI explanation of alert |
| GET | `/api/stats` | Dashboard statistics |

---

## 👥 Team
- Member 1 — Backend / ML
- Member 2 — AI Integration
- Member 3 — Frontend / Dashboard
