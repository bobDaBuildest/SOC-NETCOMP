# 📋 Project Completion Task List (Ticket-Based)

This file contains the technical roadmap for transforming the current MVP into a submission-ready AI SOC Control Center for the Netcompany Hackathon 2026.

## 🎫 Ticket 1: Persistence Layer & Event Normalization
**Objective:** Replace in-memory storage with a persistent SQLite database to satisfy "Hard Requirements" for data retention.
* **Action 1**: Create `backend/db/database.py` to initialize a SQLAlchemy engine and session factory.
* **Action 2**: Define the `Event` model in `backend/db/models.py` with fields: `id`, `timestamp`, `source_ip`, `dest_ip`, `protocol`, `bytes_sent`, `bytes_received`, `duration`, `flags`, and `is_anomaly`.
* **Action 3**: Refactor `backend/main.py` to inject a database session into `/api/detect` and `/api/detect/batch`.
* **Action 4**: Update the logic to commit every incoming log to the database before returning the detection results.

## 🎫 Ticket 2: Automated Data Seeding
**Objective:** Ensure the application is "demo-ready" with pre-loaded telemetry upon initial startup.
* **Action 1**: Create `backend/scripts/seed_db.py`.
* **Action 2**: Use `pandas` to parse `datasets/sample_logs.csv`.
* **Action 3**: Loop through entries, calculate anomaly scores using the `AnomalyDetector` class, and perform a bulk insert into the SQLite database.
* **Action 4**: Add a startup event in `main.py` to trigger this script if the database file is missing or empty.

## 🎫 Ticket 3: Knowledge Base & RAG Integration
**Objective:** Ground AI explanations in specific playbooks to improve "Impact" and "Business Value" scores.
* **Action 1**: Create `backend/data/mitigation_kb.json` with structured remediation steps for "SYN Flood", "Data Exfiltration", and "Suspicious Protocol" patterns.
* **Action 2**: Implement `backend/services/retrieval.py` using `faiss-cpu` and `sentence-transformers` (all-MiniLM-L6-v2).
* **Action 3**: Update `AIAnalyst.explain` in `backend/ai_analyst.py` to:
    1. Embed the alert description.
    2. Query FAISS for the top 2 relevant mitigation steps.
    3. Inject these steps into the OpenAI prompt context.

## 🎫 Ticket 4: Multi-Alert Correlation Logic
**Objective:** Group individual alerts into high-level "Incidents" based on entity linking.
* **Action 1**: Create an `Incident` model in the database to link multiple `Event` IDs.
* **Action 2**: Implement a correlation service that checks if a new anomaly shares a `source_ip` or `dest_ip` with any alerts from the last 10 minutes.
* **Action 3**: Create `GET /api/incidents` to return these clusters.
* **Action 4**: Add a "MITRE ATT&CK Mapping" utility that tags these incidents based on the detected heuristics (e.g., ICMP = T1071).

## 🎫 Ticket 5: Containerization & Packaging
**Objective:** Ensure the app runs in a Linux Docker environment (Non-negotiable requirement).
* **Action 1**: Create `backend/Dockerfile` using `python:3.11-slim` to install dependencies and run the Uvicorn server.
* **Action 2**: Create a root `docker-compose.yml` to orchestrate:
    * **Backend Service**: Port 8000, persistent SQLite volume.
    * **Frontend Service**: Port 3000, serving `index.html` via Nginx.
* **Action 3**: Ensure all environment variables are pulled from a central `.env` file.

---

## 🧪 Post-Implementation Validation Suite

An agent must verify the following after completing the tickets:

1.  **Persistence Test**: Submit logs, restart the backend container, and verify data still exists via `/api/stats`.
2.  **RAG Validity Test**: Analyze a "Data Exfiltration" alert and confirm the AI suggests specific steps from the `mitigation_kb.json` file.
3.  **Correlation Test**: Submit two anomalies with the same IP within 2 minutes; verify they appear as a single Incident in the UI.
4.  **Deployment Test**: Run `docker compose up --build` and verify the frontend can successfully reach the backend across container boundaries.