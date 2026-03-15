from typing import Dict, Any


class AnomalyDetector:
    """
    Anomaly detection engine.

    Phase 1 (Hackathon start): Rule-based heuristics — works immediately, no training needed.
    Phase 2 (Day 3-4):        Replace with sklearn IsolationForest trained on CICIDS dataset.
    """

    def __init__(self):
        self._total_processed = 0
        self._total_anomalies = 0

    # ── Public API ──────────────────────────────────────────────────────────

    def predict(self, log: Dict[str, Any]) -> Dict[str, Any]:
        self._total_processed += 1
        score, reasons = self._score(log)

        is_anomaly = score >= 2
        if is_anomaly:
            self._total_anomalies += 1

        threat_level = self._threat_level(score)
        confidence = min(0.5 + score * 0.1, 0.99)

        return {
            "is_anomaly": is_anomaly,
            "confidence": round(confidence, 2),
            "threat_level": threat_level,
            "details": reasons,
        }

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_processed": self._total_processed,
            "total_anomalies": self._total_anomalies,
            "anomaly_rate": round(
                self._total_anomalies / max(self._total_processed, 1), 4
            ),
        }

    # ── Internal heuristics ─────────────────────────────────────────────────

    def _score(self, log: Dict[str, Any]):
        score = 0
        reasons = []

        # Large data transfer
        if log.get("bytes_sent", 0) > 10_000_000:
            score += 2
            reasons.append("Unusually large outbound data transfer (>10MB)")

        # Very short duration with high volume
        if log.get(
                "duration",
                1) < 0.5 and log.get(
                "bytes_sent",
                0) > 1_000_000:
            score += 2
            reasons.append(
                "High-volume transfer in very short duration — possible data exfiltration")

        # Known suspicious protocols
        if log.get("protocol", "").upper() in {"ICMP", "IRC"}:
            score += 1
            reasons.append(f"Suspicious protocol: {log['protocol']}")

        # Private-to-private with unusual port flags
        src = log.get("source_ip", "")
        if src.startswith("192.168.") or src.startswith("10."):
            flags = log.get("flags", "")
            if flags and "SYN" in flags and "ACK" not in flags:
                score += 1
                reasons.append("Internal host sending SYN flood pattern")

        # Asymmetric traffic ratio
        sent = log.get("bytes_sent", 0)
        recv = log.get("bytes_received", 1)
        if recv > 0 and sent / recv > 50:
            score += 1
            reasons.append(
                "Extreme upload/download asymmetry — possible C2 beaconing")

        return score, reasons

    def _threat_level(self, score: int) -> str:
        if score >= 5:
            return "CRITICAL"
        if score >= 3:
            return "HIGH"
        if score >= 2:
            return "MEDIUM"
        return "LOW"
