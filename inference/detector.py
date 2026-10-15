"""
Stub inference/detector.py

Provides AnomalyDetector and DetectionResult so the API can import them.
The real model is not trained yet — this stub uses simple heuristics so the
API starts and all endpoints are reachable.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time


@dataclass
class DetectionResult:
    """Result of anomaly detection"""
    is_anomalous: bool
    anomaly_score: float
    threshold: float
    reconstruction_error: float
    perplexity: float
    normalized_request: str = ""
    inference_time_ms: float = 0.0
    metadata: Optional[Dict] = None

    def to_dict(self) -> Dict:
        return {
            "is_anomalous": self.is_anomalous,
            "anomaly_score": self.anomaly_score,
            "threshold": self.threshold,
            "reconstruction_error": self.reconstruction_error,
            "perplexity": self.perplexity,
            "normalized_request": self.normalized_request,
            "inference_time_ms": round(self.inference_time_ms, 2),
            "metadata": self.metadata or {},
        }


class AnomalyDetector:
    """
    Stub AnomalyDetector.

    Uses simple keyword heuristics to simulate detection until a real
    trained model is available.
    """

    # Common attack keywords for heuristic scoring
    _SQL_PATTERNS = ["select ", "union ", "' or ", "drop table", "insert into", "--", "1=1"]
    _XSS_PATTERNS = ["<script", "javascript:", "onerror=", "alert("]
    _PATH_PATTERNS = ["../", "..\\", "/etc/passwd", "c:\\windows"]
    _CMD_PATTERNS = ["| cat", "; ls", "`whoami`", "$(", "; rm"]

    def __init__(
        self,
        model_path: str = "",
        device: str = "cpu",
        threshold: float = 0.75,
        batch_size: int = 32,
        enable_jit: bool = False,
        cache_size: int = 1000,
        max_workers: int = 1,
        # hybrid classifier params (accepted but unused)
        enable_classifier: bool = False,
        classifier_model_path: str = "",
        classifier_confidence_threshold: float = 0.75,
        classifier_score_weight: float = 0.6,
        # auto-tune params (accepted but unused)
        auto_tune_threshold: bool = False,
        fp_target_rate: float = 0.05,
        fp_tuning_step: float = 0.02,
        min_threshold: float = 0.5,
        max_threshold: float = 0.95,
    ):
        self.model_path = model_path
        self.device = device
        self.threshold = threshold
        self._total = 0
        self._anomalous = 0
        self._fp_feedback: List[bool] = []

    def _heuristic_score(
        self, method: str, path: str, query_string: str, body: str
    ) -> float:
        combined = f"{path} {query_string} {body}".lower()
        if any(p in combined for p in self._SQL_PATTERNS):
            return 0.95
        if any(p in combined for p in self._XSS_PATTERNS):
            return 0.92
        if any(p in combined for p in self._PATH_PATTERNS):
            return 0.90
        if any(p in combined for p in self._CMD_PATTERNS):
            return 0.88
        return 0.08  # benign baseline

    async def detect(
        self,
        method: str,
        path: str,
        query_string: str = "",
        headers: Optional[Dict] = None,
        body: Optional[str] = None,
    ) -> DetectionResult:
        t0 = time.time()
        body = body or ""
        score = self._heuristic_score(method, path, query_string, body)
        is_anomalous = score >= self.threshold
        self._total += 1
        if is_anomalous:
            self._anomalous += 1
        return DetectionResult(
            is_anomalous=is_anomalous,
            anomaly_score=score,
            threshold=self.threshold,
            reconstruction_error=score,
            perplexity=max(1.0, score * 20),
            normalized_request=f"{method} {path}",
            inference_time_ms=(time.time() - t0) * 1000,
            metadata={"attack_type": "HEURISTIC" if is_anomalous else "NONE"},
        )

    async def detect_batch(self, requests: List[Dict]) -> List[DetectionResult]:
        results = []
        for req in requests:
            result = await self.detect(
                method=req.get("method", "GET"),
                path=req.get("path", "/"),
                query_string=req.get("query_string", ""),
                headers=req.get("headers", {}),
                body=req.get("body", ""),
            )
            results.append(result)
        return results

    def update_threshold(self, threshold: float):
        self.threshold = threshold

    def get_stats(self) -> Dict:
        return {
            "total_requests": self._total,
            "anomalous_requests": self._anomalous,
            "detector_type": "heuristic_stub",
        }

    def get_threshold_recommendation(self) -> Dict:
        return {
            "current_threshold": self.threshold,
            "recommended_threshold": self.threshold,
            "fp_rate": 0.0,
            "message": "Model not trained yet — heuristic stub active",
        }

    def record_feedback(
        self,
        predicted_anomalous: bool,
        actual_is_attack: bool,
        auto_tune: bool = True,
    ) -> Dict:
        self._fp_feedback.append(predicted_anomalous != actual_is_attack)
        return {"threshold_adjustment_applied": False}

    def shutdown(self):
        pass
