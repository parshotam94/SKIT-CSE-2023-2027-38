"""
Stub training/continuous_learning.py

Placeholder so the API can import ContinuousLearner without a trained model.
"""

from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass


@dataclass
class TrainingMetrics:
    timestamp: str
    samples_count: int
    loss: float
    learning_rate: float
    epoch: int
    model_version: str
    drift_score: float


class ContinuousLearner:
    """
    Stub ContinuousLearner.

    Accepts the detector and exposes the same interface as the real
    implementation. Returns dummy metrics since training is not yet
    implemented.
    """

    def __init__(self, detector):
        self.detector = detector

    def collect_benign_samples(
        self, log_path: Path, max_samples: int = 10000
    ) -> List[str]:
        """Read benign samples from a JSONL log file"""
        import json

        samples = []
        try:
            with open(log_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        if not event.get("is_blocked", False):
                            req = f"{event.get('method', 'GET')} {event.get('path', '/')}"
                            samples.append(req)
                            if len(samples) >= max_samples:
                                break
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass
        return samples

    def incremental_train(
        self, samples: List[str], validate: bool = True
    ) -> TrainingMetrics:
        """
        Stub training — no actual model update.
        Returns placeholder metrics.
        """
        from datetime import datetime, timezone

        return TrainingMetrics(
            timestamp=datetime.now(timezone.utc).isoformat(),
            samples_count=len(samples),
            loss=0.0,
            learning_rate=2e-5,
            epoch=0,
            model_version="stub-0.0.1",
            drift_score=0.0,
        )
