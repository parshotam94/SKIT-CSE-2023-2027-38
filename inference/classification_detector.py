"""
Classification-Based Attack Detector

Real-time HTTP request classification using supervised Transformer model.

Optimized for:
- Low latency (<50ms p99)
- High accuracy (>98%)
- Real-time inference
- Production deployment

Author: ISRO Cybersecurity Division
"""

import torch
import torch.nn.functional as F
import asyncio
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
from functools import lru_cache
import time
from collections import deque

from utils import get_config, WAFLogger
from parsing import RequestNormalizer
from tokenization import WAFTokenizer
from model.classifier_model import TransformerWAFClassifier, CLASS_LABELS


@dataclass
class ClassificationResult:
    """
    Result from attack classification.
    """
    attack_type: str
    attack_class: int
    confidence: float
    is_attack: bool
    severity: str
    all_probabilities: Dict[str, float]
    normalized_request: str
    inference_time_ms: float = 0.0
    metadata: Optional[Dict] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "attack_type": self.attack_type,
            "attack_class": self.attack_class,
            "confidence": round(self.confidence, 4),
            "is_attack": self.is_attack,
            "severity": self.severity,
            "probabilities": {
                k: round(v, 4) for k, v in self.all_probabilities.items()
            },
            "normalized_request": self.normalized_request,
            "inference_time_ms": round(self.inference_time_ms, 2),
            "metadata": self.metadata or {}
        }


@dataclass
class PerformanceMetrics:
    """Performance tracking for classifier"""
    total_requests: int = 0
    attack_requests: int = 0
    benign_requests: int = 0
    blocked_requests: int = 0
    total_inference_time_ms: float = 0.0
    attack_distribution: Dict[str, int] = None
    recent_latencies: deque = None

    def __post_init__(self):
        if self.attack_distribution is None:
            self.attack_distribution = {label: 0 for label in CLASS_LABELS.values()}
        if self.recent_latencies is None:
            self.recent_latencies = deque(maxlen=1000)

    def record_request(
        self,
        latency_ms: float,
        attack_type: str,
        is_attack: bool
    ):
        """Record a request"""
        self.total_requests += 1
        if is_attack:
            self.attack_requests += 1
        else:
            self.benign_requests += 1
        self.total_inference_time_ms += latency_ms
        self.recent_latencies.append(latency_ms)
        self.attack_distribution[attack_type] += 1

    def get_percentile(self, p: float) -> float:
        """Get latency percentile"""
        if not self.recent_latencies:
            return 0.0
        sorted_latencies = sorted(self.recent_latencies)
        idx = int(len(sorted_latencies) * p / 100.0)
        return sorted_latencies[min(idx, len(sorted_latencies) - 1)]

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        avg_latency = (
            self.total_inference_time_ms / self.total_requests
            if self.total_requests > 0
            else 0.0
        )

        return {
            "total_requests": self.total_requests,
            "attack_requests": self.attack_requests,
            "benign_requests": self.benign_requests,
            "attack_rate": (
                self.attack_requests / self.total_requests
                if self.total_requests > 0
                else 0.0
            ),
            "avg_latency_ms": round(avg_latency, 2),
            "p50_latency_ms": round(self.get_percentile(50), 2),
            "p95_latency_ms": round(self.get_percentile(95), 2),
            "p99_latency_ms": round(self.get_percentile(99), 2),
            "attack_distribution": self.attack_distribution
        }


class ClassificationDetector:
    """
    High-performance classification-based attack detector.

    Uses supervised Transformer model to classify HTTP requests
    into attack types with confidence scores.
    """

    def __init__(
        self,
        model_path: str,
        tokenizer: Optional[WAFTokenizer] = None,
        device: str = "cuda",
        confidence_threshold: float = 0.75,
        max_batch_size: int = 32,
        enable_optimization: bool = True
    ):
        """
        Initialize detector.

        Args:
            model_path: Path to trained model checkpoint