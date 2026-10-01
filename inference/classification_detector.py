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
             tokenizer: WAFTokenizer instance (created if None)
            device: Device for inference
            confidence_threshold: Minimum confidence for attack detection
            max_batch_size: Maximum batch size for inference
            enable_optimization: Enable model optimizations (JIT, etc.)
        """
        self.model_path = Path(model_path)
        self.device = device
        self.confidence_threshold = confidence_threshold
        self.max_batch_size = max_batch_size

        # Initialize logger
        self.logger = WAFLogger("ClassificationDetector")

        # Initialize tokenizer
        if tokenizer is None:
            self.logger.info("Initializing tokenizer...")
            self.tokenizer = WAFTokenizer()
        else:
            self.tokenizer = tokenizer

        # Initialize normalizer
        self.normalizer = RequestNormalizer()

        # Load model
        self.logger.info(f"Loading model from {model_path}...")
        self.model = TransformerWAFClassifier.load_model(
            str(model_path),
            device=device
        )
        self.model.eval()

        # Apply optimizations
        if enable_optimization and device == "cuda":
            self.logger.info("Applying optimizations...")
            try:
                # JIT compilation
                self.model = torch.jit.script(self.model)
                self.logger.info("✓ JIT compilation successful")
            except Exception as e:
                self.logger.warning(f"JIT compilation failed: {e}")

        # Warm up model
        self.logger.info("Warming up model...")
        self._warmup()

        # Performance metrics
        self.metrics = PerformanceMetrics()

        # Semaphore for batch control
        self.batch_semaphore = asyncio.Semaphore(max_batch_size)

        self.logger.info(f"Detector initialized successfully on {device}")

    def _warmup(self, num_warmup: int = 10):
        """Warm up model with dummy requests"""
        dummy_text = "GET /api/users?id=1 HTTP/1.1"

        for _ in range(num_warmup):
            tokenized = self.tokenizer.tokenize(dummy_text, return_original=False)
            input_ids = tokenized.input_ids.to(self.device)
            attention_mask = tokenized.attention_mask.to(self.device)

            with torch.no_grad():
                _ = self.model.predict(input_ids, attention_mask)

    @lru_cache(maxsize=10000)
    def _cached_tokenize(self, text: str) -> Tuple:
        """Cache tokenization results"""
        tokenized = self.tokenizer.tokenize(text, return_original=False)
        return (
            tokenized.input_ids,
            tokenized.attention_mask
        )

    async def detect(
        self,
        method: str,
        path: str,
        query_string: str = "",
        headers: Optional[Dict] = None,
        body: str = ""
    ) -> ClassificationResult:
        """
        Classify HTTP request.

        Args:
            method: HTTP method
            path: URL path
            query_string: Query string
            headers: Request headers
            body: Request body

        Returns:
            ClassificationResult with attack type and confidence
        """
        start_time = time.time()

        # Normalize request
        request_data = {
            "method": method,
            "path": path,
            "query": query_string,
            "headers": headers or {},
            "body": body
        }

        normalized = self.normalizer.normalize(request_data)

        # Create text representation
        text = f"{method} {path} {query_string} {body}"

        # Tokenize (with caching)
        try:
            input_ids, attention_mask = self._cached_tokenize(text)
        except TypeError:
            # Cache miss or uncacheable
            tokenized = self.tokenizer.tokenize(text, return_original=False)
            input_ids = tokenized.input_ids
            attention_mask = tokenized.attention_mask

        # Move to device
        input_ids = input_ids.to(self.device)
        attention_mask = attention_mask.to(self.device)

        # Inference
        async with self.batch_semaphore:
            with torch.no_grad():
                output = self.model.predict(input_ids, attention_mask)

        # Parse results
        attack_type = output.predicted_label
        attack_class = output.predicted_class
        confidence = output.confidence
        is_attack = attack_class != 0 and confidence >= self.confidence_threshold
        severity = self.model.get_attack_severity(attack_class, confidence)

        # Calculate inference time
        inference_time_ms = (time.time() - start_time) * 1000

        # Update metrics
        self.metrics.record_request(
            latency_ms=inference_time_ms,
            attack_type=attack_type,
            is_attack=is_attack
        )

        # Create result
        result = ClassificationResult(
            attack_type=attack_type,
            attack_class=attack_class,
            confidence=confidence,
            is_attack=is_attack,
            severity=severity,
            all_probabilities=output.to_dict()['probabilities'],
            normalized_request=normalized,
            inference_time_ms=inference_time_ms,
            metadata={
                'method': method,
                'path': path
            }
        )

        return result

    async def detect_batch(
        self,
        requests: List[Dict]
    ) -> List[ClassificationResult]:
        """
        Classify batch of HTTP requests.

        Args:
            requests: List of request dictionaries

        Returns:
            List of ClassificationResult objects
        """
        results = []

        for request in requests:
            result = await self.detect(
                method=request.get('method', 'GET'),
                path=request.get('path', '/'),
                query_string=request.get('query_string', ''),
                headers=request.get('headers', {}),
                body=request.get('body', '')
            )
            results.append(result)

        return results

    def get_metrics(self) -> Dict:
        """Get performance metrics"""
        return self.metrics.to_dict()

    def reset_metrics(self):
        """Reset performance metrics"""
        self.metrics = PerformanceMetrics()

    def get_model_info(self) -> Dict:
        """Get model information"""
        return {
            'model_path': str(self.model_path),
            'device': self.device,
            'confidence_threshold': self.confidence_threshold,
            'num_classes': len(CLASS_LABELS),
            'class_labels': list(CLASS_LABELS.values())
        }

    def update_threshold(self, new_threshold: float):
        """Update confidence threshold"""
        if 0.0 <= new_threshold <= 1.0:
            self.confidence_threshold = new_threshold
            self.logger.info(f"Threshold updated to {new_threshold}")
        else:
            raise ValueError("Threshold must be between 0.0 and 1.0")


# Factory function for backward compatibility
def create_detector(
    model_path: str,
    device: str = "cuda",
    threshold: float = 0.75
) -> ClassificationDetector:
    """
    Create classification detector.

    Args:
        model_path: Path to model checkpoint
        device: Device for inference
        threshold: Confidence threshold

    Returns:
        ClassificationDetector instance
    """
    return ClassificationDetector(
        model_path=model_path,
        device=device,
        confidence_threshold=threshold
    )