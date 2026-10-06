"""
Configuration Management for Transformer WAF
Centralizes all system configuration with environment variable support
"""

import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass


@dataclass
class WAFConfig:
    """
    Central configuration for the WAF system.
    All settings can be overridden via environment variables.
    """

    # Model Configuration
    model_path: str = os.getenv("WAF_MODEL_PATH", "./models/waf_transformer")
    model_name: str = os.getenv("WAF_MODEL_NAME", "distilbert-base-uncased")
    max_sequence_length: int = int(os.getenv("WAF_MAX_SEQUENCE_LENGTH", "128"))
    device: str = os.getenv("WAF_DEVICE", "cpu").strip()  # "cuda" or "cpu"

    # Anomaly Detection
    anomaly_threshold: float = float(
        os.getenv("WAF_ANOMALY_THRESHOLD", "0.75")
    )
    normalization_factor: float = float(
        os.getenv("WAF_NORMALIZATION_FACTOR", "1.0")
    )

    # Hybrid Classifier Configuration
    enable_classifier: bool = (
        os.getenv("WAF_ENABLE_CLASSIFIER", "true").lower() == "true"
    )
    classifier_model_path: str = os.getenv(
        "WAF_CLASSIFIER_MODEL_PATH",
        "./models/waf_classifier_dataset_balanced/best_model.pt"
    )
    classifier_confidence_threshold: float = float(
        os.getenv("WAF_CLASSIFIER_CONFIDENCE_THRESHOLD", "0.75")
    )
    classifier_score_weight: float = float(
        os.getenv("WAF_CLASSIFIER_SCORE_WEIGHT", "0.6")
    )

    # False Positive Tracking and Auto Threshold Tuning
    auto_tune_threshold: bool = (
        os.getenv("WAF_AUTO_TUNE_THRESHOLD", "false").lower() == "true"
    )
    fp_target_rate: float = float(os.getenv("WAF_FP_TARGET_RATE", "0.05"))
    fp_tuning_step: float = float(os.getenv("WAF_FP_TUNING_STEP", "0.02"))
    min_anomaly_threshold: float = float(
        os.getenv("WAF_MIN_ANOMALY_THRESHOLD", "0.5")
    )
    max_anomaly_threshold: float = float(
        os.getenv("WAF_MAX_ANOMALY_THRESHOLD", "0.95")
    )