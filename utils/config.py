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

    # Training Configuration
    batch_size: int = int(os.getenv("WAF_BATCH_SIZE", "64"))
    learning_rate: float = float(os.getenv("WAF_LEARNING_RATE", "2e-5"))
    num_epochs: int = int(os.getenv("WAF_NUM_EPOCHS", "10"))
    fine_tune_epochs: int = int(os.getenv("WAF_FINE_TUNE_EPOCHS", "3"))
    warmup_steps: int = int(os.getenv("WAF_WARMUP_STEPS", "500"))
    weight_decay: float = float(os.getenv("WAF_WEIGHT_DECAY", "0.01"))
    gradient_accumulation_steps: int = int(
        os.getenv("WAF_GRAD_ACCUM_STEPS", "1")
    )

    # Data Configuration
    train_data_dir: str = os.getenv("WAF_TRAIN_DATA_DIR", "./data/benign_logs")
    validation_split: float = float(os.getenv("WAF_VALIDATION_SPLIT", "0.1"))
    max_train_samples: Optional[int] = None  # None = use all

    # API Configuration
    api_host: str = os.getenv("WAF_API_HOST", "0.0.0.0")
    api_port: int = int(os.getenv("WAF_API_PORT", "8000"))
    api_workers: int = int(os.getenv("WAF_API_WORKERS", "4"))
    api_timeout: int = int(os.getenv("WAF_API_TIMEOUT", "30"))

    # Inference Configuration
    inference_batch_size: int = int(
        os.getenv("WAF_INFERENCE_BATCH_SIZE", "32")
    )
    max_concurrent_requests: int = int(
        os.getenv("WAF_MAX_CONCURRENT_REQUESTS", "100")
    )
    inference_timeout: float = float(os.getenv("WAF_INFERENCE_TIMEOUT", "5.0"))

    # Logging Configuration
    log_level: str = os.getenv("WAF_LOG_LEVEL", "INFO")
    log_file: Optional[str] = os.getenv("WAF_LOG_FILE", None)
    log_json: bool = os.getenv("WAF_LOG_JSON", "true").lower() == "true"
    alert_log_file: str = os.getenv(
        "WAF_ALERT_LOG_FILE",
        "./logs/alerts.jsonl"
    )

    # Storage Configuration
    checkpoint_dir: str = os.getenv("WAF_CHECKPOINT_DIR", "./checkpoints")
    save_every_n_epochs: int = int(os.getenv("WAF_SAVE_EVERY_N_EPOCHS", "1"))
    keep_last_n_checkpoints: int = int(
        os.getenv("WAF_KEEP_LAST_N_CHECKPOINTS", "3")
    )
