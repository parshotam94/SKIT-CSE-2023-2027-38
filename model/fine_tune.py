"""
Incremental Fine-Tuning for Transformer WAF
Updates model with new benign traffic without full retraining
"""

import os
import sys
import argparse
import torch
from torch.utils.data import DataLoader
from pathlib import Path
from tqdm import tqdm

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import get_config, setup_logger
from parsing import AccessLogParser, RequestNormalizer
from tokenization import WAFTokenizer
from model.transformer_model import TransformerAutoencoder
from model.train import HTTPRequestDataset, Trainer


def load_model_and_tokenizer(model_path: str, device: str = "cuda"):
    """
    Load pretrained model and tokenizer.

    Args:
        model_path: Path to saved model
        device: Device to load on

    Returns:
        Tuple of (model, tokenizer)
    """
    logger = setup_logger()
    logger.info(f"Loading model from: {model_path}")

    # Load model
    model = TransformerAutoencoder.load_pretrained(model_path)
    model = model.to(device)

    # Load tokenizer
    tokenizer = WAFTokenizer.load(model_path)

    logger.info("Model and tokenizer loaded successfully")

    return model, tokenizer


def prepare_new_data(
    log_file: str,
    normalizer: RequestNormalizer
) -> list:
    """
    Prepare new benign traffic data.

    Args:
        log_file: Path to new access log
        normalizer: RequestNormalizer instance

    Returns:
        List of normalized request texts
    """
    logger = setup_logger()
    logger.info(f"Loading new data from: {log_file}")

    parser = AccessLogParser()

    # Parse log file
    parsed_requests = parser.parse_file(log_file)
    logger.info(f"Parsed {len(parsed_requests)} requests")

    # Normalize
    normalized_texts = []
    for req in tqdm(parsed_requests, desc="Normalizing"):
        norm = normalizer.normalize(
            method=req.method,
            path=req.path,
            query_string=req.query_string,
            headers=req.headers
        )
        normalized_texts.append(norm.normalized_text)

    logger.info(f"Prepared {len(normalized_texts)} normalized requests")

    return normalized_texts