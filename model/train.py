"""
Training Pipeline for Transformer WAF
Trains model on benign HTTP request logs
"""

import os
import sys
import argparse
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from torch.optim import AdamW
from transformers import get_linear_schedule_with_warmup
from typing import List, Dict, Optional
from pathlib import Path
from tqdm import tqdm
import json

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import get_config, setup_logger
from parsing import AccessLogParser, RequestNormalizer
from tokenization import WAFTokenizer
from model.transformer_model import TransformerAutoencoder


class HTTPRequestDataset(Dataset):
    """
    Dataset for HTTP requests.
    """

    def __init__(
        self,
        texts: List[str],
        tokenizer: WAFTokenizer,
        max_length: int = 128
    ):
        """
        Initialize dataset.

        Args:
            texts: List of normalized request texts
            tokenizer: WAFTokenizer instance
            max_length: Maximum sequence length
        """
        self.texts = texts
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.texts)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        """Get a single item"""
        text = self.texts[idx]

        # Tokenize
        tokenized = self.tokenizer.tokenize(text, return_original=False)

        # Create masked input for MLM
        masked_data = self.tokenizer.create_masked_input(
            tokenized.input_ids.unsqueeze(0),
            mask_prob=0.15
        )

        return {
            "input_ids": masked_data["masked_input_ids"].squeeze(0),
            "attention_mask": tokenized.attention_mask,
            "labels": masked_data["labels"].squeeze(0)
        }

