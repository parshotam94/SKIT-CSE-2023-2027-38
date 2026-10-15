"""
Labeled Dataset Loader for Supervised WAF Training

Loads HTTP requests with attack type labels for supervised classification.

Dataset Format:
{
    "request": "GET /admin?id=1' OR '1'='1 HTTP/1.1...",
    "label": 1,  # Integer class ID
    "label_name": "SQL_INJECTION",
    "source": "CSIC2010" | "OWASP" | "synthetic",
    "metadata": {...}
}

Author: ISRO Cybersecurity Division
"""

import torch
from torch.utils.data import Dataset
from typing import List, Dict, Optional, Tuple
import json
import csv
from pathlib import Path
from collections import Counter
import numpy as np
from urllib.parse import urlparse

from model.classifier_model import CLASS_LABELS, LABEL_TO_CLASS
from parsing import AccessLogParser, RequestNormalizer
from tokenization import WAFTokenizer


class LabeledWAFDataset(Dataset):
    """
    Labeled dataset for supervised attack classification.

    Supports:
    - CSIC 2010 dataset
    - OWASP payloads
    - Custom labeled data
    - Synthetic attack generation
    """

    def __init__(
        self,
        data: List[Dict],
        tokenizer: WAFTokenizer,
        max_length: int = 128,
        normalize: bool = True
    ):
        """
        Initialize labeled dataset.

        Args:
            data: List of dictionaries with 'request' and 'label' keys
            tokenizer: WAFTokenizer instance
            max_length: Maximum sequence length
            normalize: Apply request normalization
        """
        self.data = data
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.normalize = normalize

        # Initialize normalizer if needed
        if self.normalize:
            self.normalizer = RequestNormalizer()

        # Compute class weights for imbalanced datasets
        self.class_counts = self._compute_class_distribution()
        self.class_weights = self._compute_class_weights()

    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        """
        Get a single item.

        Returns:
            Dictionary with input_ids, attention_mask, and labels
        """
        item = self.data[idx]

        # Parse and normalize request
        if self.normalize:
            try:
                parsed = AccessLogParser.parse_http_request(item['request'])
                self.normalizer.normalize(parsed)
                text = f"{parsed['method']} {parsed['path']} {parsed.get('query', '')} {parsed.get('body', '')}"
            except Exception:
                # If parsing fails, use raw request
                text = item['request']
        else:
            text = item['request']

        # Tokenize
        tokenized = self.tokenizer.tokenize(text, return_original=False)

        # Get label
        if isinstance(item['label'], str):
            label = LABEL_TO_CLASS.get(item['label'], 11)  # 11 = UNKNOWN_ATTACK
        else:
            label = item['label']

        return {
            "input_ids": tokenized.input_ids.squeeze(0),
            "attention_mask": tokenized.attention_mask,
            "labels": torch.tensor(label, dtype=torch.long)
        }

    def _compute_class_distribution(self) -> Dict[int, int]:
        """Compute class distribution"""
        labels = [
            item['label'] if isinstance(item['label'], int)
            else LABEL_TO_CLASS.get(item['label'], 11)
            for item in self.data
        ]
        return dict(Counter(labels))

    def _compute_class_weights(self) -> torch.Tensor:
        """
        Compute class weights for imbalanced dataset.

        Uses inverse frequency weighting.
        """
        total = sum(self.class_counts.values())
        num_classes = len(CLASS_LABELS)

        weights = torch.zeros(num_classes)
        for class_id in range(num_classes):
            count = self.class_counts.get(class_id, 1)
            weights[class_id] = total / (num_classes * count)

        return weights

    def get_statistics(self) -> Dict:
        """Get dataset statistics"""
        return {
            'total_samples': len(self.data),
            'num_classes': len(self.class_counts),
            'class_distribution': {
                CLASS_LABELS[k]: v
                for k, v in self.class_counts.items()
            },
            'class_weights': {
                CLASS_LABELS[i]: round(float(self.class_weights[i]), 4)
                for i in range(len(self.class_weights))
                if i in self.class_counts
            }
        }
def load_csic2010_dataset(
    dataset_path: str,
    tokenizer: WAFTokenizer,
    test_split: float = 0.2,
    val_split: float = 0.1
) -> Tuple[LabeledWAFDataset, LabeledWAFDataset, LabeledWAFDataset]:
    """
    Load CSIC 2010 HTTP dataset.

    Args:
        dataset_path: Path to CSIC2010 dataset directory
        tokenizer: WAFTokenizer instance
        test_split: Fraction for test set
        val_split: Fraction for validation set

    Returns:
        Tuple of (train_dataset, val_dataset, test_dataset)
    """
    dataset_path = Path(dataset_path)

    # Load normal traffic
    normal_file = dataset_path / "normalTrafficTraining.txt"
    anomalous_file = dataset_path / "anomalousTrafficTest.txt"

    data = []

    # Load benign requests
    if normal_file.exists():
        with open(normal_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            requests = content.split('\n\n')  # Requests separated by blank lines
            for req in requests:
                if req.strip():
                    data.append({
                        'request': req.strip(),
                        'label': 0,  # BENIGN
                        'label_name': 'BENIGN',
                        'source': 'CSIC2010'
                    })

    # Load attack requests
    if anomalous_file.exists():
        with open(anomalous_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            requests = content.split('\n\n')
            for req in requests:
                if req.strip():
                    # Auto-classify attack type based on patterns
                    attack_class = classify_attack_type(req)
                    data.append({
                        'request': req.strip(),
                        'label': attack_class,
                        'label_name': CLASS_LABELS[attack_class],
                        'source': 'CSIC2010'
                    })

    # Shuffle and split
    np.random.shuffle(data)

    total = len(data)
    test_size = int(total * test_split)
    val_size = int(total * val_split)
    train_size = total - test_size - val_size

    train_data = data[:train_size]
    val_data = data[train_size:train_size + val_size]
    test_data = data[train_size + val_size:]

    # Create datasets
    train_dataset = LabeledWAFDataset(train_data, tokenizer)
    val_dataset = LabeledWAFDataset(val_data, tokenizer)
    test_dataset = LabeledWAFDataset(test_data, tokenizer)

    return train_dataset, val_dataset, test_dataset


def load_json_dataset(
    json_path: str,
    tokenizer: WAFTokenizer,
    test_split: float = 0.2,
    val_split: float = 0.1
) -> Tuple[LabeledWAFDataset, LabeledWAFDataset, LabeledWAFDataset]:
    """
    Load dataset from JSON file.

    JSON Format:
    [
        {
            "request": "GET /path?param=value HTTP/1.1...",
            "label": 0 or "BENIGN",
            "label_name": "BENIGN",
            "metadata": {}
        },
        ...
    ]

    Args:
        json_path: Path to JSON dataset file
        tokenizer: WAFTokenizer instance
        test_split: Fraction for test set
        val_split: Fraction for validation set

    Returns:
        Tuple of (train_dataset, val_dataset, test_dataset)
    """
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Shuffle
    np.random.shuffle(data)

    # Split
    total = len(data)
    test_size = int(total * test_split)
    val_size = int(total * val_split)
    train_size = total - test_size - val_size

    train_data = data[:train_size]
    val_data = data[train_size:train_size + val_size]
    test_data = data[train_size + val_size:]

    # Create datasets
    train_dataset = LabeledWAFDataset(train_data, tokenizer)
    val_dataset = LabeledWAFDataset(val_data, tokenizer)
    test_dataset = LabeledWAFDataset(test_data, tokenizer)

    return train_dataset, val_dataset, test_dataset
