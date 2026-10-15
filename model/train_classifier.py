"""
Supervised Training Pipeline for WAF Classifier

Trains TransformerWAFClassifier on labeled attack datasets using
supervised multi-class classification.

Usage:
    python model/train_classifier.py --data data/labeled_dataset.json --epochs 15

Author: ISRO Cybersecurity Division
"""

import sys
import argparse
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from torch.optim import AdamW
from transformers import get_linear_schedule_with_warmup
from pathlib import Path
from tqdm import tqdm
import json
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    precision_recall_fscore_support,
)

try:
    from utils import setup_logger
    from tokenization import WAFTokenizer
    from model.classifier_model import TransformerWAFClassifier, CLASS_LABELS
    from model.labeled_dataset import (
        load_json_dataset,
        load_csv_dataset,
        load_csic2010_dataset,
        generate_synthetic_attacks,
    )
except ModuleNotFoundError:
    # Support running this file directly: `python model/train_classifier.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from utils import setup_logger
    from tokenization import WAFTokenizer
    from model.classifier_model import TransformerWAFClassifier, CLASS_LABELS
    from model.labeled_dataset import (
        load_json_dataset,
        load_csv_dataset,
        load_csic2010_dataset,
        generate_synthetic_attacks,
    )
