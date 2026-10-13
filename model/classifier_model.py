"""
Transformer-Based WAF Classifier Model

Supervised multi-class classification for HTTP attack detection.

Architecture:
- Encoder: Pretrained Transformer (DistilBERT)
- Classification Head: Dense layers with dropout
- Output: Attack class probabilities (12 classes)

Classes:
0: BENIGN
1: SQL_INJECTION
2: XSS
3: PATH_TRAVERSAL
4: COMMAND_INJECTION
5: XXE
6: SSRF
7: LDAP_INJECTION
8: FILE_INCLUSION
9: CSRF
10: BUFFER_OVERFLOW
11: UNKNOWN_ATTACK

Author: ISRO Cybersecurity Division
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Optional
from transformers import AutoModel, AutoConfig
from dataclasses import dataclass


# Attack class labels
CLASS_LABELS = {
    0: "BENIGN",
    1: "SQL_INJECTION",
    2: "XSS",
    3: "PATH_TRAVERSAL",
    4: "COMMAND_INJECTION",
    5: "XXE",
    6: "SSRF",
    7: "LDAP_INJECTION",
    8: "FILE_INCLUSION",
    9: "CSRF",
    10: "BUFFER_OVERFLOW",
    11: "UNKNOWN_ATTACK"
}

LABEL_TO_CLASS = {v: k for k, v in CLASS_LABELS.items()}


@dataclass
class ClassificationOutput:
    """Output from the WAF classifier"""
    logits: torch.Tensor
    probabilities: torch.Tensor
    predicted_class: int
    predicted_label: str
    confidence: float
    loss: Optional[torch.Tensor] = None
    hidden_states: Optional[torch.Tensor] = None
    attention_weights: Optional[torch.Tensor] = None

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'predicted_class': self.predicted_class,
            'predicted_label': self.predicted_label,
            'confidence': round(self.confidence, 4),
            'is_attack': self.predicted_class != 0,
            'probabilities': {
                CLASS_LABELS[i]: round(float(self.probabilities[i]), 4)
                for i in range(len(self.probabilities))
            }
        }

class TransformerWAFClassifier(nn.Module):
    """
    Transformer-based multi-class attack classifier.

    Architecture:
    Input → BERT Encoder → Pooling → Dense → Dropout → Output

    Input: Tokenized HTTP request (max_len=128)
    Output: Class probabilities (num_classes=12)

    Training:
    - Supervised learning with labeled attack datasets
    - CrossEntropyLoss
    - AdamW optimizer with learning rate warmup

    Inference:
    - Real-time classification (<50ms)
    - Returns attack type + confidence score
    """

    def __init__(
        self,
        model_name: str = "distilbert-base-uncased",
        num_classes: int = 12,
        hidden_size: Optional[int] = None,
        dropout: float = 0.3,
        freeze_encoder: bool = False
    ):
        """
        Initialize the classifier.

        Args:
            model_name: HuggingFace model name
            num_classes: Number of output classes
            hidden_size: Hidden dimension (auto-detected if None)
            dropout: Dropout probability
            freeze_encoder: Freeze encoder weights
        """
        super().__init__()

        self.model_name = model_name
        self.num_classes = num_classes

        # Load pretrained transformer encoder
        self.config = AutoConfig.from_pretrained(model_name)
        self.encoder = AutoModel.from_pretrained(model_name)

        # Get hidden size from config
        self.hidden_size = hidden_size or self.config.hidden_size

        # Freeze encoder if requested
        if freeze_encoder:
            for param in self.encoder.parameters():
                param.requires_grad = False

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(self.hidden_size, self.hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(self.hidden_size // 2, self.hidden_size // 4),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(self.hidden_size // 4, num_classes)
        )

        # Loss function
        self.loss_fn = nn.CrossEntropyLoss()