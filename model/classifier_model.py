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