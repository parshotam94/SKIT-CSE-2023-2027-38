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

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
        labels: Optional[torch.Tensor] = None,
        return_dict: bool = True
    ) -> ClassificationOutput:
        """
        Forward pass.

        Args:
            input_ids: Token IDs [batch_size, seq_len]
            attention_mask: Attention mask [batch_size, seq_len]
            labels: Ground truth labels [batch_size] (optional)
            return_dict: Return ClassificationOutput object

        Returns:
            ClassificationOutput with logits, probabilities, and predictions
        """
        # Encode
        encoder_output = self.encoder(
            input_ids=input_ids,
            attention_mask=attention_mask,
            return_dict=True
        )

        # Pool: use first token representation
        pooled_output = encoder_output.last_hidden_state[:, 0, :]

        # Classify
        logits = self.classifier(pooled_output)

        # Compute probabilities
        probabilities = F.softmax(logits, dim=-1)

        # Get predictions
        predicted_classes = torch.argmax(probabilities, dim=-1)
        confidences = torch.max(probabilities, dim=-1).values

        # Compute loss if labels provided
        loss = None
        if labels is not None:
            loss = self.loss_fn(logits, labels)

        if return_dict:
            # Return first item in batch for single prediction
            if logits.size(0) == 1:
                return ClassificationOutput(
                    logits=logits,
                    probabilities=probabilities[0],
                    predicted_class=predicted_classes[0].item(),
                    predicted_label=CLASS_LABELS[
                        predicted_classes[0].item()
                    ],
                    confidence=confidences[0].item(),
                    loss=loss,
                    hidden_states=encoder_output.last_hidden_state,
                    attention_weights=(
                        encoder_output.attentions
                        if hasattr(encoder_output, 'attentions')
                        else None
                    )
                )
            else:
                # Batch prediction
                return {
                    'logits': logits,
                    'probabilities': probabilities,
                    'predicted_classes': predicted_classes,
                    'confidences': confidences,
                    'loss': loss
                }

        return logits, probabilities, predicted_classes, confidences, loss

    def predict(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None
    ) -> ClassificationOutput:
        """
        Inference mode prediction.

        Args:
            input_ids: Token IDs
            attention_mask: Attention mask

        Returns:
            ClassificationOutput with prediction details
        """
        self.eval()

        with torch.no_grad():
            output = self.forward(
                input_ids,
                attention_mask,
                return_dict=True
            )

        return output    