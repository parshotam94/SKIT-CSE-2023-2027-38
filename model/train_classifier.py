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


class SupervisedTrainer:
    """
    Trainer for supervised WAF classifier.
    """

    def __init__(
        self,
        model: TransformerWAFClassifier,
        train_dataloader: DataLoader,
        val_dataloader: DataLoader,
        test_dataloader: DataLoader,
        learning_rate: float = 2e-5,
        num_epochs: int = 15,
        warmup_steps: int = 500,
        weight_decay: float = 0.01,
        device: str = "cuda",
        save_dir: str = "./models/waf_classifier",
        use_class_weights: bool = True,
    ):
        """
        Initialize trainer.

        Args:
            model: Model to train
            train_dataloader: Training data loader
            val_dataloader: Validation data loader
            test_dataloader: Test data loader
            learning_rate: Learning rate
            num_epochs: Number of training epochs
            warmup_steps: Learning rate warmup steps
            weight_decay: Weight decay for regularization
            device: Device to train on
            save_dir: Directory to save checkpoints
            use_class_weights: Use class weights for imbalanced data
        """
        self.model = model
        self.train_dataloader = train_dataloader
        self.val_dataloader = val_dataloader
        self.test_dataloader = test_dataloader
        self.learning_rate = learning_rate
        self.num_epochs = num_epochs
        self.device = device
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)

        # Move model to device
        self.model.to(device)

        # Setup loss function with class weights
        if use_class_weights and hasattr(
            train_dataloader.dataset, "class_weights"
        ):
            class_weights = train_dataloader.dataset.class_weights.to(device)
            self.model.loss_fn = nn.CrossEntropyLoss(weight=class_weights)

        # Setup optimizer
        self.optimizer = AdamW(
            model.parameters(), lr=learning_rate, weight_decay=weight_decay
        )

        # Setup learning rate scheduler
        total_steps = len(train_dataloader) * num_epochs
        self.scheduler = get_linear_schedule_with_warmup(
            self.optimizer,
            num_warmup_steps=warmup_steps,
            num_training_steps=total_steps,
        )

        # Setup logger
        self.logger = setup_logger("SupervisedTrainer")

        # Training metrics
        self.train_losses = []
        self.val_losses = []
        self.val_accuracies = []
        self.best_val_accuracy = 0.0

    def train_epoch(self, epoch: int) -> dict:
        """
        Train for one epoch.

        Returns:
            Dictionary with training metrics
        """
        self.model.train()
        total_loss = 0.0
        correct = 0
        total = 0

        progress_bar = tqdm(
            self.train_dataloader,
            desc=f"Epoch {epoch + 1}/{self.num_epochs} [Train]",
        )

        for batch in progress_bar:
            # Move batch to device
            input_ids = batch["input_ids"].to(self.device)
            attention_mask = batch["attention_mask"].to(self.device)
            labels = batch["labels"].to(self.device)

            # Forward pass
            output = self.model(
                input_ids, attention_mask, labels, return_dict=False
            )
            logits, probabilities, predicted_classes, confidences, loss = (
                output
            )

            # Backward pass
            self.optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
            self.optimizer.step()
            self.scheduler.step()

            # Track metrics
            total_loss += loss.item()
            correct += (predicted_classes == labels).sum().item()
            total += labels.size(0)

            # Update progress bar
            progress_bar.set_postfix(
                {"loss": f"{loss.item():.4f}", "acc": f"{correct / total:.4f}"}
            )

        avg_loss = total_loss / len(self.train_dataloader)
        accuracy = correct / total

        return {"loss": avg_loss, "accuracy": accuracy}