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

    def validate_epoch(self, epoch: int) -> dict:
        """
        Validate for one epoch.

        Returns:
            Dictionary with validation metrics
        """
        self.model.eval()
        total_loss = 0.0
        correct = 0
        total = 0
        all_predictions = []
        all_labels = []

        progress_bar = tqdm(
            self.val_dataloader,
            desc=f"Epoch {epoch + 1}/{self.num_epochs} [Val]",
        )

        with torch.no_grad():
            for batch in progress_bar:
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

                # Track metrics
                total_loss += loss.item()
                correct += (predicted_classes == labels).sum().item()
                total += labels.size(0)

                all_predictions.extend(predicted_classes.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())

        avg_loss = total_loss / len(self.val_dataloader)
        accuracy = correct / total

        # Compute additional metrics
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels, all_predictions, average="weighted", zero_division=0
        )

        return {
            "loss": avg_loss,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    def train(self):
        """
        Run full training loop.
        """
        self.logger.info(f"Starting training for {self.num_epochs} epochs")
        self.logger.info(f"Device: {self.device}")
        self.logger.info(
            f"Training samples: {len(self.train_dataloader.dataset)}"
        )
        self.logger.info(
            f"Validation samples: {len(self.val_dataloader.dataset)}"
        )

        for epoch in range(self.num_epochs):
            # Train
            train_metrics = self.train_epoch(epoch)
            self.train_losses.append(train_metrics["loss"])

            # Validate
            val_metrics = self.validate_epoch(epoch)
            self.val_losses.append(val_metrics["loss"])
            self.val_accuracies.append(val_metrics["accuracy"])

            # Log metrics
            self.logger.info(f"\nEpoch {epoch + 1}/{self.num_epochs}:")
            self.logger.info(
                f"  Train Loss: {train_metrics['loss']:.4f}, Train Acc: {train_metrics['accuracy']:.4f}"
            )
            self.logger.info(
                f"  Val Loss: {val_metrics['loss']:.4f}, Val Acc: {val_metrics['accuracy']:.4f}"
            )
            self.logger.info(
                f"  Val Precision: {val_metrics['precision']:.4f}, Val Recall: {val_metrics['recall']:.4f}, Val F1: {val_metrics['f1']:.4f}"
            )

            # Save best model
            if val_metrics["accuracy"] > self.best_val_accuracy:
                self.best_val_accuracy = val_metrics["accuracy"]
                self.save_checkpoint(epoch, val_metrics, is_best=True)
                self.logger.info(
                    f"  ✓ Saved best model (accuracy: {val_metrics['accuracy']:.4f})"
                )

            # Save regular checkpoint
            if (epoch + 1) % 5 == 0:
                self.save_checkpoint(epoch, val_metrics, is_best=False)

        self.logger.info(
            f"\nTraining complete! Best validation accuracy: {self.best_val_accuracy:.4f}"
        )

        # Evaluate on test set
        test_metrics = self.evaluate()
        return test_metrics

    def evaluate(self) -> dict:
        """
        Evaluate on test set.

        Returns:
            Dictionary with test metrics and classification report
        """
        self.logger.info("Evaluating on test set...")

        self.model.eval()
        all_predictions = []
        all_labels = []
        all_probabilities = []

        with torch.no_grad():
            for batch in tqdm(self.test_dataloader, desc="Testing"):
                input_ids = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                labels = batch["labels"]

                output = self.model(
                    input_ids, attention_mask, return_dict=False
                )
                logits, probabilities, predicted_classes, confidences, _ = (
                    output
                )

                all_predictions.extend(predicted_classes.cpu().numpy())
                all_labels.extend(labels.numpy())
                all_probabilities.extend(probabilities.cpu().numpy())

        # Calculate metrics
        accuracy = accuracy_score(all_labels, all_predictions)
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_labels, all_predictions, average="weighted", zero_division=0
        )

        # Confusion matrix
        cm = confusion_matrix(all_labels, all_predictions)

        # Per-class metrics
        class_names = [CLASS_LABELS[i] for i in sorted(set(all_labels))]
        class_report = classification_report(
            all_labels,
            all_predictions,
            target_names=class_names,
            digits=4,
            zero_division=0,
        )

        # Print results
        self.logger.info("\n" + "=" * 70)
        self.logger.info("TEST SET EVALUATION RESULTS")
        self.logger.info("=" * 70)
        self.logger.info("\nOverall Metrics:")
        self.logger.info(f"  Accuracy:  {accuracy:.4f}")
        self.logger.info(f"  Precision: {precision:.4f}")
        self.logger.info(f"  Recall:    {recall:.4f}")
        self.logger.info(f"  F1-Score:  {f1:.4f}")

        self.logger.info("\nPer-Class Performance:")
        self.logger.info(f"\n{class_report}")

        self.logger.info("\nConfusion Matrix:")
        self.logger.info(f"\n{cm}")

        # Save results
        results = {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "confusion_matrix": cm.tolist(),
            "class_report": class_report,
        }

        results_path = self.save_dir / "test_results.json"
        with open(results_path, "w") as f:
            json.dump(results, f, indent=2)

        self.logger.info(f"\nResults saved to {results_path}")

        return results

