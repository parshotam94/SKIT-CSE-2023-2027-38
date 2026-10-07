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


class Trainer:
    """
    Trainer for the WAF model.
    """

    def __init__(
        self,
        model: TransformerAutoencoder,
        train_dataloader: DataLoader,
        val_dataloader: Optional[DataLoader] = None,
        learning_rate: float = 2e-5,
        num_epochs: int = 10,
        warmup_steps: int = 500,
        weight_decay: float = 0.01,
        device: str = "cuda",
        save_dir: str = "./checkpoints",
        log_every: int = 100,
        save_every: int = 1
    ):
        """
        Initialize trainer.

        Args:
            model: Model to train
            train_dataloader: Training data loader
            val_dataloader: Validation data loader
            learning_rate: Learning rate
            num_epochs: Number of epochs
            warmup_steps: Warmup steps
            weight_decay: Weight decay
            device: Device (cuda/cpu)
            save_dir: Checkpoint save directory
            log_every: Log every N steps
            save_every: Save every N epochs
        """
        self.model = model.to(device)
        self.train_dataloader = train_dataloader
        self.val_dataloader = val_dataloader
        self.num_epochs = num_epochs
        self.device = device
        self.save_dir = Path(save_dir)
        self.log_every = log_every
        self.save_every = save_every

        # Create save directory
        self.save_dir.mkdir(parents=True, exist_ok=True)

        # Optimizer
        self.optimizer = AdamW(
            model.parameters(),
            lr=learning_rate,
            weight_decay=weight_decay
        )

        # Learning rate scheduler
        total_steps = len(train_dataloader) * num_epochs
        self.scheduler = get_linear_schedule_with_warmup(
            self.optimizer,
            num_warmup_steps=warmup_steps,
            num_training_steps=total_steps
        )

        # Setup logger
        self.logger = setup_logger()

        # Training state
        self.global_step = 0
        self.current_epoch = 0
        self.best_val_loss = float('inf')

    def train(self):
        """Run training loop"""
        self.logger.info(
            "Starting training",
            num_epochs=self.num_epochs,
            train_samples=len(self.train_dataloader.dataset),
            device=self.device
        )

        for epoch in range(self.num_epochs):
            self.current_epoch = epoch

            # Train
            train_loss = self.train_epoch()

            # Validate
            val_loss = None
            if self.val_dataloader:
                val_loss = self.validate()

            # Log epoch summary
            self.logger.log_training_progress(
                epoch=epoch + 1,
                total_epochs=self.num_epochs,
                loss=train_loss,
                learning_rate=self.scheduler.get_last_lr()[0],
                samples_processed=len(self.train_dataloader.dataset)
            )

            if val_loss is not None:
                self.logger.info(f"Validation loss: {val_loss:.6f}")

            # Save checkpoint
            if (epoch + 1) % self.save_every == 0:
                self.save_checkpoint(epoch, train_loss, val_loss)

        # Save final model
        self.save_final_model()

        self.logger.info("Training completed!")

    def validate(self) -> float:
        """Validate the model"""
        self.model.eval()
        total_loss = 0.0
        num_batches = 0

        with torch.no_grad():
            for batch in tqdm(self.val_dataloader, desc="Validating"):
                # Move to device
                input_ids = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                labels = batch["labels"].to(self.device)

                # Forward pass
                output = self.model(
                    input_ids=input_ids,
                    attention_mask=attention_mask,
                    labels=labels
                )

                total_loss += output.loss.item()
                num_batches += 1

        avg_loss = total_loss / num_batches

        # Save best model
        if avg_loss < self.best_val_loss:
            self.best_val_loss = avg_loss
            self.save_checkpoint(
                self.current_epoch,
                None,
                avg_loss,
                is_best=True
            )

        return avg_loss

    def save_checkpoint(
        self,
        epoch: int,
        train_loss: Optional[float],
        val_loss: Optional[float],
        is_best: bool = False
    ):
        """Save training checkpoint"""
        checkpoint_name = "best_model.pt" if is_best else f"checkpoint_epoch_{epoch + 1}.pt"
        checkpoint_path = self.save_dir / checkpoint_name

        torch.save({
            "epoch": epoch,
            "global_step": self.global_step,
            "model_state_dict": self.model.state_dict(),
            "optimizer_state_dict": self.optimizer.state_dict(),
            "scheduler_state_dict": self.scheduler.state_dict(),
            "train_loss": train_loss,
            "val_loss": val_loss,
            "best_val_loss": self.best_val_loss,
        }, checkpoint_path)

        self.logger.info(f"Saved checkpoint: {checkpoint_path}")

    def save_final_model(self):
        """Save final trained model"""
        model_path = self.save_dir.parent / "waf_transformer"
        self.model.save_pretrained(str(model_path))
        self.logger.info(f"Saved final model: {model_path}")

