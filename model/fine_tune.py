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

def fine_tune_model(
    model: TransformerAutoencoder,
    tokenizer: WAFTokenizer,
    new_data: list,
    num_epochs: int = 3,
    batch_size: int = 32,
    learning_rate: float = 1e-5,
    device: str = "cuda",
    save_path: str = None
):
    """
    Fine-tune model on new data.

    Args:
        model: Pretrained model
        tokenizer: Tokenizer
        new_data: New normalized request texts
        num_epochs: Number of fine-tuning epochs
        batch_size: Batch size
        learning_rate: Learning rate (lower than initial training)
        device: Device
        save_path: Path to save fine-tuned model
    """
    logger = setup_logger()
    logger.info(
        "Starting fine-tuning",
        num_samples=len(new_data),
        num_epochs=num_epochs,
        learning_rate=learning_rate
    )

    # Create dataset
    dataset = HTTPRequestDataset(
        new_data,
        tokenizer,
        max_length=tokenizer.max_length
    )

    # Create dataloader
    dataloader = DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=True,
        num_workers=4,
        pin_memory=True
    )

    # Create trainer with lower learning rate
    checkpoint_dir = Path(save_path).parent / "fine_tune_checkpoints" if save_path else "./fine_tune_checkpoints"

    trainer = Trainer(
        model=model,
        train_dataloader=dataloader,
        val_dataloader=None,  # No validation during fine-tuning
        learning_rate=learning_rate,
        num_epochs=num_epochs,
        warmup_steps=100,  # Fewer warmup steps
        device=device,
        save_dir=str(checkpoint_dir),
        save_every=1
    )

    # Fine-tune
    trainer.train()

    # Save fine-tuned model
    if save_path:
        model.save_pretrained(save_path)
        tokenizer.save(save_path)
        logger.info(f"Saved fine-tuned model to: {save_path}")


def main():
    """Main fine-tuning function"""
    parser = argparse.ArgumentParser(description="Fine-tune Transformer WAF")
    parser.add_argument("--model-path", type=str, required=True, help="Path to pretrained model")
    parser.add_argument("--log-file", type=str, required=True, help="New benign access log")
    parser.add_argument("--output-path", type=str, default=None, help="Output path (default: overwrite)")
    parser.add_argument("--epochs", type=int, default=3, help="Number of fine-tuning epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--lr", type=float, default=1e-5, help="Learning rate")
    parser.add_argument("--device", type=str, default="cuda", help="Device (cuda/cpu)")
    args = parser.parse_args()

    # Setup logger
    logger = setup_logger()
    logger.info("Starting WAF fine-tuning", args=vars(args))

    # Load model and tokenizer
    model, tokenizer = load_model_and_tokenizer(args.model_path, args.device)

    # Prepare new data
    normalizer = RequestNormalizer()
    new_data = prepare_new_data(args.log_file, normalizer)

    if len(new_data) == 0:
        logger.error("No data to fine-tune on!")
        return

    # Determine output path
    output_path = args.output_path or args.model_path

    # Fine-tune
    fine_tune_model(
        model=model,
        tokenizer=tokenizer,
        new_data=new_data,
        num_epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        device=args.device,
        save_path=output_path
    )

    logger.info("Fine-tuning complete!")


if __name__ == "__main__":
    main()