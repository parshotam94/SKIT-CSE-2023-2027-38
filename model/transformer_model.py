"""
Transformer-Based Anomaly Detection Model

Advanced autoencoder architecture for learning benign traffic patterns.

Enhanced Anomaly Scoring:
- Multi-metric ensemble (reconstruction, perplexity, attention, embedding distance)
- Attention-based anomaly localization
- Mahalanobis distance in embedding space
- Statistical calibration with running statistics
- Adaptive thresholding based on confidence intervals

Author: ISRO Cybersecurity Division
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Dict, Optional, Tuple, List
from transformers import AutoModel, AutoConfig
from dataclasses import dataclass
import math


@dataclass
class ModelOutput:
    """Output from the WAF model"""
    loss: Optional[torch.Tensor] = None
    reconstruction_loss: Optional[torch.Tensor] = None
    logits: Optional[torch.Tensor] = None
    hidden_states: Optional[torch.Tensor] = None
    attention_weights: Optional[torch.Tensor] = None


@dataclass
class AnomalyScore:
    """Comprehensive anomaly score with multiple metrics"""
    overall_score: float  # Combined anomaly score [0-1]
    reconstruction_error: float  # Token mismatch rate
    perplexity: float  # Language model perplexity
    attention_score: float  # Attention pattern anomaly
    embedding_distance: float  # Mahalanobis distance
    confidence: float  # Score confidence [0-1]
    anomaly_tokens: List[int]  # Indices of anomalous tokens

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'overall_score': self.overall_score,
            'reconstruction_error': self.reconstruction_error,
            'perplexity': self.perplexity,
            'attention_score': self.attention_score,
            'embedding_distance': self.embedding_distance,
            'confidence': self.confidence,
            'num_anomalous_tokens': len(self.anomaly_tokens)
        }


class TransformerAutoencoder(nn.Module):
    """
    Transformer-based autoencoder for HTTP request anomaly detection.

    Architecture:
    - Encoder: Pretrained Transformer (BERT/DistilBERT)
    - Decoder: Reconstruction head (predicts original tokens)

    Training:
    - Masked Language Modeling (MLM) on benign requests
    - Learn to reconstruct masked tokens

    Inference:
    - Compute reconstruction error for each request
    - High error → anomaly
    """

    def __init__(
        self,
        model_name: str = "distilbert-base-uncased",
        vocab_size: int = 30522,
        hidden_size: Optional[int] = None,
        num_labels: int = 2,
        dropout: float = 0.1,
        freeze_encoder: bool = False
    ):
        """
        Initialize the model.

        Args:
            model_name: HuggingFace model name
            vocab_size: Vocabulary size
            hidden_size: Hidden dimension (auto-detected if None)
            num_labels: Number of output labels (for classification head)
            dropout: Dropout probability
            freeze_encoder: Freeze encoder weights
        """
        super().__init__()

        self.model_name = model_name
        self.vocab_size = vocab_size

        # Load pretrained transformer encoder
        self.config = AutoConfig.from_pretrained(model_name)
        self.encoder = AutoModel.from_pretrained(model_name)

        # Get hidden size from config
        self.hidden_size = hidden_size or self.config.hidden_size

        # Freeze encoder if requested
        if freeze_encoder:
            for param in self.encoder.parameters():
                param.requires_grad = False

        # Reconstruction head (for MLM)
        self.mlm_head = nn.Sequential(
            nn.Linear(self.hidden_size, self.hidden_size),
            nn.GELU(),
            nn.LayerNorm(self.hidden_size),
            nn.Dropout(dropout),
            nn.Linear(self.hidden_size, vocab_size)
        )

        # Optional classification head (for supervised fine-tuning)
        self.classifier = nn.Sequential(
            nn.Linear(self.hidden_size, self.hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(self.hidden_size // 2, num_labels)
        )

        # Loss functions
        self.mlm_loss_fn = nn.CrossEntropyLoss(ignore_index=-100)
        self.classification_loss_fn = nn.CrossEntropyLoss()

        # Running statistics for score calibration
        self.register_buffer('running_mean', torch.zeros(1))
        self.register_buffer('running_var', torch.ones(1))
        self.register_buffer('running_count', torch.zeros(1))
        self.calibration_enabled = False

        # Attention anomaly detector
        self.attention_aggregator = nn.Linear(self.config.num_attention_heads, 1)

        # Embedding statistics for Mahalanobis distance
        self.register_buffer('embedding_mean', torch.zeros(self.hidden_size))
        self.register_buffer('embedding_cov_inv', torch.eye(self.hidden_size))

    def forward(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
        labels: Optional[torch.Tensor] = None,
        return_hidden_states: bool = False,
        return_attention_weights: bool = False
    ) -> ModelOutput:
        """
        Forward pass.

        Args:
            input_ids: Token IDs [batch_size, seq_length]
            attention_mask: Attention mask [batch_size, seq_length]
            labels: Labels for MLM [-100 for non-masked tokens]
            return_hidden_states: Return encoder hidden states
            return_attention_weights: Return attention weights

        Returns:
            ModelOutput with loss and logits
        """
        # Encode
        encoder_output = self.encoder(
            input_ids=input_ids,
            attention_mask=attention_mask,
            output_hidden_states=return_hidden_states,
            output_attentions=return_attention_weights
        )

        # Get sequence output
        sequence_output = encoder_output.last_hidden_state  # [batch, seq_len, hidden]

        # Reconstruction head
        logits = self.mlm_head(sequence_output)  # [batch, seq_len, vocab_size]

        # Compute loss if labels provided
        loss = None
        reconstruction_loss = None
        if labels is not None:
            reconstruction_loss = self.mlm_loss_fn(
                logits.view(-1, self.vocab_size),
                labels.view(-1)
            )
            loss = reconstruction_loss

        return ModelOutput(
            loss=loss,
            reconstruction_loss=reconstruction_loss,
            logits=logits,
            hidden_states=encoder_output.hidden_states if return_hidden_states else None,
            attention_weights=encoder_output.attentions if return_attention_weights else None
        )

    def get_pooled_output(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Get pooled representation (for classification).

        Args:
            input_ids: Token IDs
            attention_mask: Attention mask

        Returns:
            Pooled output [batch_size, hidden_size]
        """
        encoder_output = self.encoder(
            input_ids=input_ids,
            attention_mask=attention_mask
        )

        # Use [CLS] token representation
        pooled_output = encoder_output.last_hidden_state[:, 0, :]  # [batch, hidden]
        return pooled_output

    def classify(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
        labels: Optional[torch.Tensor] = None
    ) -> Tuple[torch.Tensor, Optional[torch.Tensor]]:
        """
        Classification forward pass.

        Args:
            input_ids: Token IDs
            attention_mask: Attention mask
            labels: Classification labels

        Returns:
            Tuple of (logits, loss)
        """
        pooled_output = self.get_pooled_output(input_ids, attention_mask)
        logits = self.classifier(pooled_output)

        loss = None
        if labels is not None:
            loss = self.classification_loss_fn(logits, labels)

        return logits, loss

    def compute_reconstruction_error(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
        reduction: str = "mean",
        return_token_scores: bool = False
    ) -> torch.Tensor:
        """
        Compute advanced reconstruction error with confidence weighting.

        Uses softmax probabilities instead of hard predictions for smoother gradients.

        Args:
            input_ids: Original token IDs
            attention_mask: Attention mask
            reduction: "mean", "sum", or "none"
            return_token_scores: Return per-token scores

        Returns:
            Reconstruction error per sample (or per token if reduction='none')
        """
        # Forward pass
        output = self.forward(input_ids, attention_mask)
        logits = output.logits  # [batch, seq_len, vocab_size]

        # Compute softmax probabilities
        probs = F.softmax(logits, dim=-1)  # [batch, seq_len, vocab_size]

        # Get probability of correct token (smooth confidence score)
        batch_size, seq_len = input_ids.shape
        correct_token_probs = probs[torch.arange(batch_size).unsqueeze(1), 
                                    torch.arange(seq_len).unsqueeze(0), 
                                    input_ids]

        # Reconstruction error = 1 - P(correct token)
        token_errors = 1.0 - correct_token_probs  # [batch, seq_len]

        # Weight by prediction entropy (low entropy = high confidence)
        entropy = -(probs * torch.log(probs + 1e-10)).sum(dim=-1)  # [batch, seq_len]
        max_entropy = math.log(self.vocab_size)
        normalized_entropy = entropy / max_entropy

        # Combine error with confidence weighting
        weighted_errors = token_errors * (1.0 + normalized_entropy)  # Higher weight for uncertain predictions

        # Apply attention mask
        if attention_mask is not None:
            weighted_errors = weighted_errors * attention_mask
            seq_lengths = attention_mask.sum(dim=1)
        else:
            seq_lengths = torch.full((batch_size,), seq_len, device=input_ids.device)

        if return_token_scores:
            return weighted_errors

        # Reduce
        if reduction == "mean":
            error = weighted_errors.sum(dim=1) / seq_lengths
        elif reduction == "sum":
            error = weighted_errors.sum(dim=1)
        else:  # "none"
            error = weighted_errors

        return error

    def compute_attention_anomaly(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Compute anomaly score based on attention patterns.

        Anomalous requests often have unusual attention distributions
        (e.g., focusing heavily on unexpected tokens).

        Args:
            input_ids: Token IDs
            attention_mask: Attention mask

        Returns:
            Attention anomaly score per sample [0-1]
        """
        # Forward pass with attention weights
        output = self.forward(
            input_ids, 
            attention_mask, 
            return_attention_weights=True
        )

        if output.attention_weights is None:
            return torch.zeros(input_ids.size(0), device=input_ids.device)

        # Average attention across layers and heads
        # attention_weights: tuple of [batch, heads, seq_len, seq_len] for each layer
        all_attentions = torch.stack(output.attention_weights)  # [layers, batch, heads, seq, seq]
        avg_attention = all_attentions.mean(dim=0)  # [batch, heads, seq, seq]

        # Compute attention statistics
        batch_size = input_ids.size(0)
        scores = []

        for i in range(batch_size):
            # Get attention for this sample
            sample_attention = avg_attention[i]  # [heads, seq, seq]

            # Compute entropy of attention distribution (higher = more uniform = potentially anomalous)
            attention_dist = sample_attention.mean(dim=0)  # [seq, seq]
            attention_entropy = -(attention_dist * torch.log(attention_dist + 1e-10)).sum(dim=-1).mean()

            # Compute attention concentration (std of attention weights)
            attention_std = sample_attention.std()

            # Combine metrics (normalized)
            max_entropy = math.log(input_ids.size(1))  # Max possible entropy
            normalized_entropy = attention_entropy / max_entropy

            # High entropy or high std indicates unusual attention
            anomaly_score = (normalized_entropy + attention_std) / 2.0
            scores.append(anomaly_score)

        return torch.tensor(scores, device=input_ids.device)

    def compute_embedding_distance(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
        use_mahalanobis: bool = True
    ) -> torch.Tensor:
        """
        Compute Mahalanobis distance from normal embedding distribution.

        Measures how far the request embedding is from the learned
        benign distribution in the embedding space.

        Args:
            input_ids: Token IDs
            attention_mask: Attention mask
            use_mahalanobis: Use Mahalanobis distance (True) or Euclidean (False)

        Returns:
            Distance score per sample
        """
        # Get pooled embeddings
        pooled = self.get_pooled_output(input_ids, attention_mask)  # [batch, hidden]

        if use_mahalanobis and self.embedding_cov_inv is not None:
            # Mahalanobis distance: sqrt((x - μ)^T Σ^-1 (x - μ))
            centered = pooled - self.embedding_mean.unsqueeze(0)

            # Compute distance
            distances = []
            for i in range(pooled.size(0)):
                diff = centered[i:i+1]  # [1, hidden]
                dist = torch.sqrt(
                    torch.mm(
                        torch.mm(diff, self.embedding_cov_inv),
                        diff.t()
                    )
                ).item()
                distances.append(dist)

            return torch.tensor(distances, device=input_ids.device)
        else:
            # Euclidean distance
            distances = torch.norm(pooled - self.embedding_mean.unsqueeze(0), dim=1)
            return distances

    def compute_perplexity(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None
    ) -> torch.Tensor:
        """
        Compute perplexity (alternative anomaly score).

        Lower perplexity = more "normal" (seen during training)
        Higher perplexity = more "anomalous" (unseen patterns)

        Args:
            input_ids: Token IDs
            attention_mask: Attention mask

        Returns:
            Perplexity per sample
        """
        # Forward pass
        output = self.forward(input_ids, attention_mask, labels=input_ids)

        # Get loss per sample (cross-entropy)
        logits = output.logits.view(-1, self.vocab_size)
        labels = input_ids.view(-1)

        # Compute loss without reduction
        loss_fn = nn.CrossEntropyLoss(reduction="none", ignore_index=-100)
        token_losses = loss_fn(logits, labels)  # [batch * seq_len]

        # Reshape and apply mask
        token_losses = token_losses.view(input_ids.size())  # [batch, seq_len]
        if attention_mask is not None:
            token_losses = token_losses * attention_mask
            seq_lengths = attention_mask.sum(dim=1)
        else:
            seq_lengths = torch.full(
                (input_ids.size(0),),
                input_ids.size(1),
                device=input_ids.device
            )

        # Average loss per sequence
        avg_loss = token_losses.sum(dim=1) / seq_lengths

        # Perplexity = exp(loss)
        perplexity = torch.exp(avg_loss)

        return perplexity

    def compute_anomaly_score(
        self,
        input_ids: torch.Tensor,
        attention_mask: Optional[torch.Tensor] = None,
        weights: Optional[Dict[str, float]] = None
    ) -> List[AnomalyScore]:
        """
        Compute comprehensive anomaly score using ensemble of metrics.

        Combines multiple scoring strategies:
        1. Reconstruction error (token-level)
        2. Perplexity (language model confidence)
        3. Attention anomaly (pattern analysis)
        4. Embedding distance (Mahalanobis)

        Args:
            input_ids: Token IDs
            attention_mask: Attention mask
            weights: Custom weights for metrics (default: equal)

        Returns:
            List of AnomalyScore objects (one per sample)
        """
        # Default weights (can be tuned based on validation data)
        if weights is None:
            weights = {
                'reconstruction': 0.35,
                'perplexity': 0.30,
                'attention': 0.20,
                'embedding': 0.15
            }

        batch_size = input_ids.size(0)

        # Compute all metrics
        with torch.no_grad():
            # 1. Reconstruction error (smooth, confidence-weighted)
            recon_errors = self.compute_reconstruction_error(
                input_ids, attention_mask, reduction="mean"
            )
            token_scores = self.compute_reconstruction_error(
                input_ids, attention_mask, reduction="none", return_token_scores=True
            )

            # 2. Perplexity
            perplexities = self.compute_perplexity(input_ids, attention_mask)

            # 3. Attention anomaly
            attention_scores = self.compute_attention_anomaly(input_ids, attention_mask)

            # 4. Embedding distance
            embedding_distances = self.compute_embedding_distance(input_ids, attention_mask)

        # Normalize metrics to [0, 1] range
        def normalize_score(scores, clip_max=None):
            """Normalize scores using min-max scaling with optional clipping"""
            if clip_max is not None:
                scores = torch.clamp(scores, max=clip_max)
            min_val = scores.min()
            max_val = scores.max()
            if max_val - min_val > 1e-6:
                return (scores - min_val) / (max_val - min_val + 1e-10)
            return scores

        # Normalize each metric
        norm_recon = recon_errors  # Already in [0, 1]
        norm_perplexity = normalize_score(perplexities, clip_max=100.0)  # Clip extreme perplexity
        norm_attention = torch.clamp(attention_scores, 0, 1)  # Already bounded
        norm_embedding = normalize_score(embedding_distances, clip_max=10.0)  # Clip extreme distances

        # Build results
        results = []
        for i in range(batch_size):
            # Weighted combination
            overall = (
                weights['reconstruction'] * norm_recon[i].item() +
                weights['perplexity'] * norm_perplexity[i].item() +
                weights['attention'] * norm_attention[i].item() +
                weights['embedding'] * norm_embedding[i].item()
            )

            # Find anomalous tokens (top-k with highest error)
            if attention_mask is not None:
                valid_length = int(attention_mask[i].sum().item())
                sample_token_scores = token_scores[i, :valid_length]
            else:
                sample_token_scores = token_scores[i]

            # Get top-5 anomalous token indices
            k = min(5, len(sample_token_scores))
            top_k_indices = torch.topk(sample_token_scores, k).indices.tolist()

            # Compute confidence (inverse of score variance)
            score_std = torch.std(torch.tensor([
                norm_recon[i].item(),
                norm_perplexity[i].item(),
                norm_attention[i].item(),
                norm_embedding[i].item()
            ]))
            confidence = 1.0 / (1.0 + score_std.item())

            result = AnomalyScore(
                overall_score=overall,
                reconstruction_error=recon_errors[i].item(),
                perplexity=perplexities[i].item(),
                attention_score=attention_scores[i].item(),
                embedding_distance=embedding_distances[i].item(),
                confidence=confidence,
                anomaly_tokens=top_k_indices
            )
            results.append(result)

        return results

    def update_statistics(
        self,
        embeddings: torch.Tensor,
        momentum: float = 0.99
    ):
        """
        Update running statistics for calibration (call during training).

        Args:
            embeddings: Batch of embeddings [batch, hidden]
            momentum: EMA momentum for running stats
        """
        with torch.no_grad():
            batch_mean = embeddings.mean(dim=0)
            batch_var = embeddings.var(dim=0)

            # Update running mean and variance (EMA)
            if self.running_count == 0:
                self.embedding_mean = batch_mean
                # Initialize covariance as diagonal
                self.embedding_cov_inv = torch.diag(1.0 / (batch_var + 1e-6))
            else:
                self.embedding_mean = momentum * self.embedding_mean + (1 - momentum) * batch_mean

                # Update covariance (simplified diagonal approximation)
                current_var = momentum * self.embedding_cov_inv.diag() + (1 - momentum) * (1.0 / (batch_var + 1e-6))
                self.embedding_cov_inv = torch.diag(current_var)

            self.running_count += embeddings.size(0)
            self.calibration_enabled = True

    def save_pretrained(self, save_path: str):
        """
        Save model to disk.

        Args:
            save_path: Directory to save model
        """
        import os
        os.makedirs(save_path, exist_ok=True)

        # Save encoder
        self.encoder.save_pretrained(os.path.join(save_path, "encoder"))

        # Save full model state
        torch.save({
            "model_state_dict": self.state_dict(),
            "config": {
                "model_name": self.model_name,
                "vocab_size": self.vocab_size,
                "hidden_size": self.hidden_size,
            }
        }, os.path.join(save_path, "model.pt"))

    @classmethod
    def load_pretrained(cls, load_path: str) -> "TransformerAutoencoder":
        """
        Load model from disk.

        Args:
            load_path: Directory containing saved model

        Returns:
            Loaded model
        """
        import os

        # Load config
        checkpoint = torch.load(
            os.path.join(load_path, "model.pt"),
            map_location="cpu"
        )

        config = checkpoint["config"]

        # Create model
        model = cls(
            model_name=config["model_name"],
            vocab_size=config["vocab_size"],
            hidden_size=config["hidden_size"]
        )

        # Load state dict
        model.load_state_dict(checkpoint["model_state_dict"])

        return model


def create_model(
    model_name: str = "distilbert-base-uncased",
    vocab_size: int = 30522
) -> TransformerAutoencoder:
    """
    Convenience function to create a model.

    Args:
        model_name: HuggingFace model name
        vocab_size: Vocabulary size

    Returns:
        TransformerAutoencoder instance
    """
    return TransformerAutoencoder(
        model_name=model_name,
        vocab_size=vocab_size
    )


if __name__ == "__main__":
    # Demo usage
    print("Transformer Autoencoder Demo\n")
    print("=" * 80)

    # Create model
    model = create_model()

    print(f"Model: {model.model_name}")
    print(f"Hidden size: {model.hidden_size}")
    print(f"Vocab size: {model.vocab_size}")
    print(f"Parameters: {sum(p.numel() for p in model.parameters()):,}")
    print()

    # Sample input
    batch_size = 4
    seq_length = 32

    input_ids = torch.randint(0, model.vocab_size, (batch_size, seq_length))
    attention_mask = torch.ones_like(input_ids)

    # Forward pass
    output = model(input_ids, attention_mask)
    print(f"Logits shape: {output.logits.shape}")

    # Compute reconstruction error
    error = model.compute_reconstruction_error(input_ids, attention_mask)
    print(f"Reconstruction error shape: {error.shape}")
    print(f"Reconstruction error: {error.tolist()}")

    # Compute perplexity
    perplexity = model.compute_perplexity(input_ids, attention_mask)
    print(f"Perplexity shape: {perplexity.shape}")
    print(f"Perplexity: {perplexity.tolist()}")

    print("\n" + "=" * 80)
