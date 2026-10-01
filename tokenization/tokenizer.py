"""
Transformer-Compatible Tokenizer
Converts normalized HTTP requests into token sequences for model input
"""

import torch
from typing import List, Dict, Optional, Union
from transformers import AutoTokenizer, PreTrainedTokenizer
from dataclasses import dataclass


@dataclass
class TokenizedRequest:
    """
    Tokenized request ready for model input.
    """
    input_ids: torch.Tensor
    attention_mask: torch.Tensor
    original_text: str
    token_count: int

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "input_ids": self.input_ids.tolist(),
            "attention_mask": self.attention_mask.tolist(),
            "original_text": self.original_text,
            "token_count": self.token_count,
        }


class WAFTokenizer:
    """
    Tokenizer for HTTP requests using pretrained transformer tokenizers.

    Supports BERT-based models (BERT, DistilBERT, RoBERTa, etc.)
    """

    def __init__(
        self,
        model_name: str = "distilbert-base-uncased",
        max_length: int = 128,
        padding: Union[str, bool] = "max_length",
        truncation: bool = True,
        return_tensors: str = "pt",
        cache_dir: Optional[str] = None
    ):
        """
        Initialize the tokenizer.

        Args:
            model_name: HuggingFace model name or path
            max_length: Maximum sequence length
            padding: Padding strategy
            truncation: Enable truncation
            return_tensors: Return type ("pt" for PyTorch)
            cache_dir: Cache directory for tokenizer
        """
        self.model_name = model_name
        self.max_length = max_length
        self.padding = padding
        self.truncation = truncation
        self.return_tensors = return_tensors

        # Load pretrained tokenizer
        self.tokenizer: PreTrainedTokenizer = AutoTokenizer.from_pretrained(
            model_name,
            cache_dir=cache_dir
        )

        # Tokenizer metadata
        self.vocab_size = self.tokenizer.vocab_size
        self.pad_token_id = self.tokenizer.pad_token_id
        self.cls_token_id = self.tokenizer.cls_token_id
        self.sep_token_id = self.tokenizer.sep_token_id
        self.mask_token_id = self.tokenizer.mask_token_id

    def tokenize(
        self,
        text: Union[str, List[str]],
        return_original: bool = True
    ) -> Union[TokenizedRequest, List[TokenizedRequest]]:
        """
        Tokenize a single text or batch of texts.

        Args:
            text: Input text(s)
            return_original: Include original text in output

        Returns:
            TokenizedRequest or list of TokenizedRequest objects
        """
        is_batch = isinstance(text, list)
        texts = text if is_batch else [text]

        # Tokenize using HuggingFace tokenizer
        encoded = self.tokenizer(
            texts,
            max_length=self.max_length,
            padding=self.padding,
            truncation=self.truncation,
            return_tensors=self.return_tensors,
            return_attention_mask=True
        )

        # Build TokenizedRequest objects
        results = []
        for i, txt in enumerate(texts):
            token_count = encoded["attention_mask"][i].sum().item()

            tokenized = TokenizedRequest(
                input_ids=encoded["input_ids"][i],
                attention_mask=encoded["attention_mask"][i],
                original_text=txt if return_original else "",
                token_count=token_count
            )
            results.append(tokenized)

        return results if is_batch else results[0]

    def tokenize_batch(
        self,
        texts: List[str],
        batch_size: Optional[int] = None
    ) -> Dict[str, torch.Tensor]:
        """
        Tokenize a batch of texts efficiently.

        Args:
            texts: List of input texts
            batch_size: Optional batch size for chunking

        Returns:
            Dictionary with input_ids and attention_mask tensors
        """
        if batch_size and len(texts) > batch_size:
            # Process in chunks
            all_input_ids = []
            all_attention_masks = []

            for i in range(0, len(texts), batch_size):
                batch = texts[i:i + batch_size]
                encoded = self.tokenizer(
                    batch,
                    max_length=self.max_length,
                    padding=self.padding,
                    truncation=self.truncation,
                    return_tensors=self.return_tensors,
                    return_attention_mask=True
                )
                all_input_ids.append(encoded["input_ids"])
                all_attention_masks.append(encoded["attention_mask"])

            return {
                "input_ids": torch.cat(all_input_ids, dim=0),
                "attention_mask": torch.cat(all_attention_masks, dim=0)
            }
        else:
            # Process all at once
            encoded = self.tokenizer(
                texts,
                max_length=self.max_length,
                padding=self.padding,
                truncation=self.truncation,
                return_tensors=self.return_tensors,
                return_attention_mask=True
            )
            return {
                "input_ids": encoded["input_ids"],
                "attention_mask": encoded["attention_mask"]
            }

    def decode(
        self,
        token_ids: torch.Tensor,
        skip_special_tokens: bool = True
    ) -> Union[str, List[str]]:
        """
        Decode token IDs back to text.

        Args:
            token_ids: Token ID tensor
            skip_special_tokens: Skip special tokens in output

        Returns:
            Decoded text(s)
        """
        # Handle single sequence or batch
        if token_ids.dim() == 1:
            return self.tokenizer.decode(
                token_ids,
                skip_special_tokens=skip_special_tokens
            )
        else:
            return self.tokenizer.batch_decode(
                token_ids,
                skip_special_tokens=skip_special_tokens
            )

    def create_masked_input(
        self,
        input_ids: torch.Tensor,
        mask_prob: float = 0.15,
        random_prob: float = 0.1,
        keep_prob: float = 0.1
    ) -> Dict[str, torch.Tensor]:
        """
        Create masked input for training (Masked Language Modeling).

        Args:
            input_ids: Input token IDs
            mask_prob: Probability of masking a token
            random_prob: Probability of replacing with random token
            keep_prob: Probability of keeping original token

        Returns:
            Dictionary with masked_input_ids and labels
        """
        labels = input_ids.clone()

        # Create mask for tokens to mask (excluding special tokens)
        probability_matrix = torch.full(labels.shape, mask_prob)
        special_tokens_mask = torch.zeros_like(labels, dtype=torch.bool)

        # Don't mask special tokens
        for special_token_id in [
            self.pad_token_id,
            self.cls_token_id,
            self.sep_token_id
        ]:
            if special_token_id is not None:
                special_tokens_mask |= (labels == special_token_id)

        probability_matrix.masked_fill_(special_tokens_mask, value=0.0)
        masked_indices = torch.bernoulli(probability_matrix).bool()

        # Only compute loss on masked tokens
        labels[~masked_indices] = -100

        # 80% of the time: replace with [MASK] token
        indices_replaced = (
            torch.bernoulli(torch.full(labels.shape, 1.0 - random_prob - keep_prob)).bool()
            & masked_indices
        )
        input_ids[indices_replaced] = self.mask_token_id

        # 10% of the time: replace with random token
        indices_random = (
            torch.bernoulli(torch.full(labels.shape, 0.5)).bool()
            & masked_indices
            & ~indices_replaced
        )
        random_words = torch.randint(
            len(self.tokenizer),
            labels.shape,
            dtype=torch.long
        )
        input_ids[indices_random] = random_words[indices_random]

        # 10% of the time: keep original token

        return {
            "masked_input_ids": input_ids,
            "labels": labels,
            "masked_indices": masked_indices
        }

    def get_vocab_size(self) -> int:
        """Get vocabulary size"""
        return self.vocab_size

    def get_special_tokens(self) -> Dict[str, int]:
        """Get special token IDs"""
        return {
            "pad_token_id": self.pad_token_id,
            "cls_token_id": self.cls_token_id,
            "sep_token_id": self.sep_token_id,
            "mask_token_id": self.mask_token_id,
        }

    def save(self, save_path: str):
        """
        Save tokenizer to disk.

        Args:
            save_path: Directory to save tokenizer
        """
        self.tokenizer.save_pretrained(save_path)

    @classmethod
    def load(cls, load_path: str, **kwargs) -> "WAFTokenizer":
        """
        Load tokenizer from disk.

        Args:
            load_path: Directory containing saved tokenizer
            **kwargs: Additional arguments for WAFTokenizer

        Returns:
            Loaded WAFTokenizer instance
        """
        return cls(model_name=load_path, **kwargs)


def create_tokenizer(
    model_name: str = "distilbert-base-uncased",
    max_length: int = 128
) -> WAFTokenizer:
    """
    Convenience function to create a tokenizer.

    Args:
        model_name: HuggingFace model name
        max_length: Maximum sequence length

    Returns:
        WAFTokenizer instance
    """
    return WAFTokenizer(model_name=model_name, max_length=max_length)


if __name__ == "__main__":
    # Demo usage
    print("WAF Tokenizer Demo\n")
    print("=" * 80)

    # Initialize tokenizer
    tokenizer = WAFTokenizer(
        model_name="distilbert-base-uncased",
        max_length=64
    )

    print(f"Model: {tokenizer.model_name}")
    print(f"Vocab size: {tokenizer.vocab_size}")
    print(f"Max length: {tokenizer.max_length}")
    print(f"Special tokens: {tokenizer.get_special_tokens()}")
    print()

    # Sample normalized requests
    sample_requests = [
        "GET /api/users/[ID] ?user_id=[ID]",
        "POST /api/login ?redirect_url=[IP]/dashboard",
        "DELETE /api/items/[ID] ?user_id=[ID]&token=[JWT]",
        "GET /files/document-[UUID].pdf",
    ]

    print("Tokenizing sample requests:\n")
    for i, request in enumerate(sample_requests, 1):
        tokenized = tokenizer.tokenize(request)

        print(f"Request {i}: {request}")
        print(f"  Token count: {tokenized.token_count}")
        print(f"  Input IDs shape: {tokenized.input_ids.shape}")
        print(f"  Input IDs (first 10): {tokenized.input_ids[:10].tolist()}")

        # Decode back
        decoded = tokenizer.decode(tokenized.input_ids)
        print(f"  Decoded: {decoded}")
        print()

    # Batch tokenization
    print("Batch tokenization:")
    batch_encoded = tokenizer.tokenize_batch(sample_requests)
    print(f"  Batch input_ids shape: {batch_encoded['input_ids'].shape}")
    print(f"  Batch attention_mask shape: {batch_encoded['attention_mask'].shape}")
    print()

    # Masked language modeling
    print("Creating masked input (for training):")
    masked_data = tokenizer.create_masked_input(
        batch_encoded["input_ids"][0].unsqueeze(0),
        mask_prob=0.15
    )
    print(f"  Original: {tokenizer.decode(batch_encoded['input_ids'][0])}")
    print(f"  Masked: {tokenizer.decode(masked_data['masked_input_ids'][0])}")
    print(f"  Masked positions: {masked_data['masked_indices'][0].sum().item()}")

    print("\n" + "=" * 80)
