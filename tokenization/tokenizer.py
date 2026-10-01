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
