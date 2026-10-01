"""
HTTP Request Normalizer
Removes dynamic tokens and standardizes requests for ML training
"""

import re
from typing import Dict, Optional
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode


@dataclass
class NormalizedRequest:
    """
    Normalized HTTP request ready for tokenization.
    """
    normalized_text: str
    original_method: str
    original_path: str
    original_query: str

    def __str__(self) -> str:
        return self.normalized_text


class RequestNormalizer:
    """
    Normalizes HTTP requests by removing dynamic tokens that would
    prevent the model from learning structural patterns.

    Removes:
    - IP addresses
    - Timestamps
    - Session IDs
    - UUIDs
    - Hashes (MD5, SHA)
    - Numeric IDs
    - Email addresses
    - File extensions (optional)
    """

    # Regex patterns for normalization
    PATTERNS = {
        # IPv4 addresses
        "ipv4": (
            re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
            "[IP]"
        ),

        # IPv6 addresses
        "ipv6": (
            re.compile(r'\b([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b'),
            "[IP]"
        ),

        # UUIDs (8-4-4-4-12 format)
        "uuid": (
            re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'),
            "[UUID]"
        ),

        # MD5 hashes (32 hex chars)
        "md5": (
            re.compile(r'\b[0-9a-fA-F]{32}\b'),
            "[HASH]"
        ),

        # SHA-1 hashes (40 hex chars)
        "sha1": (
            re.compile(r'\b[0-9a-fA-F]{40}\b'),
            "[HASH]"
        ),

        # SHA-256 hashes (64 hex chars)
        "sha256": (
            re.compile(r'\b[0-9a-fA-F]{64}\b'),
            "[HASH]"
        ),

        # Session IDs (common patterns)
        "session_id": (
            re.compile(r'\b(session|sess|token|sid)=[\w\-]+', re.IGNORECASE),
            "session=[SESSIONID]"
        ),

        # JWT tokens
        "jwt": (
            re.compile(r'\b[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b'),
            "[JWT]"
        ),

        # Email addresses
        "email": (
            re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "[EMAIL]"
        ),

        # Timestamps (various formats)
        "timestamp_iso": (
            re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b'),
            "[TIMESTAMP]"
        ),

        "timestamp_unix": (
            re.compile(r'\b\d{10,13}\b'),  # Unix timestamp (seconds or milliseconds)
            "[TIMESTAMP]"
        ),

        # Numeric IDs (path segments or query params)
        "numeric_id_path": (
            re.compile(r'/\d+(?=/|$|\?)'),
            "/[ID]"
        ),

        "numeric_id_query": (
            re.compile(r'(id|user_id|item_id|post_id|account_id)=\d+', re.IGNORECASE),
            r'\1=[ID]'
        ),

        # Generic long numbers (6+ digits)
        "long_number": (
            re.compile(r'\b\d{6,}\b'),
            "[NUM]"
        ),

        # Base64-encoded strings (long alphanumeric sequences)
        "base64": (
            re.compile(r'\b[A-Za-z0-9+/]{20,}={0,2}\b'),
            "[BASE64]"
        ),

        # Credit card numbers (for privacy)
        "credit_card": (
            re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
            "[CARD]"
        ),

        # Phone numbers
        "phone": (
            re.compile(r'\b(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
            "[PHONE]"
        ),
    }
