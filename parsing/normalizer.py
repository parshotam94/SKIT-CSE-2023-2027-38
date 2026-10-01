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

    def __init__(
        self,
        normalize_ip: bool = True,
        normalize_timestamp: bool = True,
        normalize_session_ids: bool = True,
        normalize_uuids: bool = True,
        normalize_hashes: bool = True,
        normalize_numbers: bool = True,
        normalize_emails: bool = True,
        lowercase: bool = True,
        collapse_whitespace: bool = True
    ):
        """
        Initialize normalizer with configuration.

        Args:
            normalize_ip: Replace IP addresses
            normalize_timestamp: Replace timestamps
            normalize_session_ids: Replace session IDs
            normalize_uuids: Replace UUIDs
            normalize_hashes: Replace hashes
            normalize_numbers: Replace numeric IDs
            normalize_emails: Replace email addresses
            lowercase: Convert to lowercase
            collapse_whitespace: Collapse multiple spaces
        """
        self.normalize_ip = normalize_ip
        self.normalize_timestamp = normalize_timestamp
        self.normalize_session_ids = normalize_session_ids
        self.normalize_uuids = normalize_uuids
        self.normalize_hashes = normalize_hashes
        self.normalize_numbers = normalize_numbers
        self.normalize_emails = normalize_emails
        self.lowercase = lowercase
        self.collapse_whitespace = collapse_whitespace

    def normalize(
        self,
        method: str,
        path: str,
        query_string: str = "",
        headers: Optional[Dict[str, str]] = None
    ) -> NormalizedRequest:
        """
        Normalize an HTTP request.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: URL path
            query_string: Query string
            headers: HTTP headers (optional)

        Returns:
            NormalizedRequest object
        """
        # Start with method and path
        normalized_parts = [method.upper()]

        # Normalize path
        normalized_path = self._normalize_text(path)
        normalized_parts.append(normalized_path)

        # Normalize query string
        if query_string:
            normalized_query = self._normalize_query_string(query_string)
            if normalized_query:
                normalized_parts.append(f"?{normalized_query}")

        # Optionally include user-agent (common signal)
        if headers and "User-Agent" in headers:
            user_agent = headers["User-Agent"]
            normalized_ua = self._normalize_text(user_agent)
            normalized_parts.append(f"UA:{normalized_ua}")

        # Combine into single normalized text
        normalized_text = " ".join(normalized_parts)

        # Final cleanup
        if self.lowercase:
            normalized_text = normalized_text.lower()

        if self.collapse_whitespace:
            normalized_text = re.sub(r'\s+', ' ', normalized_text).strip()

        return NormalizedRequest(
            normalized_text=normalized_text,
            original_method=method,
            original_path=path,
            original_query=query_string
        )

    def _normalize_text(self, text: str) -> str:
        """
        Apply normalization patterns to text.

        Args:
            text: Input text

        Returns:
            Normalized text
        """
        # Apply patterns in specific order (more specific first)
        if self.normalize_uuids:
            text = self.PATTERNS["uuid"][0].sub(self.PATTERNS["uuid"][1], text)

        if self.normalize_hashes:
            text = self.PATTERNS["sha256"][0].sub(self.PATTERNS["sha256"][1], text)
            text = self.PATTERNS["sha1"][0].sub(self.PATTERNS["sha1"][1], text)
            text = self.PATTERNS["md5"][0].sub(self.PATTERNS["md5"][1], text)

        if self.normalize_session_ids:
            text = self.PATTERNS["session_id"][0].sub(self.PATTERNS["session_id"][1], text)
            text = self.PATTERNS["jwt"][0].sub(self.PATTERNS["jwt"][1], text)
            text = self.PATTERNS["base64"][0].sub(self.PATTERNS["base64"][1], text)

        if self.normalize_emails:
            text = self.PATTERNS["email"][0].sub(self.PATTERNS["email"][1], text)

        if self.normalize_timestamp:
            text = self.PATTERNS["timestamp_iso"][0].sub(self.PATTERNS["timestamp_iso"][1], text)
            text = self.PATTERNS["timestamp_unix"][0].sub(self.PATTERNS["timestamp_unix"][1], text)

        if self.normalize_ip:
            text = self.PATTERNS["ipv4"][0].sub(self.PATTERNS["ipv4"][1], text)
            text = self.PATTERNS["ipv6"][0].sub(self.PATTERNS["ipv6"][1], text)

        if self.normalize_numbers:
            # Privacy-sensitive patterns
            text = self.PATTERNS["credit_card"][0].sub(self.PATTERNS["credit_card"][1], text)
            text = self.PATTERNS["phone"][0].sub(self.PATTERNS["phone"][1], text)

            # Numeric IDs
            text = self.PATTERNS["numeric_id_path"][0].sub(self.PATTERNS["numeric_id_path"][1], text)
            text = self.PATTERNS["numeric_id_query"][0].sub(self.PATTERNS["numeric_id_query"][1], text)
            text = self.PATTERNS["long_number"][0].sub(self.PATTERNS["long_number"][1], text)

        return text

    def _normalize_query_string(self, query_string: str) -> str:
        """
        Normalize query string parameters.

        Args:
            query_string: Raw query string

        Returns:
            Normalized query string
        """
        if not query_string:
            return ""

        try:
            # Parse query parameters
            params = parse_qs(query_string, keep_blank_values=True)

            # Normalize each parameter value
            normalized_params = {}
            for key, values in params.items():
                normalized_key = self._normalize_text(key)
                normalized_values = [self._normalize_text(v) for v in values]
                normalized_params[normalized_key] = normalized_values

            # Reconstruct query string (sorted for consistency)
            sorted_items = sorted(normalized_params.items())
            return "&".join(f"{k}={v[0]}" for k, v in sorted_items)

        except Exception:
            # Fallback: normalize as plain text
            return self._normalize_text(query_string)

    def normalize_batch(
        self,
        requests: list
    ) -> list:
        """
        Normalize a batch of requests.

        Args:
            requests: List of request dictionaries or ParsedRequest objects

        Returns:
            List of NormalizedRequest objects
        """
        normalized = []
        for req in requests:
            if hasattr(req, 'method'):  # ParsedRequest object
                norm = self.normalize(
                    method=req.method,
                    path=req.path,
                    query_string=req.query_string,
                    headers=req.headers
                )
            else:  # Dictionary
                norm = self.normalize(
                    method=req.get('method', ''),
                    path=req.get('path', ''),
                    query_string=req.get('query_string', ''),
                    headers=req.get('headers', {})
                )
            normalized.append(norm)
        return normalized


if __name__ == "__main__":
    # Demo usage
    normalizer = RequestNormalizer()

    # Test requests
    test_requests = [
        {
            "method": "GET",
            "path": "/api/users/12345",
            "query_string": "session=abc123def456&timestamp=1674123456",
        },
        {
            "method": "POST",
            "path": "/api/auth/login",
            "query_string": "redirect_url=http://192.168.1.100/dashboard",
        },
        {
            "method": "GET",
            "path": "/files/document-a1b2c3d4-e5f6-7890-abcd-ef1234567890.pdf",
            "query_string": "",
        },
        {
            "method": "DELETE",
            "path": "/api/items/98765",
            "query_string": "user_id=54321&token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
        },
    ]

    print("Request Normalization Demo\n")
    print("=" * 80)

    for i, req in enumerate(test_requests, 1):
        normalized = normalizer.normalize(
            req["method"],
            req["path"],
            req["query_string"]
        )

        print(f"\nRequest {i}:")
        print(f"  Original: {req['method']} {req['path']}?{req['query_string']}")
        print(f"  Normalized: {normalized.normalized_text}")

    print("\n" + "=" * 80)
