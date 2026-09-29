"""
Apache/Nginx Access Log Parser
Extracts HTTP request components from standard access log formats
"""

import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse, unquote


@dataclass
class ParsedRequest:
    """
    Structured representation of an HTTP request parsed from access logs.
    """
    method: str
    path: str
    query_string: str
    protocol: str
    status_code: int
    response_size: int
    ip_address: str
    timestamp: datetime
    user_agent: str
    referer: str
    headers: Dict[str, str]
    raw_log_line: str

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "method": self.method,
            "path": self.path,
            "query_string": self.query_string,
            "protocol": self.protocol,
            "status_code": self.status_code,
            "response_size": self.response_size,
            "ip_address": self.ip_address,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "user_agent": self.user_agent,
            "referer": self.referer,
            "headers": self.headers,
        }

class AccessLogParser:
    """
    Parser for Apache/Nginx access logs.
    Supports multiple log formats including Combined, Common, and custom formats.
    """

    # Apache/Nginx Combined Log Format
    # Example: 192.168.1.1 - - [01/Jan/2026:10:30:45 +0000] "GET /api/users?id=123 HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0"
    COMBINED_LOG_PATTERN = re.compile(
        r'^(?P<ip>[\d\.]+|[0-9a-fA-F:]+)\s+'  # IP address (IPv4 or IPv6)
        r'(?P<remote_log_name>\S+)\s+'  # Remote log name
        r'(?P<user>\S+)\s+'  # User
        r'\[(?P<timestamp>[^\]]+)\]\s+'  # Timestamp
        r'"(?P<request>[^"]*)"\s+'  # Request line
        r'(?P<status>\d{3})\s+'  # Status code
        r'(?P<size>\d+|-)\s*'  # Response size
        r'(?:"(?P<referer>[^"]*)")?\s*'  # Referer (optional)
        r'(?:"(?P<user_agent>[^"]*)")?'  # User agent (optional)
    )

    # Request line pattern (method, path, protocol)
    REQUEST_LINE_PATTERN = re.compile(
        r'^(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+(?P<protocol>HTTP/[\d\.]+)$'
    )

    # Timestamp formats
    TIMESTAMP_FORMATS = [
        "%d/%b/%Y:%H:%M:%S %z",  # Apache/Nginx default
        "%Y-%m-%d %H:%M:%S",      # Alternative format
        "%Y-%m-%dT%H:%M:%S%z",    # ISO format
    ]

    def __init__(self):
        """Initialize the parser"""
        self.parsed_count = 0
        self.error_count = 0

    def parse_line(self, line: str) -> Optional[ParsedRequest]:
        """
        Parse a single access log line.

        Args:
            line: Raw log line

        Returns:
            ParsedRequest object or None if parsing fails
        """
        line = line.strip()
        if not line:
            return None

        # Try combined log format
        match = self.COMBINED_LOG_PATTERN.match(line)
        if not match:
            self.error_count += 1
            return None

        groups = match.groupdict()

        # Parse request line (method, URI, protocol)
        request_line = groups.get("request", "")
        method, uri, protocol = self._parse_request_line(request_line)

        if not method or not uri:
            self.error_count += 1
            return None

        # Parse URI into path and query string
        path, query_string = self._parse_uri(uri)

        # Parse timestamp
        timestamp_str = groups.get("timestamp", "")
        timestamp = self._parse_timestamp(timestamp_str)

        # Parse status code and size
        try:
            status_code = int(groups.get("status", "0"))
        except ValueError:
            status_code = 0

        try:
            size_str = groups.get("size", "0")
            response_size = 0 if size_str == "-" else int(size_str)
        except ValueError:
            response_size = 0

        # Extract other fields
        ip_address = groups.get("ip", "")
        user_agent = groups.get("user_agent", "")
        referer = groups.get("referer", "")

        # Build headers dictionary
        headers = {}
        if user_agent:
            headers["User-Agent"] = user_agent
        if referer and referer != "-":
            headers["Referer"] = referer

        self.parsed_count += 1

        return ParsedRequest(
            method=method,
            path=path,
            query_string=query_string,
            protocol=protocol,
            status_code=status_code,
            response_size=response_size,
            ip_address=ip_address,
            timestamp=timestamp,
            user_agent=user_agent,
            referer=referer,
            headers=headers,
            raw_log_line=line
        )

    def _parse_request_line(self, request_line: str) -> Tuple[str, str, str]:
        """
        Parse HTTP request line.

        Args:
            request_line: Raw request line (e.g., "GET /api/users HTTP/1.1")

        Returns:
            Tuple of (method, uri, protocol)
        """
        if not request_line:
            return "", "", ""

        match = self.REQUEST_LINE_PATTERN.match(request_line)
        if match:
            return (
                match.group("method"),
                match.group("uri"),
                match.group("protocol")
            )

        # Fallback: split by spaces
        parts = request_line.split()
        if len(parts) >= 3:
            return parts[0], parts[1], parts[2]
        elif len(parts) == 2:
            return parts[0], parts[1], "HTTP/1.1"

        return "", "", ""

    def _parse_uri(self, uri: str) -> Tuple[str, str]:
        """
        Parse URI into path and query string.

        Args:
            uri: Full URI (e.g., "/api/users?id=123")

        Returns:
            Tuple of (path, query_string)
        """
        try:
            # URL decode
            uri = unquote(uri)

            # Split path and query
            if "?" in uri:
                path, query_string = uri.split("?", 1)
            else:
                path = uri
                query_string = ""

            return path, query_string
        except Exception:
            return uri, ""
