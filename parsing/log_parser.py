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

