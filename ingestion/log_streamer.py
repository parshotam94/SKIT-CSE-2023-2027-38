"""
Real-time log streaming and ingestion
Asynchronously tails Apache/Nginx access logs and streams to detection pipeline
"""

import asyncio
import re
from pathlib import Path
from typing import AsyncGenerator, Optional, Dict, Any
from datetime import datetime
import aiofiles
from dataclasses import dataclass

from utils import WAFLogger


@dataclass
class HTTPRequest:
    """Parsed HTTP request from logs"""
    timestamp: str
    ip_address: str
    method: str
    path: str
    query_string: str
    http_version: str
    status_code: int
    response_size: int
    user_agent: str
    referer: str
    raw_line: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "timestamp": self.timestamp,
            "ip_address": self.ip_address,
            "method": self.method,
            "path": self.path,
            "query_string": self.query_string,
            "http_version": self.http_version,
            "status_code": self.status_code,
            "response_size": self.response_size,
            "user_agent": self.user_agent,
            "referer": self.referer
        }


class LogStreamer:
    """
    Asynchronous log file streamer
    Tails access logs and parses HTTP requests in real-time
    """

    # Apache/Nginx combined log format regex
    LOG_PATTERN = re.compile(
        r'(?P<ip>[\d.]+) - - \[(?P<timestamp>[^\]]+)\] '
        r'"(?P<method>\w+) (?P<path>[^\s?]+)(?P<query>\S*)? (?P<version>HTTP/[\d.]+)" '
        r'(?P<status>\d+) (?P<size>\d+|-) '
        r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )

    def __init__(self, log_file: str, follow: bool = True):
        """
        Initialize log streamer

        Args:
            log_file: Path to access log file
            follow: If True, continuously tail the file
        """
        self.log_file = Path(log_file)
        self.follow = follow
        self.logger = WAFLogger(__name__)
        self._running = False

    async def tail_file(self) -> AsyncGenerator[str, None]:
        """
        Asynchronously tail log file

        Yields:
            New log lines as they appear
        """
        try:
            async with aiofiles.open(self.log_file, mode='r') as f:
                # Seek to end if following
                if self.follow:
                    await f.seek(0, 2)  # Seek to EOF

                while self._running or not self.follow:
                    line = await f.readline()

                    if line:
                        yield line.strip()
                    else:
                        if not self.follow:
                            break
                        # Wait before checking for new lines
                        await asyncio.sleep(0.1)

        except FileNotFoundError:
            self.logger.error(f"Log file not found: {self.log_file}")
            raise
        except Exception as e:
            self.logger.error(f"Error tailing log file: {e}")
            raise

    def parse_log_line(self, line: str) -> Optional[HTTPRequest]:
        """
        Parse Apache/Nginx log line

        Args:
            line: Raw log line

        Returns:
            Parsed HTTPRequest or None if parsing fails
        """
        match = self.LOG_PATTERN.match(line)

        if not match:
            self.logger.warning(f"Failed to parse log line: {line[:100]}")
            return None

        data = match.groupdict()

        try:
            return HTTPRequest(
                timestamp=data['timestamp'],
                ip_address=data['ip'],
                method=data['method'],
                path=data['path'],
                query_string=data['query'] or '',
                http_version=data['version'],
                status_code=int(data['status']),
                response_size=int(data['size']) if data['size'] != '-' else 0,
                user_agent=data['user_agent'],
                referer=data['referer'],
                raw_line=line
            )
        except Exception as e:
            self.logger.error(f"Error parsing log data: {e}")
            return None

    async def stream_requests(self) -> AsyncGenerator[HTTPRequest, None]:
        """
        Stream parsed HTTP requests

        Yields:
            Parsed HTTPRequest objects
        """
        self._running = True
        self.logger.info(f"Starting log stream from {self.log_file}")

        try:
            async for line in self.tail_file():
                request = self.parse_log_line(line)
                if request:
                    yield request
        finally:
            self._running = False
            self.logger.info("Log stream stopped")

    def stop(self):
        """Stop streaming"""
        self._running = False


class SimulatedLogStreamer(LogStreamer):
    """
    Simulated log streamer for testing and demo
    Generates synthetic HTTP requests
    """

    BENIGN_PATTERNS = [
        ("GET", "/api/users", "", "Mozilla/5.0"),
        ("GET", "/api/products", "?category=electronics", "Chrome/120.0"),
        ("POST", "/api/login", "", "Mozilla/5.0"),
        ("GET", "/", "", "Safari/17.0"),
        ("GET", "/static/css/main.css", "", "Chrome/120.0"),
        ("GET", "/api/health", "", "curl/7.88.1"),
    ]

    ATTACK_PATTERNS = [
        ("GET", "/api/users", "?id=1' OR '1'='1", "sqlmap/1.7"),  # SQL injection
        ("GET", "/api/search", "?q=<script>alert(1)</script>", "Mozilla/5.0"),  # XSS
        ("GET", "/../../../etc/passwd", "", "Nikto/2.5.0"),  # Path traversal
        ("POST", "/api/admin", "", "python-requests/2.31.0"),  # Suspicious UA
        ("GET", "/api/users", "?id=1 UNION SELECT * FROM passwords", "Mozilla/5.0"),
    ]

    def __init__(self, attack_rate: float = 0.1):
        """
        Initialize simulated streamer

        Args:
            attack_rate: Probability of generating attack (0.0-1.0)
        """
        self.attack_rate = attack_rate
        self.logger = WAFLogger(__name__)
        self._running = False
        self.request_count = 0

    async def stream_requests(self) -> AsyncGenerator[HTTPRequest, None]:
        """
        Generate simulated HTTP requests

        Yields:
            Simulated HTTPRequest objects
        """
        self._running = True
        self.logger.info("Starting simulated log stream")

        import random

        try:
            while self._running:
                # Decide if attack or benign
                is_attack = random.random() < self.attack_rate

                if is_attack:
                    method, path, query, ua = random.choice(self.ATTACK_PATTERNS)
                else:
                    method, path, query, ua = random.choice(self.BENIGN_PATTERNS)

                # Generate request
                request = HTTPRequest(
                    timestamp=datetime.now().strftime("%d/%b/%Y:%H:%M:%S %z"),
                    ip_address=f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                    method=method,
                    path=path,
                    query_string=query,
                    http_version="HTTP/1.1",
                    status_code=200 if not is_attack else random.choice([200, 403, 404]),
                    response_size=random.randint(100, 5000),
                    user_agent=ua,
                    referer="-",
                    raw_line=f"[SIMULATED] {method} {path}{query}"
                )

                self.request_count += 1
                yield request

                # Random delay between requests (0.5-2 seconds)
                await asyncio.sleep(random.uniform(0.5, 2.0))

        finally:
            self._running = False
            self.logger.info(f"Simulated stream stopped. Total requests: {self.request_count}")
