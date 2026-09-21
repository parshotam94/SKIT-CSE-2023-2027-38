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

    