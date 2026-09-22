"""
Stream Log Ingestion
Tails live access logs and sends to WAF API for real-time scanning
"""

import sys
import argparse
import asyncio
import time
import aiohttp
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import setup_logger
from parsing import AccessLogParser


class LogTailer:
    """
    Tails a log file and streams new lines.
    """

    def __init__(self, log_file: str, poll_interval: float = 0.5):
        """
        Initialize log tailer.

        Args:
            log_file: Path to log file
            poll_interval: Polling interval in seconds
        """
        self.log_file = Path(log_file)
        self.poll_interval = poll_interval
        self.file_handle = None
        self.logger = setup_logger()

    async def tail(self):
        """
        Tail the log file and yield new lines.

        Yields:
            New log lines
        """
        # Open file
        self.file_handle = open(self.log_file, 'r', encoding='utf-8', errors='ignore')

        # Seek to end
        self.file_handle.seek(0, 2)  # SEEK_END

        self.logger.info(f"Started tailing: {self.log_file}")

        try:
            while True:
                # Read new lines
                line = self.file_handle.readline()

                if line:
                    yield line
                else:
                    # No new data, wait and check again
                    await asyncio.sleep(self.poll_interval)

        except asyncio.CancelledError:
            self.logger.info("Log tailer stopped")
        finally:
            if self.file_handle:
                self.file_handle.close()


