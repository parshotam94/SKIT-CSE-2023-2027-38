"""
Batch Log Ingestion Module

Processes historical access logs for model training or offline analysis.
Supports parallel processing, output to multiple formats, and optional
WAF API scanning for anomaly detection.

Features:
- Multi-threaded log parsing for high throughput
- JSONL, CSV, and text output formats
- Optional real-time anomaly scanning via API
- Detailed statistics and progress tracking
- Error recovery and partial file processing

Author: ISRO Cybersecurity Division
"""

import sys
import asyncio
import argparse
import json
import csv
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
import time

from tqdm import tqdm
import aiohttp

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils import get_config, WAFLogger
from parsing import AccessLogParser, RequestNormalizer


@dataclass
class BatchStats:
    """Statistics for batch ingestion"""
    total_files: int = 0
    processed_files: int = 0
    failed_files: int = 0
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    anomalous_requests: int = 0
    start_time: Optional[float] = None
    end_time: Optional[float] = None

    def elapsed_time(self) -> float:
        """Get elapsed time in seconds"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

    def requests_per_second(self) -> float:
        """Calculate throughput"""
        elapsed = self.elapsed_time()
        if elapsed > 0:
            return self.successful_requests / elapsed
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            **asdict(self),
            "elapsed_time_seconds": self.elapsed_time(),
            "requests_per_second": self.requests_per_second(),
            "success_rate": self.successful_requests / max(self.total_requests, 1),
            "anomaly_rate": self.anomalous_requests / max(self.successful_requests, 1)
        }


class BatchIngester:
    """
    Batch ingestion engine for processing historical access logs.

    Supports multiple output formats and optional real-time anomaly detection
    by forwarding normalized requests to the WAF API.
    """

    def __init__(
        self,
        normalize: bool = True,
        scan_api: Optional[str] = None,
        max_workers: int = 4,
        batch_size: int = 100
    ):
        """
        Initialize batch ingester.

        Args:
            normalize: Apply normalization to requests
            scan_api: WAF API endpoint for real-time scanning (optional)
            max_workers: Number of parallel workers for file processing
            batch_size: Batch size for API scanning
        """
        self.config = get_config()
        self.logger = WAFLogger(__name__)
        self.normalize = normalize
        self.scan_api = scan_api
        self.max_workers = max_workers
        self.batch_size = batch_size

        # Initialize components
        self.parser = AccessLogParser()
        self.normalizer = RequestNormalizer() if normalize else None

        # Statistics
        self.stats = BatchStats()

        self.logger.info(
            "BatchIngester initialized",
            normalize=normalize,
            scan_api=scan_api,
            max_workers=max_workers,
            batch_size=batch_size
        )

    def process_file(self, log_file: Path) -> List[Dict[str, Any]]:
        """
        Process a single log file.

        Args:
            log_file: Path to log file

        Returns:
            List of processed request dictionaries
        """
        results = []

        try:
            # Parse log file
            parsed_requests = self.parser.parse_file(str(log_file))

            for req in parsed_requests:
                self.stats.total_requests += 1

                try:
                    # Normalize if requested
                    if self.normalizer:
                        norm = self.normalizer.normalize(
                            method=req.method,
                            path=req.path,
                            query_string=req.query_string,
                            headers=req.headers,
                            body=None
                        )
                        request_data = {
                            "normalized_text": norm.normalized_text,
                            "method": req.method,
                            "path": req.path,
                            "query_string": req.query_string,
                            "ip_address": req.ip_address,
                            "status_code": req.status_code,
                            "bytes_sent": req.bytes_sent,
                            "user_agent": req.user_agent,
                            "referer": req.referer,
                            "timestamp": req.timestamp.isoformat() if req.timestamp else None,
                            "normalized_tokens": norm.tokens,
                            "removed_patterns": norm.removed_patterns
                        }
                    else:
                        request_data = req.to_dict()

                    results.append(request_data)
                    self.stats.successful_requests += 1

                except Exception as e:
                    self.logger.error(
                        f"Failed to process request from {log_file}",
                        error=str(e),
                        method=req.method if hasattr(req, 'method') else None
                    )
                    self.stats.failed_requests += 1

            self.stats.processed_files += 1

        except Exception as e:
            self.logger.error(
                f"Failed to process file {log_file}",
                error=str(e)
            )
            self.stats.failed_files += 1

        return results

    async def scan_requests(
        self,
        requests: List[Dict[str, Any]],
        session: aiohttp.ClientSession
    ) -> List[Dict[str, Any]]:
        """
        Send requests to WAF API for anomaly detection.

        Args:
            requests: List of request dictionaries
            session: aiohttp session

        Returns:
            Requests with scan results
        """
        results = []
