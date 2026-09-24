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


class StreamIngester:
    """
    Streams access logs to WAF API for real-time scanning.
    """

    def __init__(
        self,
        log_file: str,
        api_url: str,
        batch_size: int = 10,
        max_retries: int = 3,
        timeout: float = 5.0
    ):
        """
        Initialize stream ingester.

        Args:
            log_file: Path to access log file
            api_url: WAF API URL
            batch_size: Batch size for API calls
            max_retries: Maximum retries for failed requests
            timeout: Request timeout
        """
        self.log_file = log_file
        self.api_url = api_url
        self.batch_size = batch_size
        self.max_retries = max_retries
        self.timeout = aiohttp.ClientTimeout(total=timeout)

        # Parser
        self.parser = AccessLogParser()

        # Logger
        self.logger = setup_logger()

        # Statistics
        self.stats = {
            "lines_processed": 0,
            "requests_scanned": 0,
            "anomalies_detected": 0,
            "api_errors": 0,
            "parse_errors": 0,
        }

    async def send_to_api(
        self,
        session: aiohttp.ClientSession,
        request_data: dict
    ) -> Optional[dict]:
        """
        Send request to WAF API.

        Args:
            session: aiohttp session
            request_data: Request data

        Returns:
            API response or None
        """
        for attempt in range(self.max_retries):
            try:
                async with session.post(
                    self.api_url,
                    json=request_data,
                    timeout=self.timeout
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result
                    else:
                        self.logger.warning(
                            f"API returned status {response.status}"
                        )

            except asyncio.TimeoutError:
                self.logger.warning(f"API timeout (attempt {attempt + 1})")

            except Exception as e:
                self.logger.error(f"API error: {e}")

            # Wait before retry
            if attempt < self.max_retries - 1:
                await asyncio.sleep(1.0 * (attempt + 1))

        self.stats["api_errors"] += 1
        return None

    async def process_batch(
        self,
        session: aiohttp.ClientSession,
        batch: list
    ):
        """
        Process a batch of requests.

        Args:
            session: aiohttp session
            batch: Batch of parsed requests
        """
        # Send all requests concurrently
        tasks = []
        for req in batch:
            request_data = {
                "method": req.method,
                "path": req.path,
                "query_string": req.query_string,
                "headers": req.headers,
                "body": ""
            }
            tasks.append(self.send_to_api(session, request_data))

        # Wait for all responses
        results = await asyncio.gather(*tasks)

        # Process results
        for result in results:
            if result:
                self.stats["requests_scanned"] += 1

                if result.get("is_anomalous", False):
                    self.stats["anomalies_detected"] += 1

                    # Log anomaly
                    self.logger.warning(
                        "Anomaly detected in stream",
                        anomaly_score=result.get("anomaly_score"),
                        threshold=result.get("threshold")
                    )

    async def run(self):
        """
        Run the stream ingester.
        """
        self.logger.info(
            "Starting stream ingestion",
            log_file=self.log_file,
            api_url=self.api_url
        )

        # Create tailer
        tailer = LogTailer(self.log_file)

        # Create HTTP session
        async with aiohttp.ClientSession() as session:
            batch = []

            # Start tailing
            async for line in tailer.tail():
                self.stats["lines_processed"] += 1

                # Parse line
                parsed = self.parser.parse_line(line)

                if parsed:
                    batch.append(parsed)

                    # Process batch when full
                    if len(batch) >= self.batch_size:
                        await self.process_batch(session, batch)
                        batch = []

                        # Log stats periodically
                        if self.stats["requests_scanned"] % 100 == 0:
                            self.log_stats()
                else:
                    self.stats["parse_errors"] += 1

            # Process remaining batch
            if batch:
                await self.process_batch(session, batch)

    def log_stats(self):
        """Log current statistics"""
        self.logger.info(
            "Stream ingestion statistics",
            **self.stats
        )

        if self.stats["requests_scanned"] > 0:
            anomaly_rate = (
                self.stats["anomalies_detected"] / 
                self.stats["requests_scanned"]
            )
            self.logger.log_metric(
                "stream_anomaly_rate",
                anomaly_rate,
                tags={"log_file": str(self.log_file)}
            )


async def stream_ingest(
    log_file: str,
    api_url: str,
    batch_size: int = 10
):
    """
    Stream ingest access logs to WAF API.

    Args:
        log_file: Path to access log file
        api_url: WAF API URL
        batch_size: Batch size
    """
    ingester = StreamIngester(
        log_file=log_file,
        api_url=api_url,
        batch_size=batch_size
    )

    try:
        await ingester.run()
    except KeyboardInterrupt:
        ingester.logger.info("Stream ingestion stopped by user")
        ingester.log_stats()


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Stream ingest access logs")
    parser.add_argument(
        "--log-file",
        type=str,
        required=True,
        help="Access log file to tail"
    )
    parser.add_argument(
        "--api-url",
        type=str,
        default="http://localhost:8000/scan",
        help="WAF API URL"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10,
        help="Batch size for API calls"
    )
    args = parser.parse_args()

    # Run ingestion
    asyncio.run(stream_ingest(
        log_file=args.log_file,
        api_url=args.api_url,
        batch_size=args.batch_size
    ))


if __name__ == "__main__":
    main()
