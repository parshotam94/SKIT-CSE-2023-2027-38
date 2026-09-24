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

        # Process in batches
        for i in range(0, len(requests), self.batch_size):
            batch = requests[i:i + self.batch_size]

            try:
                # Prepare batch scan request
                scan_batch = []
                for req in batch:
                    scan_batch.append({
                        "method": req.get("method", "GET"),
                        "path": req.get("path", "/"),
                        "query_string": req.get("query_string", ""),
                        "headers": {},
                        "body": ""
                    })

                # Send batch scan request
                async with session.post(
                    f"{self.scan_api}/batch-scan",
                    json={"requests": scan_batch},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        scan_results = await response.json()

                        # Merge scan results with original requests
                        for req, scan_result in zip(batch, scan_results.get("results", [])):
                            req["anomaly_score"] = scan_result.get("anomaly_score", 0.0)
                            req["is_anomalous"] = scan_result.get("is_anomalous", False)
                            req["reconstruction_error"] = scan_result.get("reconstruction_error", 0.0)
                            req["perplexity"] = scan_result.get("perplexity", 0.0)

                            if req["is_anomalous"]:
                                self.stats.anomalous_requests += 1

                            results.append(req)
                    else:
                        self.logger.error(
                            f"API scan failed with status {response.status}",
                            batch_size=len(batch)
                        )
                        results.extend(batch)

            except asyncio.TimeoutError:
                self.logger.error("API scan timeout", batch_size=len(batch))
                results.extend(batch)
            except Exception as e:
                self.logger.error(f"API scan error: {e}", batch_size=len(batch))
                results.extend(batch)

        return results

    async def process_and_scan(
        self,
        log_files: List[Path],
        output_file: Optional[str] = None,
        output_format: str = "jsonl"
    ):
        """
        Process log files and optionally scan via API.

        Args:
            log_files: List of log files to process
            output_file: Output file path
            output_format: Output format (jsonl, csv, txt)
        """
        self.logger.info(
            f"Starting batch processing",
            num_files=len(log_files),
            output_format=output_format
        )

        all_results = []

        # Process files in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.process_file, log_file): log_file
                for log_file in log_files
            }

            for future in tqdm(
                as_completed(futures),
                total=len(futures),
                desc="Processing files"
            ):
                try:
                    results = future.result()
                    all_results.extend(results)
                except Exception as e:
                    log_file = futures[future]
                    self.logger.error(f"Worker failed for {log_file}: {e}")

        # Scan via API if configured
        if self.scan_api and all_results:
            self.logger.info(
                f"Scanning {len(all_results)} requests via API",
                api_endpoint=self.scan_api
            )

            async with aiohttp.ClientSession() as session:
                all_results = await self.scan_requests(all_results, session)

        # Write output
        if output_file:
            self._write_output(all_results, output_file, output_format)

        return all_results

    def _write_output(
        self,
        results: List[Dict[str, Any]],
        output_file: str,
        output_format: str
    ):
        """
        Write results to output file.

        Args:
            results: Processed requests
            output_file: Output file path
            output_format: Output format
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if output_format == "jsonl":
            with open(output_file, 'w', encoding='utf-8') as f:
                for result in results:
                    f.write(json.dumps(result) + "\n")

        elif output_format == "csv":
            if not results:
                return

            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                # Get all unique keys
                fieldnames = set()
                for result in results:
                    fieldnames.update(result.keys())
                fieldnames = sorted(list(fieldnames))

                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)

        elif output_format == "txt":
            with open(output_file, 'w', encoding='utf-8') as f:
                for result in results:
                    f.write(result.get("normalized_text", str(result)) + "\n")

        else:
            raise ValueError(f"Unsupported output format: {output_format}")

        self.logger.info(
            f"Wrote {len(results)} requests to {output_file}",
            format=output_format
        )

    def print_summary(self):
        """Print processing summary"""
        print("\n" + "=" * 70)
        print("BATCH INGESTION SUMMARY")
        print("=" * 70)
        print(f"Files Processed:       {self.stats.processed_files}/{self.stats.total_files}")
        print(f"Failed Files:          {self.stats.failed_files}")
        print(f"Total Requests:        {self.stats.total_requests}")
        print(f"Successful Requests:   {self.stats.successful_requests}")
        print(f"Failed Requests:       {self.stats.failed_requests}")

        if self.scan_api:
            print(f"Anomalous Requests:    {self.stats.anomalous_requests}")
            print(f"Anomaly Rate:          {self.stats.anomalous_requests / max(self.stats.successful_requests, 1) * 100:.2f}%")

        print(f"Elapsed Time:          {self.stats.elapsed_time():.2f}s")
        print(f"Throughput:            {self.stats.requests_per_second():.2f} req/s")
        print(f"Success Rate:          {self.stats.successful_requests / max(self.stats.total_requests, 1) * 100:.2f}%")
        print("=" * 70)


async def async_main(
    log_dir: str,
    output_file: Optional[str] = None,
    normalize: bool = True,
    scan_api: Optional[str] = None,
    max_files: Optional[int] = None,
    max_workers: int = 4,
    batch_size: int = 100,
    output_format: str = "jsonl"
):
    """
    Main async function for batch ingestion.

    Args:
        log_dir: Directory containing log files
        output_file: Output file path
        normalize: Apply normalization
        scan_api: WAF API endpoint for scanning
        max_files: Maximum number of files to process
        max_workers: Number of parallel workers
        batch_size: Batch size for API scanning
        output_format: Output format (jsonl, csv, txt)
    """
    # Find log files
    log_path = Path(log_dir)
    if not log_path.exists():
        raise ValueError(f"Log directory does not exist: {log_dir}")

    log_files = sorted(log_path.rglob("*.log"))

    if not log_files:
        print(f"No log files found in {log_dir}")
        return

    if max_files:
        log_files = log_files[:max_files]

    # Initialize ingester
    ingester = BatchIngester(
        normalize=normalize,
        scan_api=scan_api,
        max_workers=max_workers,
        batch_size=batch_size
    )

    ingester.stats.total_files = len(log_files)
    ingester.stats.start_time = time.time()

    # Process files
    await ingester.process_and_scan(
        log_files=log_files,
        output_file=output_file,
        output_format=output_format
    )

    ingester.stats.end_time = time.time()

    # Print summary
    ingester.print_summary()

    # Log metrics
    ingester.logger.log_metric(
        "batch_ingestion_complete",
        ingester.stats.successful_requests,
        tags={
            "log_dir": log_dir,
            "output_format": output_format,
            "scan_enabled": scan_api is not None
        }
    )


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Batch ingest access logs for training or analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process logs and save as JSONL
  python batch_ingest.py --log-dir /var/log/nginx --output benign_requests.jsonl

  # Process with API scanning
  python batch_ingest.py --log-dir /var/log/apache2 --scan-api http://localhost:8000 --output results.jsonl

  # Process to CSV format
  python batch_ingest.py --log-dir ./logs --output data.csv --format csv

  # Process without normalization
  python batch_ingest.py --log-dir ./logs --no-normalize --output raw_requests.jsonl
        """
    )

    parser.add_argument(
        "--log-dir",
        type=str,
        required=True,
        help="Directory containing access logs"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path"
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["jsonl", "csv", "txt"],
        default="jsonl",
        help="Output format (default: jsonl)"
    )
    parser.add_argument(
        "--no-normalize",
        action="store_true",
        help="Skip normalization"
    )
    parser.add_argument(
        "--scan-api",
        type=str,
        default=None,
        help="WAF API endpoint for real-time scanning (e.g., http://localhost:8000)"
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Maximum number of files to process"
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=4,
        help="Number of parallel workers (default: 4)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Batch size for API scanning (default: 100)"
    )

    args = parser.parse_args()

    # Run async ingestion
    asyncio.run(
        async_main(
            log_dir=args.log_dir,
            output_file=args.output,
            normalize=not args.no_normalize,
            scan_api=args.scan_api,
            max_files=args.max_files,
            max_workers=args.max_workers,
            batch_size=args.batch_size,
            output_format=args.format
        )
    )


if __name__ == "__main__":
    main()
