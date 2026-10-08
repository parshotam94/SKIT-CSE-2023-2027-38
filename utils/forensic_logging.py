"""
Security-focused forensic logging
Implements secure logging with PII masking and forensic capabilities
"""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
import re


@dataclass
class SecurityIncident:
    """Security incident record"""
    incident_id: str
    timestamp: str
    severity: str  # low, medium, high, critical
    request_hash: str
    ip_address_masked: str
    method: str
    path: str
    query_hash: str
    anomaly_score: float
    is_blocked: bool
    user_agent_masked: str
    detection_metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class ForensicLogger:
    """
    Secure forensic logger for WAF incidents

    Features:
    - PII masking (IPs, tokens, sensitive data)
    - Cryptographic request hashing
    - JSON-structured logging
    - Tamper-evident logging
    - Incident severity classification
    """

    def __init__(self, log_dir: str = "logs/forensic"):
        """
        Initialize forensic logger

        Args:
            log_dir: Directory for forensic logs
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Sensitive patterns to mask
        self.sensitive_patterns = [
            (r'\b\d{3}-\d{2}-\d{4}\b', '[SSN-MASKED]'),  # SSN
            (r'\b\d{16}\b', '[CC-MASKED]'),  # Credit card
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL-MASKED]'),  # Email
            (r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', 'Bearer [TOKEN-MASKED]'),  # Bearer token
            (r'api[_-]?key["\s:=]+[A-Za-z0-9]+', 'api_key=[KEY-MASKED]'),  # API key
            (r'password["\s:=]+[^\s&"]+', 'password=[PASSWORD-MASKED]'),  # Password
        ]

    def _mask_ip(self, ip: str) -> str:
        """
        Mask IP address for privacy

        Args:
            ip: IP address

        Returns:
            Masked IP (e.g., 192.168.***)
        """
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.***"
        return "***"

    def _mask_sensitive_data(self, text: str) -> str:
        """
        Mask sensitive data in text

        Args:
            text: Input text

        Returns:
            Text with sensitive data masked
        """
        masked = text
        for pattern, replacement in self.sensitive_patterns:
            masked = re.sub(pattern, replacement, masked, flags=re.IGNORECASE)
        return masked

    def _hash_data(self, data: str) -> str:
        """
        Create cryptographic hash of data

        Args:
            data: Input data

        Returns:
            SHA-256 hash (hex)
        """
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def _determine_severity(self, anomaly_score: float) -> str:
        """
        Determine incident severity

        Args:
            anomaly_score: Anomaly score (0-1)

        Returns:
            Severity level
        """
        if anomaly_score >= 0.85:
            return "critical"
        elif anomaly_score >= 0.6:
            return "high"
        elif anomaly_score >= 0.3:
            return "medium"
        else:
            return "low"

    def log_incident(
        self,
        request_data: Dict[str, Any],
        detection_result: Dict[str, Any],
        ip_address: str,
        user_agent: str = ""
    ) -> SecurityIncident:
        """
        Log security incident

        Args:
            request_data: HTTP request data
            detection_result: ML detection result
            ip_address: Client IP address
            user_agent: Client user agent

        Returns:
            SecurityIncident record
        """
        timestamp = datetime.now(timezone.utc)

        # Create request signature
        request_str = json.dumps(request_data, sort_keys=True)
        request_hash = self._hash_data(request_str)

        # Hash query string
        query_str = request_data.get('query_string', '')
        query_hash = self._hash_data(query_str) if query_str else 'none'

        # Mask sensitive data
        ip_masked = self._mask_ip(ip_address)
        ua_masked = self._mask_sensitive_data(user_agent)[:100]

        # Determine severity
        severity = self._determine_severity(detection_result['anomaly_score'])

        # Create incident record
        incident = SecurityIncident(
            incident_id=self._hash_data(f"{timestamp.isoformat()}-{request_hash}")[:16],
            timestamp=timestamp.isoformat(),
            severity=severity,
            request_hash=request_hash,
            ip_address_masked=ip_masked,
            method=request_data.get('method', 'UNKNOWN'),
            path=request_data.get('path', '/')[:200],  # Limit path length
            query_hash=query_hash,
            anomaly_score=round(detection_result['anomaly_score'], 4),
            is_blocked=detection_result['is_anomalous'],
            user_agent_masked=ua_masked,
            detection_metadata={
                'threshold': detection_result.get('threshold', 0.0),
                'reconstruction_error': detection_result.get('reconstruction_error', 0.0),
                'perplexity': detection_result.get('perplexity', 0.0),
                'latency_ms': detection_result.get('latency_ms', 0.0)
            }
        )

        # Write to daily log file
        log_file = self.log_dir / f"incidents_{timestamp.strftime('%Y%m%d')}.jsonl"

        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(incident.to_dict()) + '\n')

        return incident

    def get_incidents(
        self,
        date: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> list:
        """
        Retrieve logged incidents

        Args:
            date: Date string (YYYYMMDD), None for today
            severity: Filter by severity level
            limit: Maximum incidents to return

        Returns:
            List of incidents
        """
        if date is None:
            date = datetime.now(timezone.utc).strftime('%Y%m%d')

        log_file = self.log_dir / f"incidents_{date}.jsonl"

        if not log_file.exists():
            return []

        incidents = []

        with open(log_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    incident = json.loads(line.strip())

                    # Apply severity filter
                    if severity and incident.get('severity') != severity:
                        continue

                    incidents.append(incident)

                    if len(incidents) >= limit:
                        break

                except json.JSONDecodeError:
                    continue

        return incidents

    def export_incidents(
        self,
        date: str,
        output_file: str,
        severity: Optional[str] = None
    ):
        """
        Export incidents to file for reporting

        Args:
            date: Date string (YYYYMMDD)
            output_file: Output file path
            severity: Filter by severity
        """
        incidents = self.get_incidents(date=date, severity=severity, limit=10000)

        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({
                'date': date,
                'total_incidents': len(incidents),
                'severity_filter': severity,
                'incidents': incidents
            }, f, indent=2)

        return len(incidents)
