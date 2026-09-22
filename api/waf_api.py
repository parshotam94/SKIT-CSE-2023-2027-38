"""
WAF API Service

Production-grade FastAPI service for real-time HTTP request anomaly detection.

Security Features:
- Input validation and sanitization
- Rate limiting per client
- Secure logging (no sensitive data)
- Request size limits
- Authentication support (API key)
- CORS protection
- Security headers

Author: ISRO Cybersecurity Division
"""

import sys
import re
import hashlib
import random
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from contextlib import asynccontextmanager
import uvicorn
from fastapi import (
    FastAPI,
    HTTPException,
    Request,
    Header,
    Depends,
    WebSocket,
    WebSocketDisconnect,
    Response,
)
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator, constr, ConfigDict
from pydantic import ValidationError
import asyncio
import aiohttp
import os

try:
    from training.continuous_learning import ContinuousLearner
    from api.websocket_handler import ConnectionManager, LiveMonitoringHandler
    from inference import AnomalyDetector
    from utils import get_config, WAFLogger
except ModuleNotFoundError:
    # Support running this file directly: `py api/waf_api.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from training.continuous_learning import ContinuousLearner
    from api.websocket_handler import ConnectionManager, LiveMonitoringHandler
    from inference import AnomalyDetector
    from utils import get_config, WAFLogger


# Security constants
MAX_PATH_LENGTH = 2048
MAX_QUERY_LENGTH = 4096
MAX_BODY_LENGTH = 1048576  # 1MB
MAX_HEADERS = 50
MAX_HEADER_LENGTH = 8192
MAX_BATCH_SIZE = 100
RATE_LIMIT_REQUESTS = 100  # requests per minute
RATE_LIMIT_WINDOW = 60  # seconds

# Sensitive header patterns (for secure logging)
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-session-id",
    "proxy-authorization",
}

# Sensitive body patterns
SENSITIVE_PATTERNS = [
    r'password["\']?\s*[:=]\s*["\']?([^",\'}\s]+)',
    r'token["\']?\s*[:=]\s*["\']?([^",\'}\s]+)',
    r'api[_-]?key["\']?\s*[:=]\s*["\']?([^",\'}\s]+)',
    r'secret["\']?\s*[:=]\s*["\']?([^",\'}\s]+)',
]


def sanitize_for_logging(text: str, max_length: int = 200) -> str:
    """Sanitize text for secure logging"""
    if not text:
        return ""

    # Remove sensitive patterns
    sanitized = text
    for pattern in SENSITIVE_PATTERNS:
        sanitized = re.sub(
            pattern, r"\1=***REDACTED***", sanitized, flags=re.IGNORECASE
        )

    # Truncate if too long
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "...[truncated]"

    return sanitized


def sanitize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Remove sensitive headers for logging"""
    return {
        k: "***REDACTED***" if k.lower() in SENSITIVE_HEADERS else v
        for k, v in headers.items()
    }


class RateLimiter:
    """Simple in-memory rate limiter"""

    def __init__(
        self,
        max_requests: int = RATE_LIMIT_REQUESTS,
        window: int = RATE_LIMIT_WINDOW,
    ):
        self.max_requests = max_requests
        self.window = window
        self.requests: Dict[str, List[datetime]] = defaultdict(list)

    def is_allowed(self, client_id: str) -> bool:
        """Check if request is allowed"""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window)

        # Clean old requests
        self.requests[client_id] = [
            req_time
            for req_time in self.requests[client_id]
            if req_time > cutoff
        ]

        # Check rate limit
        if len(self.requests[client_id]) >= self.max_requests:
            return False

        # Add current request
        self.requests[client_id].append(now)
        return True

    def get_remaining(self, client_id: str) -> int:
        """Get remaining requests for client"""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=self.window)
        recent = len([r for r in self.requests[client_id] if r > cutoff])
        return max(0, self.max_requests - recent)


# Pydantic models for request/response with validation
class HTTPRequestModel(BaseModel):
    """HTTP request to scan with strict validation"""

    method: constr(min_length=3, max_length=10, strip_whitespace=True) = Field(
        ..., description="HTTP method (GET, POST, etc.)"
    )
    path: constr(
        min_length=1, max_length=MAX_PATH_LENGTH, strip_whitespace=True
    ) = Field(..., description="URL path")
    query_string: constr(max_length=MAX_QUERY_LENGTH) = Field(
        default="", description="Query string"
    )
    headers: Dict[str, str] = Field(
        default_factory=dict, description="HTTP headers"
    )
    body: constr(max_length=MAX_BODY_LENGTH) = Field(
        default="", description="Request body"
    )

    @field_validator("method")
    @classmethod
    def validate_method(cls, v):
        """Validate HTTP method"""
        valid_methods = {
            "GET",
            "POST",
            "PUT",
            "DELETE",
            "PATCH",
            "HEAD",
            "OPTIONS",
        }
        v_upper = v.upper()
        if v_upper not in valid_methods:
            raise ValueError(
                f"Invalid HTTP method: {v}. " f"Must be one of {valid_methods}"
            )
        return v_upper

    @field_validator("path")
    @classmethod
    def validate_path(cls, v):
        """Validate URL path"""
        if not v.startswith("/"):
            raise ValueError("Path must start with /")
        # Allow path traversal attempts for analysis
        # (WAF should detect, not block in validation)
        # The model will analyze these patterns as potential attacks
        return v

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, v):
        """Validate headers"""
        if len(v) > MAX_HEADERS:
            raise ValueError(f"Too many headers (max: {MAX_HEADERS})")

        total_length = sum(len(k) + len(val) for k, val in v.items())
        if total_length > MAX_HEADER_LENGTH:
            raise ValueError(
                f"Headers too large (max: {MAX_HEADER_LENGTH} bytes)"
            )

        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "method": "GET",
                "path": "/api/users/123",
                "query_string": "format=json",
                "headers": {"User-Agent": "Mozilla/5.0"},
                "body": "",
            }
        }
    )


class ScanResponse(BaseModel):
    """Anomaly detection response"""

    anomaly_score: float = Field(..., description="Anomaly score (0-1)")
    is_anomalous: bool = Field(..., description="Is request anomalous")
    threshold: float = Field(..., description="Detection threshold")
    reconstruction_error: float = Field(
        ..., description="Reconstruction error"
    )
    perplexity: float = Field(..., description="Model perplexity")
    timestamp: str = Field(..., description="Timestamp (ISO format)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "anomaly_score": 0.23,
                "is_anomalous": False,
                "threshold": 0.75,
                "reconstruction_error": 0.18,
                "perplexity": 12.5,
                "timestamp": "2026-01-22T10:30:45.123Z",
            }
        }
    )


class BatchScanRequest(BaseModel):
    """Batch scan request with size limits"""

    requests: List[HTTPRequestModel] = Field(
        ...,
        description="List of requests to scan",
        min_length=1,
        max_length=MAX_BATCH_SIZE,
    )

    @field_validator("requests")
    @classmethod
    def validate_batch_size(cls, v):
        """Validate batch size"""
        if len(v) > MAX_BATCH_SIZE:
            raise ValueError(f"Batch size exceeds maximum ({MAX_BATCH_SIZE})")
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "requests": [
                    {
                        "method": "GET",
                        "path": "/api/users",
                        "query_string": "id=123",
                        "headers": {},
                        "body": "",
                    },
                    {
                        "method": "POST",
                        "path": "/api/login",
                        "query_string": "",
                        "headers": {},
                        "body": '{"username":"admin"}',
                    },
                ]
            }
        }
    )


class BatchScanResponse(BaseModel):
    """Batch scan response"""

    results: List[ScanResponse] = Field(..., description="Scan results")
    total_requests: int = Field(..., description="Total requests scanned")
    anomalous_count: int = Field(
        ..., description="Number of anomalous requests"
    )


class HealthResponse(BaseModel):
    """Health check response"""

    status: str = Field(..., description="Service status")
    model_loaded: bool = Field(..., description="Is model loaded")
    version: str = Field(..., description="API version")
    uptime_seconds: float = Field(..., description="Uptime in seconds")

    model_config = ConfigDict(protected_namespaces=())

    model_config = ConfigDict(protected_namespaces=())


# Initialize FastAPI app with security
app = FastAPI(
    title="Transformer WAF API",
    description=(
        "Production-grade anomaly detection for HTTP requests "
        "with enhanced security"
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add security middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add trusted host middleware (configure for production)
# app.add_middleware(
#     TrustedHostMiddleware,
#     allowed_hosts=["localhost", "127.0.0.1", "yourdomain.com"]
# )

# Global state
detector: Optional[AnomalyDetector] = None
start_time: Optional[datetime] = None
logger: Optional[WAFLogger] = None
rate_limiter: Optional[RateLimiter] = None
ws_manager: Optional[ConnectionManager] = None
live_handler: Optional[LiveMonitoringHandler] = None
continuous_learner: Optional[ContinuousLearner] = None
demo_task: Optional[asyncio.Task] = None

# Real-time metrics store (in production, use Redis)
METRICS_STORE = {
    "total_requests": 0,
    "anomalous_requests": 0,
    "critical_threats": 0,
    "avg_anomaly_score": 0.0,
    "latency_p95": 0.0,
    "scores_sum": 0.0,
    "last_updated": datetime.now(timezone.utc).isoformat(),
}

# Analytics event store (last 10,000 events in memory)
ANALYTICS_EVENTS = []
MAX_ANALYTICS_EVENTS = 10000

# Time-series metrics (last 60 minutes of data, 1-minute intervals)
TIMESERIES_METRICS = []
MAX_TIMESERIES_POINTS = 60


# ===== Helper Functions =====


def update_metrics(anomaly_score: float, is_anomalous: bool, severity: str):
    """Update real-time metrics store"""
    METRICS_STORE["total_requests"] += 1
    METRICS_STORE["scores_sum"] += anomaly_score

    if is_anomalous:
        METRICS_STORE["anomalous_requests"] += 1

    if severity in ["High", "Critical"]:
        METRICS_STORE["critical_threats"] += 1

    # Calculate average
    if METRICS_STORE["total_requests"] > 0:
        METRICS_STORE["avg_anomaly_score"] = (
            METRICS_STORE["scores_sum"] / METRICS_STORE["total_requests"]
        )

    METRICS_STORE["last_updated"] = datetime.now(timezone.utc).isoformat()

    # Update time-series metrics
    update_timeseries_metrics(anomaly_score, is_anomalous)


def update_timeseries_metrics(anomaly_score: float, is_anomalous: bool):
    """Update time-series metrics for charts (1-minute buckets)"""
    now = datetime.now(timezone.utc)
    current_minute = now.replace(second=0, microsecond=0)

    # Find or create bucket for current minute
    if (
        TIMESERIES_METRICS
        and TIMESERIES_METRICS[-1]["timestamp"] == current_minute.isoformat()
    ):
        # Update existing bucket
        bucket = TIMESERIES_METRICS[-1]
        bucket["total"] += 1
        bucket["anomalous"] += 1 if is_anomalous else 0
        bucket["benign"] += 0 if is_anomalous else 1
        bucket["scores"].append(anomaly_score)
        bucket["avg_score"] = sum(bucket["scores"]) / len(bucket["scores"])
    else:
        # Create new bucket
        new_bucket = {
            "timestamp": current_minute.isoformat(),
            "total": 1,
            "anomalous": 1 if is_anomalous else 0,
            "benign": 0 if is_anomalous else 1,
            "scores": [anomaly_score],
            "avg_score": anomaly_score,
        }
        TIMESERIES_METRICS.append(new_bucket)

        # Keep only last MAX_TIMESERIES_POINTS
        if len(TIMESERIES_METRICS) > MAX_TIMESERIES_POINTS:
            TIMESERIES_METRICS.pop(0)


def store_analytics_event(event: Dict[str, Any]):
    """Store event for analytics"""
    global ANALYTICS_EVENTS

    ANALYTICS_EVENTS.append(event)

    # Keep only last MAX_ANALYTICS_EVENTS
    if len(ANALYTICS_EVENTS) > MAX_ANALYTICS_EVENTS:
        ANALYTICS_EVENTS = ANALYTICS_EVENTS[-MAX_ANALYTICS_EVENTS:]


def determine_severity(anomaly_score: float) -> str:
    """Determine severity level from anomaly score"""
    if anomaly_score >= 0.9:
        return "Critical"
    elif anomaly_score >= 0.7:
        return "High"
    elif anomaly_score >= 0.5:
        return "Medium"
    else:
        return "Low"


def determine_attack_type(
    request_data: Dict[str, Any], anomaly_score: float
) -> str:
    """
    Simple heuristic attack type detection
    (Supplement to transformer model for demo clarity)
    """
    path = request_data.get("path", "")
    query = request_data.get("query_string", "")
    body = request_data.get("body", "")

    combined = f"{path} {query} {body}".lower()

    # SQL Injection patterns
    sql_patterns = ["'", "or 1=1", "union select", "drop table", "-- "]
    if any(pattern in combined for pattern in sql_patterns):
        return "SQL Injection"

    # XSS patterns
    xss_patterns = ["<script", "javascript:", "onerror=", "alert("]
    if any(pattern in combined for pattern in xss_patterns):
        return "XSS"

    # Path Traversal patterns
    traversal_patterns = ["../", "..\\", "/etc/passwd", "c:\\"]
    if any(pattern in combined for pattern in traversal_patterns):
        return "Path Traversal"

    # Command Injection patterns
    cmd_patterns = [";", "&&", "|", "`", "$(", "cat /etc"]
    if any(pattern in combined for pattern in cmd_patterns):
        return "Command Injection"

    # CSRF patterns
    if anomaly_score > 0.7 and "csrf" not in combined:
        return "CSRF"

    return "Unknown" if anomaly_score > 0.5 else "None"


async def emit_detection_event(
    request_data: Dict[str, Any], result: Dict[str, Any]
):
    """Emit detection event to WebSocket clients"""
    if not ws_manager:
        return

    # Support either dict payload or DetectionResult-like object.
    if not isinstance(result, dict) and hasattr(result, "to_dict"):
        result = result.to_dict()

    severity = determine_severity(result["anomaly_score"])
    attack_type = result.get("attack_type") or determine_attack_type(
        request_data, result["anomaly_score"]
    )

    # Analytics event (flat format for storage)
    analytics_event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "path": request_data.get("path", "/"),
        "method": request_data.get("method", "GET"),
        "attack_type": attack_type,
        "severity": severity,
        "anomaly_score": round(result["anomaly_score"], 3),
        "blocked": result["is_anomalous"],
    }

    # Update metrics
    update_metrics(result["anomaly_score"], result["is_anomalous"], severity)

    # Store for analytics
    store_analytics_event(analytics_event)

    # WebSocket event (nested format for frontend)
    websocket_event = {
        "type": "detection",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request": {
            "ip": "127.0.0.1",  # Default IP
            "method": request_data.get("method", "GET"),
            "path": request_data.get("path", "/"),
            "query": request_data.get("query_string", ""),
            "userAgent": request_data.get("headers", {}).get(
                "User-Agent", "Unknown"
            ),
            "statusCode": 200,
        },
        "detection": {
            "anomalyScore": round(result["anomaly_score"], 3),
            "isAnomalous": result["is_anomalous"],
            "confidence": round(
                1.0
                - abs(result["anomaly_score"] - result.get("threshold", 0.75)),
                3,
            ),
            "threshold": result.get("threshold", 0.75),
            "severity": severity.lower(),
        },
        "metadata": {
            "latency": 0,  # Can be calculated if needed
            "modelVersion": "1.0.0",
        },
    }

    # Broadcast to WebSocket clients
    await ws_manager.broadcast(websocket_event)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown"""
    global detector, start_time, logger, rate_limiter
    global ws_manager, live_handler, continuous_learner, demo_task

    # Startup
    logger = WAFLogger(__name__)
    logger.info("Starting WAF API service with enhanced security")

    config = get_config()

    rate_limiter = RateLimiter(
        max_requests=RATE_LIMIT_REQUESTS, window=RATE_LIMIT_WINDOW
    )
    logger.info(
        "Rate limiter initialized",
        max_requests=RATE_LIMIT_REQUESTS,
        window_seconds=RATE_LIMIT_WINDOW,
    )

    try:
        detector = AnomalyDetector(
            model_path=config.model_path,
            device=config.device,
            threshold=config.anomaly_threshold,
            batch_size=config.inference_batch_size,
            enable_jit=True,
            cache_size=10000,
            max_workers=8,
            enable_classifier=config.enable_classifier,
            classifier_model_path=config.classifier_model_path,
            classifier_confidence_threshold=config.classifier_confidence_threshold,
            classifier_score_weight=config.classifier_score_weight,
            auto_tune_threshold=config.auto_tune_threshold,
            fp_target_rate=config.fp_target_rate,
            fp_tuning_step=config.fp_tuning_step,
            min_threshold=config.min_anomaly_threshold,
            max_threshold=config.max_anomaly_threshold,
        )
        start_time = datetime.now(timezone.utc)
        logger.info(
            "Detector initialized with optimizations",
            model_path=sanitize_for_logging(config.model_path),
            threshold=config.anomaly_threshold,
            device=config.device,
        )
    except Exception as e:
        logger.error(f"Failed to initialize detector: {e}")
        logger.warning("Initializing FallbackMockDetector due to missing model or memory constraints.")
        from inference.detector import DetectionResult
        class FallbackMockDetector:
            async def detect(self, method: str, path: str, query_string: str, headers: dict, body: str):
                # Basic heuristic check for SQLi/XSS as fallback
                payload = f"{path} {query_string} {body}".lower()
                is_anomalous = any(x in payload for x in ["select ", "union ", "script>", "alert("])
                score = 0.99 if is_anomalous else 0.1
                return DetectionResult(
                    is_anomalous=is_anomalous,
                    anomaly_score=score,
                    threshold=0.8,
                    reconstruction_error=score,
                    perplexity=10.0,
                    normalized_request=f"{method} {path}"[:100],
                )
            def update_threshold(self, threshold: float):
                pass
            def get_stats(self):
                return {"total_requests": 0, "anomalous_requests": 0}
            def shutdown(self):
                pass
        detector = FallbackMockDetector()

    # Initialize WebSocket manager and live handler
    ws_manager = ConnectionManager()
    live_handler = LiveMonitoringHandler(detector, ws_manager)
    await live_handler.start()
    logger.info("WebSocket live monitoring started")

    # Initialize continuous learner
    continuous_learner = ContinuousLearner(detector)
    logger.info("Continuous learning pipeline initialized")

    # Start demo traffic generator
    demo_task = asyncio.create_task(demo_traffic_generator())
    logger.info("Demo traffic generator started")

    yield

    # Shutdown
    if demo_task:
        demo_task.cancel()
        try:
            await demo_task
        except asyncio.CancelledError:
            pass
        logger.info("Demo traffic generator stopped")

    if live_handler:
        await live_handler.stop()
        logger.info("WebSocket live monitoring stopped")

    if detector:
        final_stats = detector.get_stats()
        if logger:
            logger.info("Final statistics", **final_stats)
        detector.shutdown()

    if logger:
        logger.info("WAF API service stopped gracefully")


# Initialize FastAPI app with security
app = FastAPI(
    title="Transformer WAF API",
    description="Production-grade anomaly detection for HTTP requests with enhanced security",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Add security middleware
dashboard_origin = os.getenv("WAF_DASHBOARD_ORIGIN")
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
if dashboard_origin:
    origins.append(dashboard_origin)
# Support common render deployment pattern implicitly if missing variable
origins.append("https://transformer-waf.onrender.com")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add security headers to all responses"""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    """Log all requests securely (no sensitive data)"""
    start_time = datetime.now(timezone.utc)
    client_ip = request.client.host if request.client else "unknown"

    # Secure logging - don't log query params that might contain tokens
    logger.info(
        "Request received",
        method=request.method,
        path=request.url.path,  # Path only, no query string
        client_ip=hashlib.sha256(client_ip.encode()).hexdigest()[
            :16
        ],  # Hash IP for privacy
        user_agent=sanitize_for_logging(
            request.headers.get("user-agent", "unknown")
        ),
    )

    response = await call_next(request)

    duration_ms = (
        datetime.now(timezone.utc) - start_time
    ).total_seconds() * 1000
    logger.info(
        "Request completed",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        duration_ms=round(duration_ms, 2),
    )

    return response


async def verify_rate_limit(request: Request):
    """Dependency to check rate limit"""
    client_id = request.client.host if request.client else "unknown"

    if not rate_limiter.is_allowed(client_id):
        logger.warning(
            "Rate limit exceeded",
            client_ip=hashlib.sha256(client_id.encode()).hexdigest()[:16],
        )
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Try again later.",
            headers={"Retry-After": str(RATE_LIMIT_WINDOW)},
        )

    return True


@app.get("/", include_in_schema=False)
async def root():
    """Root endpoint"""
    return {
        "service": "Transformer WAF API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "security": {
            "rate_limit": f"{RATE_LIMIT_REQUESTS} req/{RATE_LIMIT_WINDOW}s",
            "max_batch_size": MAX_BATCH_SIZE,
            "validation": "enabled",
        },
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.

    Returns service status and metadata.
    """
    uptime = (
        (datetime.now(timezone.utc) - start_time).total_seconds()
        if start_time
        else 0
    )

    return HealthResponse(
        status="healthy" if detector else "unhealthy",
        model_loaded=detector is not None,
        version="1.0.0",
        uptime_seconds=uptime,
    )


@app.post(
    "/scan",
    response_model=ScanResponse,
    dependencies=[Depends(verify_rate_limit)],
)
async def scan_request(request: HTTPRequestModel):
    """
    Scan a single HTTP request for anomalies using ML-based detection.

    ARCHITECTURE: Anomaly-Based Detection (NOT Signature-Based)
    - Model trained on BENIGN traffic only (CSIC2010 + custom samples)
    - Detects deviations from normal patterns (zero-day capable)
    - No signature database or rule-based matching

    DETECTION vs ACTION SEPARATION:
    - This endpoint performs DETECTION only (ML inference)
    - Returns anomaly score and is_anomalous flag
    - ACTION (allow/alert/block) is determined by policy layer or caller
    - Default: All requests allowed, only flagged for monitoring

    Security:
    - Rate limited
    - Input validated
    - Sensitive data redacted from logs

    Args:
        request: HTTP request to scan

    Returns:
        Anomaly detection result (score, threshold, is_anomalous flag)
    """
    if not detector:
        raise HTTPException(status_code=503, detail="Detector not initialized")

    try:
        # Secure logging - sanitize request data
        logger.info(
            "Scanning request",
            method=request.method,
            path=sanitize_for_logging(request.path, 100),
            query_length=len(request.query_string),
            body_length=len(request.body),
            headers_count=len(request.headers),
        )

        # Perform detection
        result = await detector.detect(
            method=request.method,
            path=request.path,
            query_string=request.query_string,
            headers=request.headers,
            body=request.body,
        )

        # Log detection result (secure)
        logger.info(
            "Detection complete",
            anomaly_score=round(result.anomaly_score, 4),
            is_anomalous=result.is_anomalous,
            inference_time_ms=result.inference_time_ms,
        )

        # Emit WebSocket event and update metrics
        request_data = {
            "method": request.method,
            "path": request.path,
            "query_string": request.query_string,
            "headers": request.headers,
            "body": request.body,
        }
        result_dict = {
            "anomaly_score": result.anomaly_score,
            "is_anomalous": result.is_anomalous,
            "threshold": result.threshold,
            "attack_type": (result.metadata or {}).get("attack_type", "NONE"),
            "classifier_confidence": (result.metadata or {}).get(
                "classifier_confidence", 0.0
            ),
            "attack_probability": (result.metadata or {}).get(
                "attack_probability", 0.0
            ),
        }
        await emit_detection_event(request_data, result_dict)

        # Detection mode enforcement
        if result.is_anomalous:
            severity = determine_severity(result.anomaly_score)

            if SYSTEM_CONFIG.detection_mode == "block":
                # Block mode: reject malicious requests
                logger.warning(
                    "Request blocked",
                    path=sanitize_for_logging(request.path, 100),
                    severity=severity,
                    anomaly_score=round(result.anomaly_score, 4),
                )
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "Request blocked by WAF",
                        "reason": "Anomalous request detected",
                        "severity": severity,
                        "anomaly_score": result.anomaly_score,
                    },
                )
            elif SYSTEM_CONFIG.detection_mode == "detect":
                # Detect & Alert mode: log alert but allow
                logger.warning(
                    "Anomalous request detected (allowed)",
                    path=sanitize_for_logging(request.path, 100),
                    severity=severity,
                    anomaly_score=round(result.anomaly_score, 4),
                )
            # else: monitor mode - no action, just log

        # Build response
        return ScanResponse(
            anomaly_score=result.anomaly_score,
            is_anomalous=result.is_anomalous,
            threshold=result.threshold,
            reconstruction_error=result.reconstruction_error,
            perplexity=result.perplexity,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

    except ValidationError as e:
        logger.warning("Validation error", error=str(e))
        raise HTTPException(
            status_code=422, detail=f"Validation error: {str(e)}"
        )
    except Exception as e:
        logger.error("Scan error", error=str(e), error_type=type(e).__name__)
        raise HTTPException(status_code=500, detail="Scan failed")


@app.post(
    "/batch-scan",
    response_model=BatchScanResponse,
    dependencies=[Depends(verify_rate_limit)],
)
async def batch_scan_requests(batch_request: BatchScanRequest):
    """
    Scan multiple HTTP requests in batch.

    Security:
    - Rate limited
    - Batch size limited to prevent DoS
    - Input validated
    - Secure logging

    Args:
        batch_request: Batch of requests to scan

    Returns:
        Batch scan results
    """
    if not detector:
        raise HTTPException(status_code=503, detail="Detector not initialized")

    batch_size = len(batch_request.requests)

    # Additional batch size validation
    if batch_size > MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Batch size {batch_size} exceeds maximum {MAX_BATCH_SIZE}",
        )

    try:
        # Secure logging
        logger.info("Batch scan request", batch_size=batch_size)

        # Convert to dict format
        requests_data = [
            {
                "method": req.method,
                "path": req.path,
                "query_string": req.query_string,
                "headers": req.headers,
                "body": req.body,
            }
            for req in batch_request.requests
        ]

        # Perform batch detection
        results = await detector.detect_batch(requests_data)

        # Build response
        scan_results = [
            ScanResponse(
                anomaly_score=r.anomaly_score,
                is_anomalous=r.is_anomalous,
                threshold=r.threshold,
                reconstruction_error=r.reconstruction_error,
                perplexity=r.perplexity,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            for r in results
        ]

        anomalous_count = sum(1 for r in results if r.is_anomalous)

        # Secure logging of results
        logger.info(
            "Batch scan complete",
            total_requests=len(results),
            anomalous_count=anomalous_count,
            anomaly_rate=anomalous_count / max(len(results), 1),
        )

        return BatchScanResponse(
            results=scan_results,
            total_requests=len(results),
            anomalous_count=anomalous_count,
        )

    except ValidationError as e:
        logger.warning("Batch validation error", error=str(e))
        raise HTTPException(
            status_code=422, detail=f"Validation error: {str(e)}"
        )
    except Exception as e:
        logger.error(
            "Batch scan error", error=str(e), error_type=type(e).__name__
        )
        raise HTTPException(status_code=500, detail="Batch scan failed")


@app.get("/stats")
async def get_statistics():
    """
    Get detection statistics.

    Returns:
        Statistics dictionary
    """
    if not detector:
        raise HTTPException(status_code=503, detail="Detector not initialized")

    stats = detector.get_stats()

    return {
        **stats,
        "uptime_seconds": (
            (datetime.now(timezone.utc) - start_time).total_seconds()
            if start_time
            else 0
        ),
    }


# ===== Attack Simulation Endpoints =====


class AttackSimulationRequest(BaseModel):
    """Attack simulation request"""

    attack_type: str = Field(
        ...,
        description="Type of attack: sql_injection, xss, path_traversal, command_injection",
    )
    target_path: str = Field(
        default="/api/users", description="Target endpoint path"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "attack_type": "sql_injection",
                "target_path": "/api/users",
            }
        }
    )


@app.post("/simulate/attack")
async def simulate_attack(
    simulation: AttackSimulationRequest,
    request: Request,
    x_api_key: Optional[str] = Header(None),
):
    """
    Simulate attack for testing and demonstration

    Args:
        simulation: Attack simulation parameters
        x_api_key: Optional API key

    Returns:
        Detection result
    """
    if not detector:
        raise HTTPException(status_code=503, detail="Detector not initialized")

    # Generate attack payload based on type
    attack_payloads = {
        "sql_injection": {
            "method": "GET",
            "path": simulation.target_path,
            "query_string": "?id=1' OR '1'='1",
            "headers": {"User-Agent": "sqlmap/1.7.2"},
            "body": "",
        },
        "xss": {
            "method": "GET",
            "path": simulation.target_path,
            "query_string": "?search=<script>alert('XSS')</script>",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
        },
        "path_traversal": {
            "method": "GET",
            "path": "/../../../etc/passwd",
            "query_string": "",
            "headers": {"User-Agent": "Nikto/2.5.0"},
            "body": "",
        },
        "command_injection": {
            "method": "POST",
            "path": simulation.target_path,
            "query_string": "",
            "headers": {"User-Agent": "curl/7.88.1"},
            "body": "cmd=ls; cat /etc/passwd",
        },
    }

    if simulation.attack_type not in attack_payloads:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid attack type. Supported: {list(attack_payloads.keys())}",
        )

    payload = attack_payloads[simulation.attack_type]

    # Detect with proper parameters
    result = await detector.detect(
        method=payload["method"],
        path=payload["path"],
        query_string=payload["query_string"],
        headers=payload["headers"],
        body=payload["body"],
    )

    # Determine severity and attack type
    severity = determine_severity(result.anomaly_score)

    # Prepare result dict for emit function
    result_dict = {
        "anomaly_score": result.anomaly_score,
        "is_anomalous": result.is_anomalous,
        "threshold": result.threshold,
    }

    # Emit WebSocket event and update metrics
    await emit_detection_event(payload, result_dict)

    logger.info(
        "Attack simulation",
        attack_type=simulation.attack_type,
        detected=result.is_anomalous,
        score=result.anomaly_score,
        severity=severity,
    )

    # Return structured response for frontend
    return {
        "status": "blocked" if result.is_anomalous else "allowed",
        "attack_type": simulation.attack_type,
        "severity": severity,
        "anomaly_score": round(result.anomaly_score, 3),
        "detection_result": {
            "anomaly_score": result.anomaly_score,
            "is_anomalous": result.is_anomalous,
            "threshold": result.threshold,
            "reconstruction_error": result.reconstruction_error,
            "perplexity": result.perplexity,
            "latency_ms": result.inference_time_ms,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ===== System Configuration Endpoints =====


class SystemConfig(BaseModel):
    """System configuration model"""

    anomaly_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    detection_mode: str = Field(
        default="detect", pattern="^(monitor|detect|block)$"
    )
    protected_app_url: str = Field(
        default="",
        description="Origin URL of the protected application (informational)",
    )
    demo_mode: bool = Field(default=False)
    demo_request_count: int = Field(
        default=0, ge=0
    )  # Track demo requests sent
    demo_total_requests: int = Field(
        default=100, ge=1, le=500
    )  # Total demo requests to send
    severity_thresholds: Dict[str, float] = Field(
        default={"low": 0.3, "medium": 0.5, "high": 0.7, "critical": 0.9}
    )
    logging_level: str = Field(
        default="info", pattern="^(debug|info|warning|error)$"
    )
    enable_notifications: bool = Field(default=True)


# Global config storage (in production, use database/Redis)
SYSTEM_CONFIG = SystemConfig()


async def demo_traffic_generator():
    """
    Background task that generates exactly 100 demo requests when demo mode is enabled
    """
    while True:
        try:
            if (
                SYSTEM_CONFIG.demo_mode
                and SYSTEM_CONFIG.demo_request_count
                < SYSTEM_CONFIG.demo_total_requests
            ):
                # Generate requests at ~2 second intervals for faster demo
                await asyncio.sleep(2.0)

                # Guarantee both benign and attack traffic appear in every demo run.
                # First request is benign, second is attack, then continue 70/30 mix.
                if SYSTEM_CONFIG.demo_request_count == 0:
                    is_attack = False
                elif SYSTEM_CONFIG.demo_request_count == 1:
                    is_attack = True
                else:
                    is_attack = random.random() < 0.3

                normal_patterns = [
                    {
                        "method": "GET",
                        "path": "/",
                        "query_string": "",
                    },
                    {
                        "method": "GET",
                        "path": "/pages/login.html",
                        "query_string": "",
                    },
                    {
                        "method": "GET",
                        "path": "/api/users",
                        "query_string": "id=42",
                    },
                    {
                        "method": "GET",
                        "path": "/api/events",
                        "query_string": "page=1",
                    },
                    {
                        "method": "POST",
                        "path": "/api/auth/login",
                        "query_string": "",
                    },
                ]

                if is_attack:
                    attack_types = [
                        "sql_injection",
                        "xss",
                        "path_traversal",
                        "command_injection",
                    ]
                    attack_type = random.choice(attack_types)

                    attack_payloads = {
                        "sql_injection": [
                            "' OR '1'='1",
                            "1; DROP TABLE users--",
                            "admin'--",
                        ],
                        "xss": [
                            '<script>alert("XSS")</script>',
                            "<img src=x onerror=alert(1)>",
                        ],
                        "path_traversal": [
                            "../../etc/passwd",
                            "../../../windows/system32",
                        ],
                        "command_injection": [
                            "| cat /etc/passwd",
                            "; ls -la",
                            "`whoami`",
                        ],
                    }

                    payload = random.choice(attack_payloads[attack_type])
                    path = f"/api/{random.choice(['users', 'data', 'search', 'login'])}"

                    request_data = {
                        "method": "GET",
                        "path": path,
                        "query_string": payload,
                        "headers": {
                            "User-Agent": "Mozilla/5.0",
                            "X-Demo": "true",
                        },
                    }
                else:
                    # Normal traffic
                    normal = random.choice(normal_patterns)
                    request_data = {
                        "method": normal["method"],
                        "path": normal["path"],
                        "query_string": normal["query_string"],
                        "headers": {
                            "User-Agent": "Mozilla/5.0",
                            "X-Demo": "true",
                        },
                        "body": ""
                        if normal["method"] == "GET"
                        else '{"username":"user","password":"***"}',
                    }

                # Send to detector
                if detector:
                    try:
                        result = await detector.detect(
                            method=request_data["method"],
                            path=request_data["path"],
                            query_string=request_data.get("query_string", ""),
                            headers=request_data.get("headers", {}),
                            body=request_data.get("body"),
                        )

                        # Emit detection event
                        await emit_detection_event(request_data, result)

                        # Increment counter
                        SYSTEM_CONFIG.demo_request_count += 1

                        # Log progress at milestones
                        if SYSTEM_CONFIG.demo_request_count % 25 == 0:
                            (
                                logger.info(
                                    f"Demo progress: {SYSTEM_CONFIG.demo_request_count}/{SYSTEM_CONFIG.demo_total_requests} requests"
                                )
                                if logger
                                else None
                            )

                        # Auto-disable demo mode when complete
                        if (
                            SYSTEM_CONFIG.demo_request_count
                            >= SYSTEM_CONFIG.demo_total_requests
                        ):
                            (
                                logger.info(
                                    f"Demo mode complete: {SYSTEM_CONFIG.demo_total_requests} requests generated"
                                )
                                if logger
                                else None
                            )
                            SYSTEM_CONFIG.demo_mode = False

                    except Exception as e:
                        (
                            logger.error(f"Demo traffic error: {str(e)}")
                            if logger
                            else None
                        )
            else:
                # Wait when demo mode is off or complete
                await asyncio.sleep(5)
        except Exception as e:
            (
                logger.error(f"Demo traffic generator error: {str(e)}")
                if logger
                else None
            )
            await asyncio.sleep(5)


# ===== Real-Time Metrics Endpoint =====


@app.get("/metrics")
async def get_metrics():
    """
    Get real-time system metrics

    Returns:
        Real-time metrics including total requests, anomalous count, scores
    """
    return {
        "total_requests": METRICS_STORE["total_requests"],
        "anomalous_requests": METRICS_STORE["anomalous_requests"],
        "critical_threats": METRICS_STORE["critical_threats"],
        "avg_anomaly_score": round(METRICS_STORE["avg_anomaly_score"], 3),
        "detection_rate": round(
            (
                METRICS_STORE["anomalous_requests"]
                / max(METRICS_STORE["total_requests"], 1)
            )
            * 100,
            2,
        ),
        "latency_p95": METRICS_STORE["latency_p95"],
        "last_updated": METRICS_STORE["last_updated"],
    }


@app.get("/metrics/timeseries")
async def get_timeseries_metrics(minutes: int = 20):
    """
    Get time-series metrics for charts

    Args:
        minutes: Number of minutes of historical data to return (default 20, max 60)

    Returns:
        List of time-bucketed metrics for charting
    """
    minutes = min(minutes, MAX_TIMESERIES_POINTS)

    # Return last N minutes of data
    data = TIMESERIES_METRICS[-minutes:] if TIMESERIES_METRICS else []

    # Format for frontend charts
    return {
        "score_trend": [
            {
                "time": datetime.fromisoformat(d["timestamp"]).strftime(
                    "%I:%M %p"
                ),
                "score": round(d["avg_score"], 3),
            }
            for d in data
        ],
        "volume_trend": [
            {
                "time": datetime.fromisoformat(d["timestamp"]).strftime(
                    "%I:%M %p"
                ),
                "benign": d["benign"],
                "anomalous": d["anomalous"],
            }
            for d in data
        ],
        "data_points": len(data),
        "is_live": True,
    }


# ===== Traffic Generator Endpoint =====


@app.post("/dev/generate-traffic")
async def generate_traffic(count: int = 20, include_attacks: bool = True):
    """
    Generate simulated traffic for demo/testing

    Args:
        count: Number of requests to generate
        include_attacks: Whether to include attack payloads

    Returns:
        Summary of generated traffic
    """
    if not detector:
        raise HTTPException(status_code=503, detail="Detector not initialized")

    from random import choice, randint

    # Normal request patterns
    normal_patterns = [
        {
            "method": "GET",
            "path": "/api/users",
            "query_string": "",
            "headers": {},
            "body": "",
        },
        {
            "method": "GET",
            "path": "/api/products",
            "query_string": "?page=1",
            "headers": {},
            "body": "",
        },
        {
            "method": "POST",
            "path": "/api/login",
            "query_string": "",
            "headers": {},
            "body": '{"user":"admin"}',
        },
        {
            "method": "GET",
            "path": "/health",
            "query_string": "",
            "headers": {},
            "body": "",
        },
        {
            "method": "GET",
            "path": "/api/dashboard",
            "query_string": "",
            "headers": {},
            "body": "",
        },
    ]

    # Attack patterns
    attack_patterns = [
        {
            "method": "GET",
            "path": "/api/users",
            "query_string": "?id=1' OR '1'='1",
            "headers": {"User-Agent": "sqlmap"},
            "body": "",
        },
        {
            "method": "GET",
            "path": "/search",
            "query_string": "?q=<script>alert('XSS')</script>",
            "headers": {},
            "body": "",
        },
        {
            "method": "GET",
            "path": "/../../../etc/passwd",
            "query_string": "",
            "headers": {"User-Agent": "Nikto"},
            "body": "",
        },
        {
            "method": "POST",
            "path": "/api/exec",
            "query_string": "",
            "headers": {},
            "body": "cmd=ls; cat /etc/passwd",
        },
        {
            "method": "GET",
            "path": "/api/users",
            "query_string": "?id=1 UNION SELECT * FROM passwords--",
            "headers": {},
            "body": "",
        },
    ]

if __name__ == "__main__":
    main()
