# Transformer WAF - Complete Workflow Guide

**For Understanding, Development & Modification**

---

## 📋 Table of Contents

1. [System Architecture Overview](#system-architecture-overview)
2. [Complete Data Flow](#complete-data-flow)
3. [Training Workflow](#training-workflow)
4. [Real-Time Detection Workflow](#real-time-detection-workflow)
5. [API Request Flow](#api-request-flow)
6. [Frontend Integration Flow](#frontend-integration-flow)
7. [Development Workflow](#development-workflow)
8. [Modification Guide](#modification-guide)

---

## 🏗️ System Architecture Overview

### Core Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                    TRANSFORMER WAF SYSTEM                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │   Frontend   │───▶│   API Layer  │───▶│ Inference    │          │
│  │  (React/TS)  │◀───│  (FastAPI)   │◀───│ Engine       │          │
│  └──────────────┘    └──────────────┘    └──────┬───────┘          │
│        │                     │                    │                  │
│        │                     │                    ▼                  │
│        │                     │            ┌──────────────┐          │
│        │                     │            │ ML Model     │          │
│        │                     │            │ (Transformer)│          │
│        │                     │            └──────┬───────┘          │
│        │                     │                    │                  │
│        ▼                     ▼                    ▼                  │
│  ┌──────────────────────────────────────────────────────┐          │
│  │         WebSocket (Real-time Updates)                 │          │
│  └──────────────────────────────────────────────────────┘          │
│                                                                       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │   Parsing    │───▶│ Tokenization │───▶│ Training     │          │
│  │   Layer      │    │   Layer      │    │ Pipeline     │          │
│  └──────────────┘    └──────────────┘    └──────────────┘          │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘

           ▲                                            │
           │                                            ▼
    ┌──────────────┐                           ┌──────────────┐
    │ Web Server   │                           │  Log Files   │
    │ (Nginx/      │                           │  (Training   │
    │  Apache)     │                           │   Data)      │
    └──────────────┘                           └──────────────┘
```

### Directory Structure & Purpose

```
transformer-waf/
│
├── api/                          # 🌐 API Layer
│   ├── waf_api.py               # FastAPI endpoints, rate limiting, security
│   └── websocket_handler.py     # Real-time WebSocket streaming
│
├── model/                        # 🧠 ML Model Layer
│   ├── transformer_model.py     # Autoencoder architecture (DistilBERT)
│   ├── train.py                 # Training pipeline
│   └── fine_tune.py             # Model fine-tuning
│
├── inference/                    # ⚡ Detection Engine
│   └── detector.py              # High-perf async detection (JIT, caching)
│
├── tokenization/                 # 📝 Text Processing
│   └── tokenizer.py             # BERT tokenizer wrapper
│
├── parsing/                      # 🔍 Log Parsing
│   ├── log_parser.py            # Extract HTTP requests from logs
│   └── normalizer.py            # Normalize requests (remove IPs, dates)
│
├── training/                     # 🔄 Continuous Learning
│   └── continuous_learning.py   # Incremental fine-tuning on new data
│
├── ingestion/                    # 📥 Data Ingestion
│   ├── batch_ingest.py          # Batch log processing
│   └── stream_ingest.py         # Real-time log streaming
│
├── utils/                        # 🛠️ Utilities
│   ├── config.py                # Configuration management
│   ├── logger.py                # Structured logging
│   └── forensic_logging.py      # PII-safe forensic logs
│
├── frontend/                     # 🎨 Web UI
│   └── src/
│       ├── pages/               # Dashboard, Analytics, Simulation, etc.
│       └── services/            # API client
│
├── data/                         # 💾 Data Storage
│   ├── benign_logs/             # Training data (benign requests)
│   └── test_logs/               # Test data
│
├── models/                       # 📦 Trained Models
│   └── waf_transformer/         # Model weights, tokenizer
│
└── logs/                         # 📋 Application Logs
    └── forensic/                # Forensic incident logs
```

---

## 🔄 Complete Data Flow

### High-Level Flow

```
1. TRAINING PHASE (Offline)
   ─────────────────────────────
   Access Logs → Parse → Normalize → Tokenize → Train Model
                                                      ↓
                                               Save Model Weights

2. INFERENCE PHASE (Real-time)
   ─────────────────────────────
   HTTP Request → API → Normalize → Tokenize → Model Inference
                   ↓                                 ↓
              WebSocket ←──────────────── Anomaly Score
                   ↓
              Frontend Dashboard

3. CONTINUOUS LEARNING (Background)
   ─────────────────────────────
   New Benign Traffic → Collect → Fine-tune Model → Deploy New Version
```

### Detailed Data Transformation

```
Raw HTTP Request:
┌─────────────────────────────────────────────────────────────┐
│ GET /api/users/123?format=json HTTP/1.1                     │
│ Host: example.com                                            │
│ User-Agent: Mozilla/5.0                                      │
└─────────────────────────────────────────────────────────────┘
                          ↓
                    [PARSING]
                          ↓
Parsed Components:
┌─────────────────────────────────────────────────────────────┐
│ method: "GET"                                                │
│ path: "/api/users/123"                                       │
│ query_string: "format=json"                                  │
│ headers: {"User-Agent": "Mozilla/5.0"}                       │
└─────────────────────────────────────────────────────────────┘
                          ↓
                  [NORMALIZATION]
                          ↓
Normalized String:
┌─────────────────────────────────────────────────────────────┐
│ "GET /api/users/[ID] format=[VALUE]"                        │
│ (IPs, UUIDs, timestamps removed → focus on structure)       │
└─────────────────────────────────────────────────────────────┘
                          ↓
                  [TOKENIZATION]
                          ↓
Token IDs:
┌─────────────────────────────────────────────────────────────┐
│ [101, 2131, 1013, 8943, 2109, 1013, 102, ...]              │
│ (BERT wordpiece tokens, max 128 length)                     │
└─────────────────────────────────────────────────────────────┘
                          ↓
                  [MODEL INFERENCE]
                          ↓
Anomaly Score:
┌─────────────────────────────────────────────────────────────┐
│ {                                                            │
│   "anomaly_score": 0.23,                                     │
│   "is_anomalous": false,                                     │
│   "reconstruction_error": 0.18,                              │
│   "perplexity": 12.5                                         │
│ }                                                            │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎓 Training Workflow

### Step-by-Step Training Process

```
PHASE 1: Data Preparation
─────────────────────────
1. Collect benign access logs
   Location: data/benign_logs/
   Format: Apache/Nginx combined log format

2. Parse logs to extract HTTP requests
   Module: parsing/log_parser.py
   Class: AccessLogParser
   Output: List of ParsedRequest objects

3. Normalize requests (remove variable data)
   Module: parsing/normalizer.py
   Class: RequestNormalizer
   - Replace IPs with [IP]
   - Replace UUIDs with [UUID]
   - Replace numbers with [NUM]
   - Remove timestamps
   Output: Normalized text strings

PHASE 2: Model Training
─────────────────────────
4. Initialize tokenizer
   Module: tokenization/tokenizer.py
   Base: DistilBERT tokenizer
   Max Length: 128 tokens

5. Create dataset
   Module: model/train.py
   Class: HTTPRequestDataset
   - Tokenize normalized texts
   - Create masked inputs (15% masking for MLM)
   - Generate DataLoader

6. Initialize model
   Module: model/transformer_model.py
   Class: TransformerAutoencoder
   Architecture:
   - Encoder: DistilBERT (66M params)
   - Decoder: Linear layer for token prediction
   - Loss: Cross-entropy on masked tokens

7. Train model
   Module: model/train.py
   Class: Trainer
   Process:
   - Optimizer: AdamW (lr=2e-5)
   - Scheduler: Linear warmup
   - Epochs: 10 (configurable)
   - Batch size: 64 (configurable)
   - Validation: Track loss on val set

8. Save model
   Location: models/waf_transformer/
   Files:
   - model.pt (weights)
   - tokenizer files (vocab, config)
   - checkpoints/ (epoch snapshots)

PHASE 3: Evaluation
─────────────────────────
9. Test on validation set
   Metrics:
   - Reconstruction error distribution
   - Perplexity
   - Detection threshold calibration

10. Test on attack samples (optional)
    - Verify high anomaly scores on attacks
    - Adjust threshold if needed
```

### Training Command Examples

```bash
# Basic training
python -m model.train \
    --log-dir data/benign_logs \
    --output-dir models/waf_transformer \
    --epochs 10

# Advanced training with hyperparameters
python -m model.train \
    --log-dir data/benign_logs \
    --output-dir models/waf_transformer \
    --epochs 20 \
    --batch-size 32 \
    --learning-rate 1e-5 \
    --max-samples 100000 \
    --device cuda

# Fine-tuning existing model
python -m model.fine_tune \
    --model-path models/waf_transformer/model.pt \
    --log-dir data/new_benign_logs \
    --epochs 3
```

---

## ⚡ Real-Time Detection Workflow

### Request Detection Pipeline

```
STEP 1: Request Arrives at API
───────────────────────────────
Location: api/waf_api.py
Endpoint: POST /scan
Input: HTTPRequestModel (Pydantic validated)
{
  "method": "GET",
  "path": "/api/users/123",
  "query_string": "format=json",
  "headers": {...},
  "body": ""
}

STEP 2: Input Validation
───────────────────────────────
- Pydantic automatic validation
- Check max lengths (path: 2048, query: 4096, body: 1MB)
- Validate HTTP method
- Check rate limits

STEP 3: Sanitize & Log (Secure)
───────────────────────────────
- Redact sensitive data (passwords, tokens, cookies)
- Hash IP addresses (SHA-256)
- Log request metadata only

STEP 4: Async Detection Call
───────────────────────────────
Location: inference/detector.py
Class: AnomalyDetector
Method: detect()

  4.1 Normalize Request
      Module: parsing/normalizer.py
      - Remove IPs, UUIDs, timestamps
      - Standardize format

  4.2 Check Cache (LRU)
      - 10K request cache
      - If hit: return cached score
      - If miss: continue to inference

  4.3 Tokenize
      Module: tokenization/tokenizer.py
      - Convert to token IDs
      - Add special tokens ([CLS], [SEP])
      - Pad to max length

  4.4 Model Inference (JIT Optimized)
      Module: model/transformer_model.py
      - Forward pass through encoder
      - Reconstruct tokens
      - Calculate reconstruction error
      - Calculate perplexity

  4.5 Calculate Anomaly Score
      Formula:
      anomaly_score = (0.7 * reconstruction_error) + 
                      (0.3 * normalized_perplexity)
      
      Compare to threshold (default: 0.75)
      is_anomalous = (anomaly_score > threshold)

  4.6 Cache Result
      - Store in LRU cache
      - Evict oldest if full

STEP 5: Emit WebSocket Event
───────────────────────────────
Location: api/waf_api.py
Function: emit_detection_event()

- Create detection event with metadata
- Broadcast to all connected WebSocket clients
- Update metrics (total_requests, anomalous_count)
- Store in analytics events buffer

STEP 6: Policy Enforcement
───────────────────────────────
Based on SYSTEM_CONFIG.detection_mode:

- "monitor": Log only, allow request
- "detect": Log + alert, allow request
- "block": Log + alert + block (HTTP 403)

STEP 7: Return Response
───────────────────────────────
Output: ScanResponse
{
  "anomaly_score": 0.23,
  "is_anomalous": false,
  "threshold": 0.75,
  "reconstruction_error": 0.18,
  "perplexity": 12.5,
  "timestamp": "2026-03-03T10:30:45.123Z"
}
```

### Performance Optimizations

```
┌────────────────────────────────────────────────────────────┐
│ OPTIMIZATION TECHNIQUES                                     │
├────────────────────────────────────────────────────────────┤
│                                                             │
│ 1. JIT Compilation                                          │
│    - torch.jit.script() for model                          │
│    - 2-3x speedup                                           │
│                                                             │
│ 2. LRU Caching                                              │
│    - @lru_cache(maxsize=10000)                              │
│    - Cache tokenization results                             │
│                                                             │
│ 3. Batch Processing                                         │
│    - Process multiple requests together                     │
│    - GPU parallelization                                    │
│                                                             │
│ 4. Async I/O                                                │
│    - asyncio for non-blocking operations                    │
│    - Concurrent request handling                            │
│                                                             │
│ 5. Connection Pooling                                       │
│    - ThreadPoolExecutor for CPU-bound tasks                 │
│    - Semaphore for GPU access control                       │
│                                                             │
│ Target Latency: <15ms p99, 500+ RPS                        │
└────────────────────────────────────────────────────────────┘
```

---

## 🌐 API Request Flow

### Complete API Endpoint Map

```
FastAPI Application (api/waf_api.py)
─────────────────────────────────────

┌─ Core Detection Endpoints ─────────────────────────────────┐
│                                                             │
│ POST /scan                                                  │
│   → Single request anomaly detection                        │
│   → Input: HTTPRequestModel                                 │
│   → Output: ScanResponse                                    │
│   → Rate limited, validated                                 │
│                                                             │
│ POST /batch-scan                                            │
│   → Batch anomaly detection (up to 100 requests)           │
│   → Input: BatchScanRequest                                 │
│   → Output: BatchScanResponse                               │
│   → Optimized for high throughput                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─ System Endpoints ─────────────────────────────────────────┐
│                                                             │
│ GET /health                                                 │
│   → Health check, uptime, model status                      │
│                                                             │
│ GET /stats                                                  │
│   → Detection statistics, performance metrics               │
│                                                             │
│ GET /                                                       │
│   → API info, documentation links                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─ Configuration Endpoints ──────────────────────────────────┐
│                                                             │
│ POST /threshold                                             │
│   → Update anomaly detection threshold                      │
│                                                             │
│ POST /config                                                │
│   → Update system configuration                             │
│   → detection_mode: monitor|detect|block                    │
│                                                             │
│ GET /config                                                 │
│   → Get current configuration                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─ Analytics & Metrics Endpoints ────────────────────────────┐
│                                                             │
│ GET /metrics/realtime                                       │
│   → Real-time metrics (RPS, anomaly rate, latency)         │
│                                                             │
│ GET /metrics/timeseries                                     │
│   → Time-series data (last 60 minutes)                      │
│                                                             │
│ GET /analytics/events                                       │
│   → Historical detection events                             │
│                                                             │
│ GET /analytics/distribution                                 │
│   → Attack type distribution                                │
│                                                             │
│ GET /analytics/export                                       │
│   → Export analytics to CSV/JSON                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─ Attack Simulation Endpoints ──────────────────────────────┐
│                                                             │
│ POST /simulate/attack                                       │
│   → Simulate specific attack types                          │
│   → Types: sql_injection, xss, path_traversal, etc.        │
│                                                             │
│ POST /simulate/demo-toggle                                  │
│   → Enable/disable demo traffic generator                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─ WebSocket Endpoints ──────────────────────────────────────┐
│                                                             │
│ WS /ws                                                      │
│   → Real-time detection event streaming                     │
│   → Broadcasts to all connected clients                     │
│   → Event types: detection, metrics_update                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘

┌─ Documentation ────────────────────────────────────────────┐
│                                                             │
│ GET /docs                                                   │
│   → Swagger UI (interactive API docs)                       │
│                                                             │
│ GET /redoc                                                  │
│   → ReDoc (alternative API docs)                            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Request Lifecycle

```
1. Request Arrives
   ↓
2. Middleware Processing
   - CORS check
   - Request logging
   - Timing start
   ↓
3. Rate Limiting Check
   - verify_rate_limit() dependency
   - 100 req/min per IP
   ↓
4. Input Validation
   - Pydantic model validation
   - Type checking
   - Length limits
   ↓
5. Route Handler
   - Business logic
   - Detection call
   - Response generation
   ↓
6. Response Middleware
   - Add security headers
   - Log completion
   - Return JSON
```

---

## 🎨 Frontend Integration Flow

### Frontend Architecture

```
React Application (frontend/src/)
──────────────────────────────────

┌─ Pages ───────────────────────────────────────────────────┐
│                                                            │
│ Dashboard.tsx           → Main overview, live stats       │
│ LiveMonitoring.tsx      → Real-time detection stream      │
│ AttackSimulation.tsx    → Test attack patterns            │
│ Analytics.tsx           → Historical trends, charts       │
│ Settings.tsx            → Configuration panel             │
│ Documentation.tsx       → Security docs, API reference    │
│                                                            │
└────────────────────────────────────────────────────────────┘

┌─ Services ────────────────────────────────────────────────┐
│                                                            │
│ api.ts                  → REST API client                 │
│   - scanRequest()       → POST /scan                      │
│   - getMetrics()        → GET /metrics/realtime           │
│   - updateConfig()      → POST /config                    │
│                                                            │
│ websocket.ts            → WebSocket client                │
│   - connect()           → WS /ws                          │
│   - onDetection()       → Handle detection events         │
│   - onMetrics()         → Handle metrics updates          │
│                                                            │
└────────────────────────────────────────────────────────────┘

┌─ Components ──────────────────────────────────────────────┐
│                                                            │
│ Layout.tsx              → Main layout, navigation         │
│ ErrorBoundary.tsx       → Error handling                  │
│ DetectionCard.tsx       → Display detection result        │
│ MetricsChart.tsx        → Real-time charts                │
│ AlertPanel.tsx          → Threat alerts                   │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### WebSocket Real-Time Flow

```
Frontend Connect
     │
     ├─ WS /ws (Connect)
     │       │
     │       ├─ Connection Manager (api/websocket_handler.py)
     │       │   - Add client to active connections
     │       │   - Send initial state
     │       │
     │       └─ Client receives events:
     │
     ├─ Event: "detection"
     │   {
     │     "type": "detection",
     │     "timestamp": "...",
     │     "request": {...},
     │     "detection": {
     │       "anomalyScore": 0.85,
     │       "isAnomalous": true,
     │       "severity": "high"
     │     }
     │   }
     │   → Update LiveMonitoring page
     │   → Show alert notification
     │
     └─ Event: "metrics_update"
         {
           "type": "metrics",
           "data": {
             "total_requests": 1234,
             "anomalous_requests": 45,
             "avg_anomaly_score": 0.23
           }
         }
         → Update dashboard metrics
         → Update charts
```

---

## 👩‍💻 Development Workflow

### Local Development Setup

```bash
# 1. Clone and setup environment
git clone <repo>
cd transformer-waf
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# 2. Prepare training data
mkdir -p data/benign_logs
# Copy your access logs to data/benign_logs/

# 3. Train model (first time only)
python -m model.train \
    --log-dir data/benign_logs \
    --output-dir models/waf_transformer \
    --epochs 10

# 4. Start backend API
python -m api.waf_api

# 5. Start frontend (separate terminal)
cd frontend
npm install
npm run dev

# 6. Access application
# Backend: http://localhost:8000
# Frontend: http://localhost:3000
# API Docs: http://localhost:8000/docs
```

### Testing Workflow

```bash
# Unit tests
pytest tests/

# Test specific module
pytest tests/test_detector.py

# Test with coverage
pytest --cov=. --cov-report=html

# Manual API testing
python scripts/test_api.py

# Load testing
python scripts/load_test.py --rps 100 --duration 60

# Security scanning
cd devsecops
./bandit_scan.sh  # SAST
./zap_scan.sh     # DAST
```

### Code Quality Checks

```bash
# Linting
flake8 . --max-line-length=79

# Type checking
mypy api/ model/ inference/

# Format code
black . --line-length 79

# Security audit
safety check
bandit -r . -x venv/
```

---

## 🔧 Modification Guide

### Common Modification Scenarios

#### 1. **Add New Attack Type Detection**

**Location**: `api/waf_api.py` → `determine_attack_type()`

```python
def determine_attack_type(
    request_data: Dict[str, Any], anomaly_score: float
) -> str:
    """Add your attack type detection logic"""
    
    combined = f"{path} {query} {body}".lower()
    
    # Add your new attack type
    if "your_attack_pattern" in combined:
        return "Your Attack Type"
    
    # ... existing patterns
```

**Also update**: Frontend attack type colors/labels in `Analytics.tsx`

#### 2. **Change Model Architecture**

**Location**: `model/transformer_model.py`

```python
class TransformerAutoencoder(nn.Module):
    def __init__(
        self,
        model_name: str = "distilbert-base-uncased",  # Change model here
        # ... other params
    ):
        # Modify architecture
        self.encoder = AutoModel.from_pretrained(model_name)
        
        # Add custom layers
        self.custom_layer = nn.Linear(hidden_size, hidden_size)
```

**Requires**: Retraining the model

#### 3. **Adjust Detection Threshold**

**Via API** (Runtime):
```bash
curl -X POST http://localhost:8000/threshold \
  -H "Content-Type: application/json" \
  -d '{"threshold": 0.85}'
```

**Via Code** (Default):
```python
# utils/config.py
class Config:
    anomaly_threshold: float = 0.75  # Change default here
```

#### 4. **Add Custom Normalization Rules**

**Location**: `parsing/normalizer.py`

```python
class RequestNormalizer:
    def normalize(self, text: str) -> str:
        # Add custom normalization
        text = re.sub(r'your-pattern', '[YOUR_TOKEN]', text)
        
        # ... existing normalizations
        return text
```

#### 5. **Change Rate Limiting**

**Location**: `api/waf_api.py`

```python
# Constants at top
RATE_LIMIT_REQUESTS = 100  # Change requests limit
RATE_LIMIT_WINDOW = 60     # Change time window (seconds)
```

#### 6. **Add New API Endpoint**

**Location**: `api/waf_api.py`

```python
@app.get("/your-endpoint")
async def your_handler():
    """Your endpoint logic"""
    return {"data": "your response"}
```

**Frontend Integration**: `frontend/src/services/api.ts`

```typescript
export const yourApiCall = async () => {
  const response = await axios.get(`${API_BASE_URL}/your-endpoint`);
  return response.data;
};
```

#### 7. **Modify Anomaly Score Calculation**

**Location**: `inference/detector.py`

```python
def _calculate_anomaly_score(
    self, recon_error: float, perplexity: float
) -> float:
    """Modify scoring formula"""
    
    # Current: 70% recon + 30% perplexity
    # Change weights:
    score = (0.6 * recon_error) + (0.4 * normalized_perplexity)
    
    return score
```

#### 8. **Add New Frontend Page**

1, Create page: `frontend/src/pages/YourPage.tsx`
```typescript
export const YourPage = () => {
  return <div>Your content</div>;
};
```

2. Add route: `frontend/src/App.tsx`
```typescript
<Route path="/your-page" element={<YourPage />} />
```

3. Add navigation: `frontend/src/components/Layout.tsx`

#### 9. **Customize Logging**

**Location**: `utils/logger.py`

```python
class WAFLogger:
    def __init__(self, name: str):
        # Modify log format
        formatter = logging.Formatter(
            '%(asctime)s - YOUR_FORMAT - %(message)s'
        )
```

#### 10. **Add Model Performance Metrics**

**Location**: `inference/detector.py`

```python
@dataclass
class DetectionResult:
    # Add your custom metrics
    your_metric: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            # ... existing fields
            "your_metric": self.your_metric
        }
```

### Best Practices for Modifications

```
✅ DO:
- Test changes locally first
- Update documentation
- Add unit tests for new features
- Follow existing code style (PEP 8)
- Log important events
- Validate inputs
- Handle errors gracefully

❌ DON'T:
- Modify production models without testing
- Skip input validation
- Hard-code sensitive data
- Break API compatibility
- Ignore security best practices
- Forget to update frontend when API changes
```

---
