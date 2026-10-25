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
