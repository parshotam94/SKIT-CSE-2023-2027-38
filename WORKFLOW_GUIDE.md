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
