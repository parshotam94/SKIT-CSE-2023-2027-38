# Technologies Used and ML Training Details

This document summarizes the technology stack and the machine learning training pipeline for the Transformer WAF. It is meant to be read before a presentation.

## 1) Technology Stack

### Backend (WAF API)
- Python 3.10+
- FastAPI for the REST API and WebSocket streaming
- Uvicorn for the ASGI server
- Pydantic for request validation and typed config
- aiohttp and requests for HTTP clients and integrations

### ML / Data
- PyTorch for model training and inference
- Hugging Face Transformers for pretrained encoders and tokenizers
- Tokenizers for fast subword tokenization
- NumPy and Pandas for data processing
- tqdm for training progress tracking

### Frontend (Dashboard)
- React 18 with TypeScript
- Vite for build and dev server
- Tailwind CSS for UI
- Recharts for charts
- Axios for API calls

### DevOps / Deployment
- Docker (optional) for containerization
- Nginx / Apache integration examples
- PowerShell and batch scripts for Windows startup