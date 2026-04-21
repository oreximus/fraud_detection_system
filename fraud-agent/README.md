# Fraud Agent - Privacy-First Fraud Detection System

A production-ready, privacy-first fraud detection system that works across Android SMS, email clients, and browser extensions. The system runs on-device ML inference to classify phishing/scam content and autonomously acts based on confidence levels.

## Features

- **Privacy-First**: Raw message text NEVER leaves the device
- **Local ML Inference**: TFLite (Android) / ONNX Runtime (desktop/browser)
- **Multi-Platform**: Android app, Browser extension, Web dashboard
- **Community Reporting**: SHA-256 hashed indicators only (no raw data)
- **Detection Pipeline**: CAPTURE → QUICK_SCAN → ML_CLASSIFY → DEEP_SCAN → ACTION → EXPLAIN → REPORT

## Architecture

```
fraud-agent/
├── android/           # Kotlin + Jetpack Compose app with TFLite
├── extension/        # Browser extension (TypeScript, Plasmo, Manifest V3)
├── backend/          # FastAPI sync server with SQLite
├── ml/              # Model training + detection pipeline
├── dashboard/        # React 18 admin dashboard
└── shared/          # Shared types + hashing utilities
```

## Tech Stack

| Component | Technology |
|-----------|------------|
| Android | Kotlin, Jetpack Compose, TFLite, Room, Hilt, WorkManager |
| Extension | TypeScript, Plasmo, Manifest V3, Axios |
| Backend | Python 3.11, FastAPI, SQLAlchemy, SQLite, Celery, Redis |
| ML | HuggingFace Transformers, PyTorch, ONNX Runtime |
| Dashboard | React 18, Vite, Tailwind CSS 3, Recharts, TanStack Query |
| Shared | Python + TypeScript type definitions |

## Threat Score → Action Mapping

| Score | Action | Notification Level |
|-------|--------|-------------------|
| 0.00–0.30 | ALLOW | None |
| 0.31–0.60 | WARN | Soft notification |
| 0.61–0.85 | QUARANTINE | Alert + reason |
| 0.86–1.00 | BLOCK | Full alert + guide |

## Quick Start

### Backend (FastAPI)

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Set environment variables
export DATABASE_URL="sqlite:///./fraud_agent.db"
export REDIS_URL="redis://localhost:6379/0"
export PORT=8000

# Run the server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# API available at http://localhost:8000
# API docs at http://localhost:8000/docs
```

### ML Module

```bash
cd ml

# Install dependencies
pip install -e ".[dev]"

# Train model (generates synthetic data)
python scripts/train_model.py --output-dir ./models --epochs 10 --num-samples 1000

# Model outputs:
# - models/phishing_detector.pt (PyTorch)
# - models/phishing_detector.onnx (ONNX)
# - models/phishing_detector.tflite (TFLite)
```

### Dashboard (React)

```bash
cd dashboard

# Install dependencies
npm install

# Set API URL (optional)
export VITE_API_URL=http://localhost:8000

# Start development server
npm run dev

# Dashboard available at http://localhost:5173
```

### Android App

**Requirements:**
- Android Studio Arctic Fox or later
- JDK 17
- Android SDK 34

**Setup:**
1. Open `android/` in Android Studio
2. Add TFLite model to `app/src/main/assets/phishing_detector.tflite`
3. Build and run on device/emulator

**Permissions Required:**
- RECEIVE_SMS
- READ_SMS
- INTERNET
- POST_NOTIFICATIONS
- RECEIVE_BOOT_COMPLETED

### Browser Extension

```bash
cd extension

# Install dependencies
npm install

# Build extension
npx plasmo build

# Extension built in dist/ directory
# Load dist/ as unpacked extension in Chrome:
# 1. Go to chrome://extensions
# 2. Enable "Developer mode"
# 3. Click "Load unpacked"
# 4. Select the dist/ folder
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|------------|
| `/` | GET | Root endpoint |
| `/health` | GET | Health check |
| `/api/v1/detect` | POST | Analyze content |
| `/api/v1/detections` | GET | List detections |
| `/api/v1/detections/{id}` | GET | Get detection |
| `/api/v1/reports` | GET/List | Community reports |
| `/api/v1/stats` | GET | Statistics |

## Detection Pipeline Stages

```
┌─────────────┐     ┌─────────────┐     ┌───────────────┐
│   CAPTURE   │────▶│ QUICK_SCAN  │────▶│ ML_CLASSIFY  │
└─────────────┘     └─────────────┘     └───────────────┘
                        │                    │
                        ▼                    ▼
                 ┌─────────────┐     ┌──────────────┐
                 │  DEEP_SCAN  │────▶│    ACTION   │
                 └─────────────┘     └──────────────┘
                                         │
                                         ▼
                                  ┌─────────────┐
                                  │   EXPLAIN   │
                                  └─────────────┘
                                         │
                                         ▼
                                  ┌─────────────┐
                                  │   REPORT   │
                                  └─────────────┘
```

1. **CAPTURE**: Receive and normalize incoming content
2. **QUICK_SCAN**: Fast heuristic scanning (URLs, phones, keywords)
3. **ML_CLASSIFY**: TFLite/ONNX model inference
4. **DEEP_SCAN**: Pattern analysis (impersonation, urgency, rewards)
5. **ACTION**: Determine action (ALLOW/WARN/QUARANTINE/BLOCK)
6. **EXPLAIN**: Generate plain-language explanation
7. **REPORT**: Optional community reporting (hashed only)

## Privacy Principles

1. **Local Processing Only**: Raw content never leaves the device
2. **Hashed Sharing**: Community reports use SHA-256(url_or_phone) + score + timestamp only
3. **On-Device ML**: TFLite (Android) / ONNX Runtime (desktop) - no cloud API calls
4. **Encrypted Storage**: Android Keystore / OS keychain

## Testing

```bash
# Backend tests
cd backend
pytest tests/ -v

# ML pipeline tests
cd ml
pytest tests/ -v

# Shared module tests
cd shared/python
pytest tests/ -v
```

## Environment Variables

### Backend
| Variable | Default | Description |
|----------|---------|-------------|
| DATABASE_URL | sqlite:///./fraud_agent.db | Database connection |
| REDIS_URL | redis://localhost:6379/0 | Redis connection |
| MODEL_PATH | ../ml/models/phishing_detector.onnx | ML model path |
| PORT | 8000 | Server port |
| DEBUG | false | Debug mode |

### Dashboard
| Variable | Default | Description |
|----------|---------|-------------|
| VITE_API_URL | http://localhost:8000 | Backend API URL |

## Project Structure

```
fraud-agent/
├── android/
│   ├── app/
│   │   └── src/main/
│   │       ├── java/com/fraudagent/
│   │       │   ├── di/          # Dependency injection
│   │       │   ├── data/        # Repositories, DB, TFLite
│   │       │   ├── domain/      # Models, use cases
│   │       │   └── presentation/ # UI, ViewModels
│   │       └── AndroidManifest.xml
│   └── build.gradle.kts
├── extension/
│   ├── src/
│   │   ├── background/     # Service worker
│   │   ├── content-script/ # Page analysis
│   │   └── popup/        # Extension popup
│   └── plasmo.config.ts
├── backend/
│   ├── app/
│   │   ├── api/         # API routes
│   │   ├── core/       # Config, logging
│   │   ├── db/         # Database
│   │   ├── models/     # SQLAlchemy models
│   │   ├── services/   # Business logic
│   │   └── tasks/     # Celery tasks
│   └── pyproject.toml
├── ml/
│   ├── models/        # Detection pipeline
│   ├── scripts/      # Training scripts
│   └── tests/
├── dashboard/
│   ├── src/
│   │   ├── api/     # API client
│   │   ├── components/
│   │   ├── pages/
│   │   └── lib/
│   └── package.json
└── shared/
    ├── python/       # Shared Python utilities
    └── typescript/  # Shared TypeScript types
```

## License

MIT License - See LICENSE file for details

## Security

- Never commit secrets or API keys to version control
- Use environment variables or BuildConfig for sensitive data
- All async code handles timeouts (default 5s for ML inference)
- Structured JSON logging (no print statements)