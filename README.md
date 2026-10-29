# PhishGuard AI — AI-Powered Phishing Detection Platform

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Vercel-success?style=for-the-badge&logo=vercel)](https://phishguard-ai-one-amber.vercel.app)
[![GitHub Repo](https://img.shields.io/badge/GitHub-Repository-blue?style=for-the-badge&logo=github)](https://github.com/pasupuletiravikumar/phishguard-ai)
![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=for-the-badge&logo=fastapi)
![Next.js 14](https://img.shields.io/badge/Next.js-14.2-black?style=for-the-badge&logo=next.js)
![Tests](https://img.shields.io/badge/Tests-30%20Passed-brightgreen?style=for-the-badge)

> 🌐 **Live Web Application:** [https://phishguard-ai-one-amber.vercel.app](https://phishguard-ai-one-amber.vercel.app)  
> 💻 **GitHub Repository:** [https://github.com/pasupuletiravikumar/phishguard-ai](https://github.com/pasupuletiravikumar/phishguard-ai)

**PhishGuard AI** is a production-grade cybersecurity web platform engineered to detect malicious URLs, deceptive phishing emails, and smishing attacks through a hybrid architecture combining rule-based heuristics, RFC-compliant lexical dissection, and machine learning classification.

Developed as a **Final-Year B.Tech Computer Science and Engineering (Cybersecurity) Capstone Project**.

---

## 1. System Overview

PhishGuard AI tackles modern social engineering attacks by providing transparent, explainable threat scoring across three primary attack surfaces:
1. **URL Threat Analysis**: Investigates domain age indicators, typosquatting, Punycode homographs, IP host masking, and Shannon entropy.
2. **Email Security Analysis**: Analyzes sender/reply-to mismatches, display name spoofing, credential harvesting patterns, and urgency heuristics.
3. **SMS / Chat Smishing Analysis**: Identifies package delivery scams, banking alert frauds, and urgent shortened links.

### Key Highlights
- **Zero Fabrication**: Honest threat modeling. When machine learning models or threat feeds have limitations, they are clearly stated.
- **Probabilistic Risk Scoring**: Implements an independent risk union formula rather than naive linear summation.
- **RFC 3986 Safe Dissection**: URLs and payloads are parsed lexically without making outbound connections or downloading malicious payloads.
- **Portable Monorepo**: Operates out of the box locally using SQLite with no mandatory paid cloud subscriptions.

---

## 2. Technical Stack

| Tier | Technologies |
| :--- | :--- |
| **Frontend** | Next.js 14 (App Router), React 18, TypeScript, Tailwind CSS, Lucide Icons, Recharts |
| **Backend** | Python 3.11+, FastAPI, Pydantic v2, Uvicorn, HTTPX |
| **Machine Learning** | Scikit-learn (Random Forest Classifier), Joblib, Pandas, NumPy |
| **Database** | SQLite (Local default) / Supabase PostgreSQL (Production compatible) |
| **Testing** | Pytest, HTTPX TestClient (30 automated backend tests) |

---

## 3. Machine Learning Methodology & Metrics

The ML subsystem extracts 16 structural and lexical features from URLs:
- `url_length`, `hostname_length`, `path_length`
- `num_subdomains`, `num_dots`, `num_hyphens`, `num_underscores`, `num_slashes`, `num_digits`
- `has_ip_host`, `is_https`, `is_shortener`, `has_at_symbol`, `has_punycode`
- `hostname_entropy` (Shannon entropy)
- `keyword_count` (security and financial keywords)

### Model Performance Metrics (Actual Training Run)
The model was trained on a curated benchmark dataset of 130 URLs (80 legitimate, 50 phishing) with stratified train/test split:
- **Architecture**: `RandomForestClassifier(n_estimators=100, max_depth=10, class_weight='balanced')`
- **Accuracy**: 1.0000 (100%)
- **Precision**: 1.0000 (100%)
- **Recall**: 1.0000 (100%)
- **F1 Score**: 1.0000 (100%)
- **Confusion Matrix**:
  - True Negatives (TN): 20
  - False Positives (FP): 0
  - False Negatives (FN): 0
  - True Positives (TP): 13

> **Academic Limitation Note:** The perfect test score reflects the synthetic and curated nature of the initial training set. In live wild deployment, feature drift and novel evasion techniques will reduce empirical accuracy. PhishGuard AI treats ML inference as supplementary evidence rather than an absolute security verdict.

---

## 4. Getting Started & Local Development

### Prerequisites
- Python 3.11 or higher
- Node.js 18 or higher with npm

### 1. Backend Setup
```bash
# Navigate to backend
cd backend

# Create and activate virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run backend API server
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation will be accessible at `http://127.0.0.1:8000/docs`.

### 2. Frontend Setup
```bash
# Navigate to frontend in a new terminal
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```
The application will be live at `http://localhost:3000`.

---

## 5. Automated Verification & Tests

To execute the complete 30-test automated suite covering all analyzers, scoring formulas, and API endpoints:

```bash
# Set PYTHONPATH to include backend and ml
# PowerShell:
$env:PYTHONPATH = "backend;ml"
pytest tests/ -v

# Bash:
PYTHONPATH="backend:ml" pytest tests/ -v
```

### Test Coverage Summary:
- `test_url_analyzer.py`: 9 tests (benign URLs, IP hosts, excessive subdomains, credentials in URL, punycode homographs, shorteners, missing schemes, typosquatting, oversized URLs).
- `test_email_analyzer.py`: 5 tests (legitimate emails, urgent credential harvesting, sender/reply-to mismatch, display name spoofing, DMARC/SPF header failures).
- `test_message_analyzer.py`: 5 tests (benign SMS, postal delivery smishing, banking fraud, OTP theft, family impersonation).
- `test_risk_scoring.py`: 5 tests (zero findings, single findings, critical anchor enforcement, deduplication, 0-100 ceiling bounds).
- `test_api.py`: 6 tests (health check, URL scan, email scan, message scan, payload size limits, dashboard/history endpoints).

**Result: 30 passed in ~16s.**

---

## 6. Project Structure

```
phishguard-ai/
├── backend/
│   ├── app/
│   │   ├── api/             # API routes (scan, health, reports, demo)
│   │   ├── core/            # Configuration and environment settings
│   │   ├── database/        # SQLite / Postgres persistence layer
│   │   ├── schemas/         # Pydantic v2 data models
│   │   ├── services/        # Analyzers (URL, Email, Message, Scoring, Threat Intel)
│   │   └── main.py          # FastAPI application entrypoint
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── app/             # Next.js 14 App Router pages
│   │   │   ├── scanner/     # Multi-vector scanner interface
│   │   │   ├── dashboard/   # Threat analytics & Recharts visualizations
│   │   │   ├── history/     # Searchable scan history
│   │   │   ├── results/[id] # Forensic report detail view
│   │   │   └── about/       # Academic methodology and documentation
│   │   ├── components/      # Reusable UI components (Gauge, Badges, Cards)
│   │   ├── lib/             # API client and utilities
│   │   └── types/           # TypeScript schema interfaces
│   ├── package.json
│   └── tailwind.config.ts
├── ml/
│   ├── feature_extraction.py# 16-feature lexical extractor
│   ├── train.py             # Random Forest training script
│   └── models/              # Serialized joblib model & metrics.json
├── datasets/
│   └── phishing_urls_sample.csv # Curated training benchmark
├── docs/
│   └── architecture.md      # Detailed system diagram & data flow
├── tests/                   # 30 Pytest test suites
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

---

## 7. Security and Safe Inspection

PhishGuard AI enforces defensive development practices:
- **No Direct Fetching**: The engine does not issue outbound HTTP requests to user-submitted URLs, eliminating SSRF and payload execution hazards.
- **Size Limitation Middleware**: Large payloads (>1MB) are rejected to prevent Denial of Service.
- **Strict Headers**: Includes `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and restrictive `Referrer-Policy`.
- **Sanitized Reports**: Printable reports and JSON exports strictly escape user-provided inputs.

---

## 8. License

Distributed under the MIT License. See [LICENSE](LICENSE) for more details.
