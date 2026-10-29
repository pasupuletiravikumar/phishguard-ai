# PhishGuard AI System Architecture

## Overview
PhishGuard AI is an enterprise-grade phishing detection and threat analysis platform. It features a modern decoupled architecture separating the analytical backend engines from the user-facing web interface.

```
                              ┌────────────────────────────────────────────────┐
                              │           User Browser / SOC Analyst           │
                              └───────────────────────┬────────────────────────┘
                                                      │ HTTPS / JSON
                                                      ▼
                              ┌────────────────────────────────────────────────┐
                              │            Next.js 14 Frontend Client          │
                              │ (Tailwind CSS, Lucide Icons, Recharts, AppDir) │
                              └───────────────────────┬────────────────────────┘
                                                      │ REST API (/api/scan, /api/dashboard)
                                                      ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       FastAPI Backend Engine                                           │
│                                                                                                        │
│  ┌───────────────────────┐  ┌────────────────────────┐  ┌───────────────────────────────────────────┐  │
│  │ Security Middleware   │  │  Pydantic Schemas      │  │ Threat Intelligence Cache                 │  │
│  │ (CORS, Size, Headers) │  │  (Strict Validation)   │  │ (1-hour TTL, VirusTotal, Safe Browsing)   │  │
│  └───────────────────────┘  └────────────────────────┘  └───────────────────────────────────────────┘  │
│                                                                                                        │
│  ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │                                 Multi-Vector Detection Pipeline                                  │  │
│  │                                                                                                  │  │
│  │  ┌────────────────────────┐  ┌────────────────────────┐  ┌────────────────────────────────────┐  │  │
│  │  │      URL Analyzer      │  │     Email Analyzer     │  │          Message Analyzer          │  │  │
│  │  │ (Lexical, Typosquat,   │  │ (Urgency, Credential   │  │ (Smishing Patterns, Delivery Scam, │  │  │
│  │  │  Entropy, Punycode)    │  │  Harvest, Spoofing)    │  │  Banking Fraud, Shortlink Hunt)    │  │  │
│  │  └───────────┬────────────┘  └───────────┬────────────┘  └─────────────────┬──────────────────┘  │  │
│  │              │                           │                                 │                     │  │
│  │              └───────────────────────────┼─────────────────────────────────┘                     │  │
│  │                                          ▼                                                       │  │
│  │                       ┌─────────────────────────────────────┐                                    │  │
│  │                       │   Probabilistic Risk Scoring Engine │                                    │  │
│  │                       │   (Independent Union, Severity Caps)│                                    │  │
│  │                       └──────────────────┬──────────────────┘                                    │  │
│  │                                          │                                                       │  │
│  │                                          ▼                                                       │  │
│  │                       ┌─────────────────────────────────────┐                                    │  │
│  │                       │ Random Forest Classifier (Optional) │                                    │  │
│  │                       │ (16 Lexical/Structural URL Features)│                                    │  │
│  │                       └──────────────────┬──────────────────┘                                    │  │
│  └──────────────────────────────────────────┼───────────────────────────────────────────────────────┘  │
│                                             ▼                                                          │
│  ┌──────────────────────────────────────────────────────────────────────────────────────────────────┐  │
│  │ SQLite Scan Store / Optional Managed Supabase Postgres                                           │  │
│  └──────────────────────────────────────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Key Detection Components

### 1. URL Analysis Engine (`backend/app/services/url_analyzer.py`)
- **RFC 3986 Lexical Breakdown**: Dissects scheme, authority, path, query, and fragments without network execution.
- **Punycode / Homograph Detection**: Flags ASCII representations of internationalized domains (IDNs) commonly used in visual spoofing.
- **Shannon Entropy**: Measures randomness in hostname strings to flag algorithmically generated domains (DGA).
- **Typosquatting & Lookalikes**: Levenshtein comparison against 18 prominent target services (Google, PayPal, Apple, Microsoft, Amazon, etc.).
- **URL Shortener Detection**: Curated registry of known redirection and shortening platforms.

### 2. Email Forensics Engine (`backend/app/services/email_analyzer.py`)
- **Social Engineering Urgency Matching**: RegEx matching for artificial deadlines, account suspension threats, and coercive language.
- **Credential Harvesting Signals**: Detects sensitive form keywords (passwords, MFA codes, OTPs, PINs).
- **Header Impersonation**: Compares sender display names against actual domain origins, detects mismatching Reply-To headers, and checks SPF/DKIM/DMARC headers.

### 3. SMS & Smishing Engine (`backend/app/services/message_analyzer.py`)
- Analyzes short-form messages for package delivery notifications, banking urgent actions, and shortened link traps.

### 4. Probabilistic Risk Scoring Engine (`backend/app/services/risk_scoring.py`)
Rather than linear summation which causes score inflation, the score uses an independent risk union formula:
$$R = 1 - \prod_{i=1}^{n} (1 - w_i)$$
Where $w_i$ represents normalized weights bounded between 0.05 and 0.85 based on severity (LOW, MODERATE, HIGH, CRITICAL). This guarantees mathematical monotonicity, prevents score saturation from repetitive low-grade findings, and enforces severity baselines (e.g. CRITICAL findings automatically anchor scores $\ge 75$).
