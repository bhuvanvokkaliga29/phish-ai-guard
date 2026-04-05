# 🛡️ PhishAI Guard
## AI-Assisted Phishing & Fraud Detection Platform

> **Production-ready multi-agent AI system** for detecting phishing emails, malicious URLs, AML fraud patterns, and social engineering attacks — with full explainability.

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   PhishAI Guard Platform                │
├─────────────────────────────────────────────────────────┤
│  Frontend (HTML/CSS/JS)    │  Python Flask API Server   │
│  ─────────────────────     │  ──────────────────────    │
│  • Dark Cyberpunk UI       │  POST /api/analyze         │
│  • Live URL checker        │  GET  /api/history         │
│  • Real-time progress      │  GET  /api/stats           │
│  • Score ring animation    │  GET  /api/test-cases      │
│  • History & mini charts   │  GET  /health              │
├─────────────────────────────────────────────────────────┤
│              Multi-Agent AI Orchestrator                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ KeywordNLP   │  │URLIntelligen │  │EmailHeader   │  │
│  │ Agent ×1.4   │  │ce Agent ×1.6 │  │Agent ×1.2    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │AMLTransaction│  │Behavioral    │  │ThreatIntel   │  │
│  │Agent ×1.5    │  │Entropy ×0.9  │  │Agent ×1.3    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│              Weighted Ensemble Scorer                    │
│         Attack Classification Engine                    │
│         Explainability Generator                        │
└─────────────────────────────────────────────────────────┘
```

---

## 🤖 Agent Pipeline

### Agent 1: KeywordNLP Agent (weight ×1.4)
Analyzes text for phishing keywords, urgency language, brand impersonation, and grammar patterns.

**Feature extraction:**
- 4-tier keyword taxonomy (Critical/High/Medium/Low)
- 7 regex urgency patterns
- 12 brand impersonation targets
- Grammar anomaly detection (non-native phisher patterns)
- Exclamation abuse scoring

### Agent 2: URLIntelligence Agent (weight ×1.6)
Analyzes URLs for structural anomalies and threat indicators.

**Feature extraction:**
- HTTP vs HTTPS detection
- Suspicious TLD database (17 high-risk TLDs)
- IP-as-domain detection
- Shannon entropy analysis on domain names
- Homograph/punycode attack detection
- URL shortener identification
- Redirect chain detection
- Subdomain depth analysis

### Agent 3: EmailHeader Agent (weight ×1.2)
Validates email sender authenticity.

**Feature extraction:**
- Levenshtein distance for typosquatting (e.g., `paypa1.com` vs `paypal.com`)
- Free email + official language mismatch
- Auto-generated email pattern detection
- DKIM/SPF/DMARC validation (if headers provided)
- Reply-To mismatch detection

### Agent 4: AMLTransaction Agent (weight ×1.5)
Detects financial fraud using AML-inspired rule sets.

**Feature extraction:**
- CTR threshold check ($10,000 USD)
- Structuring/smurfing detection ($9,000–$10,000 range)
- SAR-level detection ($5,000+)
- Round-amount heuristic
- Transaction frequency analysis
- Layering pattern detection (high amount × high frequency)
- AML typology classification (Structuring, Layering, Integration)

### Agent 5: BehavioralEntropy Agent (weight ×0.9)
Analyzes text entropy and behavioral patterns.

**Feature extraction:**
- Shannon text entropy computation
- Word repetition frequency analysis
- Link-to-text ratio (phishing density)
- Special character density
- Sentence length distribution
- Capitalization abuse detection
- PII harvest attempt patterns (SSN, CVV, PIN, DOB, etc.)

### Agent 6: ThreatIntelligence Agent (weight ×1.3)
Matches against known threat databases.

**Feature extraction:**
- IOC (Indicator of Compromise) pattern matching
- Known phishing campaign fingerprinting
- Content MD5 fingerprinting
- Country-code origin risk scoring
- Campaign correlation (COVID, stimulus, IRS, shipping scams)

---

## 📊 Scoring Model

```python
# Weighted Ensemble Formula
weighted_score = Σ(agent_score × agent_weight) / Σ(weights)

# Confidence-weighted boost
boost = Σ(score × 0.1 for agents where confidence > 80% and score > 50%)
final = clamp(weighted_score + boost × 0.3, 0, 1)

# Risk Levels
0–19   → Safe       (green)
20–39  → Low Risk   (lime)
40–59  → Suspicious (yellow)
60–79  → High Risk  (orange)
80–100 → Critical   (red)
```

### Attack Classification

The system outputs probability scores for 6 attack types:
- **Phishing Email** — keyword + email + URL signals
- **URL/Link Fraud** — URL + threat intel signals
- **Financial Fraud (AML)** — transaction signals
- **Social Engineering** — keyword + entropy signals
- **Brand Impersonation** — email + threat intel signals
- **Malware Distribution** — URL + entropy signals

---

## 🚀 Quick Start

### Option 1: Python Server (Full AI Pipeline)

```bash
# Clone or extract the project
cd phishai-guard

# Install dependencies
pip install -r requirements.txt

# Start the server
python api/server.py

# Open browser
open http://localhost:5000
```

### Option 2: Static Only (Local Fallback Engine)

Just open `index.html` directly in any browser.
The JavaScript fallback engine will run locally without needing Python.

---

## ☁️ Deployment Guide

### Deploy on Render (Free, Recommended for Python)

1. Push to GitHub
2. Go to [render.com](https://render.com) → New Web Service
3. Connect repo
4. Build command: `pip install -r requirements.txt`
5. Start command: `python api/server.py`
6. Done! Free HTTPS URL provided.

### Deploy on Vercel (Static + Serverless)

```bash
npm install -g vercel

# In project root
vercel

# For local dev
vercel dev
```

Note: For Vercel, the Python backend needs to be adapted to serverless functions
(see `/api/analyze.js` for Node.js version).

### Deploy on Railway

```bash
# Install Railway CLI
npm install -g @railway/cli

railway login
railway init
railway up
```

---

## 📁 Project Structure

```
phishai-guard/
│
├── index.html              # Main UI
├── requirements.txt        # Python dependencies
├── README.md
│
├── static/
│   ├── css/
│   │   └── style.css       # Cyberpunk dark theme
│   └── js/
│       └── app.js          # Frontend logic + fallback engine
│
├── agents/
│   ├── __init__.py
│   └── orchestrator.py     # All 6 AI agents + ensemble
│
└── api/
    └── server.py           # Flask REST API
```

---

## 🧪 Test Cases

### 1. Phishing Email
```json
{
  "text": "URGENT: Your PayPal account has been suspended! Verify immediately!",
  "url": "http://paypa1-secure-verify.xyz/login",
  "sender_email": "security@paypa1-accounts.xyz"
}
```
**Expected:** Score 70-90, Level: High Risk/Critical

### 2. AML Transaction
```json
{
  "transaction": { "amount": 9500, "frequency": 8 },
  "sender_email": "finance@offshore-holdings.ru"
}
```
**Expected:** Score 60-80, Level: High Risk, Typology: Structuring

### 3. Legitimate Email
```json
{
  "text": "Hi, please review the Q3 report.",
  "url": "https://docs.google.com/spreadsheets/d/abc123",
  "sender_email": "sarah.jones@company.com",
  "transaction": { "amount": 250, "frequency": 1 }
}
```
**Expected:** Score 0-20, Level: Safe

---

## ⚠️ Limitations

1. **Rule-based scoring** — not a trained ML model; false positives possible
2. **No real-time threat feeds** — simulated IOC database
3. **No WHOIS/DNS lookup** — URL analysis is structural only
4. **No email header parsing** — header analysis requires raw headers
5. **Transaction context** — no historical baseline per user

---

## 🔮 Future Improvements

| Feature | Technology |
|---------|-----------|
| Trained ML classifier | XGBoost / LightGBM on PhishTank dataset |
| Real-time IOC feeds | VirusTotal API, AbuseIPDB |
| BERT-based NLP | HuggingFace transformers |
| WHOIS / DNS lookup | python-whois, dnspython |
| Email header parser | email.parser stdlib |
| User baseline profiling | Redis time-series |
| Graph-based AML | NetworkX + Neo4j |
| SHAP explainability | shap library |

---

## 👨‍💻 Built By

**Bhuvan Vokkaliga** — AI & ML Engineer, Full-Stack Developer  
AMC Engineering College, Bengaluru |founder @ Webi
GitHub: [bhuvanvokkaliga29](https://github.com/bhuvanvokkaliga29)

---

## 📄 License

MIT License — Free to use, modify, and deploy.
