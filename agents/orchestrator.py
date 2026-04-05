"""
PhishAI Guard – Multi-Agent AI Orchestrator
============================================
Coordinates specialized sub-agents for comprehensive threat analysis.
Each agent is responsible for a distinct domain of fraud/phishing detection.
"""

import asyncio
import json
import re
import math
import hashlib
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import urllib.parse


# ──────────────────────────────────────────────
# DATA MODELS
# ──────────────────────────────────────────────

@dataclass
class AgentSignal:
    agent: str
    score: float          # 0.0 – 1.0
    confidence: float     # 0.0 – 1.0
    findings: List[str]
    evidence: Dict        # raw evidence items
    weight: float = 1.0   # agent weight in ensemble


@dataclass
class AnalysisRequest:
    text: str = ""
    url: str = ""
    transaction_amount: float = 0.0
    transaction_frequency: int = 0
    sender_email: str = ""
    headers: Dict = field(default_factory=dict)
    session_id: str = ""


@dataclass
class AnalysisResult:
    final_score: int        # 0–100
    risk_level: str         # Safe / Suspicious / High Risk / Critical
    risk_color: str
    confidence: float
    signals: List[AgentSignal]
    explanation: List[str]
    attack_type: str
    attack_probability: Dict[str, float]
    recommendations: List[str]
    threat_intel: Dict
    processing_time_ms: int
    timestamp: str


# ──────────────────────────────────────────────
# BASE AGENT
# ──────────────────────────────────────────────

class BaseAgent:
    name: str = "BaseAgent"
    weight: float = 1.0

    def analyze(self, request: AnalysisRequest) -> AgentSignal:
        raise NotImplementedError

    def _clamp(self, val: float, lo=0.0, hi=1.0) -> float:
        return max(lo, min(hi, val))


# ──────────────────────────────────────────────
# AGENT 1 – KEYWORD & NLP AGENT
# ──────────────────────────────────────────────

class KeywordNLPAgent(BaseAgent):
    name = "KeywordNLP"
    weight = 1.4

    PHISHING_KEYWORDS = {
        # Critical triggers (weight 0.25)
        "critical": [
            "verify your account", "confirm your identity", "click here immediately",
            "your account will be suspended", "unusual activity detected",
            "update your payment", "your password has expired"
        ],
        # High risk (weight 0.18)
        "high": [
            "urgent", "immediately", "password", "ssn", "social security",
            "wire transfer", "bitcoin", "gift card", "prize winner",
            "limited time", "act now", "verify", "suspended", "blocked"
        ],
        # Medium risk (weight 0.10)
        "medium": [
            "click here", "login", "bank account", "credit card", "refund",
            "invoice", "payment required", "congratulations", "selected",
            "free", "offer", "claim", "reward", "bonus"
        ],
        # Low risk (weight 0.04)
        "low": [
            "account", "security", "update", "confirm", "access",
            "important", "notice", "required", "attention"
        ]
    }

    URGENCY_PATTERNS = [
        r"\b(within \d+ hours?)\b",
        r"\b(expires? (today|now|soon|immediately))\b",
        r"\b(last chance)\b",
        r"\b(final (notice|warning|reminder))\b",
        r"!!+",
        r"[A-Z]{5,}",    # SCREAMING CAPS
    ]

    GRAMMAR_PATTERNS = [
        r"\b(kindly|do the needful|revert back|please to)\b",
        r"(dear (customer|user|friend|valued))",
        r"\b(irregardless|supposably|expresso)\b",
    ]

    def analyze(self, request: AnalysisRequest) -> AgentSignal:
        text = (request.text + " " + request.sender_email).lower()
        score = 0.0
        findings = []
        evidence = {"keywords": [], "patterns": [], "urgency_count": 0}

        # Keyword scoring
        for level, keywords in self.PHISHING_KEYWORDS.items():
            weights = {"critical": 0.25, "high": 0.18, "medium": 0.10, "low": 0.04}
            w = weights[level]
            for kw in keywords:
                if kw.lower() in text:
                    score += w
                    evidence["keywords"].append({"keyword": kw, "level": level, "weight": w})
                    findings.append(f"🔴 [{level.upper()}] Phishing keyword detected: '{kw}'")

        # Urgency pattern scoring
        urgency_hits = 0
        for pattern in self.URGENCY_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                urgency_hits += len(matches)
                score += 0.08 * len(matches)
                evidence["patterns"].append({"pattern": pattern, "matches": matches})
        evidence["urgency_count"] = urgency_hits
        if urgency_hits > 2:
            findings.append(f"⚠️ High urgency language detected ({urgency_hits} indicators)")

        # Grammar / non-native patterns
        for pattern in self.GRAMMAR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                score += 0.06
                findings.append("🔍 Suspicious grammar pattern (possible non-native phisher)")

        # Excessive punctuation / emoji spam
        excl_count = text.count("!")
        if excl_count > 3:
            score += min(0.12, excl_count * 0.02)
            findings.append(f"⚠️ Excessive exclamation marks ({excl_count} found)")

        # Impersonation check
        brands = ["paypal", "amazon", "google", "microsoft", "apple", "netflix",
                  "irs", "fedex", "ups", "bank of america", "chase", "wells fargo"]
        impersonated = [b for b in brands if b in text]
        if impersonated:
            score += 0.20 * len(impersonated)
            findings.append(f"🚨 Brand impersonation detected: {', '.join(impersonated)}")
            evidence["impersonated_brands"] = impersonated

        confidence = min(0.95, 0.5 + score * 0.4) if score > 0 else 0.3
        return AgentSignal(
            agent=self.name,
            score=self._clamp(score),
            confidence=confidence,
            findings=findings if findings else ["✅ No suspicious keywords detected"],
            evidence=evidence,
            weight=self.weight
        )


# ──────────────────────────────────────────────
# AGENT 2 – URL & DOMAIN INTELLIGENCE AGENT
# ──────────────────────────────────────────────

class URLIntelligenceAgent(BaseAgent):
    name = "URLIntelligence"
    weight = 1.6

    SUSPICIOUS_TLDS = {
        ".xyz": 0.30, ".tk": 0.35, ".ml": 0.28, ".ga": 0.28, ".cf": 0.28,
        ".gq": 0.28, ".ru": 0.22, ".cn": 0.18, ".pw": 0.32, ".top": 0.20,
        ".club": 0.15, ".work": 0.18, ".date": 0.25, ".review": 0.25,
        ".click": 0.30, ".download": 0.35, ".stream": 0.25
    }

    LEGIT_TLDS = {".com", ".org", ".edu", ".gov", ".net", ".io", ".co.uk"}

    SUSPICIOUS_KEYWORDS_IN_URL = [
        "login", "verify", "secure", "account", "update", "confirm",
        "banking", "paypal", "amazon", "microsoft", "apple", "google",
        "password", "credential", "auth", "signin", "wallet"
    ]

    SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
                  "tiny.cc", "rb.gy", "is.gd", "buff.ly", "cutt.ly"]

    def analyze(self, request: AnalysisRequest) -> AgentSignal:
        url = request.url.strip()
        # Also extract URLs from text
        text_urls = re.findall(
            r'https?://[^\s<>"]+|www\.[^\s<>"]+', request.text
        )
        all_urls = ([url] if url else []) + text_urls

        if not all_urls:
            return AgentSignal(
                agent=self.name, score=0.0, confidence=0.2,
                findings=["ℹ️ No URL provided for analysis"],
                evidence={}, weight=self.weight
            )

        findings = []
        evidence = {"urls_analyzed": [], "flags": []}
        total_score = 0.0

        for raw_url in all_urls[:5]:  # Analyze up to 5 URLs
            url_score, url_findings, url_evidence = self._analyze_single_url(raw_url)
            total_score += url_score
            findings.extend(url_findings)
            evidence["urls_analyzed"].append({"url": raw_url[:80], **url_evidence})

        total_score = self._clamp(total_score)
        confidence = 0.85 if total_score > 0.3 else 0.6
        return AgentSignal(
            agent=self.name,
            score=total_score,
            confidence=confidence,
            findings=findings if findings else ["✅ URLs appear legitimate"],
            evidence=evidence,
            weight=self.weight
        )

    def _analyze_single_url(self, url: str) -> Tuple[float, List[str], Dict]:
        score = 0.0
        findings = []
        evidence = {}

        # Normalize
        if not url.startswith("http"):
            url = "http://" + url

        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return 0.1, ["⚠️ Malformed URL detected"], {"error": "parse_failed"}

        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        full = url.lower()

        # HTTP (not HTTPS)
        if url.startswith("http://"):
            score += 0.18
            findings.append("🔴 Insecure HTTP connection (not HTTPS)")
            evidence["protocol"] = "http"

        # Suspicious TLD
        for tld, w in self.SUSPICIOUS_TLDS.items():
            if domain.endswith(tld):
                score += w
                findings.append(f"🔴 High-risk TLD detected: '{tld}'")
                evidence["suspicious_tld"] = tld
                break

        # URL shortener
        for shortener in self.SHORTENERS:
            if shortener in domain:
                score += 0.25
                findings.append(f"⚠️ URL shortener detected ({shortener}) — destination hidden")
                evidence["shortener"] = shortener
                break

        # IP address as domain
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            score += 0.35
            findings.append("🚨 IP address used as domain (common in phishing)")
            evidence["ip_as_domain"] = True

        # Excessive subdomains
        subdomain_count = domain.count(".")
        if subdomain_count > 3:
            score += 0.15
            findings.append(f"⚠️ Excessive subdomains ({subdomain_count} dots) — obfuscation tactic")
            evidence["subdomain_depth"] = subdomain_count

        # Brand name in subdomain (not official)
        for kw in self.SUSPICIOUS_KEYWORDS_IN_URL:
            if kw in domain and kw not in ["login", "auth"]:
                score += 0.12
                findings.append(f"🔍 Brand/service name '{kw}' in domain — possible spoofing")

        # Suspicious keywords in path/query
        for kw in self.SUSPICIOUS_KEYWORDS_IN_URL:
            if kw in path or kw in query:
                score += 0.07
                findings.append(f"🔍 Suspicious path keyword: '{kw}'")

        # URL length (very long = encoded payload)
        url_len = len(url)
        if url_len > 200:
            score += 0.20
            findings.append(f"⚠️ Unusually long URL ({url_len} chars) — possible obfuscation")
            evidence["url_length"] = url_len
        elif url_len > 100:
            score += 0.08

        # Entropy analysis (random-looking domain)
        domain_part = domain.split(".")[0]
        entropy = self._entropy(domain_part)
        evidence["domain_entropy"] = round(entropy, 2)
        if entropy > 3.8 and len(domain_part) > 8:
            score += 0.20
            findings.append(f"🔍 High-entropy domain name (entropy={entropy:.2f}) — likely generated")

        # Homograph / punycode attack
        if "xn--" in domain:
            score += 0.40
            findings.append("🚨 Punycode/homograph domain detected — visual spoofing attack")

        # Multiple redirects encoded in URL
        if url.count("http") > 1:
            score += 0.25
            findings.append("🚨 Redirect chain detected in URL — evasion technique")

        return self._clamp(score), findings, evidence

    def _entropy(self, s: str) -> float:
        if not s:
            return 0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((f/n) * math.log2(f/n) for f in freq.values())


# ──────────────────────────────────────────────
# AGENT 3 – EMAIL HEADER & METADATA AGENT
# ──────────────────────────────────────────────

class EmailHeaderAgent(BaseAgent):
    name = "EmailHeader"
    weight = 1.2

    def analyze(self, request: AnalysisRequest) -> AgentSignal:
        email = request.sender_email.lower().strip()
        text = request.text.lower()
        score = 0.0
        findings = []
        evidence = {}

        if not email and not request.headers:
            # Try to extract from text
            emails_in_text = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
            if emails_in_text:
                email = emails_in_text[0].lower()
                evidence["extracted_email"] = email
            else:
                return AgentSignal(
                    agent=self.name, score=0.0, confidence=0.2,
                    findings=["ℹ️ No email address or headers provided"],
                    evidence={}, weight=self.weight
                )

        if email:
            evidence["sender"] = email
            domain = email.split("@")[-1] if "@" in email else ""
            
            # Free email services sending "official" messages
            free_domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
                          "protonmail.com", "mail.ru", "yandex.com", "aol.com"]
            official_terms = ["bank", "paypal", "amazon", "apple", "microsoft",
                            "irs", "gov", "security", "support", "noreply"]
            
            is_free = any(d == domain for d in free_domains)
            has_official_term = any(t in email for t in official_terms)
            
            if is_free and has_official_term:
                score += 0.40
                findings.append(f"🚨 Official-sounding email from free provider ({domain})")
            
            # Typosquatting check
            legit_domains = ["paypal.com", "amazon.com", "google.com", "microsoft.com",
                           "apple.com", "netflix.com", "facebook.com"]
            for legit in legit_domains:
                if domain != legit and self._levenshtein(domain, legit) <= 2 and len(domain) > 4:
                    score += 0.45
                    findings.append(f"🚨 Typosquatted domain! '{domain}' looks like '{legit}'")
                    evidence["typosquat_target"] = legit

            # Numeric or random-looking local part
            local = email.split("@")[0] if "@" in email else email
            if re.match(r'^[a-z]{2,4}\d{4,}', local):
                score += 0.15
                findings.append(f"⚠️ Auto-generated email pattern detected: '{local}'")

            # Display name mismatch (name says PayPal but domain is random)
            display_name_match = re.search(r'(paypal|amazon|bank|apple|google)', text[:200])
            if display_name_match and is_free:
                score += 0.20
                findings.append("🔍 Display name implies trusted entity but sent from free email")

        # Header analysis
        headers = request.headers
        if headers:
            if not headers.get("dkim", True):
                score += 0.25
                findings.append("🔴 DKIM signature missing or failed")
            if not headers.get("spf", True):
                score += 0.25
                findings.append("🔴 SPF record check failed")
            if not headers.get("dmarc", True):
                score += 0.20
                findings.append("🔴 DMARC policy not met")
            reply_to = headers.get("reply_to", "")
            if reply_to and email and reply_to != email:
                score += 0.30
                findings.append(f"🚨 Reply-To mismatch: replies go to '{reply_to}' not sender")

        confidence = 0.80 if score > 0 else 0.4
        return AgentSignal(
            agent=self.name,
            score=self._clamp(score),
            confidence=confidence,
            findings=findings if findings else ["✅ Email headers appear legitimate"],
            evidence=evidence,
            weight=self.weight
        )

    def _levenshtein(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                               prev[j] + (c1 != c2)))
            prev = curr
        return prev[-1]


# ──────────────────────────────────────────────
# AGENT 4 – AML TRANSACTION AGENT
# ──────────────────────────────────────────────

class AMLTransactionAgent(BaseAgent):
    name = "AMLTransaction"
    weight = 1.5

    # Thresholds from AML research
    CTR_THRESHOLD = 10000     # Currency Transaction Report threshold (USD)
    SAR_THRESHOLD = 5000      # Suspicious Activity Report consideration
    STRUCTURING_THRESHOLD = 9000   # Below CTR to avoid reporting

    def analyze(self, request: AnalysisRequest) -> AgentSignal:
        amount = request.transaction_amount
        frequency = request.transaction_frequency

        if amount == 0 and frequency == 0:
            return AgentSignal(
                agent=self.name, score=0.0, confidence=0.2,
                findings=["ℹ️ No transaction data provided"],
                evidence={}, weight=self.weight
            )

        score = 0.0
        findings = []
        evidence = {
            "amount": amount,
            "frequency": frequency,
            "flags": []
        }

        # ── Amount-based rules ──
        if amount >= self.CTR_THRESHOLD:
            score += 0.35
            findings.append(f"🚨 Transaction exceeds CTR threshold (${amount:,.0f} ≥ $10,000)")
            evidence["flags"].append("CTR_THRESHOLD")

        elif self.STRUCTURING_THRESHOLD <= amount < self.CTR_THRESHOLD:
            score += 0.45  # Structuring is MORE suspicious
            findings.append(f"🚨 Possible structuring: amount ${amount:,.0f} just below $10K reporting threshold")
            evidence["flags"].append("STRUCTURING")

        elif amount >= self.SAR_THRESHOLD:
            score += 0.20
            findings.append(f"⚠️ Amount ${amount:,.0f} warrants Suspicious Activity Report review")
            evidence["flags"].append("SAR_THRESHOLD")

        elif amount > 1000:
            score += 0.08

        # Round number check (common in fraud)
        if amount > 0 and amount % 1000 == 0:
            score += 0.10
            findings.append(f"🔍 Suspiciously round amount (${amount:,.0f}) — common in laundering")
            evidence["flags"].append("ROUND_AMOUNT")

        # ── Frequency-based rules ──
        if frequency >= 10:
            score += 0.40
            findings.append(f"🚨 Extremely high transaction frequency ({frequency}/day) — layering pattern")
            evidence["flags"].append("HIGH_FREQUENCY")
        elif frequency >= 5:
            score += 0.25
            findings.append(f"⚠️ High transaction frequency ({frequency}/day)")
        elif frequency >= 3:
            score += 0.12

        # ── Combined pattern rules ──
        if amount >= self.SAR_THRESHOLD and frequency >= 5:
            score += 0.20
            findings.append("🚨 High-amount + high-frequency combo — classic layering pattern")
            evidence["flags"].append("LAYERING_PATTERN")

        if amount > 0 and frequency > 1 and amount * frequency > 50000:
            score += 0.15
            daily_volume = amount * frequency
            findings.append(f"⚠️ Daily transaction volume ${daily_volume:,.0f} — unusually high")
            evidence["daily_volume"] = daily_volume

        # AML typology scoring
        typologies = []
        if "STRUCTURING" in evidence["flags"]:
            typologies.append("Structuring/Smurfing")
        if "LAYERING_PATTERN" in evidence["flags"]:
            typologies.append("Layering")
        if "HIGH_FREQUENCY" in evidence["flags"] and "ROUND_AMOUNT" in evidence["flags"]:
            typologies.append("Integration Phase Activity")
        
        if typologies:
            evidence["aml_typologies"] = typologies
            findings.append(f"🔴 Matched AML typologies: {', '.join(typologies)}")

        confidence = 0.85 if score > 0.3 else 0.55
        return AgentSignal(
            agent=self.name,
            score=self._clamp(score),
            confidence=confidence,
            findings=findings if findings else ["✅ Transaction patterns appear normal"],
            evidence=evidence,
            weight=self.weight
        )


# ──────────────────────────────────────────────
# AGENT 5 – BEHAVIORAL ENTROPY AGENT
# ──────────────────────────────────────────────

class BehavioralEntropyAgent(BaseAgent):
    """Analyzes text entropy, structure and behavioral anomalies"""
    name = "BehavioralEntropy"
    weight = 0.9

    def analyze(self, request: AnalysisRequest) -> AgentSignal:
        text = request.text
        if not text:
            return AgentSignal(
                agent=self.name, score=0.0, confidence=0.2,
                findings=["ℹ️ No text for behavioral analysis"],
                evidence={}, weight=self.weight
            )

        score = 0.0
        findings = []
        evidence = {}

        # Text entropy (randomness)
        entropy = self._text_entropy(text)
        evidence["text_entropy"] = round(entropy, 3)

        # Word repetition (spammers repeat key phrases)
        words = re.findall(r'\b\w+\b', text.lower())
        if words:
            word_freq = {}
            for w in words:
                if len(w) > 4:
                    word_freq[w] = word_freq.get(w, 0) + 1
            repeated = {w: c for w, c in word_freq.items() if c > 3}
            if repeated:
                score += min(0.25, len(repeated) * 0.08)
                findings.append(f"⚠️ Repetitive language detected: {list(repeated.keys())[:3]}")
                evidence["repeated_words"] = repeated

        # Link-to-text ratio (phishing emails have many links)
        link_count = len(re.findall(r'https?://\S+', text))
        word_count = len(words)
        if word_count > 0:
            ratio = link_count / max(word_count, 1)
            evidence["link_ratio"] = round(ratio, 3)
            if ratio > 0.05:
                score += 0.20
                findings.append(f"🔍 High link density ({link_count} links in {word_count} words)")

        # Emoji / special character density
        special_count = len(re.findall(r'[^\w\s]', text))
        if len(text) > 0:
            special_ratio = special_count / len(text)
            if special_ratio > 0.15:
                score += 0.12
                findings.append(f"⚠️ Unusual special character density ({special_ratio:.1%})")

        # Sentence length analysis
        sentences = re.split(r'[.!?]+', text)
        sentences = [s.strip() for s in sentences if len(s.strip()) > 5]
        if sentences:
            avg_len = sum(len(s) for s in sentences) / len(sentences)
            evidence["avg_sentence_length"] = round(avg_len, 1)
            if avg_len < 20:
                score += 0.08
                findings.append("🔍 Abnormally short sentences — telegram-style phishing pattern")

        # Capitalization abuse
        caps_words = len(re.findall(r'\b[A-Z]{3,}\b', text))
        if caps_words > 5:
            score += min(0.15, caps_words * 0.02)
            findings.append(f"⚠️ Excessive capitalization ({caps_words} ALL-CAPS words)")
            evidence["caps_abuse"] = caps_words

        # Personal information requests
        pii_patterns = [
            (r'\b(ssn|social security)\b', "SSN request", 0.35),
            (r'\b(credit card|card number|cvv)\b', "Credit card data request", 0.30),
            (r'\b(date of birth|dob)\b', "Date of birth request", 0.20),
            (r'\b(mother.?s maiden name)\b', "Security question harvest", 0.25),
            (r'\b(pin|passcode)\b', "PIN request", 0.30),
        ]
        for pattern, label, weight in pii_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                score += weight
                findings.append(f"🚨 PII harvest attempt: {label}")

        confidence = min(0.85, 0.4 + score * 0.6)
        return AgentSignal(
            agent=self.name,
            score=self._clamp(score),
            confidence=confidence,
            findings=findings if findings else ["✅ Text behavior appears normal"],
            evidence=evidence,
            weight=self.weight
        )

    def _text_entropy(self, text: str) -> float:
        if not text:
            return 0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        n = len(text)
        return -sum((f/n) * math.log2(f/n) for f in freq.values())


# ──────────────────────────────────────────────
# AGENT 6 – THREAT INTELLIGENCE AGENT
# ──────────────────────────────────────────────

class ThreatIntelAgent(BaseAgent):
    """Simulates threat intel lookup against known IOC databases"""
    name = "ThreatIntel"
    weight = 1.3

    # Simulated threat intel database
    KNOWN_MALICIOUS_PATTERNS = [
        "paypa1.com", "amaz0n.com", "g00gle.com", "micros0ft.com",
        "appie.com", "faceb00k.com", "netf1ix.com"
    ]
    KNOWN_PHISHING_CAMPAIGNS = [
        ("covid", "COVID-19 phishing campaign"),
        ("stimulus", "Government stimulus phishing"),
        ("irs refund", "IRS refund scam"),
        ("package delivery", "Shipping notification scam"),
        ("account suspended", "Account takeover campaign"),
    ]

    def analyze(self, request: AnalysisRequest) -> AgentSignal:
        text = (request.text + " " + request.url + " " + request.sender_email).lower()
        score = 0.0
        findings = []
        evidence = {"matches": [], "campaigns": []}

        # Check against known malicious patterns
        for pattern in self.KNOWN_MALICIOUS_PATTERNS:
            if pattern in text:
                score += 0.50
                findings.append(f"🚨 THREAT INTEL: Known malicious domain '{pattern}' detected")
                evidence["matches"].append(pattern)

        # Campaign matching
        for keyword, campaign_name in self.KNOWN_PHISHING_CAMPAIGNS:
            if keyword in text:
                score += 0.20
                findings.append(f"🔴 Matches known phishing campaign: '{campaign_name}'")
                evidence["campaigns"].append(campaign_name)

        # Hash-based fingerprinting (simulate IOC match)
        text_hash = hashlib.md5(text[:100].encode()).hexdigest()[:8]
        evidence["content_fingerprint"] = text_hash

        # Geolocation simulation based on TLD
        risky_countries = [".ru", ".cn", ".ng", ".pk"]
        for cc in risky_countries:
            if cc in request.url.lower() or cc in request.sender_email.lower():
                score += 0.15
                findings.append(f"⚠️ Origin country code '{cc}' associated with phishing campaigns")

        confidence = 0.75 if score > 0 else 0.4
        return AgentSignal(
            agent=self.name,
            score=self._clamp(score),
            confidence=confidence,
            findings=findings if findings else ["✅ No matches in threat intelligence database"],
            evidence=evidence,
            weight=self.weight
        )


# ──────────────────────────────────────────────
# ENSEMBLE ORCHESTRATOR
# ──────────────────────────────────────────────

class PhishAIOrchestrator:
    """
    Multi-agent ensemble orchestrator.
    Runs all agents in parallel, combines scores via weighted ensemble,
    and generates a comprehensive threat report.
    """

    def __init__(self):
        self.agents = [
            KeywordNLPAgent(),
            URLIntelligenceAgent(),
            EmailHeaderAgent(),
            AMLTransactionAgent(),
            BehavioralEntropyAgent(),
            ThreatIntelAgent(),
        ]

    def analyze(self, request: AnalysisRequest) -> AnalysisResult:
        start_time = time.time()

        # Run all agents
        signals: List[AgentSignal] = []
        for agent in self.agents:
            try:
                signal = agent.analyze(request)
                signals.append(signal)
            except Exception as e:
                signals.append(AgentSignal(
                    agent=agent.name, score=0, confidence=0,
                    findings=[f"Agent error: {str(e)}"], evidence={},
                    weight=agent.weight
                ))

        # Weighted ensemble scoring
        total_weight = sum(s.weight for s in signals)
        weighted_score = sum(s.score * s.weight for s in signals) / total_weight if total_weight > 0 else 0

        # Confidence-weighted adjustment
        avg_confidence = sum(s.confidence for s in signals) / len(signals)
        
        # Boost for high-confidence signals
        high_conf_boost = sum(
            s.score * 0.1 for s in signals 
            if s.confidence > 0.8 and s.score > 0.5
        )
        
        final_raw = self._clamp(weighted_score + high_conf_boost * 0.3)
        final_score = int(final_raw * 100)

        # Risk level
        risk_level, risk_color = self._risk_level(final_score)

        # Attack type classification
        attack_type, attack_probs = self._classify_attack(signals, request)

        # Consolidate findings
        all_findings = []
        for sig in signals:
            for finding in sig.findings:
                if "✅" not in finding or final_score < 20:
                    all_findings.append(finding)

        # Deduplicate
        seen = set()
        unique_findings = []
        for f in all_findings:
            key = f[:50]
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        # Recommendations
        recommendations = self._generate_recommendations(final_score, signals, attack_type)

        # Threat intel summary
        threat_intel = self._build_threat_intel(signals, final_score)

        processing_time = int((time.time() - start_time) * 1000)

        return AnalysisResult(
            final_score=final_score,
            risk_level=risk_level,
            risk_color=risk_color,
            confidence=round(avg_confidence, 2),
            signals=signals,
            explanation=unique_findings[:20],  # Top 20 findings
            attack_type=attack_type,
            attack_probability=attack_probs,
            recommendations=recommendations,
            threat_intel=threat_intel,
            processing_time_ms=processing_time,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

    def _clamp(self, v: float) -> float:
        return max(0.0, min(1.0, v))

    def _risk_level(self, score: int) -> Tuple[str, str]:
        if score < 20:
            return "Safe", "#00ff88"
        elif score < 40:
            return "Low Risk", "#88ff00"
        elif score < 60:
            return "Suspicious", "#ffcc00"
        elif score < 80:
            return "High Risk", "#ff6600"
        else:
            return "Critical", "#ff0033"

    def _classify_attack(self, signals: List[AgentSignal], request: AnalysisRequest) -> Tuple[str, Dict]:
        url_score = next((s.score for s in signals if s.agent == "URLIntelligence"), 0)
        keyword_score = next((s.score for s in signals if s.agent == "KeywordNLP"), 0)
        aml_score = next((s.score for s in signals if s.agent == "AMLTransaction"), 0)
        email_score = next((s.score for s in signals if s.agent == "EmailHeader"), 0)
        entropy_score = next((s.score for s in signals if s.agent == "BehavioralEntropy"), 0)
        intel_score = next((s.score for s in signals if s.agent == "ThreatIntel"), 0)

        probs = {
            "Phishing Email": round((keyword_score * 0.4 + email_score * 0.4 + url_score * 0.2) * 100, 1),
            "URL/Link Fraud": round((url_score * 0.6 + intel_score * 0.4) * 100, 1),
            "Financial Fraud (AML)": round(aml_score * 100, 1),
            "Social Engineering": round((keyword_score * 0.5 + entropy_score * 0.5) * 100, 1),
            "Brand Impersonation": round((email_score * 0.5 + intel_score * 0.5) * 100, 1),
            "Malware Distribution": round((url_score * 0.7 + entropy_score * 0.3) * 100, 1),
        }

        attack_type = max(probs, key=probs.get)
        if max(probs.values()) < 15:
            attack_type = "No Threat Detected"

        return attack_type, probs

    def _generate_recommendations(self, score: int, signals: List[AgentSignal], attack_type: str) -> List[str]:
        recs = []

        if score >= 60:
            recs.append("🛡️ DO NOT click any links or download attachments")
            recs.append("🛡️ Do not provide any personal or financial information")
            recs.append("🛡️ Report this to your security team immediately")

        if score >= 40:
            recs.append("⚠️ Verify the sender through an official channel before responding")
            recs.append("⚠️ Cross-check the URL by navigating directly to the official website")

        if "AMLTransaction" in [s.agent for s in signals if s.score > 0.3]:
            recs.append("💰 File a Suspicious Activity Report (SAR) if applicable")
            recs.append("💰 Freeze any related accounts pending investigation")

        if "URLIntelligence" in [s.agent for s in signals if s.score > 0.3]:
            recs.append("🌐 Block the domain at your DNS/firewall level")
            recs.append("🌐 Submit the URL to Google Safe Browsing for review")

        if score < 30:
            recs.append("✅ Content appears legitimate — standard caution applies")
            recs.append("✅ Continue with normal security practices")

        return recs[:6]

    def _build_threat_intel(self, signals: List[AgentSignal], score: int) -> Dict:
        intel_signal = next((s for s in signals if s.agent == "ThreatIntel"), None)
        return {
            "ioc_matches": intel_signal.evidence.get("matches", []) if intel_signal else [],
            "campaigns_matched": intel_signal.evidence.get("campaigns", []) if intel_signal else [],
            "fingerprint": intel_signal.evidence.get("content_fingerprint", "N/A") if intel_signal else "N/A",
            "threat_score_breakdown": {
                s.agent: {
                    "score": round(s.score * 100, 1),
                    "confidence": round(s.confidence * 100, 1)
                }
                for s in signals
            }
        }


# ──────────────────────────────────────────────
# SERIALIZER (convert dataclasses to JSON-safe dicts)
# ──────────────────────────────────────────────

def result_to_dict(result: AnalysisResult) -> Dict:
    return {
        "final_score": result.final_score,
        "risk_level": result.risk_level,
        "risk_color": result.risk_color,
        "confidence": result.confidence,
        "attack_type": result.attack_type,
        "attack_probability": result.attack_probability,
        "explanation": result.explanation,
        "recommendations": result.recommendations,
        "threat_intel": result.threat_intel,
        "processing_time_ms": result.processing_time_ms,
        "timestamp": result.timestamp,
        "agent_signals": [
            {
                "agent": s.agent,
                "score": round(s.score * 100, 1),
                "confidence": round(s.confidence * 100, 1),
                "findings": s.findings,
                "weight": s.weight
            }
            for s in result.signals
        ]
    }
