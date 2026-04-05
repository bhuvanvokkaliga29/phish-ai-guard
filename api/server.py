"""
PhishAI Guard – Python Flask API Server
=======================================
Serves the analysis engine over HTTP.
"""

import json
import sys
import os
import time
from pathlib import Path

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from flask import Flask, request, jsonify, send_from_directory
    from flask_cors import CORS
except ImportError:
    print("Installing dependencies...")
    os.system("pip install flask flask-cors --break-system-packages -q")
    from flask import Flask, request, jsonify, send_from_directory
    from flask_cors import CORS

from agents.orchestrator import (
    PhishAIOrchestrator, AnalysisRequest, result_to_dict
)

app = Flask(__name__, static_folder="../static", template_folder="../templates")
CORS(app)

orchestrator = PhishAIOrchestrator()

# In-memory history (last 10 analyses)
analysis_history = []


@app.route("/")
def index():
    return send_from_directory("../", "index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json(force=True)

        req = AnalysisRequest(
            text=data.get("text", ""),
            url=data.get("url", ""),
            transaction_amount=float(data.get("transaction", {}).get("amount", 0)),
            transaction_frequency=int(data.get("transaction", {}).get("frequency", 0)),
            sender_email=data.get("sender_email", ""),
            headers=data.get("headers", {}),
            session_id=data.get("session_id", "")
        )

        result = orchestrator.analyze(req)
        result_dict = result_to_dict(result)

        # Store in history
        history_entry = {
            "id": len(analysis_history) + 1,
            "timestamp": result_dict["timestamp"],
            "score": result_dict["final_score"],
            "risk_level": result_dict["risk_level"],
            "attack_type": result_dict["attack_type"],
            "preview": (data.get("text", "") or data.get("url", "") or "Transaction")[:60]
        }
        analysis_history.insert(0, history_entry)
        if len(analysis_history) > 10:
            analysis_history.pop()

        return jsonify({"success": True, "data": result_dict})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/history", methods=["GET"])
def get_history():
    return jsonify({"success": True, "data": analysis_history[:5]})


@app.route("/api/stats", methods=["GET"])
def get_stats():
    if not analysis_history:
        return jsonify({"success": True, "data": {
            "total": 0, "avg_score": 0,
            "risk_distribution": {"Safe": 0, "Suspicious": 0, "High Risk": 0, "Critical": 0}
        }})

    total = len(analysis_history)
    avg_score = sum(h["score"] for h in analysis_history) / total
    dist = {}
    for h in analysis_history:
        r = h["risk_level"]
        dist[r] = dist.get(r, 0) + 1

    return jsonify({"success": True, "data": {
        "total": total,
        "avg_score": round(avg_score, 1),
        "risk_distribution": dist
    }})


@app.route("/api/test-cases", methods=["GET"])
def get_test_cases():
    cases = [
        {
            "name": "Phishing Email",
            "icon": "📧",
            "description": "Classic PayPal credential harvest",
            "data": {
                "text": "URGENT: Your PayPal account has been suspended! Verify your account immediately or it will be permanently deleted. Click here to verify your password and banking details now! Limited time - act within 24 hours!",
                "url": "http://paypa1-secure-verify.xyz/login?redirect=account",
                "sender_email": "security@paypa1-accounts.xyz",
                "transaction": {"amount": 0, "frequency": 0}
            }
        },
        {
            "name": "AML Fraud Transaction",
            "icon": "💰",
            "description": "Structured financial transaction pattern",
            "data": {
                "text": "Wire transfer confirmation: Please process the attached invoice immediately.",
                "url": "",
                "sender_email": "finance@offshore-holdings.ru",
                "transaction": {"amount": 9500, "frequency": 8}
            }
        },
        {
            "name": "Malware URL",
            "icon": "🦠",
            "description": "Suspicious download link",
            "data": {
                "text": "Your computer is infected! Download our FREE antivirus software immediately to protect your data. Congratulations - you have been selected!",
                "url": "http://192.168.1.1/download/win-update-patch.exe",
                "sender_email": "",
                "transaction": {"amount": 0, "frequency": 0}
            }
        },
        {
            "name": "Legitimate Email",
            "icon": "✅",
            "description": "Normal business communication",
            "data": {
                "text": "Hi John, please find attached the Q3 report for your review. Let me know if you have any questions. Best regards, Sarah",
                "url": "https://docs.google.com/spreadsheets/d/abc123",
                "sender_email": "sarah.jones@company.com",
                "transaction": {"amount": 250, "frequency": 1}
            }
        }
    ]
    return jsonify({"success": True, "data": cases})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "agents": len(orchestrator.agents)})


if __name__ == "__main__":
    print("🛡️  PhishAI Guard API starting on http://localhost:5000")
    app.run(debug=True, port=5000, host="0.0.0.0")
