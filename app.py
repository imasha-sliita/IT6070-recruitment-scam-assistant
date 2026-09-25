"""
IT6070 — Recruitment Scam Red-Flag Assistant (web page).
Run: python app.py  →  http://127.0.0.1:5000
"""

import os

from dotenv import load_dotenv
from flask import Flask, render_template, request

from analyzer import AnalysisResult, analyze_message, build_guidance

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-it6070-poc")

SAMPLES = {
    "scam_fee_whatsapp": (
        "URGENT HIRING! Work from home — earn USD 1200/week guaranteed. "
        "Pay LKR 5,500 registration fee via eZ Cash before interview. "
        "WhatsApp only: 07x-xxxxxxx. Selected candidates must pay today!"
    ),
    "suspicious_vague": (
        "Foreign employment opportunity — warehouse jobs in Europe. "
        "Processing fee applies. Contact agent via WhatsApp for quick placement. "
        "Limited slots this week."
    ),
    "legit_style": (
        "ABC Pvt Ltd (Reg. PV xxxxx) invites applications for Junior Executive. "
        "Apply via careers@abc.lk with CV. Shortlisted candidates will be called "
        "for interview at our Colombo office. No fees charged from applicants."
    ),
}


def risk_class(risk: str) -> str:
    return {
        "Likely safe": "risk-safe",
        "Suspicious": "risk-warn",
        "Likely scam": "risk-danger",
    }.get(risk, "risk-warn")


@app.route("/", methods=["GET", "POST"])
def index():
    message = ""
    error = None
    analysis: AnalysisResult | None = None
    guidance = None
    sample_key = ""
    use_llm = True
    has_key = bool(os.environ.get("GEMINI_API_KEY", "").strip())

    if request.method == "POST":
        message = request.form.get("message", "")
        use_llm = request.form.get("use_llm") == "on"
        action = request.form.get("action", "analyze")
        sample_key = request.form.get("sample", "")

        if sample_key and sample_key in SAMPLES:
            message = SAMPLES[sample_key]

        try:
            if action == "analyze":
                analysis = analyze_message(message, use_llm=use_llm)
                request.environ["last_analysis"] = analysis  # noqa: B018 — sessionless PoC
            elif action == "guidance":
                analysis = analyze_message(message, use_llm=use_llm)
                guidance = build_guidance(message, analysis, use_llm=use_llm)
            elif action == "both":
                analysis = analyze_message(message, use_llm=use_llm)
                guidance = build_guidance(message, analysis, use_llm=use_llm)
        except ValueError as exc:
            error = str(exc)

    return render_template(
        "index.html",
        message=message,
        error=error,
        analysis=analysis,
        guidance=guidance,
        samples=SAMPLES,
        sample_key=sample_key,
        use_llm=use_llm,
        has_key=has_key,
        risk_class=risk_class,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
