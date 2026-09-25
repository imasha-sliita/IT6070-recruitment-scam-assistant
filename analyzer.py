"""Recruitment scam analysis: rules fallback + optional Gemini LLM."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Literal

RiskLevel = Literal["Likely safe", "Suspicious", "Likely scam"]


@dataclass
class AnalysisResult:
    risk: RiskLevel
    red_flags: list[str]
    reasons: list[str]
    source: str  # "llm" | "rules"


@dataclass
class GuidanceResult:
    verification_questions: list[str]
    safe_guidance: str
    source: str


JOB_SCAM_PATTERNS: list[tuple[str, str, int]] = [
    (r"registration fee|processing fee|training fee|pay first|upfront", "Upfront payment before hiring", 3),
    (r"whatsapp only|contact on whatsapp|dm me on whatsapp", "WhatsApp-only recruitment channel", 2),
    (r"guaranteed (income|salary|job)|earn (usd|\$|rs\.?\s*\d)", "Unrealistic guaranteed earnings", 2),
    (r"visa fee|document fee|medical fee.*pay", "Candidate asked to pay visa/document fees", 3),
    (r"within 24 hours|urgent|limited slots|act now", "High-pressure urgency", 2),
    (r"no interview|instant job|selected you", "Job offer without proper process", 2),
    (r"send (copy of )?nic|passport|bank details before", "Sensitive documents requested early", 3),
    (r"western union|mobile transfer|eZ cash|binance", "Unusual payment method", 2),
    (r"http[s]?://|bit\.ly|t\.me", "Suspicious links in ad", 1),
]


def _require_text(text: str) -> str:
    cleaned = (text or "").strip()
    if not cleaned:
        raise ValueError("Please paste a job advertisement or recruiter message.")
    return cleaned


def analyze_rules(message: str) -> AnalysisResult:
    text = _require_text(message)
    lower = text.lower()
    flags: list[str] = []
    score = 0
    for pattern, label, weight in JOB_SCAM_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            if label not in flags:
                flags.append(label)
            score += weight

    if score >= 5:
        risk: RiskLevel = "Likely scam"
    elif score >= 2:
        risk = "Suspicious"
    else:
        risk = "Likely safe"

    if flags:
        reasons = [f"Indicator: {f}" for f in flags]
    else:
        reasons = ["No common recruitment-scam indicators matched the rule list."]

    reasons.append("Rule-based mode — configure GEMINI_API_KEY for LLM analysis.")
    return AnalysisResult(risk=risk, red_flags=flags, reasons=reasons, source="rules")


def analyze_llm(message: str, api_key: str) -> AnalysisResult:
    text = _require_text(message)
    import google.generativeai as genai

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
    prompt = f"""You help career counselors triage job ads (not legal advice).
Analyze this recruitment text. Reply JSON only:
{{
  "risk": "Likely safe" | "Suspicious" | "Likely scam",
  "red_flags": ["short label", ...],
  "reasons": ["sentence", ...]
}}

Text:
{text}
"""
    response = model.generate_content(prompt)
    raw = (response.text or "").strip()
    raw = re.sub(r"^```json\s*|\s*```$", "", raw, flags=re.IGNORECASE)
    data = json.loads(raw)
    risk = data.get("risk", "Suspicious")
    if risk not in ("Likely safe", "Suspicious", "Likely scam"):
        risk = "Suspicious"
    return AnalysisResult(
        risk=risk,
        red_flags=list(data.get("red_flags") or []),
        reasons=list(data.get("reasons") or ["No reasons returned."]),
        source="llm",
    )


def analyze_message(message: str, use_llm: bool = True) -> AnalysisResult:
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if use_llm and key:
        try:
            return analyze_llm(message, key)
        except Exception:
            pass
    return analyze_rules(message)


def guidance_rules(analysis: AnalysisResult) -> GuidanceResult:
    questions = [
        "What is the registered company name and office address in Sri Lanka?",
        "Can you share an official company email domain (not only Gmail/Yahoo)?",
        "Will there be an in-person or verified video interview before any payment?",
        "Are candidates required to pay registration, training, or visa fees upfront?",
    ]
    if analysis.risk == "Likely scam":
        safe = (
            "Do not pay any fee or send NIC/passport copies yet. Verify the employer through "
            "official channels (company website, listed phone number, SEC/Registrar if claimed). "
            "If payment was requested, treat the offer as high risk until proven otherwise."
        )
    elif analysis.risk == "Suspicious":
        safe = (
            "Pause before paying or sharing documents. Ask the verification questions and "
            "confirm answers independently. Legitimate employers rarely demand upfront fees."
        )
    else:
        safe = (
            "Still verify employer identity before sharing personal documents. "
            "Never pay recruitment fees without a written contract and verified company details."
        )
    return GuidanceResult(
        verification_questions=questions,
        safe_guidance=safe,
        source="rules",
    )


def guidance_llm(message: str, analysis: AnalysisResult, api_key: str) -> GuidanceResult:
    import google.generativeai as genai

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
    prompt = f"""Career counselor tool. Risk: {analysis.risk}. Flags: {analysis.red_flags}
From this job ad/chat, output JSON only:
{{
  "verification_questions": ["question", ...],
  "safe_guidance": "short paragraph for candidate"
}}
4-6 questions. Plain guidance, not legal advice.

Text:
{message[:4000]}
"""
    response = model.generate_content(prompt)
    raw = (response.text or "").strip()
    raw = re.sub(r"^```json\s*|\s*```$", "", raw, flags=re.IGNORECASE)
    data = json.loads(raw)
    return GuidanceResult(
        verification_questions=list(data.get("verification_questions") or []),
        safe_guidance=str(data.get("safe_guidance") or guidance_rules(analysis).safe_guidance),
        source="llm",
    )


def build_guidance(message: str, analysis: AnalysisResult, use_llm: bool = True) -> GuidanceResult:
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if use_llm and key:
        try:
            return guidance_llm(message, analysis, key)
        except Exception:
            pass
    return guidance_rules(analysis)
