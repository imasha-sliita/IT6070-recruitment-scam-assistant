# LLM-Based Recruitment Scam Red-Flag Assistant

IT6070 Assignment II proof of concept — web page for a career counselor to triage fake job ads.

**Professional (pseudonym):** Ms. Silva, career counselor.

## Features

1. **Analyze** — paste job ad / chat → risk level + red flags (LLM or rule fallback).
2. **Guidance** — verification questions + safe advice for the candidate.

## Requirements

- Python 3.10+
- See `requirements.txt`

## Setup

```bash
cd it6070-recruitment-scam-assistant
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Optional: set `GEMINI_API_KEY` in `.env` for LLM mode. Without it, rule-based fallback runs.

## Run

```bash
python app.py
```

Open http://127.0.0.1:5000

## Sample login

Not applicable (no authentication in PoC).

## Known limitations

- Advisory only; not official fraud certification.
- Use fictional sample ads for demos; do not send real applicant PII to cloud APIs without approval.
- LLM may misclassify messages; human review required.
