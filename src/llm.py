
"""Optional Gemini analysis with safe fallback."""

import json
import os
import re
from pathlib import Path

import requests


PROMPT_PATH = Path(__file__).resolve().parents[1] / "prompts" / "scam_analysis.txt"


def redact(text: str) -> str:
    text = re.sub(
        r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b",
        "[EMAIL]",
        text,
    )
    text = re.sub(
        r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)",
        "[PHONE]",
        text,
    )
    text = re.sub(r"\b\d{6}\b", "[SIX_DIGIT_CODE]", text)
    return text


def analyze_llm(text: str, findings: dict) -> dict:
    key = os.getenv("GEMINI_API_KEY", "").strip()

    if not key:
        return {
            "status": "not_configured",
            "message": "Set GEMINI_API_KEY to enable LLM analysis.",
        }

    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()

    if not re.fullmatch(r"[A-Za-z0-9._-]+", model):
        return {
            "status": "error",
            "message": "Invalid model name.",
        }

    try:
        prompt = PROMPT_PATH.read_text(encoding="utf-8")

        url = (
            "https://generativelanguage.googleapis.com/"
            f"v1beta/models/{model}:generateContent"
        )

        payload = {
            "systemInstruction": {
                "parts": [{"text": prompt}]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": json.dumps(
                                {
                                    "message": redact(text),
                                    "rule_findings": findings,
                                },
                                ensure_ascii=False,
                            )
                        }
                    ],
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "responseMimeType": "application/json",
            },
        }

        response = requests.post(
            url,
            headers={"x-goog-api-key": key},
            json=payload,
            timeout=25,
        )

        response.raise_for_status()

        raw = response.json()["candidates"][0]["content"]["parts"][0]["text"]
        data = json.loads(raw)

        allowed = {
            "phishing",
            "otp_theft",
            "job_scam",
            "investment_scam",
            "payment_scam",
            "impersonation",
            "other",
            "unclear",
        }

        if not isinstance(data, dict) or data.get("category") not in allowed:
            raise ValueError("Invalid LLM category")

        for field in ("summary", "uncertainty"):
            if not isinstance(data.get(field), str):
                raise ValueError(f"Invalid {field}")

        for field in ("warning_signs", "recommended_actions"):
            values = data.get(field)
            if not isinstance(values, list) or not all(
                isinstance(item, str) for item in values
            ):
                raise ValueError(f"Invalid {field}")

            data[field] = values[:5]

        return {"status": "ok", **data}

    except requests.HTTPError as exc:
        code = (
            exc.response.status_code
            if exc.response is not None
            else "unknown"
        )
        return {
            "status": "error",
            "message": f"Gemini API HTTP status: {code}",
        }

    except (
        requests.RequestException,
        ValueError,
        KeyError,
        IndexError,
        TypeError,
        OSError,
    ) as exc:
        return {
            "status": "error",
            "message": f"Gemini error: {type(exc).__name__}",
        }
