
"""Explainable, rule-based scam risk detection.

Scores are heuristic signals, not calibrated probabilities.
No URLs are opened or visited.
"""

import ipaddress
import re
from urllib.parse import urlparse


PATTERNS = {
    "OTP or credential request": (
        r"\b(?:otp|one.time password|verification code|"
        r"upi pin|password|cvv|security code)\b",
        25,
    ),
    "Urgency or threats": (
        r"\b(?:urgent|immediately|act now|last warning|"
        r"within 24 hours|account (?:will be )?blocked|"
        r"account suspended|limited time)\b",
        16,
    ),
    "Advance payment request": (
        r"\b(?:processing fee|registration fee|"
        r"pay (?:now|first)|transfer money|send money|"
        r"advance payment|deposit required)\b",
        22,
    ),
    "Unrealistic reward": (
        r"\b(?:guaranteed returns|double your money|"
        r"free cash|won (?:a |the )?prize|lottery winner|"
        r"congratulations.{0,50}(?:won|winner|prize))\b",
        22,
    ),
    "Suspicious job offer": (
        r"\b(?:work from home|easy income|no interview|"
        r"instant joining|job offer|earn daily|"
        r"part.time income)\b",
        16,
    ),
    "Impersonation or KYC claim": (
        r"\b(?:bank support|customer care|official support|"
        r"government department|kyc update|"
        r"verify your account|update your kyc)\b",
        17,
    ),
    "Secrecy request": (
        r"\b(?:do not tell anyone|keep this secret|"
        r"don't inform anyone)\b",
        17,
    ),
    "Unsolicited loan promotion": (
        r"\b(?:pre.approved loan|instant loan|"
        r"loan approved|guaranteed loan|"
        r"loan without documents|quick loan approval)\b",
        20,
    ),
    "Sensitive financial information": (
        r"\b(?:bank details|card number|account number|"
        r"debit card details|credit card details)\b",
        15,
    ),
    "Link interaction request": (
        r"\b(?:click (?:here|this|the|on)|"
        r"open (?:this|the) link|tap (?:here|the link)|"
        r"visit (?:this|the) link)\b",
        12,
    ),
}

URL_RE = re.compile(
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
    re.I,
)

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "is.gd",
    "rb.gy",
    "tiny.cc",
    "shorturl.at",
    "go3.in",
}


def analyze_rules(text: str) -> dict:
    indicators = []
    urls = []
    score = 0
    matched = set()

    def add_indicator(name, weight):
        nonlocal score

        if name not in matched:
            indicators.append({
                "name": name,
                "weight": weight,
            })
            matched.add(name)
            score += weight

    for name, (pattern, weight) in PATTERNS.items():
        if re.search(pattern, text, re.I):
            add_indicator(name, weight)

    for match in URL_RE.findall(text):
        raw = match.rstrip(".,;!?)")

        normalized = raw
        if not raw.lower().startswith(
            ("http://", "https://")
        ):
            normalized = "https://" + raw

        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()

        if not host:
            continue

        flags = []

        if parsed.scheme == "http":
            flags.append("Unencrypted HTTP link")
            add_indicator("Unencrypted HTTP link", 10)

        if host in SHORTENERS:
            flags.append("Known link-shortening domain")
            add_indicator("Shortened link", 18)

        try:
            ipaddress.ip_address(host)
            flags.append("IP address used as host")
            add_indicator("IP-address URL", 20)
        except ValueError:
            pass

        if host.count("-") >= 3:
            flags.append("Many hyphens in domain")
            add_indicator("Unusual domain formatting", 8)

        if "@" in parsed.netloc:
            flags.append("URL contains @ symbol")
            add_indicator("Misleading URL structure", 18)

        urls.append({
            "url": raw,
            "host": host,
            "flags": flags,
        })

    if urls:
        suspicious_context = any(
            name in matched
            for name in (
                "OTP or credential request",
                "Urgency or threats",
                "Unsolicited loan promotion",
                "Unrealistic reward",
                "Impersonation or KYC claim",
                "Advance payment request",
            )
        )

        if suspicious_context:
            add_indicator(
                "Link combined with suspicious message",
                12,
            )

    score = min(100, score)

    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"

    return {
        "risk_score": score,
        "risk_level": level,
        "indicators": indicators,
        "urls": urls,
        "disclaimer": (
            "This is a heuristic risk score, not a "
            "probability or proof of safety. "
            "No URLs were opened."
        ),
    }
