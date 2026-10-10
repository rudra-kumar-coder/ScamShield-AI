"""Deterministic, explainable scam indicators. Scores are NOT probabilities."""
import ipaddress
import re
from urllib.parse import urlparse

PATTERNS = {
    "OTP / credential request": (r"\b(?:otp|one.time password|verification code|pin|password|cvv)\b", 22),
    "Urgency or threat": (r"\b(?:urgent|immediately|within 24 hours|account (?:will be )?blocked|suspended|last warning|act now)\b", 15),
    "Payment request": (r"\b(?:processing fee|registration fee|pay (?:now|first)|transfer money|send money|upi pin)\b", 18),
    "Unrealistic reward": (r"\b(?:guaranteed returns|double your money|free cash|won a prize|lottery winner)\b", 22),
    "Job offer pressure": (r"\b(?:work from home|easy income|no interview|instant joining|job offer)\b", 13),
    "Impersonation language": (r"\b(?:bank support|customer care|official support|government department|kyc update)\b", 12),
    "Secrecy request": (r"\b(?:do not tell anyone|keep this secret|don't inform)\b", 14),
}
URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy"}


def analyze_rules(text: str) -> dict:
    indicators = []
    score = 0
    for name, (pattern, weight) in PATTERNS.items():
        if re.search(pattern, text, re.I):
            indicators.append({"name": name, "weight": weight})
            score += weight
    urls = []
    for match in URL_RE.findall(text):
        raw = match.rstrip(".,;!?)")
        parsed = urlparse(raw if raw.startswith(("http://", "https://")) else "https://" + raw)
        host = (parsed.hostname or "").lower()
        if not host:
            continue
        flags = []
        if parsed.scheme == "http":
            flags.append("unencrypted HTTP")
        if host in SHORTENERS:
            flags.append("shortened link")
        try:
            ipaddress.ip_address(host)
            flags.append("IP address instead of domain")
        except ValueError:
            pass
        if host.count("-") >= 3:
            flags.append("many hyphens in domain")
        urls.append({"url": raw, "host": host, "flags": flags})
        if flags:
            score += min(20, 8 * len(flags))
            indicators.append({"name": "Suspicious URL characteristics: " + ", ".join(flags), "weight": min(20, 8 * len(flags))})
    score = min(100, score)
    if score <= 24:
        level = "low"
    elif score <= 49:
        level = "medium"
    elif score <= 74:
        level = "high"
    else:
        level = "critical"
    return {"risk_score": score, "risk_level": level, "indicators": indicators, "urls": urls,
            "disclaimer": "Heuristic risk score, not a probability or proof of safety. No URL was opened."}
