from src.engine import analyze_rules
from src.llm import redact
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_urgent_otp():
    result = analyze_rules("URGENT! Share your OTP immediately or account blocked")
    assert result["risk_score"] >= 30
    assert result["risk_level"] in {"medium", "high", "critical"}

def test_safe_looking_message_not_guaranteed_safe():
    result = analyze_rules("Hello, see you at the library tomorrow")
    assert result["risk_score"] == 0
    assert "not a probability" in result["disclaimer"]

def test_url_not_fetched():
    result = analyze_rules("Go to http://192.0.2.1/login")
    assert "IP address instead of domain" in result["urls"][0]["flags"]

def test_redaction():
    assert "[EMAIL]" in redact("contact me at demo@example.com")

def test_api_without_llm():
    response = client.post("/scan", json={"text": "Send your OTP now", "use_llm": False})
    assert response.status_code == 200
    assert response.json()["llm"]["status"] == "disabled"

def test_api_validation():
    assert client.post("/scan", json={"text": "hi"}).status_code == 422
