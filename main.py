"""ScamShield REST API."""
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from src.engine import analyze_rules
from src.llm import analyze_llm

load_dotenv()
app = FastAPI(title="ScamShield AI", version="1.0.0")
DB = os.getenv("SCAMSHIELD_DB", "scamshield.db")

class ScanRequest(BaseModel):
    text: str = Field(min_length=5, max_length=12000)
    use_llm: bool = True
    save_history: bool = False

class BatchRequest(BaseModel):
    messages: list[str] = Field(min_length=1, max_length=100)

def store(result):
    with sqlite3.connect(DB) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, timestamp TEXT, risk_score INTEGER, risk_level TEXT)")
        conn.execute("INSERT INTO scans (timestamp,risk_score,risk_level) VALUES (?,?,?)", (datetime.now(timezone.utc).isoformat(), result["risk_score"], result["risk_level"]))

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/scan")
def scan(body: ScanRequest):
    if not body.text.strip():
        raise HTTPException(422, "Message cannot be blank")
    rules = analyze_rules(body.text)
    llm = analyze_llm(body.text, rules) if body.use_llm else {"status": "disabled"}
    result = {**rules, "llm": llm}
    if body.save_history:
        store(result)
    return result

@app.post("/batch")
def batch(body: BatchRequest):
    if any(len(m) < 5 or len(m) > 12000 or not m.strip() for m in body.messages):
        raise HTTPException(422, "Each message must contain 5 to 12000 nonblank characters")
    return {"results": [analyze_rules(m) for m in body.messages], "note": "Batch mode uses deterministic analysis to control API cost."}

@app.get("/history")
def history():
    if not Path(DB).exists():
        return {"scans": []}
    with sqlite3.connect(DB) as conn:
        rows = conn.execute("SELECT id,timestamp,risk_score,risk_level FROM scans ORDER BY id DESC LIMIT 50").fetchall()
    return {"scans": [dict(zip(("id", "timestamp", "risk_score", "risk_level"), row)) for row in rows]}
