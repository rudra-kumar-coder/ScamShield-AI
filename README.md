# 🛡️ ScamShield AI — Intelligent Scam Detection System

### 🌐 Live Website

**Try ScamShield AI online:**

https://scamshield-ai-ka9yvn3ezbhmbmfyg4kpe4.streamlit.app/

### 📂 GitHub Source Code

https://github.com/rudra-kumar-coder/ScamShield-AI

### About the Project

ScamShield AI is an NLP-based scam detection system that analyzes suspicious SMS, WhatsApp messages, phishing links, fake loan offers, and job scams using rule-based detection and Gemini AI.

**Features:**
- Scam risk scoring
- Phishing and suspicious URL detection
- Gemini AI analysis
- Security recommendations
- Batch CSV analysis
- Downloadable reports

# ScamShield AI — Colab, Gemini, GitHub and Streamlit Cloud

Scam detection with explainable NLP rules, URL syntax checks, optional Gemini API, and batch CSV screening. Risk scores are heuristics, not fraud probabilities.

## Google Colab
1. Open https://colab.research.google.com/ and upload `ScamShield_AI_Colab.ipynb`.
2. Run the first cell, upload the ZIP, and run the install cell.
3. Create a Gemini key at https://aistudio.google.com/app/apikey.
4. In Colab's Secrets (key icon), add `GEMINI_API_KEY` and enable notebook access.
5. Run the remaining cells to test Gemini and the included unit tests.

## Public Streamlit website
1. Create a GitHub repo and upload extracted project files (not just the ZIP). Do not upload `.env`, API keys, databases or confidential messages.
2. Open https://share.streamlit.io and connect GitHub.
3. Select the repository, branch `main`, and entry point `app.py`.
4. In Advanced settings / App settings → Secrets, add:
```toml
GEMINI_API_KEY = "YOUR_REAL_KEY"
GEMINI_MODEL = "gemini-2.5-flash"
```
5. Deploy, open the generated `*.streamlit.app` link and test with a fictional message.

The public `app.py` imports `src.engine` and `src.llm` directly. **No separate FastAPI deployment is needed.** `main.py` is retained as an optional API for local development.

## Optional local commands
```bash
pip install -r requirements.txt
streamlit run app.py
python -m pytest -q
```

## Structure
- `app.py`: Streamlit Cloud website
- `main.py`: optional FastAPI backend
- `src/engine.py`: explainable heuristics and URL checks
- `src/llm.py`: Gemini API, partial redaction and structured output
- `prompts/scam_analysis.txt`: LLM system prompt
- `config/settings.yaml`: configuration
- `tests/`: unit tests
- `ScamShield_AI_Colab.ipynb`: Colab notebook

## Security and limitations
Never share real OTPs, passwords, bank details, or private messages. Partial redaction is not comprehensive anonymization. URLs are parsed, not visited. No history is stored by the public Streamlit app. Public use may consume API quota. Do not expose the optional FastAPI server without authentication and rate limiting. Tests verify code behavior, not accuracy; labeled data is required for precision/recall/F1.
