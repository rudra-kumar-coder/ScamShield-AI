
import csv
import io
import json
import os

import streamlit as st
from dotenv import load_dotenv

from src.engine import analyze_rules
from src.llm import analyze_llm


load_dotenv()

st.set_page_config(
    page_title="ScamShield AI | Message Safety",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

try:
    for name in ("GEMINI_API_KEY", "GEMINI_MODEL"):
        if name in st.secrets:
            os.environ[name] = str(st.secrets[name])
except (FileNotFoundError, KeyError):
    pass


st.markdown("""
<style>
.block-container {
    max-width: 1120px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}
[data-testid="stMetric"] {
    background: rgba(128,128,128,0.08);
    border: 1px solid rgba(128,128,128,0.16);
    border-radius: 14px;
    padding: 18px;
}
.stButton > button[kind="primary"] {
    border-radius: 10px;
    font-weight: 650;
}
</style>
""", unsafe_allow_html=True)


def display_report(result):
    score = result["risk_score"]
    level = result["risk_level"].upper()
    llm = result.get("llm", {})
    ai_ok = llm.get("status") == "ok"

    st.divider()
    st.subheader("📊 Security Assessment")

    col1, col2, col3 = st.columns(3)

    col1.metric("Rule-based risk score", f"{score}/100")
    col2.metric("Rule-based risk level", level)
    col3.metric(
        "Gemini analysis",
        "Complete" if ai_ok else "Unavailable",
    )

    st.progress(score / 100)

    if ai_ok:
        category = llm.get("category", "unclear")
        st.markdown(
            f"**AI classification:** "
            f"{category.replace('_', ' ').title()}"
        )

    if level == "CRITICAL":
        st.error(
            "🚨 Critical warning: Multiple strong scam "
            "indicators were detected."
        )
    elif level == "HIGH":
        st.error(
            "⚠️ High risk: This message contains "
            "significant scam warning signs."
        )
    elif level == "MEDIUM":
        st.warning(
            "⚠️ Caution: Suspicious indicators were found."
        )
    else:
        st.info(
            "ℹ️ Few rule-based indicators were found. "
            "This does not prove the message is safe."
        )

    if ai_ok and llm.get("category") not in (
        "unclear",
        "other",
    ):
        st.warning(
            "🤖 Gemini identified a potential scam category. "
            "Review its findings even if the rule-based "
            "score is low."
        )

    st.subheader("🔍 Detected Warning Signs")

    indicators = result.get("indicators", [])

    if indicators:
        for item in indicators:
            st.markdown(
                f"⚠️ **{item['name']}** "
                f"— +{item['weight']} heuristic points"
            )
    else:
        st.info(
            "No rule-based warning signs matched. "
            "Unknown scams can still be dangerous."
        )

    if ai_ok:
        st.subheader("🧠 Gemini AI Analysis")

        st.markdown("**AI assessment**")
        st.write(llm.get("summary", "No summary available."))

        signs = llm.get("warning_signs", [])
        if signs:
            st.markdown("**Additional warning signs**")
            for sign in signs:
                st.markdown(f"- {sign}")

        actions = llm.get("recommended_actions", [])
        if actions:
            st.markdown("**Recommended safety actions**")
            for index, action in enumerate(actions, 1):
                st.markdown(f"{index}. {action}")

        uncertainty = llm.get("uncertainty", "")
        if uncertainty:
            st.caption(f"AI uncertainty: {uncertainty}")

    elif llm.get("status") == "error":
        st.warning(
            "Gemini analysis is temporarily unavailable. "
            "Rule-based results are still shown."
        )
        with st.expander("Technical error details"):
            st.code(llm.get("message", "Unknown error"))

    elif llm.get("status") == "not_configured":
        st.info(
            "Gemini API key is not configured. "
            "Showing rule-based analysis only."
        )

    st.subheader("🔗 URL Safety")

    urls = result.get("urls", [])

    if urls:
        for entry in urls:
            with st.container(border=True):
                st.write(f"**Host:** {entry['host']}")
                st.code(entry["url"], language=None)

                if entry["flags"]:
                    for flag in entry["flags"]:
                        st.warning(flag)
                else:
                    st.caption(
                        "No URL syntax flags detected. "
                        "Destination was not verified."
                    )
    else:
        st.info("No URLs detected in this message.")

    st.caption(result["disclaimer"])

    st.download_button(
        "📥 Download Full Analysis (JSON)",
        data=json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        ),
        file_name="scamshield_report.json",
        mime="application/json",
    )


with st.sidebar:
    st.title("🛡️ ScamShield AI")
    st.caption("Intelligent Scam Detection")
    st.divider()

    mode = st.radio(
        "Navigation",
        ["Single Message", "Batch CSV", "About"],
    )

    st.divider()
    st.caption("Privacy-first message analysis")
    st.caption("Links are inspected, never opened.")


if mode == "Single Message":
    st.title("🛡️ ScamShield AI")
    st.markdown(
        "### Detect suspicious messages before you trust them"
    )
    st.caption(
        "Analyze SMS, WhatsApp messages, loan offers, "
        "job offers, and phishing attempts."
    )

    st.warning(
        "Do not submit real OTPs, passwords, bank "
        "details, or private conversations. Gemini "
        "receives partially redacted text."
    )

    msg = st.text_area(
        "📩 Paste a suspicious message",
        height=170,
        max_chars=12000,
        placeholder=(
            "Example: Congratulations! You have won "
            "a prize. Click this link to claim it..."
        ),
    )

    llm_enabled = st.checkbox(
        "Enable Gemini AI analysis",
        value=True,
    )

    if st.button(
        "🔍 Analyze Message",
        type="primary",
        use_container_width=True,
    ):
        if len(msg.strip()) < 5:
            st.error("Enter at least 5 characters.")
        else:
            with st.spinner("Analyzing message..."):
                result = analyze_rules(msg)

                if llm_enabled:
                    result["llm"] = analyze_llm(
                        msg,
                        result,
                    )
                else:
                    result["llm"] = {
                        "status": "disabled"
                    }

                st.session_state["last_report"] = result
                st.session_state["last_message"] = msg

    if (
        "last_report" in st.session_state
        and st.session_state.get("last_message") == msg
    ):
        display_report(st.session_state["last_report"])


elif mode == "Batch CSV":
    st.title("📁 Batch Scam Detection")
    st.write(
        "Upload a UTF-8 CSV containing a column named "
        "`message`. Maximum 100 rows. Rules only."
    )

    uploaded = st.file_uploader(
        "Choose CSV file",
        type=["csv"],
    )

    if uploaded and st.button(
        "Analyze CSV",
        type="primary",
    ):
        try:
            if uploaded.size > 500000:
                raise ValueError("File is too large.")

            content = uploaded.getvalue().decode(
                "utf-8-sig"
            )

            rows = list(
                csv.DictReader(io.StringIO(content))
            )

            if not 1 <= len(rows) <= 100:
                raise ValueError(
                    "CSV must contain 1 to 100 rows."
                )

            output = []

            for index, row in enumerate(rows, 1):
                message = row["message"]

                if not 5 <= len(message.strip()) <= 12000:
                    raise ValueError(
                        f"Invalid message in row {index}"
                    )

                result = analyze_rules(message)

                output.append({
                    "row": index,
                    "risk_score": result["risk_score"],
                    "risk_level": result["risk_level"],
                })

            st.success("Batch analysis completed.")
            st.dataframe(
                output,
                use_container_width=True,
            )

            buffer = io.StringIO()
            writer = csv.DictWriter(
                buffer,
                fieldnames=[
                    "row",
                    "risk_score",
                    "risk_level",
                ],
            )
            writer.writeheader()
            writer.writerows(output)

            st.download_button(
                "📥 Download Results CSV",
                data=buffer.getvalue(),
                file_name="batch_results.csv",
                mime="text/csv",
            )

        except (
            KeyError,
            ValueError,
            UnicodeDecodeError,
        ) as exc:
            st.error(f"CSV error: {exc}")


else:
    st.title("ℹ️ About ScamShield AI")

    st.write(
        "ScamShield AI is a message-analysis project "
        "that combines explainable rule-based detection "
        "with optional Gemini AI analysis."
    )

    st.markdown("""
### Features

- Scam keyword and phrase detection
- Suspicious URL syntax analysis
- Explainable heuristic risk scores
- Gemini-powered message classification
- Security recommendations
- Batch CSV processing
- Downloadable analysis reports

### Limitations

- Scores are not probabilities.
- AI classifications can be incorrect.
- No URL destination is visited or verified.
- A low score does not guarantee safety.
- This application is not a replacement for
  professional fraud investigation.
""")
