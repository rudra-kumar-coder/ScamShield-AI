import csv, io, json, os
import streamlit as st
from dotenv import load_dotenv
from src.engine import analyze_rules
from src.llm import analyze_llm
load_dotenv()
st.set_page_config(page_title='ScamShield AI', page_icon='🛡️', layout='wide')
try:
    for name in ('GEMINI_API_KEY', 'GEMINI_MODEL'):
        if name in st.secrets and not os.getenv(name): os.environ[name] = str(st.secrets[name])
except (FileNotFoundError, KeyError): pass
st.title('🛡️ ScamShield AI')
st.caption('Risk scores are heuristics, not probabilities.')
st.warning('Never enter real OTPs, passwords, bank details or private messages. Gemini receives partially redacted text.')
mode = st.sidebar.radio('Mode', ['Single message', 'Batch CSV', 'About'])
if mode == 'Single message':
    msg = st.text_area('Suspicious message', height=180, max_chars=12000)
    llm_enabled = st.checkbox('Use Gemini analysis', value=True)
    if st.button('Analyze', type='primary'):
        if len(msg.strip()) < 5: st.error('Enter at least five characters.')
        else:
            result = analyze_rules(msg)
            result['llm'] = analyze_llm(msg, result) if llm_enabled else {'status':'disabled'}
            a,b = st.columns(2)
            a.metric('Heuristic score', f"{result['risk_score']}/100")
            b.metric('Risk level', result['risk_level'].upper())
            st.subheader('Indicators'); st.write(result['indicators'] or 'No matched indicators; not proof of safety.')
            st.subheader('URLs (not opened)'); st.write(result['urls'] or 'None')
            st.subheader('Gemini'); st.json(result['llm'])
            st.info(result['disclaimer'])
            st.download_button('Download JSON', json.dumps(result, indent=2), 'scamshield_report.json', 'application/json')
elif mode == 'Batch CSV':
    st.write('Upload a UTF-8 CSV with a message column (1–100 rows). Rules only, no LLM calls.')
    uploaded = st.file_uploader('CSV file', type='csv')
    if uploaded and st.button('Analyze CSV'):
        try:
            if uploaded.size > 500000: raise ValueError('File too large')
            rows = list(csv.DictReader(io.StringIO(uploaded.getvalue().decode('utf-8-sig'))))
            if not 1 <= len(rows) <= 100: raise ValueError('CSV must have 1–100 rows')
            output=[]
            for i,row in enumerate(rows,1):
                msg=row['message']
                if not 5 <= len(msg.strip()) <= 12000: raise ValueError(f'Invalid message in row {i}')
                result=analyze_rules(msg)
                output.append({'row':i,'risk_score':result['risk_score'],'risk_level':result['risk_level']})
            st.dataframe(output)
            buff=io.StringIO(); writer=csv.DictWriter(buff,fieldnames=['row','risk_score','risk_level'])
            writer.writeheader(); writer.writerows(output)
            st.download_button('Download CSV',buff.getvalue(),'batch_results.csv','text/csv')
        except (KeyError,ValueError,UnicodeDecodeError) as e: st.error(str(e))
else:
    st.write('NLP rules, URL syntax analysis, optional Gemini explanations, batch processing and downloadable reports. No message history stored by this website.')
