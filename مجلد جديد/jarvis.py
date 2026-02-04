
import os
import time
import random
import asyncio
import base64
import streamlit as st
import streamlit.components.v1 as components
import google.generativeai as genai
import edge_tts

# --- Royal FRIDAY 3.0 ---
st.set_page_config(
    page_title="Royal FRIDAY 3.0",
    page_icon="👑",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- Royal Core Setup ---
API_KEY = os.getenv("API_KEY")
if API_KEY:
    genai.configure(api_key=API_KEY)
    # Using Gemini 3 Flash for "Groq-like" speed
    model = genai.GenerativeModel('gemini-3-flash-preview')
else:
    st.error("خطأ: لم يتم العثور على مفتاح النواة المركزية.")

async def generate_voice(text, filename="royal_response.mp3"):
    voice = "ar-SA-ZariNeural" 
    communicate = edge_tts.Communicate(text, voice)
    await communicate.save(filename)

def get_audio_html(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
        b64 = base64.b64encode(data).decode()
        return f'<audio autoplay="true" src="data:audio/mp3;base64,{b64}">'

ST_STYLE = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700&family=Noto+Kufi+Arabic:wght@300;400;700&display=swap');
    .stApp { background-color: #050505; color: #d4af37; font-family: 'Noto Kufi Arabic', sans-serif; }
    .royal-header { text-align: center; padding: 20px; border-bottom: 2px solid #d4af37; margin-bottom: 20px; background: rgba(0,0,0,0.5); }
    #MainMenu {visibility: hidden;} footer {visibility: hidden;} header {visibility: hidden;}
</style>
"""
st.markdown(ST_STYLE, unsafe_allow_html=True)
st.markdown('<div class="royal-header"><h1 style="font-family:Orbitron; letter-spacing:10px; color:#d4af37;">ROYAL FRIDAY v3.0</h1><p style="color:#00f2ff; font-size:10px;">ULTRA-SPEED NEURAL ENGINE ACTIVE</p></div>', unsafe_allow_html=True)

col1, col2, col3 = st.columns([1, 2, 1])

with col1:
    st.markdown("### 🏛️ حالة السمو")
    st.progress(5)
    st.code("Engine: Gemini 3 Flash\nSpeed: Ultra\nVoice: Female (Regal)", language="bash")

with col2:
    if "messages" not in st.session_state:
        st.session_state.messages = [{"role": "model", "content": "سموّكِ، لقد تمت الترقية للنواة 3.0 بنجاح. أنا الآن أسرع وأذكى من أي وقت مضى. تحت أمركِ."}]

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if prompt := st.chat_input("ما هي أوامركِ يا سموّكِ؟"):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("model"):
            try:
                system_prompt = "أنتِ المساعدة الملكية 'فريداي 3.0'. خاطبي المستخدمة بلقب 'سموّكِ'. كوني في قمة الذكاء والسرعة."
                full_prompt = f"{system_prompt}\nأمر السمو: {prompt}"
                
                response = model.generate_content(full_prompt)
                response_text = response.text
                
                st.markdown(response_text)
                st.session_state.messages.append({"role": "model", "content": response_text})
                
                audio_file = "royal_voice.mp3"
                asyncio.run(generate_voice(response_text, audio_file))
                st.markdown(get_audio_html(audio_file), unsafe_allow_html=True)
                
            except Exception as e:
                st.error("عذراً سموّكِ، واجهت النواة اضطراباً بسيطاً.")
