import streamlit as st
import json
import matplotlib.pyplot as plt
from firewall_engine import PhishingDefenseFirewall
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from datetime import datetime
import tempfile

# -------------------------------------------------
# Page Config
# -------------------------------------------------
demo

# -------------------------------------------------
# Load Firewall (cached)
# -------------------------------------------------
@st.cache_resource
def load_firewall():
    return PhishingDefenseFirewall()

firewall = load_firewall()

# -------------------------------------------------
# Session History
# -------------------------------------------------
if "history" not in st.session_state:
    st.session_state.history = []

# -------------------------------------------------
# Title
# -------------------------------------------------
st.title("🛡️ AI-Powered Phishing Defense Firewall")
st.caption("Rule-Based + Machine Learning Email Security System")

# -------------------------------------------------
# Sidebar — Metadata
# -------------------------------------------------
st.sidebar.header("📧 Email Metadata")

sender = st.sidebar.text_input("From", "security@paypal-alert.ml")
subject = st.sidebar.text_input("Subject", "URGENT: Verify your account")
timestamp = st.sidebar.text_input("Timestamp", "2025-01-15 02:30:00")

spf = st.sidebar.selectbox("SPF", ["pass", "fail", "none"])
dkim = st.sidebar.selectbox("DKIM", ["pass", "fail", "none"])
dmarc = st.sidebar.selectbox("DMARC", ["pass", "fail", "none"])

relay_hops = st.sidebar.slider("Relay Hops", 0, 15, 7)

# -------------------------------------------------
# Email Input Section
# -------------------------------------------------
st.subheader("✉️ Email Content")

uploaded_file = st.file_uploader(
    "Upload Email File (.txt or .eml)",
    type=["txt", "eml"]
)

email_text = ""
if uploaded_file:
    email_text = uploaded_file.read().decode("utf-8", errors="ignore")
    st.success("📄 File loaded successfully")
else:
    email_text = st.text_area(
        "Paste Email Content",
        height=220,
        value="URGENT! Your PayPal account has been suspended. Verify immediately: http://paypa1-verify.tk/login"
    )

urls_input = st.text_input(
    "URLs (comma-separated)",
    "http://paypa1-verify.tk/login"
)
urls = [u.strip() for u in urls_input.split(",") if u.strip()]

# -------------------------------------------------
# Analyze Button
# -------------------------------------------------
if st.button("🔍 Analyze Email"):
    email_data = {
        "text": email_text,
        "urls": urls,
        "metadata": {
            "from": sender,
            "subject": subject,
            "timestamp": timestamp,
            "received_spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "relay_hops": relay_hops
        }
    }

    with st.spinner("Analyzing email with AI models..."):
        result = firewall.analyze_email(email_data)

    # Save history
    st.session_state.history.append(result)

    # -------------------------------------------------
    # RESULTS
    # -------------------------------------------------
    st.markdown("---")
    st.subheader("📊 Detection Result")

    col1, col2, col3 = st.columns(3)
    col1.metric("Final Risk Score", f"{result['final_score']} / 100")
    col2.metric("Threat Level", result['threat_level'])
    col3.metric("Action", result['action'])

    st.info(result["recommendation"])

    # -------------------------------------------------
    # Risk Gauge
    # -------------------------------------------------
    st.subheader("🚦 Risk Meter")
    st.progress(int(result["final_score"]))

    # -------------------------------------------------
    # Flags
    # -------------------------------------------------
    st.subheader("🚩 Detected Threat Indicators")
    for flag in result["all_flags"]:
        st.warning(flag)

    # -------------------------------------------------
    # Chart: Rule vs ML vs Final
    # -------------------------------------------------
    st.subheader("📈 Score Comparison")

    labels = ["Email Text", "URL Analysis", "Metadata"]
    scores = [
        result["layer_scores"]["email_text"]["score"],
        result["layer_scores"]["url_analysis"]["score"],
        result["layer_scores"]["metadata"]["score"]
    ]

    fig, ax = plt.subplots()
    ax.bar(labels, scores)
    ax.set_ylim(0, 100)
    ax.set_ylabel("Risk Score")
    st.pyplot(fig)

    # -------------------------------------------------
    # Download PDF Report
    # -------------------------------------------------
    st.subheader("📄 Download Analysis Report")

    if st.button("⬇️ Generate PDF Report"):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            c = canvas.Canvas(tmp.name, pagesize=A4)
            width, height = A4

            c.setFont("Helvetica-Bold", 16)
            c.drawString(40, height - 40, "AI Phishing Detection Report")

            c.setFont("Helvetica", 10)
            y = height - 80
            for k, v in {
                "Final Score": result["final_score"],
                "Threat Level": result["threat_level"],
                "Action": result["action"],
                "Confidence": result["confidence"]
            }.items():
                c.drawString(40, y, f"{k}: {v}")
                y -= 15

            c.drawString(40, y - 10, "Detected Flags:")
            y -= 30
            for flag in result["all_flags"][:10]:
                c.drawString(50, y, f"- {flag}")
                y -= 12

            c.drawString(40, y - 10, f"Generated on: {datetime.now()}")
            c.save()

            with open(tmp.name, "rb") as f:
                st.download_button(
                    "📥 Download PDF",
                    f,
                    file_name="phishing_report.pdf",
                    mime="application/pdf"
                )

    # -------------------------------------------------
    # Raw Output
    # -------------------------------------------------
    with st.expander("🧪 Raw JSON Output"):
        st.json(result)

# -------------------------------------------------
# HISTORY
# -------------------------------------------------
if st.session_state.history:
    st.markdown("---")
    st.subheader("🕒 Session Analysis History")
    for i, h in enumerate(st.session_state.history[::-1][:5], 1):
        st.write(f"{i}. Score: {h['final_score']} | Threat: {h['threat_level']} | Action: {h['action']}")

