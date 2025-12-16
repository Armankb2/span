import streamlit as st
from firewall_engine import PhishingDefenseFirewall

st.set_page_config(page_title="Phishing Firewall", layout="wide")

st.title("🛡️ AI Phishing Defense Firewall")

# Load firewall safely
try:
    firewall = PhishingDefenseFirewall()
    st.success("✅ Firewall loaded successfully")
except Exception as e:
    st.error("❌ Firewall failed to load")
    st.exception(e)
    st.stop()

email_text = st.text_area(
    "Paste Email Content",
    value="URGENT! Verify your account: http://fake-login.tk",
    height=200
)

if st.button("Analyze"):
    email_data = {
        "text": email_text,
        "urls": ["http://fake-login.tk"],
        "metadata": {
            "from": "security@paypal-alert.tk",
            "subject": "URGENT",
            "timestamp": "2025-01-15 02:30:00",
            "received_spf": "fail",
            "dkim": "none",
            "dmarc": "none",
            "relay_hops": 7
        }
    }

    result = firewall.analyze_email(email_data)

    st.subheader("Result")
    st.metric("Final Score", result["final_score"])
    st.write("Threat Level:", result["threat_level"])
    st.write("Action:", result["action"])
    st.warning(" | ".join(result["all_flags"]))
