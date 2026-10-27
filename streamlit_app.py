
import re
import ipaddress
from urllib.parse import urlparse

import streamlit as st


# ---------- PAGE CONFIGURATION ----------
st.set_page_config(
    page_title="PhishGuard | URL Security",
    page_icon="🛡️",
    layout="wide"
)

# ---------- CUSTOM DESIGN ----------
st.markdown("""
<style>
.stApp {
    background-color: #0b1120;
    color: #f1f5f9;
}
h1, h2, h3 {
    color: #38bdf8 !important;
}
.stTextInput input {
    background-color: #172033;
    color: white;
    border: 1px solid #38bdf8;
}
.stButton button {
    background: linear-gradient(90deg, #0891b2, #6366f1);
    color: white;
    border: none;
    border-radius: 10px;
    font-weight: bold;
    width: 100%;
    min-height: 45px;
}
.info-card {
    background: #172033;
    padding: 20px;
    border-radius: 12px;
    border: 1px solid #263449;
}
</style>
""", unsafe_allow_html=True)


# ---------- URL ANALYSIS ----------
def analyze_url(url):
    url = url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    if any(char.isspace() for char in url):
        raise ValueError("The URL must not contain spaces.")

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    if parsed.scheme not in ("http", "https") or not hostname:
        raise ValueError("Please enter a valid website URL.")

    risk_points = 0
    findings = []

    if parsed.scheme == "http":
        risk_points += 15
        findings.append("The URL uses HTTP instead of HTTPS.")

    if "@" in parsed.netloc:
        risk_points += 25
        findings.append("The URL contains an @ symbol in its address.")

    try:
        ipaddress.ip_address(hostname)
        risk_points += 25
        findings.append("The hostname is a direct IP address.")
    except ValueError:
        pass

    if len(url) > 100:
        risk_points += 10
        findings.append("The URL is unusually long.")

    if hostname.count("-") >= 3:
        risk_points += 10
        findings.append("The hostname contains several hyphens.")

    if hostname.startswith("xn--") or ".xn--" in hostname:
        risk_points += 20
        findings.append("The hostname uses an encoded international domain.")

    suspicious_words = [
        "login", "verify", "update", "secure",
        "account", "password", "confirm", "banking"
    ]

    matches = [
        word for word in suspicious_words
        if word in (hostname + parsed.path + parsed.query).lower()
    ]

    if matches:
        risk_points += min(20, len(matches) * 5)
        findings.append(
            "Potentially sensitive keywords found: "
            + ", ".join(matches)
        )

    risk_points = min(risk_points, 100)

    if risk_points >= 40:
        verdict = "Potentially Suspicious"
    elif risk_points >= 20:
        verdict = "Use Caution"
    else:
        verdict = "No Major Warning Signs Found"

    if not findings:
        findings.append(
            "No warning signs were detected by these basic checks."
        )

    return url, risk_points, verdict, findings


# ---------- WEBSITE HEADER ----------
st.title("🛡️ PhishGuard")
st.subheader("Phishing URL Detection System")
st.write(
    "Inspect a website address for common phishing warning signs."
)

st.markdown("""
<div class="info-card">
<b>URL Security Scanner</b><br>
Enter a website address below to check its URL structure.
</div>
""", unsafe_allow_html=True)

st.write("")

# ---------- INPUT ----------
url_input = st.text_input(
    "Website URL",
    placeholder="https://example.com",
    help="Enter the website address you want to inspect."
)

if st.button("🔍 Scan URL"):
    try:
        scanned_url, score, verdict, findings = analyze_url(url_input)

        st.markdown("---")
        st.subheader("Scan Results")

        st.write("**Scanned URL:**")
        st.code(scanned_url)

        col1, col2 = st.columns(2)

        with col1:
            st.metric("Heuristic Risk Score", f"{score}/100")

        with col2:
            st.metric("Assessment", verdict)

        st.progress(score / 100)

        if score >= 40:
            st.error("Warning: This URL has multiple warning signs.")
        elif score >= 20:
            st.warning("Caution: Review this URL carefully.")
        else:
            st.success("Few warning signs were detected.")

        st.subheader("Analysis Details")

        for finding in findings:
            st.write(f"• {finding}")

        st.caption(
            "Educational heuristic analysis only. "
            "This does not query threat-intelligence databases "
            "or use your trained machine-learning model. "
            "A low score does not prove a website is safe."
        )

    except ValueError as error:
        st.error(str(error))

# ---------- FOOTER ----------
st.markdown("---")
st.caption(
    "PhishGuard | Cybersecurity Awareness Project"
)
