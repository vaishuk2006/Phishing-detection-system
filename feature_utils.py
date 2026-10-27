
from urllib.parse import urlparse
import ipaddress
import re

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account",
    "banking", "signin", "password", "confirm", "wallet"
]


def extract_features(url):
    """Extract simple URL features for phishing-risk analysis."""

    url = url.strip()

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "at_count": url.count("@"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "digit_count": sum(char.isdigit() for char in url),
        "https": int(parsed.scheme.lower() == "https"),
        "has_ip": has_ip,
        "suspicious_word": int(
            any(word in url.lower() for word in SUSPICIOUS_WORDS)
        ),
        "subdomain_count": max(0, len(hostname.split(".")) - 2),
        "has_port": int(parsed.port is not None) if parsed.netloc else 0,
    }

    return features
