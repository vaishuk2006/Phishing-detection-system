from flask import Flask, render_template, request,session
from urllib.parse import urlparse
import ipaddress
import re

app = Flask(__name__)
app.secret_key = "phishguard-demo-key-change-this"


SUSPICIOUS_WORDS = [
    "login", "verify", "verification", "secure",
    "account", "update", "banking", "password",
    "signin", "confirm", "wallet", "free-gift"
]


def analyze_url(url):
    """Extract URL features and calculate a rule-based risk assessment."""

    url = url.strip()

    # Validate the URL before analyzing it.
    if not url or len(url) > 2048:
        raise ValueError("Please enter a URL between 1 and 2048 characters.")

    if any(char.isspace() for char in url):
        raise ValueError("The URL must not contain spaces.")

    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise ValueError(
            "Please include http:// or https:// in your URL."
        )

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname or "." not in hostname:
        raise ValueError(
            "Please enter a valid website address, such as https://example.com."
        )

    # Detect whether the hostname is an IP address.
    try:
        ipaddress.ip_address(hostname)
        has_ip = True
    except ValueError:
        has_ip = False

    hostname_without_www = hostname.lower().removeprefix("www.")
    domain_parts = hostname_without_www.split(".")
    subdomain_count = max(0, len(domain_parts) - 2)

    url_lower = url.lower()
    matched_words = [
        word for word in SUSPICIOUS_WORDS if word in url_lower
    ]

    features = {
        "URL Length": len(url),
        "Hostname Length": len(hostname),
        "Path Length": len(parsed.path),
        "Dot Count": url.count("."),
        "Hyphen Count": url.count("-"),
        "At Count": url.count("@"),
        "Question Count": url.count("?"),
        "Equal Count": url.count("="),
        "Digit Count": sum(char.isdigit() for char in url),
        "HTTPS": "Yes" if parsed.scheme.lower() == "https" else "No",
        "Has IP Address": "Yes" if has_ip else "No",
        "Suspicious Keywords": (
            ", ".join(matched_words) if matched_words else "None detected"
        ),
        "Subdomain Count": subdomain_count,
        "Has Port": "Yes" if parsed.port is not None else "No"
    }

    # Simple demonstration rules. These are indicators, not proof.
    warnings = []

    if parsed.scheme.lower() != "https":
        warnings.append("The URL does not use HTTPS")

    if has_ip:
        warnings.append("The hostname is an IP address")

    if "@" in url:
        warnings.append("The URL contains an @ symbol")

    if matched_words:
        warnings.append("The URL contains suspicious keywords")

    if len(url) > 100:
        warnings.append("The URL is unusually long")

    if subdomain_count >= 3:
        warnings.append("The hostname has multiple subdomains")

    if hostname.count("-") >= 3:
        warnings.append("The hostname contains many hyphens")

    if len(warnings) >= 3:
        risk = "High"
        status = "Potentially Suspicious"
        status_class = "high"
        message = (
            "Multiple suspicious indicators were detected. "
            "Avoid entering sensitive information until the website "
            "has been independently verified."
        )
    elif len(warnings) >= 1:
        risk = "Medium"
        status = "Use Caution"
        status_class = "medium"
        message = (
            "Some warning signs were detected. Check the website's "
            "identity before sharing personal or financial information."
        )
    else:
        risk = "Low"
        status = "No Obvious Warning Signs"
        status_class = "low"
        message = (
            "No warning signs were detected by these basic rules. "
            "This does not guarantee that the website is safe."
        )

    return {
        "url": url,
        "status": status,
        "status_class": status_class,
        "risk": risk,
        "message": message,
        "warnings": warnings,
        "features": features
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/about-model")
def about_model():
    return render_template("about_model.html")


@app.route("/history")
def history():
    return render_template(
        "history.html",
        history=session.get("scan_history", [])
    )


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "")

    try:
        result = analyze_url(url)

        session.setdefault("scan_history", [])
        session["scan_history"].insert(0, {
            "url": result["url"],
            "risk": result["risk"],
            "status": result["status"]
        })
        session["scan_history"] = session["scan_history"][:50]
        session.modified = True

        return render_template(
            "index.html",
            result=result,
            features=result["features"]
        )

    except ValueError as error:
        return render_template(
            "index.html",
            error=str(error),
            submitted_url=url
        ), 400

    except Exception:
        app.logger.exception("Unexpected error while analyzing URL")
        return render_template(
            "index.html",
            error="The scan could not be completed. Please try again.",
            submitted_url=url
        ), 500

    try:
        result = analyze_url(url)
        return render_template(
            "index.html",
            result=result,
            features=result["features"]
        )

    except ValueError as error:
        return render_template(
            "index.html",
            error=str(error),
            submitted_url=url
        ), 400

    except Exception:
        app.logger.exception("Unexpected error while analyzing URL")
        return render_template(
            "index.html",
            error=(
                "The scan could not be completed due to an application "
                "error. Please try again."
            ),
            submitted_url=url
        ), 500


if __name__ == "__main__":
    app.run(debug=True)