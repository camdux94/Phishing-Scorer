"""
External checks: domain age (RDAP), SSL certificate, Google Safe Browsing,
and page content analysis for phishing-specific patterns.
"""

import requests
import ssl
import socket
import datetime
import os
import re

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")


def check_domain_age(domain):
    """Domain age via free RDAP. New domains are one of the strongest phishing signals."""
    data = None
    for attempt in range(2):
        try:
            url = f"https://rdap.org/domain/{domain}"
            r = requests.get(url, timeout=25, headers={"Accept": "application/rdap+json"})
            if r.status_code != 200:
                return {"found": False, "score": 30, "details": "Could not verify domain age — treat with caution."}
            data = r.json()
            break
        except requests.exceptions.Timeout:
            if attempt == 1:
                return {"found": False, "score": 30, "details": "RDAP lookup timed out after retry."}
            continue
        except Exception as e:
            return {"found": False, "score": 30, "details": f"RDAP lookup failed: {str(e)}"}

    try:
        created_date_str = None
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                created_date_str = event.get("eventDate", "")
                break

        if not created_date_str:
            return {"found": False, "score": 30, "details": "Domain registration date unavailable."}

        created = datetime.datetime.strptime(created_date_str[:10], "%Y-%m-%d")
        age_days = (datetime.datetime.now() - created).days

        if age_days < 7:
            score = 90
            details = f"Domain registered only {age_days} day(s) ago — extremely strong phishing signal"
        elif age_days < 30:
            score = 70
            details = f"Domain registered {age_days} days ago — very new, high risk"
        elif age_days < 180:
            score = 40
            details = f"Domain registered {age_days} days ago — relatively new"
        elif age_days < 365:
            score = 15
            details = f"Domain is {age_days // 30} months old"
        else:
            score = 0
            details = f"Domain is {age_days // 365} year(s) old — established"

        return {"found": True, "score": score, "age_days": age_days, "details": details}
    except Exception as e:
        return {"found": False, "score": 30, "details": f"Could not parse domain age: {str(e)}"}


def check_ssl(domain):
    """SSL presence — phishing sites increasingly have valid SSL, so absence is
    notable but presence alone doesn't mean safe."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            return {"valid": True, "score": 0, "details": "SSL certificate present."}
    except ssl.SSLError:
        return {"valid": False, "score": 25, "details": "SSL certificate invalid or missing — red flag."}
    except Exception:
        return {"valid": False, "score": 15, "details": "Could not verify SSL — site may not support HTTPS."}


def check_safe_browsing(url):
    """Direct check against Google's known-malicious URL list."""
    if not GOOGLE_API_KEY:
        return {"safe": True, "score": 0, "details": "Safe Browsing check skipped — no API key configured."}
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        payload = {
            "client": {"clientId": "phishing-scorer", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        r = requests.post(api_url, json=payload, timeout=10)
        data = r.json()
        if data.get("matches"):
            threat_types = [m.get("threatType") for m in data["matches"]]
            return {"safe": False, "score": 100, "details": f"CRITICAL: URL flagged by Google Safe Browsing ({', '.join(threat_types)})."}
        return {"safe": True, "score": 0, "details": "Not flagged by Google Safe Browsing."}
    except Exception as e:
        return {"safe": True, "score": 0, "details": f"Safe Browsing check inconclusive: {str(e)}"}


def check_page_content(url):
    """Fetches the page and looks for phishing-specific content patterns:
    fake login forms, urgency language, brand mentions that don't match the domain."""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"}
        r = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        if r.status_code >= 400:
            return {"checked": True, "score": 20, "details": f"Page returned error {r.status_code}."}

        html = r.text.lower()
        score = 0
        flags = []

        has_password_field = 'type="password"' in html or "type='password'" in html
        if has_password_field:
            score += 15
            flags.append("Page contains a password input field")

        urgency_phrases = [
            "verify your account", "account will be suspended", "confirm your identity",
            "unusual activity", "click here immediately", "your account has been limited",
            "action required", "expires in 24 hours"
        ]
        found_urgency = [p for p in urgency_phrases if p in html]
        if found_urgency:
            score += 20
            flags.append(f"Urgency/pressure language detected: \"{found_urgency[0]}\"")

        brand_pattern_hits = {}
        for brand in ["paypal", "amazon", "apple", "microsoft", "netflix", "bank of america"]:
            matches = re.findall(r'\b' + re.escape(brand) + r'\b', html)
            if len(matches) >= 2:
                brand_pattern_hits[brand] = len(matches)
        domain = url.lower()
        mismatched_brands = [b for b in brand_pattern_hits if b.replace(" ", "") not in domain]
        if mismatched_brands:
            score += 25
            flags.append(f"Page repeatedly mentions '{mismatched_brands[0]}' ({brand_pattern_hits[mismatched_brands[0]]}x) but domain doesn't match that brand")

        if not flags:
            flags.append("No suspicious content patterns detected")

        return {"checked": True, "score": min(score, 100), "details": "; ".join(flags)}
    except Exception as e:
        return {"checked": False, "score": 10, "details": f"Could not fetch page content: {str(e)}"}
