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
