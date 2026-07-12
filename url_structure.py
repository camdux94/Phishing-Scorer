"""
URL structure analysis — checks the URL itself for patterns common in phishing
links, independent of any external API. This is the signal type most specific
to phishing detection (as opposed to general domain reputation).
"""

import re
import urllib.parse

# Common brands frequently impersonated in phishing — used for lookalike detection
COMMON_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix", "bankofamerica",
    "wellsfargo", "chase", "citibank", "instagram", "facebook", "linkedin",
    "irs", "usps", "fedex", "ups", "dhl", "coinbase", "binance"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"
]


def analyze_url_structure(url):
    """Returns a 0-100 risk score plus reasons, based purely on URL structure."""
    score = 0
    reasons = []
    flags = []

    parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
    host = parsed.netloc.lower().split(":")[0]
    path = parsed.path.lower()
    full_url = url.lower()

    # IP address used instead of a domain name — very strong phishing signal
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(host):
        score += 40
        flags.append("URL uses a raw IP address instead of a domain name")

    # Punycode / internationalized domain — often used for homoglyph attacks
    if "xn--" in host:
        score += 25
        flags.append("Domain uses punycode encoding — possible homoglyph/lookalike attack")

    # @ symbol trick — everything before @ is ignored by browsers, used to disguise real destination
    if "@" in full_url.split("://", 1)[-1]:
        score += 35
        flags.append("URL contains '@' symbol — classic technique to disguise the real destination")

    # Excessive subdomains
    subdomain_count = host.count(".") - 1 if host.count(".") > 1 else 0
    if subdomain_count >= 3:
        score += 20
        flags.append(f"Excessive subdomains ({subdomain_count}) — often used to bury the real domain")
    elif subdomain_count >= 2:
        score += 10

    # Excessive hyphens — common in generated lookalike domains
    hyphen_count = host.count("-")
    if hyphen_count >= 3:
        score += 15
        flags.append(f"Domain contains {hyphen_count} hyphens — common in generated lookalike domains")

    # URL shortener — hides the real destination entirely
    if any(short in host for short in URL_SHORTENERS):
        score += 20
        flags.append("URL uses a link shortener — real destination is hidden")

    # Brand name appears in the domain, but domain isn't the brand's actual site
    for brand in COMMON_BRANDS:
        if brand in host and not host.endswith(f"{brand}.com") and not host == brand:
            # crude but effective: brand name present but not as the actual registered domain
            score += 30
            flags.append(f"Contains brand name '{brand}' but domain doesn't match {brand}'s actual site — likely impersonation")
            break

    # Suspicious TLDs commonly abused for cheap/fast phishing domain registration
    suspicious_tlds = [".xyz", ".top", ".club", ".work", ".gq", ".tk", ".ml", ".click", ".loan"]
    if any(host.endswith(tld) for tld in suspicious_tlds):
        score += 15
        flags.append(f"Uses a TLD ({host.split('.')[-1]}) commonly associated with low-cost, fast phishing registrations")

    # Suspicious keywords in path — urgency/account-action language often paired with phishing
    urgent_keywords = ["verify", "suspend", "confirm-account", "update-billing", "secure-login", "unlock"]
    if any(kw in path for kw in urgent_keywords):
        score += 10
        flags.append("URL path contains urgency/account-action keywords")

    if not flags:
        reasons.append("No suspicious URL structure patterns detected")
    else:
        reasons = flags

    return min(score, 100), reasons, host
