"""
Analyzes raw email headers for phishing/spoofing signals: SPF/DKIM/DMARC
authentication results, From/Reply-To mismatches, display name spoofing,
and suspicious Received-path patterns.

Expects raw header text (as copy-pasted from an email client's "show original"
view) or a parsed email.message.Message object.
"""

import re
import email
from email.utils import parseaddr


def analyze_headers(raw_headers):
    """
    raw_headers: either a raw header string, or an email.message.Message
    Returns: (header_score, reasons, parsed_info)
      header_score: 0-100, higher = more suspicious
      reasons: list of human-readable flags
      parsed_info: dict of extracted fields for display
    """
    if isinstance(raw_headers, str):
        msg = email.message_from_string(raw_headers)
    else:
        msg = raw_headers

    reasons = []
    score = 0

    from_header = msg.get("From", "") or ""
    reply_to = msg.get("Reply-To", "") or ""
    return_path = msg.get("Return-Path", "") or ""
    auth_results = msg.get("Authentication-Results", "") or ""
    received = msg.get_all("Received", []) or []

    from_name, from_addr = parseaddr(from_header)
    reply_name, reply_addr = parseaddr(reply_to)

    from_domain = _extract_domain(from_addr)
    reply_domain = _extract_domain(reply_addr)

    # --- SPF / DKIM / DMARC ---
    spf_result = _extract_auth_result(auth_results, "spf")
    dkim_result = _extract_auth_result(auth_results, "dkim")
    dmarc_result = _extract_auth_result(auth_results, "dmarc")

    if spf_result == "fail":
        score += 25
        reasons.append("SPF check failed — sending server not authorized for this domain")
    elif spf_result == "none":
        score += 10
        reasons.append("No SPF record found for sending domain")

    if dkim_result == "fail":
        score += 20
        reasons.append("DKIM signature failed — message may have been altered or spoofed")
    elif dkim_result == "none":
        score += 8
        reasons.append("No DKIM signature present")

    if dmarc_result == "fail":
        score += 25
        reasons.append("DMARC check failed — domain policy rejects this authentication result")

    # --- From / Reply-To mismatch ---
    if reply_addr and from_domain and reply_domain and from_domain != reply_domain:
        score += 20
        reasons.append(
            f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}) "
            "— replies would go somewhere other than the visible sender"
        )

    # --- Return-Path mismatch ---
    return_path_addr = parseaddr(return_path)[1]
    return_path_domain = _extract_domain(return_path_addr)
    if return_path_domain and from_domain and return_path_domain != from_domain:
        score += 10
        reasons.append(
            f"Return-Path domain ({return_path_domain}) differs from From domain ({from_domain})"
        )

    # --- Display name spoofing ---
    # Flags cases like: "PayPal Support" <random123@totally-different-domain.com>
    brand_flag = _check_display_name_spoofing(from_name, from_domain)
    if brand_flag:
        score += 25
        reasons.append(brand_flag)

    # --- Received path anomalies ---
    if len(received) > 8:
        score += 5
        reasons.append(f"Unusually long relay path ({len(received)} hops) — may indicate relay abuse")

    if not received:
        score += 5
        reasons.append("No Received headers present — header may be incomplete or stripped")

    score = min(score, 100)

    parsed_info = {
        "from_name": from_name,
        "from_address": from_addr,
        "from_domain": from_domain,
        "reply_to_address": reply_addr,
        "reply_to_domain": reply_domain,
        "spf": spf_result,
        "dkim": dkim_result,
        "dmarc": dmarc_result,
        "hop_count": len(received),
    }

    return score, reasons, parsed_info


def _extract_domain(addr):
    if not addr or "@" not in addr:
        return ""
    return addr.split("@")[-1].lower().strip()


def _extract_auth_result(auth_results, mechanism):
    """
    Pulls e.g. 'spf=pass' out of an Authentication-Results header string.
    Returns 'pass', 'fail', 'softfail', 'neutral', or 'none' if not found.
    """
    if not auth_results:
        return "none"
    pattern = rf"{mechanism}=(\w+)"
    match = re.search(pattern, auth_results, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return "none"


# Common brand names attackers impersonate in display names.
# Not exhaustive — meant to catch the highest-volume phishing targets.
_WATCHED_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "bank of america", "wells fargo", "chase", "irs", "usps", "fedex",
    "ups", "docusign", "linkedin", "facebook", "instagram", "venmo",
    "zelle", "coinbase", "office 365", "outlook", "dhl",
]


def _check_display_name_spoofing(display_name, from_domain):
    """
    Flags when a display name references a known brand but the sending
    domain has nothing to do with that brand.
    """
    if not display_name or not from_domain:
        return None

    name_lower = display_name.lower()
    for brand in _WATCHED_BRANDS:
        if brand in name_lower:
            brand_slug = brand.replace(" ", "")
            if brand_slug not in from_domain.replace(".", "").replace("-", ""):
                return (
                    f'Display name "{display_name}" references "{brand}" but the sending domain '
                    f'({from_domain}) does not match that brand — likely impersonation'
                )
    return None
