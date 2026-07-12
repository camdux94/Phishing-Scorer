"""
Combines URL structure, domain age, SSL, Safe Browsing, and content analysis
into a single 0-100 phishing risk score and verdict.
"""

from url_structure import analyze_url_structure
from external_checks import check_domain_age, check_ssl, check_safe_browsing, check_page_content


def analyze_url(url):
    if "://" not in url:
        url = f"http://{url}"

    structure_score, structure_reasons, domain = analyze_url_structure(url)
    rdap_domain = domain[4:] if domain.startswith("www.") else domain
    age_result = check_domain_age(rdap_domain)
    ssl_result = check_ssl(domain)
    safe_browsing_result = check_safe_browsing(url)
    content_result = check_page_content(url)

    # Safe Browsing match is an instant, overriding signal — Google has already
    # confirmed this URL is malicious, so don't let other checks dilute it.
    if not safe_browsing_result.get("safe", True):
        overall = 100
    else:
        # Only weight checks that actually returned real data — a failed/unavailable
        # check (e.g. domain doesn't resolve, content couldn't be fetched) should not
        # dilute a strong signal from a check that DID succeed, like URL structure.
        weighted_components = [(structure_score, 0.35)]  # structure always available

        if age_result.get("found"):
            weighted_components.append((age_result.get("score", 0), 0.25))
        if ssl_result.get("valid") is not None:
            weighted_components.append((ssl_result.get("score", 0), 0.10))
        if content_result.get("checked"):
            weighted_components.append((content_result.get("score", 0), 0.30))

        total_weight = sum(w for _, w in weighted_components)
        overall = round(sum(s * w for s, w in weighted_components) / total_weight) if total_weight else structure_score

        # A domain that fails to resolve at all (age check AND content check both
        # failed) is itself a red flag worth surfacing, not just a neutral gap —
        # real phishing domains are frequently unreachable shortly after being
        # reported or taken down.
        if not age_result.get("found") and not content_result.get("checked"):
            overall = max(overall, structure_score, 40)

    if overall >= 70:
        verdict = "phishing"
        verdict_label = "High Risk — Likely Phishing"
    elif overall >= 35:
        verdict = "suspicious"
        verdict_label = "Suspicious — Manual Review Recommended"
    else:
        verdict = "safe"
        verdict_label = "Low Risk"

    return {
        "domain": domain,
        "overall_score": min(overall, 100),
        "verdict": verdict,
        "verdict_label": verdict_label,
        "structure_score": structure_score,
        "structure_reasons": structure_reasons,
        "age_result": age_result,
        "ssl_result": ssl_result,
        "safe_browsing_result": safe_browsing_result,
        "content_result": content_result,
    }
