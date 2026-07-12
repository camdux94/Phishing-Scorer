"""
Top-level orchestrator for email phishing analysis. Combines:
  1. Header analysis (email_headers.py) — SPF/DKIM/DMARC, spoofing
  2. Embedded link analysis — reuses the EXISTING analyzer.analyze_url()
     from your phishing-scorer app for every URL found in the body
  3. Social engineering language scoring (email_language.py)

Into a single blended verdict. Does not duplicate any URL-scoring logic —
every link found gets run through your existing, already-tested analyzer.
"""

import re
import email
from email import policy
from email.parser import BytesParser, Parser

from email_headers import analyze_headers
from email_language import score_email_language

# This imports your EXISTING analyzer.py from the phishing-scorer app.
# Both files must live in the same repo/directory for this import to work.
from analyzer import analyze_url


_URL_PATTERN = re.compile(r'https?://[^\s<>"\'\)\]]+', re.IGNORECASE)


def analyze_email(raw_email_input, is_raw_source=True):
    """
    raw_email_input: either the full raw email source (headers + body, as
      copy-pasted from "Show Original" in Gmail/Outlook), or a plain string
      if the user only pastes body text with no headers.
    is_raw_source: True if raw_email_input includes headers, False if it's
      body-text-only (skips header analysis in that case).

    Returns a dict shaped for direct use in the Flask response / template.
    """
    if is_raw_source:
        msg = Parser(policy=policy.default).parsestr(raw_email_input)
        header_score, header_reasons, header_info = analyze_headers(msg)
        body_text = _extract_body_text(msg)
    else:
        header_score, header_reasons, header_info = 0, ["No headers provided — header checks skipped"], {}
        body_text = raw_email_input

    # --- Extract and score every link in the body ---
    urls = _extract_urls(body_text)
    link_results = []
    worst_link_score = 0

    for url in urls[:10]:  # cap at 10 links to keep this fast and bounded
        try:
            result = analyze_url(url)
            link_score = result.get("overall_score", 0)
            link_results.append({
                "url": url,
                "score": link_score,
                "verdict": result.get("verdict", "unknown"),
            })
            worst_link_score = max(worst_link_score, link_score)
        except Exception as e:
            link_results.append({
                "url": url,
                "score": None,
                "verdict": f"analysis failed ({type(e).__name__})",
            })

    # --- Score the social engineering language ---
    language_score, language_flags, language_summary = score_email_language(body_text)

    # --- Combined verdict ---
    # Header issues and worst embedded link are treated as strong signals;
    # language manipulation is weighted slightly lower since aggressive but
    # legitimate marketing copy can otherwise trigger false positives.
    overall_score = round(
        header_score * 0.35 +
        worst_link_score * 0.40 +
        language_score * 0.25
    )
    overall_score = max(0, min(100, overall_score))

    if overall_score >= 70:
        verdict = "phishing"
    elif overall_score >= 40:
        verdict = "suspicious"
    else:
        verdict = "likely safe"

    return {
        "overall_score": overall_score,
        "verdict": verdict,
        "header_score": header_score,
        "header_reasons": header_reasons,
        "header_info": header_info,
        "links": link_results,
        "worst_link_score": worst_link_score,
        "language_score": language_score,
        "language_flags": language_flags,
        "language_summary": language_summary,
        "urls_found": len(urls),
    }


def _extract_urls(text):
    if not text:
        return []
    return list(dict.fromkeys(_URL_PATTERN.findall(text)))  # dedupe, preserve order


def _extract_body_text(msg):
    """Pulls plain-text body from a parsed email.message.Message, falling
    back to a naive HTML strip if only an HTML part is present."""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                return part.get_content()
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                return _strip_html(part.get_content())
        return ""
    else:
        content_type = msg.get_content_type()
        content = msg.get_content()
        if content_type == "text/html":
            return _strip_html(content)
        return content


def _strip_html(html):
    text = re.sub(r'<[^>]+>', ' ', html)
    return re.sub(r'\s+', ' ', text).strip()
