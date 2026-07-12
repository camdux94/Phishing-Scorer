"""
Claude writes a plain-language explanation of why a URL scored the way it did.
Same trust pattern as BizVerify and Chargeback Analyzer: Claude explains,
deterministic code decides.
"""

import os
import anthropic

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))


def generate_explanation(url, result):
    prompt = f"""You are a security analyst writing a brief explanation of a phishing risk assessment.

URL analyzed: {url}
Domain: {result['domain']}

Computed scores (already calculated — do not recalculate or contradict these):
- Overall risk score: {result['overall_score']}/100
- Verdict: {result['verdict_label']}
- URL structure score: {result['structure_score']}/100 — {'; '.join(result['structure_reasons'])}
- Domain age: {result['age_result'].get('details', 'unknown')}
- SSL: {result['ssl_result'].get('details', 'unknown')}
- Google Safe Browsing: {result['safe_browsing_result'].get('details', 'unknown')}
- Page content: {result['content_result'].get('details', 'unknown')}

Write a concise (3-4 sentence) explanation of why this URL received its risk score,
in plain language. Reference the specific signals above. Do not state a different
score or verdict than the one given. Do not use markdown formatting."""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=250,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text.strip()
    except Exception as e:
        return f"Explanation unavailable — Claude API error: {str(e)}"
