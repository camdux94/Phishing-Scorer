"""
Scores email body text for social engineering language patterns using Claude:
urgency framing, authority impersonation, fear tactics, generic greetings,
and credential/payment requests. Follows the same call pattern as
claude_explain.py — Claude does the language judgment, this module just
packages the prompt/response.
"""

import os
import json
import anthropic

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

_SYSTEM_PROMPT = """You are a security analyst scoring email body text for \
social engineering / phishing language patterns. You are NOT evaluating URLs \
or technical headers — only the human-language manipulation tactics used in \
the text itself.

Score the text 0-100 (0 = no manipulation signals, 100 = textbook phishing \
language) based on presence and intensity of:
- Urgency framing ("act now", "within 24 hours", "your account will be closed")
- Authority impersonation (claiming to be IT, a bank, government, executive)
- Fear/threat tactics (suspension, legal action, financial loss framing)
- Generic/impersonal greetings ("Dear Customer" instead of a real name)
- Requests for credentials, payment, gift cards, or sensitive personal info
- Unusual request patterns (wire transfers, urgent favors, secrecy requests)

Respond with ONLY valid JSON, no other text, in this exact shape:
{
  "score": <integer 0-100>,
  "flags": [<list of short strings, each naming one detected pattern with a brief quote or paraphrase>],
  "summary": "<one or two plain-language sentences explaining the verdict>"
}
"""


def score_email_language(body_text):
    """
    body_text: the plain-text body of the email (strip HTML before calling if needed)
    Returns: (score, flags, summary)
      score: 0-100, higher = more manipulative/phishing-like language
      flags: list of specific patterns detected
      summary: plain-language explanation
    """
    if not body_text or not body_text.strip():
        return 0, [], "No body text provided to analyze."

    # Cap input length to keep this fast and cheap — phishing language
    # patterns show up early, we don't need the whole email if it's long.
    truncated = body_text[:6000]

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=500,
            system=_SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": f"Email body text to analyze:\n\n{truncated}"}
            ],
        )
        raw_text = response.content[0].text.strip()

        # Strip markdown code fences if Claude wraps the JSON despite instructions
        if raw_text.startswith("```"):
            raw_text = raw_text.strip("`")
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
            raw_text = raw_text.strip()

        parsed = json.loads(raw_text)
        score = int(parsed.get("score", 0))
        score = max(0, min(100, score))
        flags = parsed.get("flags", [])
        summary = parsed.get("summary", "")
        return score, flags, summary

    except (json.JSONDecodeError, KeyError, IndexError, anthropic.APIError) as e:
        # Fail safe: don't block the whole analysis if language scoring breaks —
        # return a neutral score and surface the error for debugging.
        return 0, [], f"Language analysis unavailable ({type(e).__name__})"
