# Phishing URL Scorer

Analyzes a URL for phishing risk using URL structure analysis, domain age
(via free RDAP — no API key or quota), SSL certificate presence, Google Safe
Browsing, and page content patterns. Claude writes a plain-language
explanation of the result; deterministic code computes every score.

## Setup

```bash
cd phishing-scorer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=your_key_here
export GOOGLE_API_KEY=your_key_here   # optional — reuse the one from BizVerify
python3 app.py
```

Then open `http://localhost:5000`.

## How it works

- **url_structure.py** — pure pattern analysis on the URL itself: IP addresses
  used as hosts, punycode, the @ symbol trick, excessive subdomains/hyphens,
  URL shorteners, brand impersonation, suspicious TLDs, urgency keywords.
  No external API — this is the fastest, most phishing-specific signal.
- **external_checks.py** — domain age via free RDAP (25s timeout + retry),
  SSL presence, Google Safe Browsing, and page content analysis (password
  fields, urgency language, brand/domain mismatch).
- **analyzer.py** — combines everything. A confirmed Safe Browsing match
  overrides everything else (instant 100). Otherwise, only checks that
  actually returned real data are averaged together — a failed/unreachable
  domain doesn't dilute a strong structure-analysis signal, and a domain
  that fails to resolve at all is itself treated as suspicious.
- **claude_explain.py** — writes the plain-language explanation. Never
  recalculates or contradicts the given score.
- **app.py** — Flask routes: `/samples` (a few real safe URLs plus
  fabricated lookalike examples for demo), `/analyze` (the core check).

## Deploying

Same pattern as your other projects:

1. `git init && git add . && git commit -m "Initial commit"`
2. Push to `github.com/camdux94/phishing-scorer`
3. Deploy to Render, set `ANTHROPIC_API_KEY` and `GOOGLE_API_KEY` as
   environment variables
4. Update cameronhall.dev to link to the live tool
