from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from dotenv import load_dotenv

from analyzer import analyze_url
from claude_explain import generate_explanation

load_dotenv()

app = Flask(__name__)
CORS(app)

# Real, safe, well-known URLs used as "try a sample" buttons — since we can't
# link to live phishing sites, these demo the "safe" end of the scoring range.
SAMPLE_URLS = [
    "https://www.google.com",
    "https://www.github.com",
    "https://www.wikipedia.org",
    "http://192.168.1.1-paypal-verify.xyz/login",
    "http://secure-appleid-verify-account.top/signin",
    "http://bit.ly/3xK9pL2"
]


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/samples", methods=["GET"])
def samples():
    return jsonify(SAMPLE_URLS)


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Please provide a URL."}), 400

    try:
        result = analyze_url(url)
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

    explanation = generate_explanation(url, result)

    return jsonify({
        "url": url,
        "result": result,
        "explanation": explanation
    })


if __name__ == "__main__":
    app.run(debug=True)
