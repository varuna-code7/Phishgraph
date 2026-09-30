import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request

from . import fusion

PROJECT_ROOT = Path(__file__).resolve().parent.parent

app = Flask(__name__, template_folder=str(PROJECT_ROOT / "templates"))


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/analyze")
def analyze():
    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        return jsonify(error="Request body must be a JSON object."), 400
    for field in ("sender", "subject", "body"):
        if field not in d:
            return jsonify(error=f"Missing required field: {field}."), 400
        if not isinstance(d[field], str):
            return jsonify(error=f"Field '{field}' must be a string."), 400
    return jsonify(fusion.analyze_email(d.get("sender", ""), d.get("subject", ""), d.get("body", "")))


@app.post("/feedback")
def feedback():
    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        return jsonify(error="Request body must be a JSON object."), 400
    domains = d.get("domains")
    if not isinstance(domains, list):
        return jsonify(error="Field 'domains' must be a list."), 400
    if any(not isinstance(domain, str) or not domain.strip() for domain in domains):
        return jsonify(error="Each domain must be a non-empty string."), 400
    fusion.report(domains)
    return jsonify(ok=True)


@app.errorhandler(500)
def internal_error(_error):
    if request.path in ("/analyze", "/feedback"):
        return jsonify(error="Internal server error."), 500
    return "Internal server error.", 500


if __name__ == "__main__":
    app.run(debug=os.environ.get("PHISHGRAPH_DEBUG", "0").lower() in {"1", "true", "yes"})
