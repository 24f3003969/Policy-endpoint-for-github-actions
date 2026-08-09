from flask import Flask, request, jsonify

from policy import evaluate

app = Flask(__name__)


@app.post("/release-gate")
def release_gate():
    payload = request.get_json(silent=True, force=True) or {}
    result = evaluate(payload)
    return jsonify(result), 200


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
