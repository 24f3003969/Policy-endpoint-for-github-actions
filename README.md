# release-gate

Deterministic policy endpoint that decides whether a GitHub Actions run may
promote a container image.

## Endpoint

`POST /release-gate` — returns `{"decision": "promote" | "block", "violations": [...]}`.

See `policy.py` for the rule engine (pure function, fully unit tested in
`tests/test_policy.py`) and `app.py` for the thin Flask HTTP wrapper.

## Run locally

```bash
pip install -r requirements.txt
python app.py
# in another shell:
curl -X POST http://127.0.0.1:8000/release-gate -H "Content-Type: application/json" -d @sample.json
```

## Test

```bash
python -m pytest tests/ -v
```

## Deploy

Any host that can run a Flask app works (Render, Railway, Fly.io, a small
VM, etc.). Point the process at `app.py`; it binds `0.0.0.0:8000` by
default (override via the platform's usual `PORT`/proxy conventions if
needed).
