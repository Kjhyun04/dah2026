"""viewer — FastAPI 3-panel replay dashboard (V3 §8 · H-K).

Panels: 동작(decision JSONL) / 통신(14560 telemetry) / 검증(Verifier 대조). Renders an
``agent ≠ truth`` banner at the top (the agent's posture is NOT ground truth), reads only
already-redacted JSONL (record-time redact is the contract; no display-time redaction),
serves read-only GETs behind a bearer token, and binds loopback / management-net only
(PS-8: never 0.0.0.0). The independent Verifier (mdg.verifier) is the trust root shown in
panel 3.
"""
