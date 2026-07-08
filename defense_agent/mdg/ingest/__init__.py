"""ingest — control-plane transport (:50051 mTLS) + PS-2 consumption verifier.

server.py : the gRPC transport that accepts SensorEnvelopes over mTLS and relays them
            to the in-proc queue that ``sense`` drains. Transport auth (mTLS) here;
            payload auth (HMAC/seq) is deliberately deferred to consumption (PS-2).
verify.py : the sense-facing ``verify(env) -> (ok, reason, SensorEv)`` callable that
            enforces HMAC + seq (+ ts skew) at drain and drops forgeries.
"""
