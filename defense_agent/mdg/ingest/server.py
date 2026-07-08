"""Ingest gRPC server (:50051) — mTLS transport that relays envelopes to sense (PS-5/8).

Design points:
  - Transport-only: this server authenticates the CLIENT (mTLS, require_client_auth)
    and relays the raw envelope to the in-proc queue. It does NOT verify the envelope
    HMAC/seq — that is the consumption gate (PS-2, ingest.verify) at sense drain, so
    the in-proc and gRPC paths share one authentication standard.
  - Bind loopback (127.0.0.1) or a dedicated mgmt netns — NEVER 0.0.0.0 (PS-8), so an
    attacker UE (10.45.0.x) cannot reach it.
  - Pre-auth DoS caps (PS-8): mTLS enforced before any RPC work, max_message_length
    256 KiB, bounded thread pool / max concurrent RPCs.
  - No protobuf codegen: uses a generic unary-unary handler carrying the envelope as
    canonical JSON bytes, so the module needs only grpcio (no protoc step).

grpcio may be absent in a given environment (local dev); the module imports cleanly and
raises a clear error only when ``serve`` is actually called without grpcio. The
envelope codec and the enqueue servicer are grpc-independent and unit-testable.
"""
from __future__ import annotations

import json
import queue
from typing import Optional

from ..collector.ingest import SensorEnvelope

_MAX_MSG = 256 * 1024              # PS-8 pre-auth DoS cap: 256 KiB
_SERVICE = "mdg.ingest.Ingest"
_METHOD = "Submit"

try:                              # optional dependency
    import grpc                   # type: ignore
    _HAS_GRPC = True
except Exception:                 # pragma: no cover
    grpc = None                   # type: ignore
    _HAS_GRPC = False


# --------------------------------------------------------------------------- #
# Envelope codec (grpc-independent, testable)
# --------------------------------------------------------------------------- #
def encode_envelope(env: SensorEnvelope) -> bytes:
    return json.dumps({
        "payload": env.payload, "source_id": env.source_id, "kid": env.kid,
        "seq": env.seq, "ts": env.ts, "nonce": env.nonce, "hmac": env.hmac,
    }, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def decode_envelope(data: bytes) -> SensorEnvelope:
    if len(data) > _MAX_MSG:
        raise ValueError("envelope exceeds max message length")
    obj = json.loads(data.decode("utf-8"))
    return SensorEnvelope(
        payload=dict(obj.get("payload") or {}), source_id=str(obj.get("source_id", "")),
        kid=str(obj.get("kid", "")), seq=int(obj.get("seq", 0)),
        ts=float(obj.get("ts", 0.0)), nonce=str(obj.get("nonce", "")),
        hmac=str(obj.get("hmac", "")),
    )


class EnqueueServicer:
    """Transport servicer: decode envelope -> put on the in-proc queue. Reusable
    without grpc (drives the same logic the generic handler calls)."""
    def __init__(self, inbox: "queue.Queue"):
        self.inbox = inbox
        self.accepted = 0
        self.rejected = 0

    def submit(self, request_bytes: bytes, context=None) -> bytes:
        try:
            env = decode_envelope(request_bytes)
        except Exception as exc:
            self.rejected += 1
            if context is not None and _HAS_GRPC:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)  # type: ignore
                context.set_details(str(exc))
            return b'{"ok":false}'
        try:
            self.inbox.put_nowait(env)          # relay; consumption gate verifies later
            self.accepted += 1
            return b'{"ok":true}'
        except queue.Full:
            self.rejected += 1                  # backpressure, not a crash
            return b'{"ok":false,"reason":"full"}'


# --------------------------------------------------------------------------- #
# mTLS credentials + server
# --------------------------------------------------------------------------- #
def build_server_credentials(server_key: bytes, server_cert: bytes, root_ca: bytes):
    """mTLS server creds with client auth REQUIRED (PS-5/PS-8). Short-lived certs +
    CRL are managed out of band (tmpfs mount, PS-5); this binds the handshake policy."""
    if not _HAS_GRPC:                            # pragma: no cover
        raise ImportError("grpcio is required for mTLS credentials")
    return grpc.ssl_server_credentials(          # type: ignore
        [(server_key, server_cert)],
        root_certificates=root_ca,
        require_client_auth=True,                # reject any client without a valid cert
    )


def serve(inbox: "queue.Queue", *, host: str = "127.0.0.1", port: int = 50051,
          credentials=None, max_workers: int = 8, max_concurrent_rpcs: int = 32):
    """Start the gRPC server bound to loopback with mTLS + DoS caps. Returns
    (server, servicer). Caller keeps the server handle and calls ``server.stop(...)``.

    Refuses to bind 0.0.0.0 (PS-8) and refuses insecure/no-mTLS bind in production —
    ``credentials`` must be provided (mTLS). Raises if grpcio is unavailable.
    """
    if not _HAS_GRPC:
        raise ImportError(
            "grpcio is required to serve :50051 (pip install -r requirements.txt). "
            "The envelope codec and EnqueueServicer are usable without grpcio."
        )
    if host in ("0.0.0.0", "::", ""):
        raise ValueError("ingest server must bind loopback/mgmt netns, not 0.0.0.0 (PS-8)")
    if credentials is None:
        raise ValueError("mTLS credentials are required (PS-5/PS-8); no insecure bind")

    from concurrent import futures
    servicer = EnqueueServicer(inbox)

    options = [
        ("grpc.max_receive_message_length", _MAX_MSG),
        ("grpc.max_send_message_length", _MAX_MSG),
        ("grpc.max_concurrent_streams", max_concurrent_rpcs),
    ]
    server = grpc.server(                        # type: ignore
        futures.ThreadPoolExecutor(max_workers=max_workers),
        maximum_concurrent_rpcs=max_concurrent_rpcs,
        options=options,
    )

    handler = grpc.unary_unary_rpc_method_handler(  # type: ignore
        servicer.submit,
        request_deserializer=lambda b: b,        # raw bytes in
        response_serializer=lambda b: b,         # raw bytes out
    )
    generic = grpc.method_handlers_generic_handler(  # type: ignore
        _SERVICE, {_METHOD: handler})
    server.add_generic_rpc_handlers((generic,))

    server.add_secure_port(f"{host}:{port}", credentials)   # mTLS only, loopback
    server.start()
    return server, servicer
