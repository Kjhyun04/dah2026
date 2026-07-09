"""Ingest gRPC 서버 (:50051) — envelope 를 sense 로 중계하는 mTLS 전송 계층 (PS-5/8).

설계 포인트:
  - 전송 전용: 이 서버는 CLIENT 를 인증(mTLS, require_client_auth)하고 raw envelope 를
    in-proc 큐로 중계한다. envelope 의 HMAC/seq 는 검증하지 않는다 — 그것은 sense drain
    시점의 소비 게이트(PS-2, ingest.verify)이며, 그 결과 in-proc 경로와 gRPC 경로가
    하나의 인증 표준을 공유한다.
  - loopback(127.0.0.1) 또는 전용 mgmt netns 에 바인드 — 절대 0.0.0.0 금지(PS-8), 그래야
    공격자 UE(10.45.0.x)가 도달할 수 없다.
  - 인증 전 DoS 상한(PS-8): 모든 RPC 작업 전에 mTLS 강제, max_message_length 256 KiB,
    유계 스레드 풀 / 최대 동시 RPC 수.
  - protobuf 코드 생성 없음: envelope 를 canonical JSON 바이트로 실어 나르는 generic
    unary-unary 핸들러를 사용하므로 모듈은 grpcio 만 필요(protoc 단계 불필요).

grpcio 는 특정 환경(로컬 개발)에서 부재할 수 있다. 모듈은 깔끔하게 import 되며 ``serve`` 가
grpcio 없이 실제로 호출될 때만 명확한 오류를 낸다. envelope 코덱과 enqueue servicer 는
grpc 비의존이며 단위 테스트 가능하다.
"""
from __future__ import annotations

import json
import queue
from typing import Optional

from ..collector.ingest import SensorEnvelope

_MAX_MSG = 256 * 1024              # PS-8 인증 전 DoS 상한: 256 KiB
_SERVICE = "mdg.ingest.Ingest"
_METHOD = "Submit"

try:                              # 선택적 의존성
    import grpc                   # type: ignore
    _HAS_GRPC = True
except Exception:                 # pragma: no cover
    grpc = None                   # type: ignore
    _HAS_GRPC = False


# --------------------------------------------------------------------------- #
# Envelope 코덱 (grpc 비의존, 테스트 가능)
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
    """전송 servicer: envelope 디코드 -> in-proc 큐에 넣기. grpc 없이도 재사용 가능
    (generic 핸들러가 호출하는 것과 동일한 로직을 구동)."""
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
            self.inbox.put_nowait(env)          # 중계; 소비 게이트가 나중에 검증
            self.accepted += 1
            return b'{"ok":true}'
        except queue.Full:
            self.rejected += 1                  # 크래시가 아닌 backpressure
            return b'{"ok":false,"reason":"full"}'


# --------------------------------------------------------------------------- #
# mTLS 자격증명 + 서버
# --------------------------------------------------------------------------- #
def build_server_credentials(server_key: bytes, server_cert: bytes, root_ca: bytes):
    """클라이언트 인증을 필수로 하는 mTLS 서버 자격증명(PS-5/PS-8). 단명 인증서 + CRL 은
    대역 외로 관리되며(tmpfs 마운트, PS-5), 이 함수는 핸드셰이크 정책을 고정한다."""
    if not _HAS_GRPC:                            # pragma: no cover
        raise ImportError("grpcio is required for mTLS credentials")
    return grpc.ssl_server_credentials(          # type: ignore
        [(server_key, server_cert)],
        root_certificates=root_ca,
        require_client_auth=True,                # 유효한 인증서 없는 클라이언트는 거부
    )


def serve(inbox: "queue.Queue", *, host: str = "127.0.0.1", port: int = 50051,
          credentials=None, max_workers: int = 8, max_concurrent_rpcs: int = 32):
    """loopback 에 바인드된 gRPC 서버를 mTLS + DoS 상한과 함께 시작. (server, servicer) 를
    반환한다. 호출자는 server 핸들을 보유하고 ``server.stop(...)`` 을 호출한다.

    0.0.0.0 바인드를 거부하고(PS-8) 운영에서 insecure/mTLS 없는 바인드를 거부한다 —
    ``credentials`` 가 반드시 제공되어야 한다(mTLS). grpcio 가 없으면 예외를 낸다.
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
        request_deserializer=lambda b: b,        # raw 바이트 입력
        response_serializer=lambda b: b,         # raw 바이트 출력
    )
    generic = grpc.method_handlers_generic_handler(  # type: ignore
        _SERVICE, {_METHOD: handler})
    server.add_generic_rpc_handlers((generic,))

    server.add_secure_port(f"{host}:{port}", credentials)   # mTLS 전용, loopback
    server.start()
    return server, servicer
