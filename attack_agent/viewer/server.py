"""viewer.server — FastAPI + 수동 SSE StreamingResponse (GET 전용·변경 엔드포인트 0).

grep0: core.* / supervisor.* 를 import 하지 않는다. 상류 산출 파일을 read + HTTP-serve 만 한다.
- action_log 를 절대 write-open 하지 않는다(공격 agent 입력 오염 0).
- @app.post/put/delete/patch 부재 → 공격 agent 주입면 신설 없음(read-only 소비자).
- SSE 는 sse-starlette 무추가, 수동 event/data 프레이밍. 0.5s 파일 폴링 멀티플렉스.

라우트(전부 GET):
  GET /              → static/index.html
  GET /static/*      → StaticFiles (정적, 외부요청 0)
  GET /api/snapshot  → ingest.build_snapshot (초기 페인트)
  GET /sse           → text/event-stream (action/comms/supervisor 증분 멀티플렉스)

실행: uvicorn viewer.server:app  또는  python -m viewer.server --config config.yaml
작성 2026-07-06.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import AsyncIterator, Optional

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from viewer import ingest

_HERE = Path(__file__).resolve().parent
_STATIC = _HERE / "static"
_SAMPLE = _HERE / "sample"

_POLL_S = 0.5          # 파일 폴링 주기
_HEARTBEAT_EVERY = 30  # keep-alive 주석 프레임 주기(폴 횟수)


# ═══════════════════════════════════════════════════════════════════════════
# SSE 프레이밍 (수동 · sse-starlette 무추가)
# ═══════════════════════════════════════════════════════════════════════════


def _sse_pack(event: str, data: dict) -> str:
    """단일 SSE 이벤트 직렬화: event: <name>\\ndata: <json>\\n\\n."""
    payload = json.dumps(data, ensure_ascii=False, default=str)
    return f"event: {event}\ndata: {payload}\n\n"


async def _sse_stream(request: Request, paths: dict) -> AsyncIterator[str]:
    """0.5s 폴링 멀티플렉스: action/comms 증분 tail + evaluation mtime 재read.

    finally 에서 참조 정리(파일핸들은 tail_lines/read 가 with 로 즉시 닫음 → orphan 0).
    await request.is_disconnected() 로 확실 종료 → 소켓은 uvicorn 소유(단일 프로세스).
    """
    action_p = paths["action"]
    eval_p = paths["evaluation"]
    comms_p = paths.get("comms")

    action_off = 0
    comms_off = 0
    eval_mtime: Optional[float] = None
    # action 스텝 누적(주입 레인 재계산용) — 되먹임 아님, 표시 파생 상태.
    action_steps: list[dict] = []
    ticks = 0
    try:
        # 초기 전량 동기화(스냅샷과 정합) 후 증분.
        init = ingest.build_snapshot(action_p, eval_p, comms_p)
        action_steps = list(init["action"]["steps"])
        action_off = _size(action_p)
        comms_off = _size(comms_p) if comms_p else 0
        eval_mtime = ingest.file_mtime(eval_p)
        yield _sse_pack("snapshot", init)

        while True:
            if await request.is_disconnected():
                break
            await asyncio.sleep(_POLL_S)
            ticks += 1

            # 1) 동작 로그 증분
            new_lines, action_off = ingest.tail_lines(action_p, action_off)
            new_steps: list[dict] = []
            new_campaign: Optional[dict] = None
            for ln in new_lines:
                rec = ingest.parse_action_line(ln)
                if rec is None:
                    continue
                if rec.get("type") == "step":
                    new_steps.append(rec)
                elif rec.get("type") == "campaign_result":
                    new_campaign = rec
            if new_steps or new_campaign:
                action_steps.extend(new_steps)
                yield _sse_pack("action", {
                    "steps": new_steps,
                    "campaign": new_campaign,
                    "count": len(action_steps),
                })

            # 2) 통신 스트림 증분(있을 때) — 주입 레인은 항상 재계산해 정합 유지
            new_frames: list[dict] = []
            if comms_p:
                c_lines, comms_off = ingest.tail_lines(comms_p, comms_off)
                for ln in c_lines:
                    fr = ingest.parse_frame_line(ln)
                    if fr is not None:
                        new_frames.append(fr)
            if new_frames or new_steps:
                yield _sse_pack("comms", {
                    "frames": new_frames,
                    "injections": ingest.inject_rows_from_action(action_steps),
                })

            # 3) 감독 evaluation mtime 변화 → 전량 재read
            m = ingest.file_mtime(eval_p)
            if m is not None and m != eval_mtime:
                eval_mtime = m
                ev = ingest.load_evaluation(eval_p)
                if ev is not None:
                    agree = ((ev.get("verdict") or {}).get("autonomy_accuracy") or {}).get("agree")
                    yield _sse_pack("supervisor", {
                        "evaluation": ev,
                        "banner": {"mismatch": agree is False},
                    })

            # 4) keep-alive 주석(프록시 idle-timeout 방지)
            if ticks % _HEARTBEAT_EVERY == 0:
                yield ": keep-alive\n\n"
    except asyncio.CancelledError:  # 클라이언트 절단/서버 종료
        pass
    finally:
        # tail_lines/read 는 with 컨텍스트로 핸들 즉시 반환 → 잔여 핸들 없음.
        action_steps.clear()


def _size(path: "str | Path | None") -> int:
    if path is None:
        return 0
    try:
        return Path(path).stat().st_size
    except OSError:
        return 0


# ═══════════════════════════════════════════════════════════════════════════
# 앱 팩토리 (라우트 전부 GET·read-only)
# ═══════════════════════════════════════════════════════════════════════════


def create_app(
    *,
    action_log: Path,
    evaluation: Path,
    comms_stream: Optional[Path],
    static_dir: Path = _STATIC,
) -> FastAPI:
    app = FastAPI(title="dah viewer", docs_url=None, redoc_url=None)
    paths = {
        "action": Path(action_log),
        "evaluation": Path(evaluation),
        "comms": Path(comms_stream) if comms_stream else None,
    }
    # 경로 동일성 경고(오설정 방어) — supervisor.emit 이 이미 sink≠agent-log 강제하나 이중화.
    if paths["evaluation"] == paths["action"]:
        import warnings
        warnings.warn("viewer: action_log == evaluation 경로 (동일 파일 이중소비 위험)", stacklevel=2)

    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/")
    async def index() -> FileResponse:  # noqa: ANN202
        return FileResponse(str(static_dir / "index.html"))

    @app.get("/api/snapshot")
    async def snapshot() -> JSONResponse:  # noqa: ANN202
        snap = ingest.build_snapshot(paths["action"], paths["evaluation"], paths["comms"])
        return JSONResponse(snap)

    @app.get("/sse")
    async def sse(request: Request) -> StreamingResponse:  # noqa: ANN202
        return StreamingResponse(
            _sse_stream(request, paths),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    return app


# ═══════════════════════════════════════════════════════════════════════════
# 경로 해석 (--config pyyaml 직독 또는 명시 인자)
# ═══════════════════════════════════════════════════════════════════════════


def resolve_paths(args: argparse.Namespace) -> dict:
    """--config(out.log/viewer.port) 또는 명시 인자 → {action,evaluation,comms,static,port}.

    config 는 pyyaml 로 직독(core.common.config 미import — grep0/완전분리).
    evaluation/comms 기본값은 action_log 형제 파일(evaluation.json/supervisor.jsonl).
    """
    action: Optional[Path] = Path(args.action_log) if args.action_log else None
    port: int = args.port
    if args.config:
        import yaml  # pyyaml 직독(core config 로더 미경유)
        cfg = yaml.safe_load(Path(args.config).read_text(encoding="utf-8")) or {}
        out = (cfg.get("out") or {})
        if action is None and out.get("log"):
            action = Path(out["log"])
        viewer = (cfg.get("viewer") or {})
        if args.port == _DEFAULT_PORT and viewer.get("port"):
            port = int(viewer["port"])

    if action is None:
        action = _SAMPLE / "action.jsonl"  # 데모 폴백(샘플)

    base = action.resolve().parent
    evaluation = Path(args.evaluation) if args.evaluation else base / "evaluation.json"
    if not evaluation.exists() and (_SAMPLE / "evaluation.json").exists() and action == _SAMPLE / "action.jsonl":
        evaluation = _SAMPLE / "evaluation.json"

    if args.comms_stream:
        comms: Optional[Path] = Path(args.comms_stream)
    else:
        sib = base / "supervisor.jsonl"
        comms = sib if sib.exists() else None
        if comms is None and action == _SAMPLE / "action.jsonl" and (_SAMPLE / "supervisor.jsonl").exists():
            comms = _SAMPLE / "supervisor.jsonl"

    return {"action": action, "evaluation": evaluation, "comms": comms,
            "static": _STATIC, "port": port}


_DEFAULT_PORT = 8090


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="viewer.server", description="dah viewer (read-only 3패널)")
    p.add_argument("--config", help="config.yaml (out.log/viewer.port 직독)")
    p.add_argument("--action-log", help="공격 agent action JSONL 경로")
    p.add_argument("--evaluation", help="감독 evaluation.json 경로")
    p.add_argument("--comms-stream", help="감독 supervisor.jsonl 프레임 스트림(선택)")
    p.add_argument("--port", type=int, default=_DEFAULT_PORT, help="HTTP 포트")
    p.add_argument("--host", default="127.0.0.1", help="바인드 호스트")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    paths = resolve_paths(args)
    application = create_app(
        action_log=paths["action"],
        evaluation=paths["evaluation"],
        comms_stream=paths["comms"],
        static_dir=paths["static"],
    )
    import uvicorn
    uvicorn.run(application, host=args.host, port=paths["port"], log_level="info")
    return 0


# 모듈수준 app (uvicorn viewer.server:app) — 기본 샘플 경로로 데모 기동.
app: FastAPI = create_app(
    action_log=_SAMPLE / "action.jsonl",
    evaluation=_SAMPLE / "evaluation.json",
    comms_stream=(_SAMPLE / "supervisor.jsonl") if (_SAMPLE / "supervisor.jsonl").exists() else None,
    static_dir=_STATIC,
)


if __name__ == "__main__":
    raise SystemExit(main())
