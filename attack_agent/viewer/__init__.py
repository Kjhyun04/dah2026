"""viewer — READ-ONLY 3패널 관측기 (동작·통신·감독).

완전분리(grep0): 이 패키지는 core.* / supervisor.* 를 절대 import 하지 않는다.
상류 산출(action JSONL·evaluation.json·supervisor.jsonl)을 **read + HTTP-serve** 만 하며
공격 agent 로의 되먹임 채널이 0이다(변경 엔드포인트 없음, action_log write-open 없음).

- ingest : 순수 파서·재구성·redact (fastapi/core/supervisor 무의존).
- server : FastAPI + 수동 SSE StreamingResponse (GET 전용).
- static : 빌드툴 0·외부요청 0 정적 HTML/JS/CSS.

작성 2026-07-06.
"""
from __future__ import annotations

__all__ = ["ingest", "server"]
