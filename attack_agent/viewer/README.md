# viewer — READ-ONLY 3패널 관측기 (동작·통신·감독)

정적 HTML/JS + FastAPI(수동 SSE) 로 P5/P6 산출물을 **읽기 전용**으로 시각화한다.
스택에 sse-starlette·빌드툴·CDN·외부폰트가 없다(자기완결). 3D 없음 — 2D 표/타임라인.

## 완전분리(grep0) 불변식
- `viewer/*.py` 는 `core.*` / `supervisor.*` 를 **정적·동적 모두 import 안 함**. `ingest` 는 dict 만 다루며 pydantic/registry/get_spec 미참조(표시용 상수는 offline baked).
- 공격 agent 로의 **되먹임 채널 0**: action_log 를 write-open 하지 않고, evaluation/supervisor.jsonl 도 read-only. 변경 엔드포인트(POST/PUT/DELETE/PATCH) 부재 → 주입면 신설 없음.
- 상류가 1차 redact, `ingest.redact()` 가 방어심층 2차(hex≥16·base64≥24·키명 마스킹) — 브라우저 송신 전 마스킹.
- `verify_viewer.py` 가 AST 로 위 불변식을 강제(위반 시 FAIL).

## 3패널
1. **동작** — 공격 agent `action` JSONL(`core.driver.campaign_to_jsonl`: `type=step` / `type=campaign_result`). step 인덱스 순 타임라인(verdict 색상, `blocked_by`→"blocked→pivot" 배지).
2. **통신** — 감독 복호 wire(`supervisor.jsonl` 프레임; 부재 시 `evaluation.json` 의 `mode_timeline`(down)+`uplink_cmds`(up)에서 재구성) + 공격측 INJECT 스텝 주입로그 레인.
3. **감독**(사용자 전용) — `supervisor.build_evaluation` 산출 `evaluation.json`: `truth_verdict` + `autonomy_accuracy(agent/truth/agree)` + `ground_truth` 요약. `agree==false` 면 최상단 적색 "agent≠truth" 배너.

## 데이터 소스 (READ-ONLY)
| 소스 | 파일 | 생산자 |
|------|------|--------|
| 동작 | `out.log` (예 `run.jsonl`) | 공격 agent (`core.driver.write_jsonl`) |
| 감독 | `evaluation.json` | 감독 (`supervisor.emit`) |
| 통신 | `supervisor.jsonl` (선택) | 감독 per-frame 스트림 (현재 예약; 부재 시 evaluation 재구성 폴백) |

> 통신 wire 가 `reconstructed` 로 뜨면 per-frame 스트림이 없어 evaluation 에서 되살린 것이다. 이 경우 프레임별 `signed` 는 미기록(None)이며 링크 전역 `signing_observed` 만 감독 패널에 표기된다.

## 실행 (운영자 · 서버 on-host)
사전: `pip install fastapi uvicorn pyyaml` (pyproject 선언; 오프라인 검증엔 불필요).

```bash
# 샘플 데모 (기본 app = viewer/sample/*)
uvicorn viewer.server:app --port 8090

# config.yaml 의 out.log/viewer.port 직독
python -m viewer.server --config config.yaml

# 명시 경로
python -m viewer.server \
  --action-log runs/run.jsonl \
  --evaluation runs/evaluation.json \
  --comms-stream runs/supervisor.jsonl \
  --port 8090
```

라우트(전부 GET·read-only): `/`(index) · `/static/*` · `/api/snapshot` · `/sse`(text/event-stream).
SSE 는 0.5s 파일 폴링으로 action/comms 증분 tail + evaluation mtime 재read 를 멀티플렉스하고, `: keep-alive` heartbeat 를 보낸다. `request.is_disconnected()` 로 종료, 파일핸들은 `with` 로 즉시 회수(orphan 0).

## 정직 배너(설계상 한계)
- `StepRecord` 에 timestamp 가 없어 **동작 타임라인은 step 인덱스 순**, **통신은 감독 캡처 시각(t) 순** → 두 타임라인의 절대시각 정렬 불가. 인과 상관은 감독 자체의 uplink↔downlink 매칭(evaluation)만 인용한다.
- 주입로그 레인의 `accepted` 는 공격 agent 자기-ACK(`verdict==OK`)일 뿐 ground-truth 가 아니다 — 실제 mode 전이는 감독 패널(`ground_truth`)이 독립 판정한다.

## 오프라인 검증
```bash
python viewer/verify_viewer.py   # py_compile + AST 분리 + HTML/JS 자기완결 + ingest 라운드트립 + redact + soft 분류정합
```
네트워크·docker·테스트베드 0. 서버 실행(uvicorn)·라이브 SSE 는 운영자 사후 수동 단계.
