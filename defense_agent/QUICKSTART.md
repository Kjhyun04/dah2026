# defense_agent — QUICKSTART (한 장 요약)

> 파일·명령이 많아 보이지만, **실제로 쓰는 건 런처 하나(`dah.sh`)** 입니다.
> 아래만 알면 됩니다. 상세는 [README.md](./README.md) / `docs/`.

---

## 0. 정신모델 (딱 이거)

```
제어흐름 = 결정론 LangGraph (11 노드)         ← 절대 LLM 이 라우팅 못 함 (불변식①)
  sense→orient→correlate→compute_impact→select_policy→legality→rank_recovery→decide→gate→act→confirm
LLM = orient·decide 2곳뿐, advisory (참고만)   실행 = leak-0 (프로세스/비밀 잔여 0, 불변식②)
독립 Verifier = replay 전용, core 격리          진실은 agent posture 아님 (agent≠truth)
기본 = read-only / DRY. 실 상태변경 = 단일 가역 DROP 하나 (MDG_ALLOW_LIVE=1 operator-go)

python -m mdg.live_autorun   = 자율런 (DRY 기본)
python -m mdg.campaign.e2e    = 오프라인 결정론 6공격 캠페인 (헤드라인 오프라인 증거)
verify.py                     = 무결성 게이트 (평소 실행 X)
dah.sh                        = 위 전부를 감싼 단일 런처
```

## 1. 설치 · 환경 (오프라인은 비밀 불필요)

```bash
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"    # 런타임+pytest. 런타임만이면 'pip install -e .'
cp .env.example .env       # live/status 쓸 때만 값 채움(오프라인 실행엔 불필요)
```

`.env` 핵심(전부 커밋 금지, .env.example 만 커밋):
- `TESTBED_HOST` / `TESTBED_USER` / `SSH_KEY` — live/status 접속 (오프라인엔 불필요)
- `ANTHROPIC_API_KEY` — LLM advisory (**비워도 됨**, 코어는 결정론)
- `MDG_ALLOW_LIVE` — operator-go. **0/미설정=전부 DRY**, `1`=단일 가역 DROP 창 개방

## 2. 런처 한 방 (`./dah.sh <명령>`)

| 명령 | 하는 일 | 내부적으로 |
|---|---|---|
| `./dah.sh verify` | 무결성 게이트 전부 PASS/FAIL | `verify.py` |
| `./dah.sh test` | pytest 회귀 (~192 passed / 2 skipped) | `python -m pytest mdg/tests -q` |
| `./dah.sh campaign out` | **오프라인 결정론 6공격** → out/report.json | `python -m mdg.campaign.e2e out` |
| `./dah.sh autorun` | 자율런 (DRY 기본) | `python -m mdg.live_autorun --out … --run-id …` |
| `./dah.sh live` | 온-테스트베드 검증 (read-only) | `bash mdg/live/run_autonomous.sh` [.env] |
| `./dah.sh viewer out/run.jsonl` | read-only 뷰어 (127.0.0.1:8787) | `python -m mdg.viewer.app` |
| `./dah.sh status` | 컨테이너 + 탐지 tail | `ssh … docker ps` [.env] |

**가장 흔한 흐름:** `./dah.sh verify` → `./dah.sh test` → `./dah.sh campaign out`

## 3. 3~4 명령이면 뜬다

```bash
cp .env.example .env      # (선택) live/status 쓸 때만
./dah.sh verify           # ALL GATES PASS 확인 (오프라인·무해)
./dah.sh test             # 192 passed / 2 skipped (SKIP 2 = langgraph 부재 예상, 실패 아님)
./dah.sh campaign out     # out/report.json — live_executions=0 확인
```

## 4. 2 SKIP 이 왜 정상인가 (안심용)

`./dah.sh test` 의 SKIP 2건은 **langgraph 의존 그래프-컴파일 테스트**입니다. langgraph 가 없으면 SKIP 되며
이는 **예상된 동작(실패 아님)**. `pip install -e .` 로 langgraph 설치 시 실행됩니다. 나머지 ~192개는 항상 green.

## 5. 검증 게이트가 왜 있나 (안심용)

평소 실행엔 **하나도 필요 없습니다.** `./dah.sh verify` 한 줄이 **2대 불변식**(① 결정론 라우팅 ② leak-0 실행)을
정적으로 증명하는 CI 게이트일 뿐입니다.

| 게이트 | 증명하는 것 | 불변식 |
|---|---|---|
| `verify_routing` | 제어흐름에 LLM 산출 키(FORBIDDEN_KEYS) 0 | ① |
| `verify_graph` | 토폴로지 단일소스·11노드·cycle-0·trust-root 격리 | ① |
| `verify_models` | orient/decide role→model 슬롯 무-스왑 | ① |
| `verify_leak0` | 비밀 미노출·spawn 프로세스 잔여 0 | ② |
| `verify_no_fw_subproc` | 방화벽 조작은 actuator 단일경로만 | ② |
| `verify_keys` | 키·비밀 리터럴 0 (env 주입) | ② |
| `verify_grep0` | core ⟂ Verifier 완전분리 | ② |
| `verify_tools` / `verify_d11_collector_disjoint` | tool 계약·6 vantage disjoint | ② |
