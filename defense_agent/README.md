# defense_agent — DAH 2026 MDG 자율 방어 에이전트 (자립형 통합 매뉴얼)

인가된 격리 테스트베드(4G EPC + srsRAN + ArduPilot SITL + ARIA-256-GCM UAV C2, dahv2 Open5GS
split-core) 전용 **Mission-centric Defense Gateway(MDG)** 방어 AI 에이전트입니다.
공격(주입/백도어/PFCP teardown/무서명 command/텔레메트리 침묵)을 관측근거 위에서 탐지하고,
**결정론 제어흐름 + LLM advisory** 로 대응(policy→legality→recovery)을 선정해 **단일 가역 조치**까지
자율 수행합니다. 이 한 문서로 **정체(왜)·아키텍처(어떻게)·배포·실행·검증·불변식·한계**를 이해하고
실행할 수 있게 통합했습니다. 보조 문서는 [QUICKSTART.md](./QUICKSTART.md), [CHANGELOG.md](./CHANGELOG.md),
그리고 `docs/`(설계·검증·감사 원문)에 남습니다.

> ⚠️ **범위·안전(SCOPE & SAFETY):** 모든 실행은 **인가된 격리 테스트베드(SITL·실기체 아님)** 에서만.
> 실이동통신망/실서비스 금지, 컨테이너 stop 금지. 기본 상태는 **read-only / DRY**.
> 실 상태변경은 **단일 가역 DROP** 하나뿐이며, `MDG_ALLOW_LIVE=1`(operator-go) + trap 무조건 revert
> 하에서만 개방된다. **ANTHROPIC_API_KEY·SSH 키·서버 IP 는 커밋 금지**(env 로만 주입). 문서 IP 는 마스킹.

---

## ⚡ 빠른참조 — 입력 파라미터 & 실행 방법 (한 곳 통합)

> 아래 세 표만 보면 **무엇을 입력하고(=.env) 무엇을 실행하는지(=dah.sh)** 가 끝난다. 상세는 Part 4·5.

### A. 입력 파라미터 (`.env`) — `cp .env.example .env` 후 값 채움
`.env` 는 gitignore, `.env.example`(플레이스홀더)만 커밋. `dah.sh` 가 자동 로드해
`TESTBED=${TESTBED_USER}@${TESTBED_HOST}`·`SSH_KEY` 를 `mdg/live/*.sh` 로 export.

| 변수 | 필수? | 값 예시 | 용도 |
|---|---|---|---|
| `TESTBED_HOST` | live·status 만 | `<TESTBED-IP>` | 테스트베드 서버 IP/호스트 |
| `TESTBED_USER` | live·status 만 | `ubuntu` | SSH 사용자(기본 ubuntu) |
| `SSH_KEY` | live·status 만 | `~/.ssh/<KEY>.pem` | SSH 개인키 경로 (**커밋 금지**) |
| `ANTHROPIC_API_KEY` | 선택(전 명령) | `<API-KEY>` | LLM(orient/decide) **advisory**. 비우면 코어는 결정론 동작 |
| `MDG_ALLOW_LIVE` | autorun·live 선택 | `0`(기본)/`1` | operator-go 게이트. `0`/blank=전부 DRY, `1`=단일 가역 DROP 창 |
| `MDG_VIEWER_TOKEN` | viewer 선택 | (blank) | 뷰어 bearer 토큰(blank=토큰 게이트 없음) |
| `MDG_TESTBED_LABEL` | 선택 | `<testbed>` | 리포트 호스트 라벨(미설정 시 IP 미노출) |

> **오프라인 경로(verify·test·campaign·autorun-DRY)는 `.env`·비밀·테스트베드 전부 불필요.** LLM 키가 없어도 동작.

### B. 명령별 필요 파라미터 매트릭스 (command × 입력)
| 명령 | 실행 위치 | 필요 `.env` 변수 | SSH 접속 | 상태변경 |
|---|---|---|---|---|
| `verify` | 어디서나(오프라인) | — | ✗ | 없음 |
| `test` | 어디서나(오프라인) | — | ✗ | 없음 |
| `campaign` | 어디서나(오프라인) | — | ✗ | 없음 (`live_executions=0`) |
| `autorun` | **테스트베드 온-호스트** | (선택) `MDG_ALLOW_LIVE`·`ANTHROPIC_API_KEY` | ✗(온-호스트) | **DRY 기본** / `MDG_ALLOW_LIVE=1` 시 단일 가역 DROP |
| `live` | 로컬 → SSH | **`SSH_KEY`·`TESTBED_HOST`·`TESTBED_USER`** (+`MDG_ALLOW_LIVE`) | ✓ | read-only / `ALLOW_LIVE=1` 시 집행 |
| `viewer` | 로컬 | (선택) `MDG_VIEWER_TOKEN`·`PORT` | ✗ | 없음(read-only) |
| `status` | 로컬 → SSH | **`SSH_KEY`·`TESTBED_HOST`·`TESTBED_USER`** | ✓ | 없음(read-only) |

> `mdg/live/*.sh` 는 `${SSH_KEY:?…}`/`${TESTBED:?…}` 로 **미설정 시 즉시 실패**(baked-in 기본값 없음).

### C. 실행 방법 (두 갈래)
```bash
# ── 0) 설치 (공통) ──
git clone <repo-url> && cd defense_agent
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .

# ── 오프라인 (비밀·테스트베드 불필요) ──
./dah.sh verify              # 무결성 게이트 (ALL GATES PASS 확인)
./dah.sh test                # pytest 회귀 (~192 passed / 2 skipped)
./dah.sh campaign out        # 결정론 6공격 캠페인 → out/report.json (live_executions=0)

# ── 라이브 (테스트베드 온-호스트, .env 필요) ──
cp .env.example .env         # 값 채움: TESTBED_HOST/USER/SSH_KEY (+ 선택 ANTHROPIC_API_KEY)
./dah.sh autorun             # 자율런 (DRY 기본 — 상태변경 0)
MDG_ALLOW_LIVE=1 ./dah.sh autorun   # (operator 승인 시) 단일 가역 DROP 집행 창
./dah.sh live                # 온-테스트베드 오케스트레이션 검증 (read-only 기본)
./dah.sh status              # read-only 스냅샷 (docker ps + 탐지 tail)
./dah.sh viewer out/run.jsonl  # read-only 뷰어 (127.0.0.1:8787)
```
직접 파이썬 등가: `python -m mdg.live_autorun --out live_out --run-id live` /
`python -m mdg.campaign.e2e out` / `python verify.py` / `python -m pytest mdg/tests -q`.

---

## Part 0 · 개요 · 클론 즉시 실행

```bash
git clone <repo-url> && cd defense_agent
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e .                                       # pyproject.toml 의존성
cp .env.example .env                                   # (선택) live/status 쓸 때만 값 채움
./dah.sh verify        # 무결성 게이트 (오프라인·무해, 테스트베드/비밀 불필요)
./dah.sh test          # pytest 회귀 (기준선 ~192 passed / 2 skipped)
./dah.sh campaign out  # 오프라인 결정론 6공격 캠페인 → out/report.json
```
라이브 검증(`./dah.sh live`/`autorun`/`status`)은 테스트베드 서버(온-호스트)에서 실행하며 Part 3·4 참조.

### 저장소 구조 · 정신모델

```
verify.py                무결성 게이트 단일 러너 (= ./dah.sh verify)
dah.sh                   단일 런처 (verify|test|campaign|autorun|live|viewer|status) ← 평소엔 이것만
pyproject.toml           의존성 (langgraph·litellm·pydantic·jinja2·pyyaml·grpcio·httpx)
.env.example             배포 의존값/비밀 템플릿 (.env 로 복사; .env=gitignore)

mdg/                     방어 에이전트 패키지 (python -m mdg.*)
  ├ core/       graph.py(LangGraph 조립)·topology.py(단일소스 토폴로지)·state.py·edges.py
  │   └ nodes/  11 노드: sense·orient·correlate·compute_impact·select_policy·
  │             legality·rank_recovery·decide·act·effect_confirm·escalate
  ├ collector/  6 vantage collector(air-tap/PFCP :9090/ss/mongo/…) — read-only 관측
  ├ verifier/   독립 Verifier(trust-root, replay 전용) — core 를 import 안 함(격리)
  ├ safe_exec/  Backend(단일 spawn 사이트·R1~R6 teardown·leak-0 계약)
  ├ llm/        orient·decide (advisory-only; jinja 프롬프트) + client(모델 라우팅)
  ├ campaign/   e2e.py(오프라인 6공격 결정론 캠페인)·artifacts.py·honest.py
  ├ live/       run_autonomous.sh + s3*/s4* (온-테스트베드 검증 스텝)
  ├ live_autorun.py       자율런 엔트리(DRY 기본; operator-go 시 집행)
  ├ viewer/app.py         read-only 뷰어(127.0.0.1 루프백 바인드 · PS-8)
  ├ verify/     무결성 게이트(routing·graph·leak0·grep0·keys·tools·models·no_fw_subproc·d11)
  ├ config/     defaults.py·loader.py·input_spec.yaml·recovery_priors.yaml (토폴로지·정책)
  └ tests/      pytest 회귀 스위트
docs/                    설계·검증·감사 원문 (LIVE_VERIFICATION_STATUS_20260708.md 등)
```

**정신모델(딱 이거):** 파일이 많아 보여도 평소 쓰는 건 **런처 하나(`dah.sh`)** 다.
에이전트 본체는 `python -m mdg.live_autorun`(자율런)·`python -m mdg.campaign.e2e`(오프라인 캠페인)이고,
제어흐름은 **결정론 LangGraph** 이며 LLM 은 2곳(orient/decide)에서 **advisory** 로만 붙는다.
`verify.py`(게이트)는 1회성 무결성 증명이라 평소 실행 경로가 아니다.

---

## Part 1 · 정체 · 서사

### 1.1 정체 (Identity)
MDG 는 **미션(보호 UAV 의 C2 무결성·가용성) 중심** 자율 방어 에이전트다. 공격자 관측이 아니라
**방어자 vantage 6곳의 read-only collector 신호**로 사건을 상관(correlate)하고, 영향도(impact band:
Green/Yellow/Red)를 산정한 뒤 **정책 선정 → 합법성(legality) 게이트 → 복구 우선순위 → 결정 → 단일 가역 조치**를
결정론 그래프로 수행한다. 정직한 재정의는 "완전 자율 성공"이 아니라
**"배포 가능한 결정론 방어 추론 + 독립 검증(trust-root 격리)"** 이다.

### 1.2 핵심 서사 — fail-closed, 가역, 최소권한
> *탐지가 불확실하면 조치하지 않는다(fail-closed·DRY). 조치하면 단 하나, 되돌릴 수 있는 것만
> (단일 가역 DROP). 진실은 에이전트의 posture 가 아니라 독립 Verifier(replay 전용)가 판정한다(agent≠truth).*

이걸 코드로 강제하는 것이 아래 **2대 불변식**이며, `mdg/verify/*.py` 게이트가 정적으로 지킨다.

---

## Part 2 · 2대 불변식 (손수 지키는 심장)

프레임워크(LangGraph + litellm + OSS 스택)에 얹되, **딱 2가지만 손수** 불변식으로 강제한다.

### ① 결정론 라우팅 (Deterministic Routing)
**제어흐름(그래프 라우팅·게이트 분기)은 LLM 이 절대 만지지 못한다.** LLM 산출(orient/decide)은
**advisory** 로 노드 안에서 참고될 뿐, `route_after_impact`/`route_after_decide` 등 분기 결정과
`legality`/`gate` 통과 여부는 **결정표(pure 함수)** 로만 계산된다.
- `verify_routing` — `edges.py`·`gate`·`legality`·`rank_recovery`·`select_policy` 의 제어흐름 조건에
  **FORBIDDEN_KEYS(LLM 산출 키)** 가 스며들지 않음을 정적 스캔(회귀가드).
- `verify_graph` — 토폴로지 단일소스(`core/topology.py`)·11 노드·in-graph cycle 0·조건분기 END 포함·
  trust-root(verifier) 가 core 를 import 하지 않음(격리)을 AST 로 강제.
- `verify_models` — orient/decide 의 role→model 슬롯이 뒤바뀌지 않음.

### ② leak-0 실행 (Leak-0 Execution)
**실행이 남기는 것은 0이다** — 비밀은 로그/산출물에 노출되지 않고, spawn 한 프로세스/컨테이너는
확실히 회수된다(R1~R6 teardown). 관측은 read-only 라 세마포어를 획득하지 않아 다틱 자율런이 정체되지 않는다.
- `verify_leak0` — 비밀 리터럴 미노출 + `Backend` spawn 후 라벨 프로세스 잔여 0(고아 0).
- `verify_no_fw_subproc` — 방화벽 조작이 임의 subprocess 로 새지 않고 **actuator 단일 경로**로만 나감.
- `verify_keys` — 코드/설정에 키·비밀 리터럴 0(env 이름으로만 주입).
- `verify_grep0` — 방어 core ⟂ 독립 Verifier 완전분리(되먹임 0).
- `verify_tools` / `verify_d11_collector_disjoint` — tool 계약·바인딩 정합, 6 collector vantage disjoint(귀속 정합).

> `./dah.sh verify` 가 이 게이트 전부를 오프라인·무해로 돌려 PASS/FAIL 요약한다. **ALL GATES PASS** 여야 한다.

---

## Part 3 · 파이프라인 (evidence → … → act)

제어평면은 **결정론 LangGraph** 다. 한 틱의 흐름:

```
 sense ─▶ orient ─▶ correlate ─▶ compute_impact ─┬─(Green: 조치불요)─────────────▶ END
 (관측)   (advisory) (사건상관)   (impact band)    │
                                                  └─(Yellow/Red)─▶ select_policy ─▶ legality
                                                                                       │
   act ◀─ gate ◀─ decide ◀─ rank_recovery ◀───────(정책 합법?)──────────────────────┘
    │        │       (advisory)   (복구 우선순위)         └─(불법/무조치)──────────────▶ END
    ▼        └─(operator_gate: 승인 필요 → escalate ─▶ END)
 effect_confirm ─▶ END           (act = 단일 가역 조치; DRY 기본, operator-go 시에만 집행)
```

| 단계 | 노드 | 역할 |
|---|---|---|
| evidence | `sense` | 6 collector 의 read-only 관측 신호 수집(air-tap·PFCP :9090·ss·mongo…) |
| — | `orient` | **LLM advisory** — 상황 해석(제어흐름 불가시) |
| correlate | `correlate` | 신호 상관 → 사건(BACKDOOR_5762·PFCP_Delete·Unauthorized_Command 등) |
| impact | `compute_impact` | 영향도 band 산정(Green/Yellow/Red) + Green tick 조기 END |
| select_policy | `select_policy` | band→정책 후보(backdoor_drop/backdoor_pause/none…) 결정론 선정 |
| legality | `legality` | 정책의 **합법성 게이트**(범위·가역성·최소권한) — 불법이면 무조치 END |
| rank_recovery | `rank_recovery` | 복구 우선순위(recovery_priors) 랭킹 |
| — | `decide` | **LLM advisory** — 대응 서술(결정 자체는 결정표) |
| gate | `gate` | operator_gate(승인 필요 시 `escalate`) · AUTO(즉시 가역) 이원 게이트 |
| act | `act` | **단일 가역 조치**(예: `iptables -I INPUT -s <attacker> -j DROP`). DRY 기본 |
| confirm | `effect_confirm` | 조치 효과 확인 → END |

- **독립 검증:** `mdg/verifier/verifier.py` 는 core 를 import 하지 않고(격리) **replay 전용**으로 링크
  지상진실을 판정한다. agent 의 posture 와 다르면 산출물에 **agent≠truth** 로 노출된다.
- **operator-go:** `act` 의 실 집행은 `MDG_ALLOW_LIVE` truthy 일 때만. 아니면 전부 **inert-DRY**(계획까지만).

---

## Part 4 · 실행 — 런처 하나로 (`./dah.sh <명령>`)

```bash
cd defense_agent
./dah.sh verify           # ① 무결성 게이트 (ALL PASS 확인, 오프라인)
./dah.sh test             # ② pytest 회귀 (~192 passed / 2 skipped)
./dah.sh campaign out     # ③ 오프라인 결정론 6공격 캠페인 → out/report.json (live_executions=0)
./dah.sh autorun          # ④ 자율런 (DRY 기본; 실 DROP 은 MDG_ALLOW_LIVE=1 operator-go)
./dah.sh live             # ⑤ 온-테스트베드 오케스트레이션 검증 (read-only; ALLOW_LIVE=1 시 집행) [.env]
./dah.sh viewer out/run.jsonl   # ⑥ read-only 뷰어 (127.0.0.1:8787 · 루프백 바인드 PS-8)
./dah.sh status           # ⑦ read-only 테스트베드 스냅샷 (docker ps + 탐지 tail)             [.env]
```

| 명령 | 하는 일 | 내부적으로 |
|---|---|---|
| `verify` | 무결성 게이트 전부 PASS/FAIL | `verify.py`(`python -m mdg.verify.<gate>`) |
| `test` | pytest 회귀 | `python -m pytest mdg/tests -q` |
| `campaign` | **오프라인 결정론 6공격** → report.json | `python -m mdg.campaign.e2e <out>` |
| `autorun` | 자율런(DRY 기본) | `python -m mdg.live_autorun --out … --run-id …` |
| `live` | 온-테스트베드 검증 오케스트레이션 | `bash mdg/live/run_autonomous.sh`(.env 로 SSH_KEY/TESTBED export) |
| `viewer` | read-only 3패널 뷰어 | `python -m mdg.viewer.app <run.jsonl> --host 127.0.0.1 --port 8787` |
| `status` | 컨테이너 + 탐지 tail | `ssh … 'docker ps …'` + run.jsonl grep |

**가장 흔한 흐름:** `./dah.sh verify` → `./dah.sh test` → `./dah.sh campaign out`

**상세**
- **③ campaign (헤드라인 오프라인 증거)** — 테스트베드 무접속 순수 결정론 재생. 6공격(A1 command hijack·
  A2 PFCP teardown·A3 무서명 command·A4 5762 backdoor·A5 mongo dbaccess·A6 telemetry silence)을 탐지→대응
  계획까지 돌리고 `report.json` 을 낸다. **`live_executions` 는 반드시 0**(라이브 상태변경 없음). 대응 효력은
  6 중 2공격만 관측-검증(telemetry·PFCP), 나머지는 미검증으로 정직 표기.
- **④ autorun** — `Backend(allow_live=False)` 가 기본이라 모든 상태변경이 DRY. 실 actuation 은
  `MDG_ALLOW_LIVE=1` 로 operator 가 승인했을 때만 **단일 가역 DROP 집행 창**이 열린다.
- **⑤ live** — `mdg/live/run_autonomous.sh` 가 S1(사전조건 read-only)→S2(자율런 기동)→S3(공격 순차 주입 +
  각 스텝 탐지 확인)→S4(`ALLOW_LIVE=1` 시 E4 자율 DROP 실증)→S5(종료·누수-0 검증, EXIT trap) 를 조율.
  기본 read-only, 집행은 **명시 승인(`ALLOW_LIVE=1`)** 하에서만.
- **⑥ viewer** — `127.0.0.1` **루프백 바인드(PS-8, 관리평면은 절대 wildcard 로 bind 안 함)**. read-only,
  선택적 `MDG_VIEWER_TOKEN` 게이트.

---

## Part 5 · 요구사항 · 배포 · .env

### 5.1 요구사항
| 대상 | 요구 |
|---|---|
| 로컬(오프라인) | Python **3.12+**, `pip install -e .`(langgraph·litellm·pydantic·jinja2·pyyaml·grpcio·httpx) |
| 테스트베드 서버 | Ubuntu, Docker, `sudo nsenter`(단일 가역 DROP·관측 netns 진입) |
| 실행 위치 | **온-호스트 LocalBackend** — 자율런/라이브 검증은 테스트베드 서버에서 |

> 오프라인 경로(`verify`/`test`/`campaign`/`autorun`-DRY)는 **테스트베드·비밀 불필요**. LLM 키가 없어도
> 코어는 결정론으로 동작한다(LLM 은 advisory).

### 5.2 .env 설정 (배포 의존값·비밀 외부화)
`cp .env.example .env` 후 값을 채운다. `.env` 는 gitignore, `.env.example`(플레이스홀더)만 커밋된다.
`dah.sh` 가 `.env` 를 자동 로드하고 `TESTBED=${TESTBED_USER}@${TESTBED_HOST}` + `SSH_KEY` 를
export 해 `mdg/live/*.sh` 로 전달한다.

| 변수 | 용도 | 비고 |
|---|---|---|
| `TESTBED_HOST` / `TESTBED_USER` / `SSH_KEY` | live/status 접속 | 오프라인 실행엔 불필요 |
| `ANTHROPIC_API_KEY` | LLM(orient/decide) advisory | **비워도 됨**(코어는 결정론), 프로세스 env 로만 |
| `MDG_ALLOW_LIVE` | operator-go 게이트 | 미설정/0/false=전부 DRY · 1=단일 가역 DROP 창 |
| `MDG_VIEWER_TOKEN` | (선택) 뷰어 bearer 토큰 | blank=루프백 뷰어 토큰 게이트 없음 |
| `MDG_TESTBED_LABEL` | (선택) 리포트 호스트 라벨 | 미설정 시 `<testbed>`(IP 미노출) |

> **GIT-READY:** 커밋 파일에 실제 테스트베드 IP·SSH user·`.pem` 경로·키값 **0**. `mdg/live/*.sh` 는
> `${SSH_KEY:?…}`/`${TESTBED:?…}` 로 **미설정 시 즉시 실패**(baked-in 기본값 없음).

---

## Part 6 · 알려진 한계 (정직 표기)

- **P4 SMF 교차확인 레이어 미배선** — 이 Open5GS split-core 는 IMSI↔IP 단일로그가 없어 SMF 교차확인이
  recon-only best-effort 로만 발화한다(안전측, 후속과제). `docs/LIVE_VERIFICATION_STATUS_20260708.md` 참조.
- **캠페인 대응 효력 부분검증** — 오프라인 6공격 중 대응 효력이 관측-검증된 것은 telemetry(D-1)·PFCP(B-1)
  2공격뿐, 나머지는 미검증으로 표기(`agent≠truth` 노출).
- **결정론 scoring 영향분 문서화-보류** — air_side band·sense liveness·미방출 metric 등 일부 품질항목은
  자율DROP 경로 영향분이라 강행 대신 문서화-보류(`docs/PHASE3_DEFERRED_20260708.md`).
- **langgraph-의존 그래프-컴파일 테스트 2건 SKIP** — langgraph 부재 환경에서 SKIP 되며 이는 **예상**이다
  (실패 아님). 설치 시 실행된다.

---

## Part 7 · 문서 · 이식성 · 언어 정책

- **문서(`docs/`):** 라이브 검증 종합 상태 [`docs/LIVE_VERIFICATION_STATUS_20260708.md`],
  프레임워크 스택 [`docs/FRAMEWORK_STACK.md`], 설계검증/매트릭스/감사/리뷰/보류 원문 다수.
  변경이력 요약은 [CHANGELOG.md](./CHANGELOG.md), 한 장 요약은 [QUICKSTART.md](./QUICKSTART.md).
- **이식성:** 환경 의존값·비밀은 env 로만 주입(하드코딩 0). UE/RAN CIDR(`10.45.0.0/16`·`10.44.0.0/16`)는
  **토폴로지 config**(`mdg/config`)이며 라이브 UE IP 는 런타임 해석(A-1, 절대 pin 안 함) — 비밀 아님.
- **언어 정책:** 문서·주석은 한국어 주 + 기술용어 영문 병기, **식별자는 영문**. `.md` UTF-8,
  `.py`/`.sh` BOM 금지·LF(`.gitattributes` 강제).
- **PS-8 보안 바인드:** `mdg/viewer/app.py`·`mdg/ingest/server.py` 의 `127.0.0.1` 루프백 바인드는
  관리평면이 공격 UE 가 닿는 wildcard(0.0.0.0)로 절대 열리지 않게 하는 의도적 보안 불변식이다.

---

## Part 8 · 변경이력 요약

전체 이력은 [CHANGELOG.md](./CHANGELOG.md). 핵심(2026-07-08 세션): Phase 3 품질 28건(verify_routing
FORBIDDEN_KEYS 스코프 확대·회귀테스트 19건), attacker attach 환경복구(enb2 ZMQ `fail_on_disconnect`
근본수정), **라이브 자율 DROP 전 구간 실서버 관통 검증**(탐지→legality→실 iptables DROP→revert·누수0),
프롬프트 enrich(orient/decide advisory 불변식 보존), 코드리뷰 medium 2건 수정. 서버 pytest 193 green.
