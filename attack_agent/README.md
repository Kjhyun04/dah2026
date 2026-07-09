# attack_agent — DAH 2026 공격 자동수행 에이전트 (자립형 통합 매뉴얼)

인가된 격리 테스트베드(4G EPC + srsRAN + ArduPilot SITL + ARIA-256-GCM UAV C2) 전용
**계획된 공격 시나리오 자동수행 에이전트**입니다. 이 한 문서만 읽어도 **설계 근거(왜)·아키텍처(어떻게)·
배포·실행·검증·서브시스템·운영·한계**를 모두 이해하고 실행할 수 있도록 통합했습니다.
보조 문서(요약/설계/런북/변경이력)는 각각 [QUICKSTART.md](./QUICKSTART.md), [docs/DESIGN.md](./docs/DESIGN.md),
[docs/DEPLOY_VERIFY_RUNBOOK.md](./docs/DEPLOY_VERIFY_RUNBOOK.md), [CHANGELOG.md](./CHANGELOG.md) 에 원문으로 남습니다.

> ⚠️ **범위·안전(SCOPE & SAFETY):** 모든 실행은 **인가된 격리 테스트베드(SITL·실기체 아님)** 에서만.
> 실이동통신망/실서비스 금지, 컨테이너 stop 금지, 구성 변경은 가역적으로. **ARIA/서명 키는 서버 밖 반출 금지.**
> 상태변경(주입/설치/명령, 특히 force-land)은 실행 직전 사용자 확인. 데모용 외부 IP 표기는 RFC5737 대역.

**목차(파트 구성)**
- Part 0 · 개요 · 클론 즉시 실행 · 저장소 구조
- Part 1 · 설계 근거 · 정체 · 서사 (왜 재설계인가)
- Part 2 · 아키텍처 (3 컴포넌트 · 관측 데몬 · 판정 3층 · FSM · 안전)
- Part 3 · 요구사항 · 배포 (로컬 → 서버)
- Part 4 · 실행 — 런처 하나로 (`./dah.sh`)
- Part 5 · 검증 게이트 (11개 · 게이트→증명 매핑)
- Part 6 · 공격 카탈로그 (enabler 6 · ADAPT · win_cause)
- Part 7 · 서브시스템 (사이드카 이미지 · 뷰어)
- Part 8 · 파라미터 파일 · 산출물
- Part 9 · 운영 런북 · 트러블슈팅
- Part 10 · 알려진 한계 (§6.5 정직 표기)
- Part 11 · 이식성 · 언어 정책
- Part 12 · 변경이력 요약

---

## Part 0 · 개요 · 클론 즉시 실행

```bash
git clone <repo-url> && cd attack_agent
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .                                     # pyproject.toml 의존성
./dah.sh verify        # 11개 무결성 게이트 (오프라인·무해, 테스트베드 불필요)
./dah.sh recon         # 정찰 폐루프 (오프라인 mock)
```
라이브 캠페인(`./dah.sh campaign`)·착륙 데모(`./dah.sh land`)는 테스트베드 서버(온-호스트)에서 실행하며 Part 3·Part 4 참조.

### 저장소 구조 · 정신모델

```
run.py                         에이전트 본체 (플래그로 offline/live 전환)
  ├ run_live_gate5.py          캠페인 실행기 (감독은 --skip-supervisor 로 분리)
  └ run_supervisor_standalone.py  독립 감독 (gcs_proxy netns 14555 ARIA 복호)
dah.sh                         단일 런처 (verify|recon|campaign|land|viewer|status) ← 평소엔 이것만
verify.py                      11개 게이트 단일 러너 (= ./dah.sh verify)
land_demo.py                   착륙 데모 주입기(사이드카로 파이프)

configs/   config.{testbed,live,example}.yaml · models.yaml   (환경·타깃·모델)
goals/     goal.{testbed,p4,land,example}.yaml                (공격 목표·scope)
tests/     verify_{p0,p2,parsers,bindings,models,hygiene,structure,prompt,quality}.py (게이트 9)
core/      오케스트레이터·실행엔진·KB      supervisor/ 독립 감독(+verify_grep0)
  ├ common/   types(Channel/Action)·config·llm·prompts·workdb
  ├ modules/  backends/{base,mock,local}·parsers·tools·guardrail·safety·budget·locks
  ├ obs/      obs_daemon(host-side 관측·14555 tap·5762 pool=1)·signals
  └ agents/   planner·evidence
sidecar/   공격 도구 코퍼스(baked 이미지)  viewer/ 3패널 뷰어(+verify_viewer)
prompts/   default.yaml                   docs/ 설계·런북 원문
```

**정신모델(딱 이거):** 흩어진 파일이 많아 보여도 평소 쓰는 건 **런처 하나(`dah.sh`)** 다.
`run.py` 가 본체이고 플래그로 offline/live 를 전환하며, `run_live_gate5.py`(캠페인)와
`run_supervisor_standalone.py`(감독)는 netns 분리를 위해 나뉘어 있고, `verify_*.py`(11개)는
1회성 무결성 게이트로 평소 실행 경로가 아니다.

---

## Part 1 · 설계 근거 · 정체 · 서사 (왜 재설계인가)

### 1.1 재설계 동기 — agent_v1 은 왜 무너졌나 (DESIGN §0)
이전 세대(agent_v1)는 **판정 정직성**은 성공했으나(구 "ACK=무조건 성공" 버그가 실인프라에서 미재현),
**실행/관측의 실환경 견고성이 무너졌다.** 관측이 도구 호출마다 `docker run` **단명 컨테이너**를 띄웠는데,
이 컨테이너가 신뢰성 있게 죽지 않았다(`killpg`·`timeout` 은 dockerd 소유 컨테이너를 못 죽인다).
그 결과 **컨테이너 누수 → SITL 5762 단일 TCP 연결 포화 → 캠페인 연쇄 hang → 테스트베드 오염**(AMI 복원)에 이르렀다.
따라서 재설계의 심장은 두 가지다: **(A) 확실히 죽는 실행/관측 아키텍처**와 **(B) effected(물리효과) 신호원.**
이 둘을 코드 이전에 확정한다(재설계 게이트 0).

### 1.2 정체 (Identity)
방어가 비어 있는 **신뢰경계·인증·키관리 빈틈을 자율로 찾아 찌르고, 방어가 진화하면 벡터를 전환(ADAPT)** 하는
**이식형(portable)** 공격 에이전트. 정직한 재정의는 "완전 자율 성공"이 아니라
**"배포 가능한 자율 공격 추론 + 테스트베드 독립 채점"** 이며, 이를 3분리 아키텍처로 실현한다:
- **Autonomous Reasoner** — 공격자 관측 신호로만 흐름·pivot·reward 를 결정(배포 가능).
- **Independent Verifier(심판)** — 테스트베드 전용, 기본 off, 에이전트 흐름과 완전 분리.
- **Reconciler** — 자율 판정 ↔ 심판 판정 대조로 정확도(autonomy_accuracy) 채점.

### 1.3 핵심 서사 — 계층 방어(Layered Defense)
> *ARIA-256-GCM 알고리즘 자체는 안 뚫린다. 성립하는 공격은 전부 그 주변(오라클·재생·peer 학습·키노출·
> 무인증 웹서명)의 **설계 결함**이다.*

이걸 공격 측 **단독**으로 증명하는 것이 간판 혁신 **Differential BlockProof** 다.

### 1.4 간판 혁신 — Differential BlockProof (DESIGN §10)
naive(무키·차단 baseline) ↔ enabler(성립) 를 **연속 실행하여 차분**함으로써 "알고리즘은 막고 설계 결함만 뚫림"을
**심판 없이 공격 측 단독으로** 증명한다. 각 공격에는 verdict(성립/조건부/방어) + `blocked_by` +
`defense_snapshot`(signing ON/OFF 등)이 바인딩된다. 셀룰러 C2 서명은 강제되지만 직결 5762 경로로 우회되는 식의
대비가 곧 증명이 된다.

---

## Part 2 · 아키텍처 (어떻게)

### 2.1 3 컴포넌트 데이터 흐름 (DESIGN §3)
```
                    ┌───────────────── attack_agent (rogue UE 위치 or local 배포) ─────────────────┐
                    │                                                                            │
  [관측 데몬]  ─push(비동기)─▶  ┌─ Autonomous Reasoner (결정론 FSM + LLM 2곳) ─┐  ──▶ 산출물       │
  (host-side,       │          │  Recon → Select(LLM) → Execute → Infer(자율) │     timeline.html  │
   단일·수명관리)   │          │        ↑ pivot(LLM, blocked_by)  ↓ verdict    │     blockproof.md  │
   14555 rate tap   │          └──────────────────────────────────────────────┘     reward.json    │
   (effected 신호)  │                       │ 흐름·reward·pivot = 공격자 신호만                      │
                    │                       ▼                                                       │
                    │          ┌─ Independent Verifier (심판) ─┐ ── 기본 OFF ──▶ evaluation.json     │
                    │          │  SITL 5762 평문 before→after  │  (테스트베드 전용·비동기·격리)       │
                    │          └───────────────────────────────┘        │                          │
                    │                                                    ▼                          │
                    │                                    ┌─ Reconciler ─┐  autonomy_accuracy         │
                    │                                    │ 자율 ↔ 심판   │  (품질 지표, reward 아님)  │
                    │                                    └───────────────┘                          │
                    └────────────────────────────────────────────────────────────────────────────┘
```
- **제어평면 = 결정론 FSM.** LLM 은 2곳뿐(Planner: select/pivot · Evidence: correlate/narrate). 나머지는 결정론.
- **관측 데몬은 에이전트 밖의 장수 프로세스** — 에이전트는 데몬이 push 한 신호만 소비한다(동기 인라인 금지).
- **심판은 완전 분리** — 에이전트 흐름 코드가 truth 를 절대 안 본다(grep 0). off 로도 캠페인을 완주한다.

### 2.2 인프라 전제 (DESIGN §1.2)
- 공격 거점 = **`attacker_ue`(rogue UE)**. 셀룰러 attach(정상 UAV `uav_ue` 와 동일 APN·동일 UE풀 10.45.0.0/16).
- 종단 암호 = **ARIA-256-GCM 프록시 쌍.** 봉투 `VER(0x01)‖nonce(12 rand)‖CT‖TAG(16)`.
- **MAVLink2 업링크 서명 강제 = ON**(라이브 확인: 무서명/오서명/리플레이 폐기).
- 컨테이너 로스터(19~20개): epc 7-NF(mme/hss/mongo/pcrf/sgwc/sgwu/smf/upf) + ran_enb×2 +
  uav_{sitl,ue,proxy,gps} + gcs_{proxy,c2} + web_backend + **attacker_ue** + sgi_test.
- **포트:** `14555` 암호문(셀룰러) · `14556` 평문 오라클(gcs_proxy) · `14560` fan-out 평문(web) ·
  `14550` 프록시↔C2/SITL 평문(loopback) · `14540` GPS_INPUT · **`5762` SITL 상태(단일 TCP, 포화 주의)** ·
  `8080/8081` 대시보드.

### 2.3 실행/관측 아키텍처 — obs_daemon (DESIGN §4, 이번 실패의 근원)
> **원칙: "실행"과 "정리"를 하나의 계약으로. 확실히 죽고, 자원을 회수한다.**

**안티패턴(금지):** ❌ 도구마다 `docker run --rm` 단명 컨테이너(신뢰성 있게 못 죽음 → 누수) ·
❌ `subprocess.run(capture_output=True, timeout=)` 로 컨테이너/장기 프로세스(손자 파이프 데드락) ·
❌ 손자/컨테이너를 `killpg`·`timeout` 으로 죽인다고 가정(dockerd 소유 → 못 죽임) ·
❌ 관측을 goal 루프에 **동기 인라인**(심판 hang 이 캠페인 전체 차단).

**채택 = 단일 host-side 관측 데몬(obs_daemon).** 장수 프로세스 1개가 모든 관측 자원을 소유·수명관리하고,
에이전트엔 신호를 **비동기 push** 한다.

| 책임 | 설계 |
|------|------|
| effected 신호(주) | `attacker_ue` netns 또는 host 에서 **14555 암호문 tap**(rate/유무). SITL 평문 미접근. |
| 심판 신호(부·off 기본) | SITL 5762 **단일 연결 재사용**(풀=1, 다중 연결 금지 → 포화 방지). 켤 때만. |
| 종료 계약 | 데몬이 자기 자식/소켓을 소유 → 프로세스 트리 단일. 종료 시 소켓 close + 자식 정리. **`docker run` 손자 없음.** |
| 에이전트 인터페이스 | `daemon.latest_signals()`(논블로킹 read) — 에이전트는 관측을 호출·대기하지 않음. |
| 장애 격리 | 데몬이 죽어도 에이전트는 `signals=stale/none` 으로 진행(fail-open, 보수 판정). |

**백엔드 실행 계약(LocalBackend):** `Backend.run(cmd)->Result` + `Backend.teardown()`. 모든 실행은
(타임아웃 + 확실한 강제종료 + 자원회수)를 보장. **PIPE 캡처 금지 → 파일/스트림 + 워치독.** 비밀은 파일+권한.
백엔드는 `mock`(개발)·**`local`(배포·SSH불필요)**·`ssh`(선택)이며, mock 통과 ≠ 실환경 안전(게이트 1 통합테스트로만 판정).

### 2.4 effected 신호원 · verdict 체계 (DESIGN §5)
`attacker_ue` 위치에서 **관측 가능한 것만** 자율 판단에 쓴다(SITL 평문 직독은 심판 특권, 자율 금지).

| 신호 | 취득 | 강도 | 기여 |
|------|------|------|------|
| 오라클/웹 ACK (`{ok:true,signed:true}`) | 주입 응답 | 약 | accepted (+0.3) |
| **C2 하트비트 두절/재개** | 14555 rate=0/급감(obs_daemon) | **강** | effect (+0.5) |
| 텔레메트리 트래픽 패턴 변화 | 14555 rate 급변 | 중 | effect (+0.3) |
| 응답 없음/폐기/재전송 요구 | 주입 응답 | — | rejected |
| 타임아웃 | — | 약 | unknown |

→ **verdict ∈ {effected, accepted, rejected, unknown} + confidence[0,1].**
**effected** = 물리효과 고신뢰(하트비트두절 or 트래픽변화 필수) · **accepted** = ACK만(효과불명) ·
**rejected** = 차단 · **unknown** = 불확실. 모니터 미배선/데몬 장애 시 **최대 accepted 까지 보수**(허위 effected 0).

### 2.5 판정 3층 · reward (DESIGN §6)
| 층 | 신호원 | 언제 | 역할 |
|----|--------|------|------|
| ① 자율 | 공격자 신호(2.4) | 항상(배포 포함) | **흐름·pivot·reward** |
| ② 심판 | SITL 평문 | 테스트베드·off 기본 | 평가·튜닝(에이전트 미사용) |
| ③ 대조 | ①↔② 일치 | 테스트베드 | autonomy_accuracy(품질지표) |

reward 는 배포 환경서도 계산 가능한 공격자 신호만 사용한다: `defenses_bypassed`, `autopilot_effect_estimated`,
`c2_disruption`, `confidence_weighted`. **금지:** `accepted`(ACK만)을 "성공"으로 서술하는 것 →
"명령 수용, 물리효과 미확인"으로 축소 표기하고, 불일치는 산출물 최상단 배너로 노출한다.

### 2.6 제어평면 = 결정론 FSM + LLM 2곳 (DESIGN §7)
- **FSM:** `RECON → SELECT → EXECUTE → INFER → (goal? END : PIVOT) → SELECT …`(max_pivots 하드캡).
- **LLM ① Planner:** `select`(target_node+방어상태+goal(expect_mode·mavcmd) 주입) / `pivot`(blocked_by→enabler ADAPT).
  출력 = `Channel`(전송) + `Action`(intent) 분리 + enabler 레지스트리(6) pydantic 검증(무효값 폴백).
- **LLM ② Evidence:** correlate(신호 종합) / narrate(BlockProof 서술).
- **LLM 은 증강이지 load-bearing 아님** — 렌더 실패/장애 = 결정표 폴백 직행(빈 프롬프트 호출 금지).
- **Recon 은 1급 단계** — 캠페인 전에 signing 등 방어상태를 선제 확보(discover 도구는 파서/결과모델/node_cmd 완전 등록).

### 2.7 비행상태 종속 안전 (DESIGN §8, 방산 1순위)
- `_is_safe`/`_safe_undo` 는 **비행상태 분기:** 지상=disarmed / 비행=자율모드(GUIDED/LOITER/RTL) 유지.
  **비행 중 STABILIZE·disarm 금지**(추락).
- undo = "직전 자율모드 재명령" or LOITER. **force-land = (위치known ∧ 착륙영역clear ∧ 통제강하) ∧ RTL불가일 때만
  최후수단(HITL 인간승인).** 1차 failsafe = RTL.
- `record_intent`(ledger)는 **guard 밖** — 항상 기록(recover_on_boot 보장).
- **Watchdog** 독립 데몬 스레드(캠페인 중 기동, finally stop). HITL 이원게이트(고위험=인간승인 / 긴급복구=화이트리스트 즉시).

---

## Part 3 · 요구사항 · 배포 (로컬 → 서버)

### 3.1 요구사항 (의존성)
| 대상 | 요구 |
|---|---|
| 테스트베드 서버 | Ubuntu, Python **3.12+**, Docker(무-sudo 권장), `sudo nsenter`(감독용) |
| 실행 위치 | **온-호스트 LocalBackend** — 에이전트를 테스트베드 서버에서 실행(로컬 SSH 백엔드 아님) |
| Python 패키지 | `pip install -e .`(litellm·pymavlink·fastapi·uvicorn·pydantic·PyYAML — `pyproject.toml`) |
| 컨테이너 | 테스트베드 컨테이너 다수(19~20) Up + `dahv2/air` 이미지(정찰/주입 사이드카) |
| 네트워크 | 대시보드 `127.0.0.1:8080`(SSH 터널), 뷰어 `127.0.0.1:8090` |

**환경변수(비밀 2개 + 자동 기본값):**
| 변수 | 용도 | 출처 |
|---|---|---|
| `OPENROUTER_API_KEY` | live LLM(litellm) | `.env.openrouter`(런처 자동 로드) |
| `ARIA_KEY` | 감독 14555 복호 | `~/testbed/.env-aria`(런처 자동 해석) |
| 그 외 기본값 | 캐시억제 등 | dah.sh 내장 |

> 배포 의존값(테스트베드 IP·SSH키)·비밀은 **`.env`** 에 모은다(`.env.example` 복사→값 채움, `.env`=gitignore).
> config 의 `${VAR}`(예: `${TESTBED_HOST}`/`${TESTBED_USER}`/`${SSH_KEY}`)가 치환되며,
> 비밀은 **env 이름으로만** 주입한다(코드/문서 하드코딩 0). 값은 서버 밖 반출 금지.

### 3.2 배포 절차 (RUNBOOK §1~§4)
```powershell
# 로컬 PowerShell — 프로젝트를 서버 홈에 전송 (키 = <KEY>.pem)
tar -czf - -C "C:\Users\user\Desktop\dah\dah_attack" attack_agent `
| ssh -i "C:\Users\user\.ssh\<KEY>.pem" ubuntu@<TESTBED_IP> "cd ~ && tar -xzf -"
```
```bash
# 서버 — venv + 설치
cd ~/attack_agent
python3 -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip && pip install -e .
```
접속 · 대시보드 터널:
```bash
ssh -i "C:\Users\user\.ssh\<KEY>.pem" ubuntu@<TESTBED_IP>
ssh -i "C:\Users\user\.ssh\<KEY>.pem" -L 8080:127.0.0.1:8080 ubuntu@<TESTBED_IP>   # 대시보드 볼 때만
```
비밀값은 `.env`(권장) 또는 export 로 주입 후 존재만 확인한다(값 출력 금지):
```bash
python - <<'PY'
import os
print("OPENROUTER_API_KEY:", bool(os.getenv("OPENROUTER_API_KEY")))
print("ARIA_KEY:", bool(os.getenv("ARIA_KEY")))
PY
```

> 참고: 원문 런북(RUNBOOK)에는 키 경로가 `Downloads\` 로 남아 있으나 **본 매뉴얼의 정규 표기는
> `~/.ssh/<KEY>.pem` + `<TESTBED_IP>` 플레이스홀더** 다. 게이트 개수도 원문 "8개"는 stale 이며 **현재 11개**가 정답.

---

## Part 4 · 실행 — 런처 하나로 (`./dah.sh <명령>`)

```bash
cd ~/attack_agent
./dah.sh verify      # ① 11개 무결성 게이트 (ALL PASS 확인)
./dah.sh recon       # ② 정찰 (오프라인 mock 기본; 테스트베드 실측은 --backend local)
./dah.sh campaign    # ③ 라이브 캠페인 + 감독 (헤드라인)  [OPENROUTER_API_KEY 필요]
./dah.sh land        # ④ 착륙 시각화 데모 (대시보드 고도↓)  [명시 승인 하]
./dah.sh viewer      # ⑤ 뷰어 3패널 (127.0.0.1:8090)
./dah.sh status      # ⑥ 컨테이너 + 드론 상태
```

| 명령 | 하는 일 | 내부적으로 |
|---|---|---|
| `./dah.sh verify` | 11개 게이트 전부 PASS/FAIL | `verify.py`(11게이트) |
| `./dah.sh recon` | 정찰만(오프라인·무해) | `run.py --config configs/config.testbed.yaml --goal goals/goal.testbed.yaml` |
| `./dah.sh campaign` | **라이브 캠페인 + 감독**(헤드라인) | 내장 2-프로세스 오케스트레이션(nsenter 감독 + 캠페인) |
| `./dah.sh land` | 착륙 시각화 데모(대시보드 고도↓) | 내장(5762 직결 LAND + `land_demo.py`) |
| `./dah.sh viewer` | 뷰어 3패널(8090) | `viewer.server` |
| `./dah.sh status` | 컨테이너 + 드론 상태 | `docker ps` + 5762 readback |

**가장 흔한 흐름:** `./dah.sh verify` → `./dah.sh campaign` → `./dah.sh viewer`

**각 명령 상세**
- **② recon** — 기본은 오프라인(backend=mock·no-llm)이라 테스트베드 무접속 폐루프. 실측 정찰은 `./dah.sh recon --backend local`.
- **③ campaign (GATE5, 헤드라인)** — dah.sh 내장 오케스트레이션. **검증된 2-프로세스**로 동작한다:
  - 감독 = `sudo nsenter -t <gcs_proxy pid> -n … run_supervisor_standalone.py`(gcs_proxy netns 에서 14555 ARIA 복호 → ground-truth).
  - 캠페인 = `run_live_gate5.py --skip-supervisor`(호스트 netns, live LLM ReAct).
  - ⚠️ `run_live_gate5` 의 **in-process 감독은 호스트 netns 라 14555 를 못 잡는다** → 반드시 분리 실행(dah.sh campaign 이 내장 처리).
  - 조정: `CONFIG=… GOAL=… SUP_WINDOW=… ./dah.sh campaign`. 산출: `run_live.jsonl`·`evaluation_live.json`·`supervisor_live.jsonl`.
- **④ land (착륙 시각화)** — 공격자(attacker_ue)→UE격리부재→노출 5762 직결로 `DO_SET_MODE 9(LAND)`, **복원 없음**.
  3중 증거(감독 mode 타임라인 · 대시보드 `/stats` Altitude · 5762 readback)를 `runs/land_*.log` 에 남긴다.
  UAV IP 는 런타임 해석(하드코딩 0). **지속 착륙이라 명시 승인 하에서만.**
- **⑤ viewer** — action/comms/evaluation 3패널을 `127.0.0.1:8090` 에 서빙(터널 `-L 8090:127.0.0.1:8090`).
- **⑥ status** — `docker ps` + 5762 HEARTBEAT readback(mode·armed·rel_alt).

---

## Part 5 · 검증 게이트 (11개)

`./dah.sh verify` 는 **11개 게이트**를 단일 러너로 돈다: `tests/` 의
`hygiene·p0·p2·models·parsers·bindings·structure·prompt·quality` + `supervisor/verify_grep0` + `viewer/verify_viewer`.
전부 `PASS` 여야 하며 스크래치 `.cache_verify` 는 전후 자동정리된다. **평소 실행 경로가 아니라 코드 무결성을 증명하는
CI 게이트**이며, 보고서의 "검증 PASS" 증거로 쓰인다.

**게이트 → 증명하는 것 (QUICKSTART §5 매핑표 흡수)**
| 게이트 | 증명하는 것 |
|---|---|
| `verify_p0` | 22 tool 계약 · 타입 · legality |
| `verify_p2` | recon 폐루프 · 실행 글루 |
| `verify_grep0` | 공격 core ⟂ 감독 완전분리(되먹임 0) |
| `verify_viewer` | 뷰어 read-only · redact · 3패널 |
| `verify_models` | role→model 라우팅 |
| `verify_bindings` | registry exec 바인딩 |
| `verify_parsers` | raw→모델 파서 |
| `verify_structure` | 데드코드 0 · 모듈 docstring · 하드코딩 리터럴 0 |
| `verify_prompt` | 레시피 금지 · Jinja StrictUndefined 실렌더 · tool 3자 정합(23개) |
| `verify_quality` | 타입힌트 완전 · CLI 스키마 · 구조↔문서 · 비밀 리터럴 0 · **언어정책** · 스텁↔문서(은폐금지) |
| `verify_hygiene` | UTF-8 · BOM/LF · 비밀 미노출 · 필수문서 |

> **게이트 8 → 11 이력(CHANGELOG):** 2026-07-08 재구성에서 `verify_structure`·`verify_prompt`·`verify_quality`
> 3종이 신규 추가되어 8개에서 11개로 늘었다. `verify_quality` 의 P8(코드 주석의 실측주장↔근거 연결)은
> 본질적으로 주관적이라 자동 게이트가 아닌 **수동 리뷰 항목**으로 둔다.

> ✅ **클론 검증됨(CHANGELOG 2026-07-08):** 새 `git clone` → `pip install -e .` → `./dah.sh verify` = 11/11 PASS +
> `./dah.sh recon` 정상(오프라인, 테스트베드 불필요) 실측 확인. `.env` 외부화 후에도 `config host=127.0.0.1`
> 기본값으로 동작(하드코딩·비밀 0).

---

## Part 6 · 공격 카탈로그 (DESIGN §9)

**enabler 레지스트리(코드강제 6, pydantic validator 로 무효값 reject):**
| enabler | 의미 |
|---|---|
| `naive` | 무키·차단 baseline(Differential 의 대조군) |
| `oracle` | 14556 평문 오라클 경로 |
| `webcmd` | 무인증 웹 서명 우회(NF-4) |
| `forge` | 위조 봉투(NF-6) |
| `serial5762` | SITL 5762 직결 |
| `forceland` | 강제 착륙 · HITL |

**노드(실측 판정, 요약):** naive(차단 baseline) · TM1/V2 oracle(성립) · forceland(HITL) · V1 리플레이(성립) ·
V3 peer(조건부) · V4 키노출(성립) · V5 nonce(잠재) · TM2(완화) · TM3(ARIA 무력) · NF-3 가입자DB · NF-4 웹서명우회 · NF-6 서명키.

**ADAPT:** 방어가 벡터를 차단(3실패/페로몬 or `blocked_by=signing`)하면 사전 미정의 대체 벡터로 자율 전환한다
(예: `oracle → webcmd → forge`). `blocked_by`(signing/auth/no_effect)는 **파싱 응답에서 도출**하며 이름을 하드코딩하지 않는다.
ADAPT 가 LLM 값어치의 핵심이다.

**win_cause:** `crypto-break`(미발생) / `key-leak`(V4·NF-6) / `config-flaw`(TM1·NF-3·NF-4).

**수행/보조:** 수행(perform)=rogue UE 단독(oracle/forceland/V1/V4/webcmd/forge). 보조(assist)=foothold 필요(NF-3·TM2·V3).

---

## Part 7 · 서브시스템

### 7.1 사이드카 이미지 (sidecar/)
공격 도구 코퍼스를 baked 한 **툴링 사이드카 이미지 정의**다. 이 디렉터리는 이미지 정의(Dockerfile)와
vendor/exec 채움 계약만 담으며, 워크플로우는 **완전 오프라인·테스트베드 무접속**(어떤 에이전트도 SSH/scp/`docker build`/배포를 하지 않는다).
실제 build/채움/기동은 별도 **통제단계**에서 수행한다.

| 이미지 | 디렉터리 | 계층 | vantage(sidecar) | 도구 | config 키 |
|--------|----------|------|------------------|------|-----------|
| `dahv2/air` | `air/` | A · D | `tools_ue`(`--network container:attacker_ue`) · `tools_sgi`(net_sgi) | pymavlink + OpenSSL(ARIA, vendored) | `tools.image.air`(필수) |
| `dahv2/pfcp-poc` | `pfcp/` | B | `tools_core`(net_core, pivot 후) | scapy | `tools.image.pfcp`(옵션) |

**공통 계약:**
- **장수 사이드카 + `docker exec`:** 모든 이미지 CMD = `sleep infinity`. 이미지는 실행 주체가 아니며,
  host 실행기가 `docker exec` 로만 baked 스크립트를 구동한다(누수 0 종료계약).
- **금지(하드):** `docker run --rm` 단명 사이드카 · ENTRYPOINT 자동 공격실행 · SSH · 넓은 grep 기반 kill ·
  PIPE 캡처 · 5762 다중연결.
- **R2 라벨:** 이미지는 `org.dah.image` 정체 라벨만 갖고, 런타임 회수 라벨(`dahv2.owner=agent`·`dahv2.run_id=$RUN`)은
  실행기가 `docker create/run --label` 로 부여한다.
- **vendor/exec 슬롯:** `vendor/aria_gcm.py`(placeholder sentinel — R3 preflight 로 실체 교체 강제)와 `exec/`(baked 스크립트 트리)는
  통제단계에서 **read-only scp 로만** 채운다. 미충전 상태로 사이드카를 기동하면 R3 preflight 가 실패해 해당 계층 실행이 봉쇄된다(허위 실행 방지).
- **PIPE 데드락 회피:** `docker exec` 출력은 컨테이너 내부 파일(`/tmp/out.$JOB`)로 리다이렉트하고 실행기가 파일/스트림으로 읽는다.

### 7.2 뷰어 (viewer/)
정적 HTML/JS + FastAPI(수동 SSE)로 산출물을 **읽기 전용**으로 시각화하는 3패널 관측기(CDN/외부폰트 0, 자기완결, 3D 없음).

**완전분리(grep0) 불변식:** `viewer/*.py` 는 `core.*`/`supervisor.*` 를 정적·동적 모두 import 하지 않는다.
공격 agent 로의 **되먹임 채널 0**(action_log write-open 안 함, evaluation/supervisor.jsonl 도 read-only),
**변경 엔드포인트(POST/PUT/DELETE/PATCH) 부재**(주입면 신설 없음), `ingest.redact()` 가 방어심층 2차 마스킹(hex≥16·base64≥24·키명).
`verify_viewer.py` 가 AST 로 이 불변식을 강제한다.

**3패널:** ① **동작** — 공격 agent `action` JSONL(step 인덱스 타임라인, verdict 색상, `blocked_by`→"blocked→pivot" 배지) ·
② **통신** — 감독 복호 wire(`supervisor.jsonl`; 부재 시 `evaluation.json` 에서 재구성) + 공격측 INJECT 주입로그 레인 ·
③ **감독**(사용자 전용) — `evaluation.json` 의 `truth_verdict`+`autonomy_accuracy`+`ground_truth`, `agree==false` 면 최상단 **적색 "agent≠truth" 배너**.

**데이터 소스(READ-ONLY):** 동작=`out.log`(예 `run.jsonl`, 생산자 공격 agent) · 감독=`evaluation.json`(생산자 감독) ·
통신=`supervisor.jsonl`(선택; 부재 시 evaluation 재구성 폴백, 이 경우 프레임별 `signed` 는 미기록).

**기동(운영자·서버 on-host):**
```bash
uvicorn viewer.server:app --port 8090                       # 샘플 데모(기본 app=viewer/sample/*)
python -m viewer.server --config config.yaml                # config 의 out.log/viewer.port 직독
python -m viewer.server \
  --action-log runs/run.jsonl --evaluation runs/evaluation.json \
  --comms-stream runs/supervisor.jsonl --port 8090          # 명시 경로
```
라우트는 전부 GET·read-only(`/`·`/static/*`·`/api/snapshot`·`/sse`). SSE 는 0.5s 파일 폴링 + `: keep-alive` heartbeat,
`request.is_disconnected()` 로 종료, 파일핸들은 `with` 로 즉시 회수(orphan 0).

**정직 배너(설계상 한계):** `StepRecord` 에 timestamp 가 없어 **동작 타임라인은 step 인덱스 순**, **통신은 감독 캡처 시각(t) 순** →
두 타임라인의 절대시각 정렬 불가(인과 상관은 감독 자체의 uplink↔downlink 매칭만 인용). 주입로그의 `accepted` 는
공격 agent 자기-ACK(`verdict==OK`)일 뿐 ground-truth 가 아니다 — 실제 mode 전이는 감독 패널(`ground_truth`)이 독립 판정한다.

**오프라인 검증:** `python viewer/verify_viewer.py`(py_compile + AST 분리 + HTML/JS 자기완결 + ingest 라운드트립 + redact). 네트워크·docker·테스트베드 0.

---

## Part 8 · 파라미터 파일 · 산출물

### 8.1 파라미터 파일 — 뭘 고르나
| 종류 | 실제 사용 | 변형(참고) |
|---|---|---|
| config | **`configs/config.live.yaml`**(라이브) | `configs/config.testbed.yaml`(오프라인 베이스), `configs/config.example.yaml`(템플릿) |
| goal | **`goals/goal.p4.yaml`**(서명우회=헤드라인) | `goals/goal.land.yaml`(착륙), `goals/goal.testbed.yaml`(정찰), `goals/goal.example.yaml`(템플릿) |
| models | **`configs/models.yaml`**(역할→모델 라우팅) | — |

config = 접속·vantage·타깃 이름, goal = 공격 목표·방어 시드·계층 scope. **하드코딩 0** — 값은 전부 파일로 주입.
CLI 즉석 목표: `run.py --goal-expr "mode_set mode=4 defense=on success=ack scope=A,C"`.

### 8.2 산출물
| 파일 | 내용 |
|---|---|
| `run_live.jsonl` | 에이전트 액션 로그(체인·goal_reached·defenses_bypassed) |
| `evaluation_live.json` | 감독 ground-truth 판정(mode 타임라인·autonomy_accuracy) |
| `supervisor_live.jsonl` | 뷰어 통신 프레임 |
| `runs/archive_*` · `runs/GATE5_*` · `runs/LAND_DEMO_*` | 타임스탬프 백업/스냅샷 |

---

## Part 9 · 운영 런북 · 트러블슈팅

### 9.1 실행 중 체크리스트 (RUNBOOK §7)
```bash
# 프로세스/리소스
ps -ef | rg "python|run.py|run_live_gate5.py" || true
free -h ; df -h
# Docker 상태
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Image}}"
# 출력 로그 증가/오류 감시
tail -n 50 -f run.jsonl
rg -n "Traceback|ERROR|CRSError|Exception" run*.jsonl evaluation*.json supervisor*.jsonl
# 단일 연결 민감 포트(5762) 누적 감시
ss -antp | rg 5762 || true
```
판단 기준: **5762 연결 수가 비정상 누적되지 않아야** 하며, 실행 종료 후 잔여 프로세스/컨테이너가 계속 증가하면 즉시 중단 후 원인 분석.

### 9.2 종료 · 정리 (RUNBOOK §8)
```bash
ps -ef | rg "run.py|run_live_gate5.py" || true                 # 프로세스 종료 확인
mkdir -p runs/archive_$(date +%Y%m%d_%H%M%S)                   # 산출물 백업
cp -a run*.jsonl evaluation*.json supervisor*.jsonl runs/archive_$(date +%Y%m%d_%H%M%S)/ 2>/dev/null || true
```

### 9.3 장애 대응 기본 원칙 (RUNBOOK §9)
- `verify_*` 실패 상태로 실행을 진행하지 않는다.
- 런타임 오류 시: ① 마지막 200줄 로그 확보 → ② 환경변수/경로/권한 점검 → ③ 동일 입력 재현 확인.
- **임시 우회보다 원인 수정 우선**(재현 가능성 유지). 파괴적 조작은 대상 정확 지정(넓은 grep kill 금지), AMI 스냅샷 전제.

### 9.4 트러블슈팅 (알려진 함정)
| 증상 | 원인 | 해결 |
|---|---|---|
| `bash: $'\r': command not found` | Windows CRLF `.sh` | 저장소 `.sh` 는 LF. 재발 시 `sed -i 's/\r$//' *.sh` |
| campaign evaluation 0프레임 | in-process 감독이 호스트 netns | `dah.sh campaign` 사용 — nsenter 로 gcs_proxy netns 진입 |
| `verify_hygiene FAIL: .cache_verify` | p2/parsers 스크래치 잔여 | `dah.sh verify` 가 전후 자동정리(수동 시 `rm -rf .cache_verify`) |
| campaign LLM 전 호출 실패(402) | OpenRouter 크레딧 0 | 크레딧 충전(`.env.openrouter` 키 유효 확인) |
| land TARGET unreachable | UE풀 IP 변동/미도달 | dah.sh land 가 `docker exec` 로 IP 재해석 + 주입기 discover 폴백 |
| `status` 드론 읽기 실패 | `dahv2/air` 이미지 부재 | 이미지 빌드/확인 |

> **드론 상태 주의:** 착륙 데모 후 `mode9/disarmed/landed`(복구 안 함). 재이륙하려면 GUIDED→arm→takeoff.

---

## 6.5 알려진 한계 (정직 표기)

> (Part 10) 아래 한계는 은폐하지 않고 명시한다. 게이트 `verify_quality`(P7)의 스텁↔문서 은폐금지 앵커이기도 하다.

- `forge_aria`/`forge_sign`(ARIA/서명 위조 tool)은 **스텁(stub)** — 실제 암호연산 미구현. 헤드라인 관통은 노출면
  `serial5762`(tcp/5762) 경로로 실증하며, forge 경로는 "가정·미구현"으로 정직 표기한다.
- `orchestrator.py` 의 결정론 폴백 등 일부 경로에 미완 표식이 남아 있으며, 본 한계는 은폐하지 않고 여기 명시한다.
- PFCP 코어 세션 파괴(`pfcp_delete`)는 공유 코어 영향·복구 불확실로 실측 캠페인에서 기본 제외.

---

## Part 11 · 이식성 · 언어 정책 (규칙)

- 환경 의존값·비밀은 config/env 로만 주입(하드코딩 0).
- 텍스트 UTF-8. 한글 `*.md` 는 콘솔 호환 위해 UTF-8 **BOM** 유지, `*.py`/`*.sh` 는 **BOM 금지**(`verify_hygiene`·`verify_structure` 강제).
- 셸 스크립트 `.sh` 는 **LF** 유지(`.gitattributes` 로 체크아웃 강제).
- **주석·언어 정책(language policy):** 문서·주석은 **한국어 주 + 기술용어 영문 병기** 허용, **식별자(변수·함수·모듈)는 영문**.
  프롬프트는 용어정의(glossary)에 정의된 표현만 사용(동의어 혼용 금지).

---

## Part 12 · 변경이력 요약 (CHANGELOG)

전체 이력은 [CHANGELOG.md](./CHANGELOG.md). 핵심(2026-07-08 재구성):
- **구조 정리:** 루트 파일 → 디렉터리화(`configs/`·`goals/`·`tests/`), **단일 셸 진입점 `dah.sh`**,
  **단일 게이트 러너 `verify.py`**, 개발·세션 문서는 저장소 밖 분리(git 엔 운영문서만).
  `.gitignore`(.venv·캐시·runs·`.env*`·`*.pem`) + `.gitattributes`(LF) + `pyproject.toml`.
- **검증 게이트 8 → 11:** `verify_structure`(데드코드 0·docstring·하드코딩 0) · `verify_prompt`(레시피 금지·StrictUndefined·tool 3자 정합 23개) ·
  `verify_quality`(타입힌트 완전·CLI 스키마·구조↔문서·비밀 리터럴 0·언어정책·스텁↔문서) 신규.
- **보안(비밀·서버정보 외부화):** 배포 의존값·비밀 → `.env`. `core/common/config.py` 의 `_load_yaml` 에 `${VAR:-default}` env 치환 추가.
  `configs/*.yaml` 의 host/user/ssh_key → `${TESTBED_HOST/USER/SSH_KEY}`, 실 IP·키파일명 전수 genericize. **git 추적 파일에 실제 키값·서버 IP 0.**
- **정직성:** 본 README §6.5 에 `forge_aria`/`forge_sign` 스텁·pfcp 기본 제외를 명시.
