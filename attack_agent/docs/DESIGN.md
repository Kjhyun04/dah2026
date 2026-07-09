# attack_agent — 재설계 설계도 (DESIGN / Canonical)

> **위치·상태:** 이 문서 = attack_agent 재설계의 단일 진입점. 작성 2026-07-05.
> **근거 문서:** `agent_v1/RETROSPECTIVE_REDESIGN_GUIDE.md`(회고·DO/DON'T) · `agent_v1/VERDICT_SPEC.md`(판정 W1~W7) · `agent_v1/AUDIT_FINDINGS.md`(C/H/M+B1~B8) · `agent_v1/EXPERT_ANALYSIS.md`(3인 수렴) · `testbed/ARCHITECTURE.md`(인프라) · `dah_attack/MASTER_SUMMARY.md`(공격 실증) · 라이브 실측(2026-07-05, 아래 §1.2).
> **정직성:** 인가된 격리 테스트베드 전용 · 전 과정 가역·무해 · 실기체/실이동통신망 아님. agent≠truth 불일치는 산출물 최상단 노출.

---

## 0. 왜 재설계인가 (한 문단)

agent_v1은 **판정 정직성(W1~W6)은 성공**했으나(구 "ACK=무조건 성공" 버그가 실인프라에서 미재현), **실행/관측의 실환경 견고성이 무너졌다** — 관측이 도구마다 `docker run` 단명 컨테이너를 띄웠고, 이게 신뢰성 있게 죽지 않아(`killpg`·`timeout`은 dockerd 소유 컨테이너를 못 죽임) 누수→SITL 5762 단일연결 포화→캠페인 연쇄 hang→테스트베드 오염(AMI 복원)에 이르렀다. 따라서 재설계의 심장은 두 가지다: **(A) 확실히 죽는 실행/관측 아키텍처**와 **(B) effected 물리효과 신호원**. 이 둘을 코드 이전에 확정한다(재설계 게이트 0).

---

## 1. 정체 · 서사 · 전제

### 1.1 정체 (유지)
방어가 비어 있는 **신뢰경계·인증·키관리 빈틈을 자율로 찾아 찌르고, 방어가 진화하면 벡터를 전환(ADAPT)** 하는 **이식형(portable)** 공격 에이전트.

**핵심 서사(계층방어):** *ARIA-256-GCM 알고리즘 자체는 안 뚫린다. 성립하는 공격은 전부 그 주변(오라클·재생·peer학습·키노출·무인증 웹서명)의 설계 결함이다.* → 이걸 공격 측 단독으로 증명하는 것이 **Differential BlockProof**(naive↔enabler 차분).

**정직한 재정의:** "완전 자율 성공"이 아니라 **"배포 가능한 자율 공격 추론 + 테스트베드 독립 채점"**.
- **Autonomous Reasoner** (공격자 신호·배포가능) + **Independent Verifier** (심판·테스트베드 전용·off 기본) + **Reconciler** (정확도 채점).

### 1.2 인프라 전제 (라이브 실측 2026-07-05 — 설계가 겨냥하는 실체)
- 서버 `ubuntu@<TESTBED_IP>` (키 `<KEY>.pem`, IP 가변). **19 컨테이너**: epc 7-NF(mme/hss/mongo/pcrf/sgwc/sgwu/smf/upf) + ran_enb + ran_enb2 + uav_{sitl,ue,proxy,gps} + gcs_{proxy,c2} + web_backend + **attacker_ue(rogue UE)** + sgi_test.
- **공격 거점 = `attacker_ue`**, 셀룰러 attach `10.45.0.2/24`(정상 UAV `uav_ue` = `10.45.0.3`, 동일 APN·동일 UE풀 10.45.0.0/16).
- **종단 암호 = ARIA-256-GCM 프록시 쌍.** 봉투 `VER(0x01)‖nonce(12 rand)‖CT‖TAG(16)`.
- **MAVLink2 업링크 서명 강제 = ON**(라이브 확인: gcs_c2 `🔒 서명 송신 ON`, uav_proxy 무서명/오서명/리플레이 폐기). 토글 코드 = `testbed/{gcs/gcs.py, proxy/mav_aria_proxy.py, web/backend/app.py}`.
- **포트:** 14555 암호문(셀룰러) · 14556 평문 오라클(gcs_proxy) · 14560 fan-out 평문(web) · 14550 프록시↔C2/SITL 평문(loopback) · 14540 GPS_INPUT · **5762 SITL 상태(단일 TCP, 포화 주의)** · 8080/8081 대시.
- ⚠ 현재 C2 링크는 두절 상태(병행 세션 복구 중) — 설계는 링크 정상 전제로 하되, **관측 데몬은 링크 부재도 신호로 취급**(§4).

---

## 2. 절대 규칙 & 재설계 게이트 (설계 불변식)

**절대 규칙 9 (요약, 위반 금지):**
1. reward·흐름·pivot = **공격자 관측 신호로만**. 심판(SITL 평문) 의존 금지.
2. 성공 = **물리효과(effected)**. ACK 수용(accepted)은 성공 아님. (단 effected 신호원을 먼저 설계 — §4.)
3. 안전 = **비행상태 함수**. 지상=disarmed / 비행=자율모드(GUIDED/LOITER/RTL) 유지. 비행 중 STABILIZE·disarm 금지. force-land=조건부 최후수단(HITL). 고위험 안전행동은 예산으로 굶기지 않음.
4. 샌드박스 전용·가역·무해. 데모 IP=RFC5737. 실기체/실망/실서비스 금지.
5. 상태변경(주입/설치/명령, 특히 force-land)은 **실행 직전 사용자 확인**.
6. 비밀 마스킹(redact). 키는 커맨드라인/평문 env 금지. core/private 분리.
7. 정직성. agent≠truth 불일치는 산출물 최상단 노출.
8. 적대적 검증 습관. 중요 판단·수정은 서브에이전트 독립 재검증.
9. 사용자 한국어면 한국어.

**재설계 게이트 (통과 전 다음 단계 금지):**
- **[게이트 0]** 코드 전에 **실행/관측 아키텍처(§4)와 effected 신호원(§5)** 확정. ← 이 문서가 그 산출.
- **[게이트 1]** "실 docker 관측 경로가 **누수 0**으로 타임아웃·강제종료된다"를 첫 통과 기준(§13). **통과 전 캠페인 실측 금지.**
- **[불변식]** 심판(observe)은 **절대 load-bearing 아님** — 비동기·격리·타임아웃·**기본 off**. 흐름 게이트/블록 불가.

---

## 3. 아키텍처 개관 (3 컴포넌트 · 데이터 흐름)

```
                    ┌───────────────────── attack_agent (rogue UE 위치 or local 배포) ─────────────────────┐
                    │                                                                                  │
  [관측 데몬]  ──push(비동기)──▶  ┌─ Autonomous Reasoner (결정론 FSM + LLM 2곳) ─┐   ──▶ 산출물         │
  (host-side,       │            │  Recon → Select(LLM) → Execute → Infer(자율)  │      timeline.html   │
   단일·수명관리)   │            │        ↑ pivot(LLM, blocked_by)  ↓ verdict     │      blockproof.md   │
   14555 rate tap   │            └───────────────────────────────────────────────┘      reward.json     │
   (effected 신호)  │                         │ 흐름·reward·pivot = 공격자 신호만                        │
                    │                         ▼                                                          │
                    │            ┌─ Independent Verifier (심판) ─┐  ── 기본 OFF ──▶ evaluation.json       │
                    │            │  SITL 5762 평문 before→after   │  (테스트베드 전용·비동기·격리)         │
                    │            └────────────────────────────────┘         │                            │
                    │                                                        ▼                            │
                    │                                        ┌─ Reconciler ─┐  autonomy_accuracy          │
                    │                                        │ 자율 ↔ 심판   │  (품질 지표, reward 아님)   │
                    │                                        └───────────────┘                            │
                    └──────────────────────────────────────────────────────────────────────────────────┘
```

- **제어평면 = 결정론 FSM.** LLM = 2곳(Planner select/pivot · Evidence correlate/narrate). 나머지 결정론.
- **관측 데몬은 에이전트 밖의 장수 프로세스** — 에이전트는 데몬이 push한 신호만 소비(동기 인라인 금지 = B1 재발 방지).
- **심판은 완전 분리**: 에이전트 흐름 코드가 truth를 절대 안 봄(grep 0). off로도 캠페인 완주.

---

## 4. ★게이트 0-A — 실행/관측 아키텍처 (이번 실패의 근원)

> **원칙: "실행"과 "정리"를 하나의 계약으로. 확실히 죽고, 자원을 회수한다.**

### 4.1 안티패턴 (금지 — 회고 §5 실증)
- ❌ 도구 호출마다 `docker run --rm` 단명 컨테이너 (신뢰성 있게 못 죽음 → 누수).
- ❌ `subprocess.run(capture_output=True, timeout=)`로 컨테이너/장기 프로세스 (손자 파이프 데드락, 40s 안전장치조차 무력).
- ❌ 손자/컨테이너를 `killpg`·`timeout`으로 죽인다고 가정 (dockerd 소유 → 못 죽임).
- ❌ 관측을 goal 루프에 **동기 인라인** (심판 hang이 캠페인 전체 차단 = B1).

### 4.2 채택: **단일 host-side 관측 데몬** (obs_daemon)
장수 프로세스 **1개**가 모든 관측 자원을 소유·수명관리하고, 에이전트엔 신호를 **비동기 push**한다.

| 책임 | 설계 |
|------|------|
| **effected 신호(주)** | `attacker_ue` netns 또는 host에서 **14555 암호문 tap** (rate/유무). SITL 평문 미접근 = 공격자 관측 신호(§5). |
| **심판 신호(부·off기본)** | SITL 5762 **단일 연결 재사용**(풀=1, 절대 다중 연결 금지 → 5762 포화 방지). 켤 때만. |
| 종료 계약 | 데몬은 자기 자식/소켓을 소유 → 프로세스 트리 단일. 종료 시 소켓 close + 자식 정리. **`docker run` 손자 없음**(누수 원천 제거). |
| 에이전트 인터페이스 | `daemon.latest_signals()` (논블로킹 read) — 에이전트는 절대 관측을 **호출·대기하지 않음**. |
| 장애 격리 | 데몬 죽어도 에이전트는 `signals=stale/none`으로 진행(fail-open, 보수판정). |

**대안(백로그):** 장수 사이드카 컨테이너 + `docker exec`(컨테이너 dockerd 소유라 안정하나 exec 세션 수명관리 필요). host-side 데몬이 1순위(회고 §4-A).

### 4.3 백엔드 실행 계약 (LocalBackend 재설계)
```
Backend.run(cmd) -> Result           # 실행
Backend.teardown()                   # 표준 정리 (자식·소켓·임시파일)
계약: 모든 실행은 (타임아웃 + 확실한 강제종료 + 자원회수)를 보장.
      PIPE 캡처 금지 → 파일/스트림 + 워치독. 비밀은 파일+권한(커맨드라인 금지).
```
- `mock`(개발) · **`local`(배포·SSH불필요)** · `ssh`(선택). mock은 실환경 특성(누수·연결한계) 미모사이므로 **게이트 1 통합테스트로만 배포 안전 판정**(mock 통과 ≠ 안전).

---

## 5. ★게이트 0-B — effected 신호원 (물리효과 판정)

> **effected를 주장하려면 효과 모니터를 1급 시민으로 먼저 설계한다. 못 하면 accepted까지만 정직 축소.**

### 5.1 공격자 관측 신호 (배포 가능 — 이것만으로 흐름·reward)
`attacker_ue` 위치에서 **관측 가능한 것만**. SITL 평문 직독 = 심판특권, **자율판단 금지**.

| 신호 | 취득 | 강도 | 기여 |
|------|------|------|------|
| 오라클/웹 ACK (`{ok:true,signed:true}`) | 주입 응답 | 약 | accepted (+0.3) |
| **C2 하트비트 두절/재개** | 14555 암호문 rate = 0/급감 (obs_daemon) | **강** | effect (+0.5) |
| **텔레메트리 트래픽 패턴 변화** | 14555 rate 급변 | 중 | effect (+0.3) |
| 응답 없음/폐기/재전송 요구 | 주입 응답 | — | rejected |
| 타임아웃 | — | 약 | unknown |

→ 신호 종합 → **verdict ∈ {effected, accepted, rejected, unknown} + confidence[0,1]**.
- **effected** = 물리효과 고신뢰(하트비트두절 or 트래픽변화 필수). **accepted** = ACK만(효과불명). **rejected** = 차단. **unknown** = 불확실.
- 모니터 미배선/데몬 장애 시 **최대 accepted까지 보수**(허위 effected 0).

### 5.2 심판 (테스트베드 전용·평가용·에이전트 미사용)
소유자 특권으로 SITL 5762 평문 before→after 차분 → `success/blocked/inconclusive`(목표==현재상태=inconclusive). **에이전트는 이 값을 보지 않는다.** off로도 캠페인 완주.

---

## 6. 판정 3층 · reward (VERDICT_SPEC 계승)

| 층 | 신호원 | 언제 | 역할 |
|----|--------|------|------|
| **① 자율** | 공격자 신호(§5.1) | 항상(배포 포함) | **흐름·pivot·reward** |
| **② 심판** | SITL 평문(§5.2) | 테스트베드·off기본 | 평가·튜닝(에이전트 미사용) |
| **③ 대조** | ①↔② 일치 | 테스트베드 | autonomy_accuracy(품질지표) |

```python
reward = {  # 배포 환경서도 계산 가능한 공격자 신호만
  "defenses_bypassed": count(effected 중 방어우회),
  "autopilot_effect_estimated": any(v=="effected"),
  "c2_disruption": 하트비트두절 감지,
  "confidence_weighted": sum(conf for effected),
}
evaluation = { "autonomy_accuracy":…, "truth_success":…, "agent_vs_truth":[…] }  # 심판 기반 별도
```
**금지:** `accepted`(ACK만)을 "성공"으로. → "명령 수용, 물리효과 미확인"으로 서술. 3층 병기(자율/심판/대조), 불일치는 산출물 최상단 배너.

---

## 7. 제어평면 = 결정론 FSM + LLM 2곳

- **FSM 상태:** `RECON → SELECT → EXECUTE → INFER → (goal? END : PIVOT) → SELECT …` (max_pivots 하드캡, 고위험 안전목표는 전 예산사유 면제 = M6).
- **LLM ① Planner:** `select`(target_node+방어상태+**goal(expect_mode·mavcmd) 주입**) / `pivot`(blocked_by→enabler ADAPT). 출력 = `Channel`(전송) + `Action`(intent) 분리 + **enabler 레지스트리(5) pydantic 검증**(무효값 폴백). 캐시키 = precond+goal.
- **LLM ② Evidence:** correlate(신호 종합) / narrate(BlockProof 서술).
- **LLM은 증강이지 load-bearing 아님** — 렌더 실패/장애 = 결정표 폴백 직행(빈 프롬프트 호출 금지). self.name 뮤테이션 금지.
- **Recon 1급 단계:** 캠페인 전에 signing 등 방어상태 선제 확보(discover 도구 = 파서/결과모델/node_cmd **완전 등록**, 유령 금지 = B6 해소).

---

## 8. 안전 (비행상태 종속 — 방산 1순위)

- `_is_safe`/`_safe_undo` **비행상태 분기**: 지상=disarmed / 비행=자율모드 복귀 + LOITER/RTL + EKF healthy. **비행 중 STABILIZE/disarm 금지**(추락).
- undo = "직전 자율모드 재명령" or LOITER. **force-land = (위치known ∧ 착륙영역clear ∧ 통제강하) ∧ RTL불가일 때만 최후수단(HITL 인간승인)**. 1차 failsafe = RTL.
- `record_intent`(ledger)를 **guard 밖** — 항상 기록(recover_on_boot 보장). `recover_on_boot(all_runs)` 이전 run 스캔.
- **Watchdog** 독립 데몬 스레드(캠페인 중 기동, finally stop). HITL 이원게이트(고위험=인간승인 / 긴급복구=화이트리스트 즉시).

---

## 9. 공격 노드 카탈로그 · enabler(5) · ADAPT

**노드(실측 판정, MASTER_SUMMARY):** naive(차단 baseline) · TM1/V2 oracle(성립) · forceland(HITL) · V1 리플레이(성립) · V3 peer(조건부) · V4 키노출(성립) · V5 nonce(잠재) · TM2(완화) · TM3(ARIA무력) · **NF-3 가입자DB·NF-4 웹서명우회·NF-6 서명키**(실측).

**enabler 레지스트리(코드강제 5):** `naive`(차단) · `oracle`(14556 평문) · `webcmd`(NF-4 서명우회) · `forge`(NF-6 위조봉투) · `forceland`(강제착륙·HITL). — pydantic validator로 무효값 reject.

**ADAPT:** 방어가 벡터 차단(3실패/페로몬 or blocked_by=signing) → 사전 미정의 대체 벡터 자율 전환(oracle→webcmd→forge). `blocked_by`(signing/auth/no_effect)는 **파싱응답에서 도출**(이름 하드코딩 금지 = F5). ADAPT가 LLM 값어치의 핵심.

**win_cause:** `crypto-break`(미발생) / `key-leak`(V4·NF-6) / `config-flaw`(TM1·NF-3·NF-4).

**수행(perform)/보조(assist):** 수행=rogue UE 단독(oracle/forceland/V1/V4/webcmd/forge). 보조=foothold 필요(NF-3·TM2·V3).

---

## 10. 간판 혁신 — Differential BlockProof

naive(무키·차단) ↔ enabler(성립) **연속 실행 차분** → "알고리즘은 막고 설계 결함만 뚫림"을 **공격 측 단독** 증명(심판 불필요). 각 공격에 verdict(성립/조건부/방어) + blocked_by + defense_snapshot(signing ON/OFF 등) 바인딩.

---

## 11. 산출물 → 예선보고서 6장(AI 25점)

`python demo.py` → 정적 export 3+1종:
- **timeline.html** — FSM 진행·신호·판정 타임라인(3층 병기, redact).
- **blockproof.md** — Differential 차분 표(naive↔enabler, win_cause).
- **reward.json** — 공격자 신호 기반 reward(§6).
- **evaluation.json** — 심판 기반 별도(autonomy_accuracy) — 있을 때만.
- **최상단 배너:** agent≠truth 불일치 노출 + "배포 시 심판 없이 자율 신호만으로 동작" 명시.

---

## 12. 코드 구조 (core/private 분리)

```
attack_agent/
  core/
    common/   types(Channel/Action)·config·llm(replay/live)·prompts·workdb
    modules/  backends/{base,mock,local}·parsers·tools·guardrail·safety·budget·locks
    obs/      daemon(host-side 관측·14555 tap·5762 pool=1)·signals   # ★신규 1급
    agents/   planner·evidence
    orchestrator.py    # 결정론 FSM (관측 동기호출 0·truth 미접근)
  prompts/default.yaml   configs/models.yaml
  viewer/   export·server   demo.py   tests/(+통합)   fixtures_public/
  private/  ssh·키·targets·fixtures_real   config/demo.env(RFC5737 중립)
```
**살림(재사용):** FSM+LLM2곳 · 이원판정 개념 · 비행상태 안전 · 정직성 서사 · BlockProof · enabler 레지스트리 · redact/core-private. **버림:** §4.1 안티패턴 전부.

---

## 13. ★게이트 1 — 통합테스트 계획 (누수 0 = 첫 통과 기준)

캠페인 실측 **전** 반드시 통과:
1. **관측 데몬 수명:** 데몬 기동→N회 관측→종료 시 **잔존 프로세스·컨테이너·소켓 0** (`docker ps` diff = 0, 5762 연결 free).
2. **타임아웃 실효:** 느린/무응답 백엔드 모사 → 하드 타임아웃에 **확실히 종료·회수**(hang 없음).
3. **심판 non-load-bearing:** observe 무한블록 모사 → **캠페인 완주 + inconclusive**(흐름 미차단).
4. **truth 격리:** 에이전트 흐름 코드가 truth 미접근(grep 0).
5. **보수판정:** 모니터 미배선 시 effected 0(허위성공 0).
- 실측은 **AMI 스냅샷·상태캡처 전제**, 파괴적 조작은 대상 정확 지정(넓은 grep kill 금지).

---

## 14. 미결 결정 (사용자 확인 후 확정)

| # | 결정 | 기본안(잠정) |
|---|------|--------------|
| Q1 | 산출물 형태(HTML 시각 설계도 / DESIGN.md / 둘 다) | 이 DESIGN.md 먼저 → HTML 후속 |
| Q2 | 관측 데몬 배치(host-side vs 사이드카 exec) | **host-side 데몬**(회고 §4-A 1순위) |
| Q3 | effected 심판 대조를 본선 데모에 켤지 | 기본 off, 테스트베드 튜닝 시만 |
| Q4 | agent_v1 코드 재사용 범위(포팅 vs 신규) | modules/safety·enabler·export 포팅, obs/·backend계약 신규 |
| Q5 | `~/agent_deploy` 소실 → 재배포 경로 | C2 복구 후 재배포 스크립트 신설 |

---

*이 문서는 재설계의 단일 진실이다. 실행/관측(§4)·effected(§5)를 확정한 뒤에만 코드에 착수한다(게이트 0). 캠페인 실측은 게이트 1(누수 0) 통과 후.*
