# DAH 2026 MDG 방어 에이전트 — 빌드 종합 보고서 (BUILD_REPORT)

- 프로젝트: DAH 2026 방어 AI 에이전트(MDG) — 인가된 격리 샌드박스 보안평가
- 작성일: 2026-07-07
- 구현 루트: `C:/Users/user/Desktop/dah/dah_defense/mdg/`
- 스택: pydantic v2 · LangGraph · litellm · grpcio · FastAPI · pytest (Python 3.12)
- 정본 계약: `mdg/DESIGN_DECISIONS.md`(락) 우선, `docs/FRAMEWORK_STACK.md` · `docs/DEFENSE_AGENT_DEV_WORKFLOW.html`(P0~P6) · `docs/IMPLEMENTATION_GAPS_20260707.md`(§P 라이브 실측)

## 2대 불변식 (전 Phase 위반 0 확인)
- **① 결정론 제어흐름**: 조건부 엣지는 `impact.band` · `spec.risk` 수치/불린으로만 분기. LLM은 orient/decide 2노드·temp0·조언(경계 상향만·엣지 미참여). `verify_routing` PASS로 전 Phase 재확인.
- **② 누수-0 실행**: 모든 도구 부작용은 `safe_exec/backend.py`의 `Backend.run` 단일 subprocess 경로 경유. 노드의 직접 subprocess 0. grep0 Verifier는 별 프로세스(코어 import 0).

## 운영 제약 (전 Phase 준수)
testbed(<TESTBED-IP>) 상태변경 자동실행 **0**. 라이브 상태변경(nsenter DROP·docker pause·서명명령 발행·컨테이너 stop·설정수정)은 코드+하네스+DRY/read-only 검증까지만, 실집행은 **operator-go 유보**. `Backend(allow_live=False)` 기본값으로 구조적으로 강제(DRY-RUN). read-only SSH 관측도 불요분은 미실행.

---

## Phase별 결과

### P0 — 형식코어 + LangGraph 스캐폴드 — 통과 ✅
**산출 파일(대표)**: `core/state.py`(MDGState TypedDict, operator.add 3채널 리듀서, `to_record()` allow-field projection), `core/worldstate.py`(닫힌술어 pydantic 모델), `core/scoring.py`(E5~E8·E19 수식), `core/edges.py`(2개 결정론 조건부엣지), `core/advice.py`(tighten_only), `core/graph.py`(build_graph 11노드·recursion_limit=16), `core/nodes/*`(sense·correlate·compute_trust·compute_impact·orient·select_policy·rank_recovery·decide·act·effect_confirm·escalate), `tools/registry.py`(26 tool Literal 화이트리스트), `tools/defresult.py`, `safe_exec/backend.py`, `collector/ingest.py`, `ledger/intent_ledger.py`, `config/*.yaml`(5종), `verify/*`(6종), `tests/test_math.py`. (전체 목록: 첨부 빌드데이터 P0)

**검증**: self-verify 전부 PASS — verify_tools 178 · verify_graph 13 · verify_routing 12 · verify_grep0 278 · verify_keys 173 · verify_no_fw_subproc 94, test_math 15/15, compileall clean. 파이프라인/act/escalate 라우팅·redact·seq-watermark·ingest-HMAC 통합검증 통과.

**잔여 findings**:
- (low) `collector/ingest.py` — X1 canonical MAC input이 `SensorEnvelope.kid`를 미포함. kid는 자기인증(변조 시 잘못된 키로 재계산→HMAC 불일치→reject)이라 착취 불가. 명시성/심층방어 위해 `_canonical`에 kid 바인딩 권고.
- (info) `verify/verify_no_fw_subproc.py` — AST 검사가 `from os import system` 재바인딩 회피는 미포착. 실제 위반 없음(grep 확인). 정적 사각 하드닝 선택.
- (info) `verify/verify_routing.py` — 문자열 연결/비-`route_` 헬퍼로 조립된 금지키는 회피 가능. 실제 위반 없음. 선택적 하드닝.

### P1 — 실행/관측 엔진 + 누수-0 — 통과 ✅ (신규 파일 없음, 전량 Read·실측 검증)
락된 계약대로 이미 완전 구현되어 있어 재작성 없이 동작 검증. 표준 레이아웃 매핑:
- `safe_exec/backend.py` — Backend.run 유일 subprocess 경로(mock/local, allow_live 기본 False→DRY). PrioritySemaphore(1), nsenter pool=1.
- `safe_exec/safeexec.py` — R1 하드타임아웃 · R2 setsid 프로세스그룹 · R3 라벨 `dah_def` · R4 컨테이너-스코프 reap · R5 secret stdin · R6 멱등 teardown.
- `collector/`(5종) — AirCommandTap(gcs_proxy:14556)·AirTelemetryTap(uav_ue lo:14550 교차 D-1)·NetworkMetricCollector(:9090 양수카운터 diff, 음수게이지 회피 P4-3)·MongoLogCollector(docker logs id22943)·MissionConfigCollector. 전부 그래프 밖 데몬 스레드, bounded queue DoS캡. (SmfSessionCollector·SignLogCollector는 P2/P3에서 추가 배선.)
- `ingest/server.py` — gRPC :50051 mTLS·loopback 강제(PS-8)·max 256KiB. `ingest/verify.py` — 드레인 시점 HMAC→seq(HWM)→ts skew 순 검증.
- `ledger/intent_ledger.py` — record_intent JSONL append+fsync(부작용 前·guard 밖), SeqWatermark(HWM+seen-bitmap fsync), boot_recover.
- `watchdog.py` — G7 독립 스레드, collector heartbeat 감시→서명 sensor_loss 봉투 인큐.

**잔여 findings**:
- (low) `verify/verify_no_fw_subproc.py` — 스캔 루트가 core/*만 커버. collector/·watchdog·ingest/·ledger/·tools/·targets/ 미스캔(현재 clean, grep 확인). 스캔 루트 확장 권고.
- (low) `verify/verify_no_fw_subproc.py` — docstring이 "subprocess import는 backend.py만"이라 하나 safeexec.py도 import(teardown TCB, spawn 없음). docstring 정정 권고.
- (low) `ingest/verify.py` — verify_envelope가 seq를 먼저 소비 후 ts skew 체크. fail-closed 방향·착취 불가(HMAC 선게이트). retransmit-after-skew 운영요구 시 순서 조정.

### P2 — 정찰/타깃 해석 — 통과 ✅ (잔여 0)
**산출 파일**: `targets/resolve.py`(role→container→IP 2단계 verify: inspect Pid/IP → tun_srsue nsenter 스캔, docker exec→nsenter 전송교체 P2-Q1), `targets/inputspec.py`(하드코딩 IP 0, config 소스), `targets/behavioral.py`, `core/recon.py`(recon_boot: signing=UNKNOWN 3치 P2-Q2, 닫힌 reach 어휘 시드, RTT baseline, PS-6 HWM+ledger recover), `collector/smf_session.py`(IMSI↔동적tun-IP 양방향, ANSI-strip, stale evict, P4-4 조인), `config/defaults.py`, `tests/test_p2_recon.py`.

비-allow_live Backend는 DRY-RUN→tun IP 미해석·fail-closed inert. 라이브 tun-scan 실집행 operator-go 유보. **잔여 findings 없음.**

### P3 — 분석 + phase-LLM — 통과 ✅ (신규 파일 없음, 전량 검증)
계약 경로 전부 동작 코드로 이미 존재. DESIGN_DECISIONS 835줄 대조·2불변식 검증·테스트 통과.
- `core/evidence.py`(band→sev/dev scoring 위임, TTL freshness PP-3), `core/nodes/correlate.py`(E19 time-window, IMSI 조인은 out-of-graph SmfSessionCollector가 evidence로 방출—그래프 노드 경계), `core/nodes/compute_trust.py`(E5/E6/E7, tamper/unverified 제외 PS-2), `core/nodes/compute_impact.py`(PP-3 present-set max, Green/Yellow/Red, all-stale hold), `llm/orient.py`+`core/nodes/orient.py`(temp0, OrientNote severity_bump Literal[0,1] raise-only, PS-7 derived-only, G6 fallback), `core/nodes/select_policy.py`, `core/nodes/rank_recovery.py`(PP-1 success_probability≥feasible_min, 결정론 sort key), `core/nodes/decide.py`(DecideNote advice-only, chosen_action 미설정), `llm/decide.py`, `llm/prompts/*.jinja`(StrictUndefined), `llm/apply_advice.py`(단일 tighten_only 재수출), `config/models.yaml`.
- LLM은 Yellow/Red만(Green→END). edges는 LLM 노트필드 미참조. client.py: num_retries=0, temp=0(샘플링 계열만), model_validate_json extra='forbid'.

**잔여 findings** (전부 info — 도메인 sign-off 항목, 코드변경 불요):
- `config/models.yaml` — 모델ID 현행성(opus-4-8/sonnet-4-5/haiku-4-5 미폐기) 정적 결정 불가. operator-go LLM 실행 전 라이브 resolve 확인.
- `core/nodes/rank_recovery.py` — 캘리브레이션 상수(success_prob_feasible_min=0.70, priors) 도메인 sign-off. 결정론/배선은 정상.
- `llm/client.py` — 라이브 LLM temp0/fallback 미실증(litellm 로컬 부재). 오프라인은 G6 결정론 폴백으로 보존. GATE-live operator-go 유보.

### P4 — 대응/집행 + 안전 계층 — 통과 ✅ (신규 파일 없음, 전량 검증)
- `safe_exec/response.py`(ResponseController: bundle 규율→2-tier gate→AUTO nsenter DROP, P4-2 두-엔드포인트 pid⟂src_ip 순수조회, 미검증→fail-closed inert DRY), `safe_exec/act_host.py`(nsenter iptables DROP argv 빌더, OPER은 sock-proxy backend 경유), `safe_exec/signer_shim.py`(command_digest 스코핑, OperatorGate key-free issue-only·nonce durable), `core/gate.py`(2-tier: AUTO는 registry AUTO∧risk∈{LOW,MED}∧reversible만), `core/bundle.py`(risk=max/reversible=all, 멱등·debounce·deescalation 순수술어), `ledger/operator_ledger.py`(secret-free receipt+소비-nonce durable).
- subprocess import 0, 엣지 target/enforce_at 미참조, 라이브 상태변경 전부 DRY operator-go 유보.

**잔여 findings**:
- (medium) `core/graph.py:64`(+escalate.py:29, act.py:71) — 런타임 그래프가 OperatorGate 미주입. 런타임 operator-gate Intent는 command_digest만·nonce=""·expiry=0. nonce/TTL 락아웃은 구현·유닛테스트되나 컴파일 그래프가 미실행(operator/verifier 도메인에 암묵 위임). build_graph deps에 optional gate 훅 배선 또는 명시 계약/테스트 추가 권고.
- (low) `core/nodes/act.py:75` — act OPER-tier가 gate 훅 없이 digest-only(escalate와 비대칭). 실집행 아님(operator-go). 배선 또는 문서화 권고.
- (low) `core/bundle.py:106` — deescalation_due가 flight를 rule-name 접두사 휴리스틱으로 분류(registry effect 대신). 현재 dead-defensive이나 취약. `REGISTRY[tool].effect=='flight_mode_set'` 사용 권고.
- (info) `verify/verify_d11_collector_disjoint.py:46` — netns DROP source(UE풀 10.45.0.0/16) disjoint 증명이 loopback만 대상. :50051이 mgmt-bridge 바인드 시 미커버. config에서 실 bind CIDR pin 권고.
- (info) `core/nodes/escalate.py:35` — 기록 Intent가 target/enforce_at 미복사(digest는 암호학적 바인딩). 감사 UX 갭, 보안영향 0. operator 가시성 위해 복사 권고.

### P5 — 리플레이 + 독립검증 + Viewer — 통과 ✅
**산출 파일**: `replay/record.py`(canonical node-I/O JSONL, redact 단일계약 재사용, sort_keys+compact→byte-identical, virtual-clock 주입), `replay/play.py`(오프라인 재실행 0, tick=sense 경계 PA-1, 신·구 스키마 tolerant), `verifier/verifier.py`(그래프 밖 독립 신뢰루트, mdg.core.* import 0, cross-root link health·telemetry-silence·agent≠truth 발산 산출→truth.jsonl), `viewer/app.py`(FastAPI 3-panel 동작/통신/검증, record-time redact only+load-time secret scan fail-closed, GET-only·bearer auth·loopback 강제), `tests/test_p5_replay_viewer.py`.

**GATE2 4속성 GREEN**: (1) 리플레이 결정론(byte-identical, PYTHONHASHSEED 0 vs 1, secret-canary 0), (2) cross-root 로직(both up→HEALTHY, disagree→INCONSISTENT, single→None), (3) Verifier 비-게이팅(gate는 registry tier+risk+reversible만, verifier 미참조), (4) Viewer redact(record-time only, fail-closed SecretLeakError, loopback bind).

**잔여 findings**:
- (info/accepted) `verifier/verifier.py` — P5-Q3: `gcs_proxy_alive`는 coarse presence 확인(음수/침묵 탐지기 없음). gcs_proxy 컨테이너 존재 유지하며 명령평면 위조하는 MITM은 단독으로 CROSS_ROOT_INCONSISTENT 미유발. anti-spoof는 텔레메트리 루트의 드론측 lo:14550 교차탭에 의존. 문서화된 수용 한계(P5 리그레션 아님).

### P6 — E2E 하네스 + 정직성 + 보고서 — 통과 ✅
**산출 파일**: `campaign/e2e.py`(5 실증공격 재생→탐지→대응→검증, langgraph-free `_TickExecutor`가 실 11노드+edges 재사용·production과 byte-identical run.jsonl, PS-2 ingest 실통과, 실집행 DRY), `campaign/honest.py`(5 disclosed limitation+banner), `campaign/artifacts.py`(AttackOutcome/CampaignResult→6장 보고서), `campaign/RUNBOOK.md`(라이브 실집행 절차·가역/복원표·롤백), `tests/test_p6_campaign.py`.

**5공격 결과**: A1 명령하이재킹(command floor71 Red), A2 PFCP storm(session floor71 Red, verified B-1), A3 무인증명령 반복(Yellow), A5 mongo(under-weighted→Green, dilution 실증), A6 telemetry silence(Yellow via E8 bump, verified D-1, agent≠truth 2발산).

**불변식**: 라우팅 수치/불린만(①), Backend.run 단일경로·노드 spawn 0·Verifier 별프로세스(②), live_executions=0 하드가드.

**잔여 findings**:
- (low) `tests/test_graph_parity.py` — 컴파일 그래프(langgraph) vs langgraph-free _TickExecutor 패리티가 로컬 skip(langgraph 미설치 D-2). 런타임 패리티는 단일 `core.topology`(ENTRY/LINEAR_EDGES/COND_EDGES+BIND) 공유로 구조 보장. operator-go 환경에서 실행하여 잔여 폐쇄 권고.

---

## 게이트 상태

| 게이트 | 정의 | 상태 | 근거 |
|--------|------|------|------|
| **GATE0** | 형식코어·불변식·정적검증 | ✅ PASS | verify 6종+test_math 전부 PASS, compileall clean. 2불변식 정적 재확인(verify_routing/grep0). |
| **GATE1** | 누수-0 실집행 실측 | ⏸ 코드·DRY 검증 완료 / 라이브 실측 **operator-go 유보** | Backend allow_live=False 구조 강제. secret-canary=0(리플레이·run 레벨). 라이브 nsenter/pause/서명 미실행. |
| **GATE2** | 효력(탐지·대응·독립검증) | ✅ 오프라인 GREEN / 라이브 효력 실측 유보 | P5 4속성 GREEN, P6 5공격 재생 탐지·대응·독립검증·정직성 통과. 실 testbed 집행은 operator-go. |

## 다음 실행 절차 — 라이브 캠페인 operator-go 조건
1. **환경 패리티**: operator-go 환경에 langgraph·litellm 설치, `test_graph_parity`(P6 잔여) 실행하여 컴파일 그래프 = _TickExecutor 패리티 폐쇄.
2. **LLM 라이브 sign-off**(P3 info): opus-4-8/sonnet-4-5/haiku-4-5 3개 ID를 api.anthropic.com에 라이브 resolve 확인, temp0/fallback-chain 실증.
3. **캘리브레이션 sign-off**(P3 info): thresholds.yaml/recovery_priors(success_prob_feasible_min=0.70 등) 도메인 확정.
4. **OperatorGate 배선**(P4 medium): build_graph에 gate 훅 주입 또는 "런타임 intents는 digest-only, nonce/TTL은 operator 도메인 소유" 명시 계약/테스트 추가.
5. **GATE1 라이브 실측**: `Backend(allow_live=True)` 승격은 operator 승인 하에서만. RUNBOOK.md 집행순서(PA-6: legality→record_intent→tool_wrap) 준수, 가역/복원표 확보, 중단롤백 경로 확인.
6. **read-only 관측 검증**: `ssh -i <KEY>.pem ${TESTBED} "<read-only>"`로 §P 실측값(gcs_proxy:14556, 14560/lo:14550, PFCP s5c_rx_deletesession, 서명드롭로그) 라이브 재확인 후 실집행 승인.

## 정직 한계
- **라이브 실집행 0**: 전 Phase는 코드+하네스+DRY/mock/read-only까지. nsenter DROP·docker pause·서명명령 등 상태변경은 실제 testbed에서 미실행(operator-go 유보). GATE1/2의 라이브 실측은 미검증.
- **LLM 라이브 미실증**: litellm 로컬 부재로 실 엔드포인트 temp0/fallback 미실행. 오프라인은 G6 결정론 폴백으로 정합 유지되나, 라이브 모델 응답 결정론은 sign-off 필요.
- **langgraph 미설치(D-2)**: 컴파일 그래프 런타임 패리티 로컬 미실행. topology 단일소스로 구조 보장만.
- **탐지 사각(P6 disclosed)**: V4 탐지불가, mission-weighted dilution(A5 mongo→Green 희석 실증), 5공격 중 3공격 미검증(독립 verified는 A2/A6), blast-radius self-DoS 가능성.
- **anti-spoof 한계(P5-Q3)**: gcs_proxy presence-only 확인. 컨테이너 유지형 MITM 단독 미탐, 텔레 교차탭 의존.
- **캘리브레이션 미확정**: 회복 priors/임계값은 도메인 sign-off 대기(결정론·배선은 정상).

## 총평
P0~P6 전 Phase가 락된 `DESIGN_DECISIONS.md` 계약대로 동작 코드(스텁 0)로 구현·검증되었으며, 2대 불변식(결정론 제어흐름·누수-0 실행)과 testbed 상태변경 자동실행 금지 운영제약을 위반 없이 준수한다 — GATE0는 정적·오프라인 전 항목 GREEN이고, P5/P6의 리플레이 결정론·독립검증·5공격 재생까지 오프라인 효력이 실증되었다. 다만 프로젝트의 본질적 정직 한계는 명확하다: 모든 라이브 상태변경과 LLM 실호출이 설계상 `allow_live=False`/도구 부재로 봉인되어 있어 GATE1(누수-0 실측)과 GATE2(라이브 효력)는 코드·DRY 수준까지만 확정되고 실 testbed 집행은 전적으로 operator-go에 유보된다. 따라서 현 산출물은 "실집행 직전까지 검증 완료된, 감사가능·되돌이가능한 방어 파이프라인"으로 요약되며, 남은 것은 새 코드가 아니라 operator 승인 하의 환경 패리티(langgraph/litellm)·모델/캘리브레이션 sign-off·라이브 실측 6단계 절차의 순차 집행이다.
