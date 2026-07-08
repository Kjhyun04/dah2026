# 자율 복구 시각화 구현계획 (Recovery Demo Plan)

> 목표: 감독관이 `MDG_ALLOW_LIVE=1 MDG_OPERATOR_AUTO=1`(기본값) 상태로 실행하면
> **공격 → 탐지 → 대응선택 → 집행 → 효과확인 → 회복** 전 과정을 재현·관람할 수 있게 한다.
> 두 시나리오: (S1) 컨테이너 격리 복구(docker_pause), (S2) 비행 30m 복귀(send_signed_mode).

---

## 0. 현재 코드가 복구를 "안 보여주는" 4대 차단 지점 (근거)

| # | 위치 | 현재 동작 | 결과 |
|---|------|-----------|------|
| B1 | `core/gate.py::gate_for` | OPER 티어 → escalate(미집행), AUTO만 자동 | OPER 복구 미집행 |
| B2 | `core/nodes/rank_recovery.py` | `backdoor_pause`(succ 0.95) > `backdoor_drop`(0.85) → OPER 선택 | AUTO 드롭도 미선택 |
| B3 | `rank_recovery` 주석 L6-7 | provenance/debounce 게이트가 **주입 고심각의 자동대응 차단**(PS-7) | 주입공격 자동대응 억제 |
| B4 | `core/legality.py::_predicate_holds('signing')` | `send_signed_mode`는 `signing=CONFIRMED_ON`일 때만 legal | 비행복구 봉쇄(signing=unknown) |
| B5 | `core/nodes/effect_confirm.py` | `observe=None` → 항상 `confirmed=False` | 복구완료 신호 없음 |
| B6 | `viewer/app.py` | 복구 타임라인 없음(틱별 결정만) | 시각화 부재 |

> 원칙: **불변식①(결정론 라우팅)·②(leak-0)는 유지**. operator 게이트만 샌드박스 플래그로 자율화하며,
> 모든 집행은 **가역(reversible)·원장(ledger) 기록·revert_cmd 보유**. 실기체 아님(SITL 전용).

---

## Phase 0 — 기본값 무조건 1 (자율 집행 on)

**목적**: 감독관이 별도 설정 없이 실행해도 자율 복구가 돌도록.

**위치 / 구현**
- `.env.example`, 서버 `.env`:
  ```ini
  MDG_ALLOW_LIVE=1        # AUTO 티어 실집행 창 개방
  MDG_OPERATOR_AUTO=1     # OPER 티어 샌드박스 자동승인(신규)
  ```
- `mdg/live_autorun.py`: `parse_allow_live()` 옆에 `parse_operator_auto(env)` 추가(동일 truthy 파서).
  `run()`이 `operator_auto` 를 build_graph deps 로 전달.
- `mdg/dah.sh`: `monitor)`/`autorun)`에서 `MDG_OPERATOR_AUTO` 를 `_load_env` 로 로드(이미 .env 소싱).
- `mdg/core/graph.py::build_graph(deps)`: `deps["operator_auto"]` 를 gate/edge 로 주입.

**검증**: `parse_operator_auto({"MDG_OPERATOR_AUTO":"1"}) is True`; 기본 미설정 시 False(안전).

**주의**: 이 변경은 "안전 기본=DRY" 포스처를 바꾼다. `verify_routing`·invariant 테스트가
DRY 기본을 가정하면 **샌드박스 플래그 분기**를 반영하도록 갱신(Phase 7).

---

## Phase 1 — 운영자 자동승인 (OPER 집행 경로) — B1 해소

**목적**: OPER 대응(docker_pause / send_signed_mode)을 escalate 대기가 아니라 **자동 승인 후 집행**.

**위치 / 구현**
1. `mdg/core/gate.py`
   - `gate_for(tool_id, risk, reversible, operator_auto=False)` 시그니처 확장.
   - OPER 판정 지점에서 `operator_auto=True`면 `GateDecision(..., auto=True, tier2="AUTO_BY_OPERATOR", reason="sandbox operator auto-confirm")` 반환.
   - **단, flight/irreversible도 승인**하되 `flight`/`registry_tier` 필드는 그대로 실어 라우팅·원장이 "원래 OPER였음"을 알 수 있게(투명성).
2. `mdg/core/edges.py` (gate → act vs escalate 분기)
   - `operator_required` 판정에 `operator_auto` 반영: `auto or operator_auto` → **act 로 라우팅**.
   - `operator_auto`로 통과한 경우 `state["operator_auto_confirmed"]=True` 마킹.
3. `mdg/core/nodes/act.py` (원장 기록)
   - ledger 항목에 `operator_gate=true`, `operator_auto_confirmed=true`, `authority="sandbox-auto"` 필드 추가 → 감독관이 "자동승인으로 집행됨"을 구분.
   - `operator_confirm` 도구(레지스트리 control)를 합성 호출로 기록(감사 추적).
4. `mdg/core/nodes/decide.py` / DecideNote: `escalate_recommended`는 유지(조언), 실제 라우팅만 operator_auto가 좌우(불변식① — LLM 불가시).

**검증**: operator_auto=1일 때 OPER 액션이 act로 라우팅되어 `enforcement` 기록 + 실제 backend 호출.
operator_auto=0이면 기존대로 escalate(회귀 없음).

---

## Phase 2 — provenance/debounce 게이트 완화 (데모 모드) — B3 해소

**목적**: 주입 공격이 자동대응을 트리거하도록(현재 PS-7 게이트가 억제).

**위치 / 구현**
- `mdg/core/nodes/rank_recovery.py` (주석 L6-7의 provenance/debounce 로직 위치 확인)
  - `MDG_OPERATOR_AUTO`(=데모) 하에서는 provenance 게이트를 **"신뢰 소스 요구"에서 "기록 후 통과"로 완화**하되, 완화 사실을 ledger/trace에 명시(`provenance_relaxed=true`).
  - debounce(dry_streak/N-tick)는 유지하되 데모용으로 짧게(예 1틱) 설정 가능한 config 키(`demo_debounce_ticks`).
- `mdg/config/thresholds.yaml`: `demo_mode.provenance_relaxed`, `demo_mode.debounce_ticks` 추가.

**검증**: 주입 LAND 1건 → 다음 틱 이내 chosen_action 이 실제 대응 도구로 결속.

**주의**: provenance 완화는 **자가-DoS 위험**(공격자가 방어 자동대응을 유도). 데모 전용 플래그로만,
프로덕션 기본은 엄격 유지.

---

## Phase 3 — rank_recovery 선택 조정 (시각화 가능한 도구 선택) — B2 해소

**목적**: 시나리오별로 "보이는 복구"를 내는 도구가 선택되게.

**위치 / 구현**
- `mdg/config/recovery_priors.yaml`
  - **S1(격리)**: `backdoor_pause`(docker_pause) 유지 — 자동승인으로 집행되면 공격자 컨테이너 정지가 관측됨.
  - **S2(비행복구)**: `signing=enforced`(Phase 6) 후 `signed_guided` 가 legal 후보로 진입.
    복구 우선순위를 위해 `signed_guided.success_probability` 를 상향(예 0.92)하거나,
    사건 kind→rtype 매핑에 `command_hijack→signed_guided` 를 추가.
- `mdg/core/nodes/select_policy.py::_INCIDENT_RECOVERY`
  - 필요 시 `single-signal` → `["backdoor_pause","signed_guided"]` 로 확장(둘 다 후보 → rank가 선택).
- 대안: `rank_recovery._sort_key` 에 "가시적 복구 우선" 보정을 넣지 말고 **priors 값으로만** 조정
  (결정론·config-단일소스 유지, 코어 하드코딩-0).

**검증**: S1에서 chosen_action.tool_id == docker_pause; S2(서명 후)에서 send_signed_mode 선택.

---

## Phase 4 — effect_confirm observe 배선 (복구 "완료" 관측) — B5 해소

**목적**: 대응 집행 후 실제 효과를 관측해 `applied[rule].confirmed=true` → 복구완료 신호.

**위치 / 구현**
- 신규 `mdg/safe_exec/observer.py`: `make_effect_observer(docker, netns) -> (rule)->bool`
  - `backdoor_pause` → `docker inspect <enforce_at>`가 `Paused`인지
  - `backdoor_drop`(nsenter_input_drop) → 대상 netns에서 `ss` 로 공격자 5762 연결 소멸 확인
  - `signed_guided`/`signed_*` → 14560 텔레메트리 `rel_alt` 가 목표(30m ± tol) 회복 & `mode`가 LAND 아님
- `mdg/live_autorun.py`: `deps["observe"] = make_effect_observer(...)` 주입(현재 None).
- `mdg/core/nodes/effect_confirm.py`: 변경 최소(이미 `observe(rule)` 호출). 
  confirmed 시 `worldstate.applied[rule].confirmed=true` + delta note(before/after 값) 기록.

**검증**: docker_pause 집행 → 다음 effect_confirm 틱에서 confirmed=true; 미집행이면 false 유지.

**leak-0(②)**: observer는 read-only(inspect/ss/telemetry). 단일 Backend._spawn 규약 준수.

---

## Phase 5 — 비행상태 관측 (mode/altitude) — S2 필수 — B(신규)

**목적**: 30m→하강→복귀를 데이터로 관측(effect_confirm과 뷰어 그래프의 y축).

**위치 / 구현**
- 텔레메트리 콜렉터(14560 tap, `tap_telemetry_14560` / `col_web`):
  MAVLink `GLOBAL_POSITION_INT.relative_alt`, `HEARTBEAT.custom_mode` 를 SensorEv metric으로 방출
  (`metric="rel_alt"`, `metric="flight_mode"`). 이미 있으면 확인만, 없으면 추가.
- `mdg/viewer/app.py::_telemetry_rows` 가 rel_alt/flight_mode 를 통신패널에 싣도록(이미 generic).

**검증**: 라이브 run.jsonl에 `metric":"rel_alt"` / `"flight_mode"` 존재; LAND 주입 시 rel_alt 하강 관측.

---

## Phase 6 — (S2) 업링크 서명 강제 확정 (테스트베드) — B4 해소

**목적**: `signing=enforced` → `send_signed_mode` legal → 비행복구 가능 + 평시 노이즈 제거.

**위치 / 구현** (테스트베드측, 에이전트 코드 아님)
- `uav_proxy`(`mav_aria_proxy.py`)가 미서명 MAVLink 를 실제 드롭하고 **드롭로그를 남기도록** 확인.
  이미 `allow_unsigned_callback=lambda:False` + "서명검증 실패→차단" 로그 존재 → 실제 미서명 트래픽이
  proxy 경유하도록 경로 구성(현재 signing=unknown = 드롭로그 부재).
- `tail_signing_drops`(`col_uav`) 콜렉터가 그 드롭로그를 읽어 `world.signing=CONFIRMED_ON` 으로 관측.
- 검증: `legality.signing_enforced(world.signing)==True` → `send_signed_mode` 가 legal_actions에 진입.

**주의**: 5762 백도어는 proxy 우회 직결이라 **서명 강제로도 5762 LAND 자체는 못 막음**.
S2 복구는 "5762 트래픽 DROP(차단) → signed_guided 로 30m 재확립" 2단으로 시연.

---

## Phase 7 — 뷰어 "복구 타임라인" + 비행상태 시각화 — B6 해소

**목적**: 공격→대응→집행→확인→회복 lifecycle을 감독관이 한눈에.

**위치 / 구현** (`mdg/viewer/app.py`)
- `load_panels`: 신규 `recovery` 패널 산출 —
  ledger(rule/tool_id/revert_cmd/operator_auto_confirmed) + `applied[rule].confirmed` + view_band 전이를
  사건별로 묶어 lifecycle 단계 배열 생성:
  ```
  {incident, tool, tier, enforced(bool), confirmed(bool),
   band_before, band_after, alt_before, alt_after, steps:[탐지,대응,집행,확인,회복]}
  ```
- HTML: 좌측 상단에 "복구 진행" 카드(단계 체크리스트 + 색상), 우측 비행상태(고도 스파크라인: 30m→하강→복귀).
- 기존 view_band/상시패널과 공존(상시 취약점은 우측 상태, 복구는 좌측 타임라인).

**검증**: S1에서 카드가 [탐지✓ 대응✓ 집행(auto)✓ 확인✓ 회복(Green)✓]; S2에서 고도 그래프 30m 회복.

---

## Phase 8 — 테스트 · 검증 · 배포

- **단위테스트**(`mdg/tests/`):
  - `test_operator_auto_routing`: operator_auto=1 → OPER 액션 act 라우팅; =0 → escalate(회귀).
  - `test_effect_observer`: 각 rule의 observe True/False 경로.
  - `test_recovery_panel`: load_panels가 recovery lifecycle/flight state 노출.
  - `test_provenance_relaxed`: 데모 플래그 하 주입공격이 대응 트리거.
- **무결성 게이트**(`verify.py`): verify_routing/verify_leak0 가 새 라우팅·observer(read-only) 통과하도록 갱신.
- **라이브 재현**: `MDG_ALLOW_LIVE=1 MDG_OPERATOR_AUTO=1 dah.sh monitor` + land 주입 →
  뷰어 복구 타임라인·고도 그래프 확인. `dah.sh viewer` 로 관람.
- **배포**: commit/push → 서버 git pull → 재기동.

---

## 시나리오별 최소 구현 세트

| 시나리오 | 필요 Phase | 관람 결과 |
|---|---|---|
| **S1 컨테이너 격리 복구** (오늘 가능) | 0,1,2,3(priors 유지),4,7 | 탐지→docker_pause 자동집행→공격자 정지→trust 회복→Green |
| **S2 비행 30m 복귀** (완전) | S1 + 5,6 | 위 + 5762 DROP→signed_guided→고도 30m 회복 |

## 권장 순서
0 → 1 → 4 → 7 (여기까지 S1 관람 가능) → 2 → 3 → 5 → 6 (S2 완성) → 8.

## 리스크 / 불변식 영향
- **완전 자율 집행**(operator_auto=1 기본): 고위험/비가역 비행명령도 자동. **SITL 전용**·가역·원장기록 전제.
- provenance 완화: 자가-DoS 표면 확대 — 데모 플래그로만, 프로덕션 기본 엄격.
- 불변식①(결정론): operator_auto는 env 입력으로 결정론 유지(LLM 불가시). ②(leak-0): observer read-only.
- 기존 "안전 기본=DRY, OPER=사람" 서술 문서/테스트 동반 갱신 필요.
