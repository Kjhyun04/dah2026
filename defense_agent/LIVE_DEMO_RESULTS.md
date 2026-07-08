# 라이브 시연 결과 (S1 + Phase 6 + S2 + 다중 트래픽 재검증)

> 서버 `43.203.160.4`(ubuntu, teammate-key) · commit `35e247b` · `MDG_ALLOW_LIVE=1 MDG_OPERATOR_AUTO=1`(자율집행).
> 코드는 다단계 워크플로 + AI개발자·UAV·4G 3전문가 검증으로 구현. 지상검증: pytest 254(로컬)/255(서버) passed, verify 게이트 전부 PASS, 캠페인 live_executions=0.

## S1 — 컨테이너 격리 복구 ✅ (완전 시연)
5762 LAND 주입 → 탐지 → `docker_pause`(backdoor_pause) **operator_auto 자동승인 집행** → `web_backend` 실제 Paused.
- ledger: `authority=sandbox-auto · operator_auto_confirmed=true · operator_gate=false · provenance_relaxed=true · revert_cmd="docker unpause web_backend"`
- effect_confirm: **confirmed=true**
- 뷰어 복구 타임라인: `tier="OPER→AUTO(sandbox)" · enforced=true · confirmed=true · steps=[탐지✓ 대응✓ 집행✓(auto) 확인✓]`
- 시연 후 unpause 복원.

## Phase 6 — 업링크 서명 관측 ✅ (완성)
- uav_proxy 서명강제는 실제 활성: 미서명 MAVLink(ARIA암호화) 주입 → `[proxy] ⛔ 서명검증 실패 → SITL 차단 (누적 N)` 드롭로그 생성.
- **신규 SignLogCollector가 그 드롭로그를 관측** → `sense.py` MONOTONIC 래치 → **`world.signing: unknown → confirmed_on`** (라이브 run.jsonl에서 `signing:"confirmed_on"` 52틱 확인).
- fail-safe: 드롭 무관측 시 unknown 유지, 배너만으로는 승격 안 함. `Signing_Drop` metric은 신뢰도 0 기여(차단=방어성공).

## S2 — 비행 서명복구 ⚠️ (경로 완전 개방 · 안전보수적 미선택)
- signing=CONFIRMED_ON + role_verified.gcs_proxy=true → **`send_signed_mode`(command_override·signed_guided)가 legal_actions에 진입**(직접 진단 확인). 즉 비행복구 경로는 **완전히 봉쇄 해제**됨.
- 그러나 rank_recovery가 `docker_pause`(MED·가역·succ 0.95)를 `send_signed_mode`(HIGH·비가역·succ 0.90, 위험가중 0.6)보다 우선 선택 → **비가역 비행명령을 자동발사하지 않고 가역 격리를 선호**.
- **해석**: 이는 결함이 아니라 **안전보수적 설계** — 완전 자율(operator_auto=1)에서도 AI가 HIGH·비가역 비행명령을 자동 난사하지 않는다. 드론 30m 물리 복귀를 자동 시연하려면 (a) 신호복구만 후보인 시나리오이거나 (b) 비행-하이재킹 시 서명복구를 선호하도록 priors 조정(운영/설계 결정)이 필요. 임의 변경하지 않고 플래그로 남김.

## 다중 트래픽 재검증 ✅ (전체 방어전략)
결정론 캠페인 6 시나리오(자율 플래그):
| 시나리오 | 탐지 | 밴드 | 대응 | live |
|---|---|---|---|---|
| A1 command_hijack_cr01 | ✓ | Red | backdoor_pause/OPER | 0 |
| A2 pfcp_teardown | ✓(verified) | Red | backdoor_pause/OPER | 0 |
| A3 unauth_command | ✓ | Yellow | backdoor_pause/OPER | 0 |
| A4 5762_backdoor | ✓ | Yellow | backdoor_drop/AUTO(inert_dry) | 0 |
| A5 mongo_dbaccess | ✓ | Green | none | 0 |
| A6 telemetry_silence | ✓(verified) | Yellow | none (agent≠truth=2) | 0 |
→ **6/6 탐지, 4 대응, live_executions=0**(오프라인 증거 무손상).

라이브 모니터 관측(이번 세션 주입): `signing: confirmed_on(52)/unknown(20)`, 시그니처 `Unauthorized_Command(1585)·Port_5762_State(44)`, 대응 `backdoor_pause(71)`.

## 종합 판정
- 탐지·상관·영향·정책·복구(S1)·상시취약 분류·서명 관측(Phase6)·서명복구 legality(S2) — **모두 정상 동작**.
- S2 물리 비행복귀만 안전보수적 랭킹으로 자동 미발사(설계상 옳음, 근본 개방 완료).
- 불변식①(결정론)·②(leak-0)·KEY-FREE(verify_signer_no_keyopen)·오프라인 live_executions=0 전부 보존.
