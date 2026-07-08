# 방어 에이전트 개발 세션 로그 — 2026-07-07

> 대상: DAH 2026 방어 AI 에이전트(채점 ③ 아키텍처 25점, 보고서 마감 2026-07-10 23:59 KST).
> 목적: 이번 세션까지의 전 진행 상태·산출물·다음 착수점을 한 문서로 고정.

---

## 0. 한 줄 요약

**설계·검증·워크플로우는 100% 완료(정본 확정). 남은 것은 코드 구현(P0→P6) 뿐.**
직전 P0 빌드 워크플로우는 **서버 일시 레이트리밋**으로 24개 에이전트 전부 실패(0 완료) → 코드 미생성. 설계 결함 아님. 재실행 대기 상태.

---

## 1. 이번 세션까지 완료된 것 (설계·검증 단계)

| 단계 | 산출물 | 상태 |
|------|--------|------|
| 공격/testbed 분석 | (라이브 실측 포함) | ✅ 완료 |
| 방어 전략 인지(MDG) | mission_defense_*.html 6종 | ✅ 완료 |
| 실현가능성 감사(104요소) | `FEASIBILITY_AUDIT_20260706.md` | ✅ 완료 |
| 구현 설계 v2(도메인) | `DEFENSE_AGENT_PROTOTYPE_DESIGN.html` | ✅ 완료 |
| 오류검증 E1~E24 (라이브 확정) | `DEFENSE_AGENT_DESIGN_VERIFICATION_20260706.md` Part A-F | ✅ 완료 |
| 교차모델검증 X1~X13 (agy/codex) | 동 문서 | ✅ 완료 |
| 집행/누수 갭 G1~G11 | 동 문서 Part G | ✅ 완료 |
| 구축형식 갭 H-A~P | 동 문서 Part H | ✅ 완료 |
| v3 설계(구축형식+인프라) | `DEFENSE_AGENT_V3_DESIGN.html` | ✅ 완료 |
| 자기봉쇄 적대검증 D-1~D-12 | v3 §9 | ✅ 완료 |
| 프레임워크 확정 | **LangGraph** 오케스트레이션 + litellm + OSS 스택 (2026-07-07 개정, `FRAMEWORK_STACK.md`) | ✅ 완료 |
| 75항목 검증 매트릭스 | `DEFENSE_VERIFICATION_MATRIX_20260707.md` | ✅ 완료 |
| 프레임워크 시각화 | `DEFENSE_AGENT_FRAMEWORK_DIAGRAM.html` | ✅ 완료 |
| 개발 워크플로우 P0-P6 | `DEFENSE_AGENT_DEV_WORKFLOW.html` | ✅ 완료 |
| **P0 코드 구현** | `mdg/` (빈 디렉토리) | ⏸ **레이트리밋 실패, 재실행 대기** |

**검증 매트릭스 결론:** 75항목 → 9 확정 / 57 구현가능 / 9 선행수정 / 0 불가. **조건부 GO.**

---

## 2. 라이브 실측으로 확정된 핵심 사실 (설계의 근거)

- **명령 진입점** = `gcs_proxy plain-listen 14556`(상행). 14560 = 복호 **하행** 텔레메트리 팬아웃.
- **드론측 교차루트(D-1 확정)**: uav_* 4컨테이너 단일 netns 공유, `lo:14550`에 **평문 MAVLink v2**(magic 0xFD, incompat 0x00=UNSIGNED, sysid 0x01=autopilot/0xFF=GCS). ARIA 미경유 → 5762 없이 비행모드 지상진실 확보.
- **집행 근거(E3 ★정정)**: nsenter DROP은 **호스트 root 자신의 capability**로 동작(컨테이너 CAP_NET_ADMIN 아님) → caps=[]인 epc_mongo netns에도 집행 가능.
- **br_netfilter 미로드(E4)**: same-bridge inter-container는 호스트 iptables 미경유 → **netns-INPUT 집행만 유효**.
- **5762 백도어(G4 ★정정)**: tcp/5762 arducopter LISTEN backlog=5·활성 실무상 1. 방어가 여기 connect하면 슬롯점유+봉쇄 시 실명 → **제거하고 lo:14550 HEARTBEAT로 대체**.
- **서명**: gcs_c2가 `/sign.key`로 link_id=0 서명 발행 중. timestamp는 정규 MAVLink epoch(양호). → **operator-gate shim은 gcs_c2 netns에**(키 비확산).
- **프레임워크**: 서버 Python **3.12.3**(PEP695 동작), 로컬 3.14.0.

---

## 3. 개발 워크플로우 (P0→P6, 게이트 GATE0/1/2)

- **P0** 형식 코어(DefResult/tool_wrap/types/worldstate/legality/registry/config) + P3 결정론 엔진(evidence→correlation→trust→impact→policy→recovery→decision) → **GATE0**
- **P1** 집행/누수-0(그린필드 gRPC :50051 스택) → **GATE1**(누수-0 통과 전 라이브 캠페인 금지)
- **P2** 정찰/이식성 → **GATE2**
- **P3** LLM 분석부 / **P4** 대응·효력(GATE2 라이브 필요) / **P5** Verifier·replay / **P6** E2E·보고
- 각 페이즈 = **구현→검증→수정** 루프. GATE0 선행: 정본 개정 확인·verify_tools/keys/leak0 신규작성·H-A 예외규율(tool_wrap는 CRSError만 포획).

---

## 4. 직전 시도 상세 (P0 빌드 실패)

- 워크플로우 `mdg-p0-build`: Decide(DEC-1~5, 페르소나 3×+통합) → Build(구현 1, effort high) → Verify(러너+적대리뷰) → Fix.
- **결과**: 24개 에이전트 전부 `API Error: Server is temporarily limiting requests (not your usage limit) · Rate limited`. **0개 완료, 결과 공백.**
- **원인**: 순수 서버 일시 레이트리밋. 설계/코드 결함 아님.
- **재실행 스크립트**: `<session>/workflows/scripts/mdg-p0-build-wf_8ac6fe71-fd5.js` (runId `wf_8ac6fe71-fd5`). 0개 캐시 → 신규 재실행 또는 resume 모두 전체 재실행.

---

## 5. 다음 착수점 (이 세션 종료 후)

1. **P0 빌드 워크플로우 재실행** — 레이트리밋 해소 후. **LangGraph 스캐폴드**(MDGState·노드·결정론 조건부 엣지) + pydantic 계약 + verify-suite 실코드를 `mdg/`에 생성. (★stdlib-only 폐기 — deps 핀 고정, base `python:3.12-slim`; 상세 `FRAMEWORK_STACK.md`.)
2. GATE0 통과 후 P1→P6 순차, 각 구현→검증→수정, GATE 순서(GATE1 누수-0 통과 전 라이브 금지) 준수.

---

## 6. 운영·보안 제약 (전 과정 불변)

인가된 격리 샌드박스 · 전 과정 read-only/가역·무해 · 컨테이너 stop 금지 · ARIA키·서명키(/sign.key) 서버 밖 반출 금지·문서 마스킹 · 검증 중 상태변경(DROP·pause·서명명령) 금지 · 실기체/실이동통신망 아님.
