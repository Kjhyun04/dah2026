# 방어 에이전트 검증 매트릭스 — 검증자·구체화·구현가능성 (2026-07-07)

> 대상: 축적된 전 검증항목(E1~E24 · X1~X13 · G1~G11 · H-A~P · D-1~D-12, 총 75).
> 방법: 9-에이전트 워크플로우(라이브 read-only 실측 2 → 클러스터 매트릭스 6 → 통합 적대검증 1).
> 산출: 각 항목에 **구체화 + 검증자 + 구현가능성** 부여 + 게이트 블로커 + 검증불가 항목 식별.
> 전체 항목 매트릭스 원본: `<scratch>/vmatrix.txt`(75행). 이 문서는 요약·결론.

---

## 0. 결과 요약

| 구현가능성 | 수 | 의미 |
|---|---|---|
| **ALREADY-CONFIRMED** | 9 | 라이브로 확인됨 |
| **IMPLEMENTABLE** | 57 | 표준 구현 가능(지금 착수 가능) |
| **NEEDS-FIX** | 9 | 추가 구체화/선행 필요 |
| **BLOCKED** | 0 | 이 testbed에서 불가 없음 |

**총평(적대검증 verdict): 조건부 GO.** 결정론 코어(Evidence→Trust→Impact→Policy 파이프라인·WorldState/닫힌 행동공간 형식·관측 사이드카·teardown 계약)와 형식 스캐폴드 **~57항목은 지금 착수 가능**. 단 3대 선행을 먼저 닫아야 함(§4).

---

## 1. 라이브 실측으로 확정/정정된 것 (하부 사실)

| 항목 | 라이브 결과 |
|---|---|
| **D-1 드론측 교차루트** | ✅ **확정.** uav_* 4컨테이너가 단일 netns 공유, `lo:14550`에 **평문 MAVLink v2**(magic 0xFD, incompat 0x00=UNSIGNED, sysid 0x01=autopilot·0xFF=GCS 양방향). ARIA 미경유 → **비행모드 지상진실을 5762 없이 확보**(E2 자기봉쇄 해소). |
| **E3/E4 집행 근거 ★정정** | nsenter DROP이 되는 근거는 "컨테이너 netns의 CAP_NET_ADMIN"이 **아니라 "호스트 root 자신의 capability"** — 그래서 **caps=[]인 epc_mongo netns에도 `sudo nsenter -t <pid> -n iptables` 집행 가능**(read-only `-S` 확인). 설계문서의 "netns에 CAP_NET_ADMIN 존재" 서술 정정 필요. |
| **E4 br_netfilter** | ✅ **미로드 확정**(`/proc/sys/net/bridge` 부재, `DOCKER-USER` 빈 체인). same-bridge inter-container는 호스트 iptables 미경유 → pfcp_firewall/mongo_acl은 **netns-INPUT 집행만 유효**(호스트-DOCKER-USER 방식 NEEDS-FIX). |
| **E1 관측점** | ✅ 명령원=`gcs_proxy:14556`(상행), 14560=텔레. tm1_signing_defense도 ORACLE 기본 `172.30.0.10:14556`. (단 설계 정본에 완전 반영됐는지 개정 확인 — G0) |
| **G4 5762 ★정정** | "pool=1"을 **"LISTEN backlog=5·활성세션 실무상 1"**로 정밀화. ★결함: 기존 `tm1_signing_defense.read_mode()`가 **tcp 5762에 connect**(슬롯 점유+봉쇄시 실명) → 제거하고 `lo:14550` HEARTBEAT로 대체 필수. |
| **X3 서명 timestamp ★정정** | tm1_signing_defense의 timestamp는 **정규 MAVLink epoch(2015-01-01, 10μs)** = 자의적 미래점프 아님(양호). link_id=7로 gcs_c2 link_id=0과 분리. 잔여: 방어 호스트 벽시계가 gcs_c2보다 앞서면 초기 floor 상승→정상 link0 락아웃 가능 → **서명자간 시계협조 필요**. |
| **D-2 signer-shim** | ✅ gcs_c2가 `/sign.key`로 서명 발행 중(gcs.py `setup_signing link_id=0`) → 이 netns에 operator-gate shim 삽입 가능(키 비확산). 현행 tm1_signing_defense의 `docker run --network container:attacker_ue -v /sign.key`는 **E11/H5 재현**(공격자 netns 경유+키 확산) → 교체 필요. |
| **act_host 권한분리** | ✅ ubuntu∈docker + passwordless sudo iptables → signed-path(gcs_c2 shim)와 iptables/nsenter-agent(호스트 root) 별도 배치 가능. |
| **H-C 프레임워크** | ✅ 서버 **Python 3.12.3** 동작. ★2026-07-07 개정: 오케스트레이션 **LangGraph** + litellm + OSS 스택(pydantic/grpcio/FastAPI/pytest, `FRAMEWORK_STACK.md`). Robo Duck은 safe-exec/tool_wrap/pool=1만 이식. (이전 "thin-custom on litellm" 대체) |

---

## 2. 검증자 유형별 커버리지

| 검증자 | 커버 | 우려 |
|---|---|---|
| **live-probe** | E1/E2/E3/E16/E18/X12/X13/D1/D4/D5/D7/G9/H-I/D12 (관측점·netns·IP맵 read-only grounding) | 상태변경 액션의 **효력은 판정 불가**(read-only) → effect-confirm은 GATE2 |
| **unit-test** | E5-E8/E13-15/E19/E21-24/X2/X5-X10/D9-12/G6/G7/G10/H-B/H-E/H-L/H-P (결정성·상태기계) | **캘리브레이션 정확성 미검증**(ground truth 없음) → E5-E8/E22 동어반복 |
| **integration-test** | E9/E15/E24/G1/G3/H-J/H-M (e2e·replay·crash) | 상태변경분은 GATE 승인 전 미실행 |
| **build-gate** | E4/G2/G5/G8/H-N (정적·누수0 강제) | verify_tools/keys/leak0 미존재→러너 미완 |
| **verify-script** | E11/E20/X1/D2/D3/D11/G4/H-D/H-G/H-H/G11 (AST·정규식 정적) | verify_keys/tools 신규작성 필요 |
| **reference-alignment** | E10/H-A/H-B/H-C/D8/G6 (참조 3파일 라인인용) | WorldState(H-E) 참조부재→신규 |
| **domain-agent** | E17/X3/H-F/H-O (precond·서명 시맨틱·4패널) | 4G 인프라 심층 전문가 갭 |
| **operator-manual** | X2/X9/D6 (인증서·안전예외·failsafe) | 기계검증 불가 |

---

## 3. NEEDS-FIX 9건 (선행 수정)

| # | 항목 | 수정 |
|---|---|---|
| E4 | inter-container 필터 효력 | netns-INPUT 집행 + **GATE2 가역 DROP 1건 실측**(read-only 미확정) |
| E9 | gRPC ingest 인증 | mTLS+전체봉투 HMAC+per-agent 키+seq 단조 — **그린필드**(:50051·grpc 미설치) |
| E17 | 서명 검출 | incompat_flags&0x01(signed여부)+uav_proxy 서명드롭(진위) 이원 |
| X1 | 봉투 전체 HMAC | ingest키≠audit키, mTLS — E9와 동형 그린필드 |
| X3 | 서명 timestamp 락아웃 | **서명자간 시계협조**·초기 floor 협상(현 검증자로 미달, integration-test 필요) |
| X9 | 운영자 채널 | mTLS+단회토큰+signer-shim 자체 인증 — 그린필드 |
| X10 | Verifier-down 정책 | **D-3로 재프레임**(가역 AUTO는 verifier 무관, fail-closed는 비가역만) |
| G4 | 관측 async+5762 pool | 느린 Collector/Verifier가 루프 미차단·5762 connect 제거 |
| H-E | 형식 WorldState/KB | 닫힌 술어/아티팩트 **완전표**(누락 술어=legal 탈락 데드락) |

---

## 4. 게이트 블로커 (착수 전 필수)

**GATE 0 (형식·코드 전):**
- **정본(설계 HTML) 개정** — E1 14556 관측점·X1 전체봉투 MAC이 정본에 완전 반영됐는지 확인/개정(낡은 정본 코딩=결함 재유입).
- **verify_tools/verify_keys/verify_leak0 신규 작성** — 라이브 부재 확인(기존은 verify_p0/parsers/grep0/hygiene/bindings/models/p2만). GATE0 러너가 5종 exit0 요구.
- **E20 proto/enum 통일**(col_network→col_net, identity→identity_access, 유령tool 0) = verify_tools PASS 전제.
- **H-A 예외규율 확정** — ★정정: `tool_wrap`의 except가 **CRSError만 포획**(라이브 확인). bare ValueError/TimeoutError 누출 → "전 tool CRSError-only raise" 규율 또는 except 확장 필요.

**GATE 1 (누수-0·실측 전):**
- verify_keys + **E9/X1 gRPC :50051 스택 그린필드** 없이는 ingest 음성테스트 불가.
- verify_leak0 + **실백엔드 누수-0 통합테스트**(mock 판정 금지, G8).
- E24 원자번들 rollback·E11 /sign.key mdg 미마운트 불변식·G3 record_intent 선행.

**GATE 2 (이식성·효력):**
- **E4 netns-INPUT 실효력 1건**(가역 DROP→도달차단→revert) — 현재 prior 미확정.
- E18/X13/H-I 부팅 role→container→IP 맵 + HEARTBEAT sysid=1 재검증.
- H-H InputSpec 하드코딩0 정본화(라이브 IP≠문서 사례) · H-J replay 바이트동일(X3 벽시계 시드).

---

## 5. 검증자가 실제로 판정 못 하는 것 (cannot_verify 6)

1. **E5~E8·E22 수식** — unit-test는 산술 결정성만 확인, **값의 정확성은 ground truth 부재로 검증 불가**(동어반복). → H-O 도메인 sign-off를 필수 게이트로 승격, unit-test는 "산술 검증"으로 정직 라벨.
2. **X3 시계 락아웃** — 시계협조 인프라 미구현, 모든 skew 무-락아웃을 소스독해로 못 닫음 → 프로토콜 설계+integration-test.
3. **E4 inter-container 효력** — 실 DROP+revert 없이 확정 불가 → GATE2 가역 실측.
4. **H-M/D5 봉쇄 효력** — read-only는 "DROP 적용·공격자 무활동"과 "DROP 무효"를 둘 다 UNCONFIRMED로만 관측 → 정직 표기 유지, GATE2 능동프로브만 확정력.
5. **E16 다중호스트 skew 분기** — 다중호스트 collector 부재로 검증불가 → 단일호스트 전제 preflight 강제.

## 6. 근거 과장 정정 (overstated 3)
- **H-A**: "예외 누출 0"은 보편 참 아님(CRSError만 포획) → 규율/except 확장 필요(위 GATE0).
- **verify 스위트**: "참조골격 실재→재사용"이 과장 — verify_tools/keys/leak0는 **신규 작성** 대상.
- **E10**: H-E(WorldState)·H-P(프롬프트 계층)가 NEEDS-FIX/미설계인데 IMPLEMENTABLE로 표기 → 선행 미충족 = 사실상 NEEDS-FIX.

---

## 7. 결론

**결정론 코어 + 형식 게이트 = GREEN**(지금 착수). **ingest-auth 클러스터(E9/X1/X9) + 정본 개정 = G0/G1 선행 BLOCK.** 캘리브레이션 점수항(E5~E8·E19·E22·E23)은 H-O 도메인 sign-off 필수, 상태변경 봉쇄 효력(E4·H-M)은 GATE2 가역 1건 실측으로 확정. BLOCKED 0건 — 모든 P0 집행경로에 라이브 대체재 존재.

**착수 순서:** ①정본 개정(E1/X1 반영 확인) + verify-suite 3종 작성 + H-A 예외규율 → GATE0 → ②ingest gRPC 스택 + 누수-0 통합테스트 → GATE1 → ③E4 효력 실측 + 이식형 InputSpec + replay → GATE2.
