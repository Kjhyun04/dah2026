# 미해결 사항 목록 + 해결 계획 (2026-07-08)

## 진행 상태 (갱신 2026-07-08)
- **Phase 0 (서버정리) ✅ 완료**: H1 `reverent_euler` 자동제거(20 복원)·H2 targets.env 실IP 정확(자가치유)·H3 모드복원 발행+testbed 건강.
- **Phase 1 (프로덕션필수) ✅ 완료**: P4 stale-binding·P1 R4 reap·P3 checkpointer pruning·P2 live_autorun 런처 구현+3인검증. 외부API 웹검증(delete_thread langgraph-checkpoint≥2.0.25 소스확인·os.kill 시맨틱 Python docs). **+ Gap1 해소**(P4 smf_table을 topology→act→ResponseController 배선 + 런처가 EPC collector로 SmfSessionTable 공급 = P4 프로덕션 활성). **pytest 169 passed·verify 9종 PASS.**
  - 잔여 주의(배포/라이브 반영): ①서버 `langgraph-checkpoint≥2.0.25` 해석 확인(아니면 P3 no-op) ②P4는 라이브 SMF 귀속 존재 시에만 DROP 발화(SMF rotate 시 safety-first 차단) ③verify_leak0 A1/A1b 라이브는 서버(POSIX)에서 D-2 재확인.
- **Phase 2 (배포+라이브) ✅ 완료**: D1 배포·D2 서버 pytest 189 green·D3 라이브 A~C(read-only/DRY)·**D구간 실 자율 DROP 집행+E복원(operator `!`-run, allow_live=True)**. 상세 `docs/LIVE_VERIFICATION_STATUS_20260708.md`. 유일 잔여=P4 SMF 교차확인(split-core 한계, recon-only 발화).
- **Phase 3 (품질보완 Q) ✅ 완료**: ultracode 4그룹(G-A/G-C/G-D/G-B) 배포, 서버 189 passed. 결정론 영향분은 `PHASE3_DEFERRED_20260708.md`로 문서화-보류.
- **종합 상태 문서**: `docs/LIVE_VERIFICATION_STATUS_20260708.md` (전 과정 + 잔여과제).

---


> 기준: 자율 DROP 11단계 최소셋은 **구현·로컬검증 완료(pytest 159 passed)**. 아래는 그 밖의 미해결 전부.
> 분류: [H]서버 정리 · [P]프로덕션-필수 보완(라이브 전) · [D]배포·라이브검증 · [Q]품질 보완(라이브 후 가능)
> 근거: `docs/CODE_AUDIT_20260708.md`(28 medium/low) + 라이브 검증 중 발생 잔여물.

---

## 0. 미해결 사항 전체 목록

### [H] 서버 housekeeping — 라이브 검증 중 발생, 정리 필요 (3건)
| # | 항목 | 상태 | 위험 |
|---|---|---|---|
| H1 | 잔여 컨테이너 `reverent_euler`(hung read_mode의 dahv2/air 아티팩트) | 분류기가 `docker rm` 차단 | 낮음(무해, 베이스라인 21≠20) |
| H2 | `~/dah_exec/lib/targets.env`를 실 IP로 수정(UAV_SERIAL/UAV_IP/ATTACKER_IP) | 잔존 | 낮음(discover.sh 재생성, 동적) |
| H3 | UAV SITL 모드 — 5762로 변경 후 복원 태스크 exit 0이나 실제 모드값 미확인 | 미확인 | 낮음(SITL 지상·가역) |

### [P] 프로덕션-필수 보완 — **라이브 검증 전 처리 권장** (불변식②·생명주기·self-DoS 인접, 4건)
| # | 파일:라인 | 문제 | 위험 |
|---|---|---|---|
| P1 | `safe_exec/backend.py:196` | `teardown()`/R4 reap이 `not allow_live`에서 dead no-op — read_only가 실제 spawn하는 기본모드에서 크래시-고아 회수 primitive 꺼짐 | 불변식② 크래시복구 갭 |
| P2 | `mdg/live_autorun` 부재 | 프로덕션 자율 런처 없음 → collector.stop()/join()/teardown() 소유자 없음, 종료 시 관측자 미회수. (현 스크래치패드 `live_autorun.py`는 임시) | ② 생명주기 누수 |
| P3 | `core/driver.py:78` | 매틱 fresh thread_id인데 InMemorySaver pruning 없음 → O(ticks×state) 무한누적 | ② 메모리 누수(장기런) |
| P4 | `safe_exec/response.py:65`, `recon.py` | recon stale binding — 재할당된 UE-pool IP를 smf_table 교차확인 없이 DROP → 무고 UE self-DoS 가능 | self-DoS(재할당 IP) |

### [D] 배포 + 라이브 검증 — 대기 (미실행, 버그 아님)
| # | 항목 | 선행 |
|---|---|---|
| D1 | 11단계 코드 서버 배포(현재 로컬만) | H·P |
| D2 | 서버 pytest 159 + verify 9종 재확인 | D1 |
| D3 | `AUTODROP_LIVE_VERIFY.md` A→E 라이브 검증(D구간 operator 승인) | D2 |

### [Q] 품질 보완 — 라이브 후 가능 (감사 medium/low 잔여, 그룹별)
**Q-A 불변식① 정적가드**
- `verify/verify_routing.py:39` — FORBIDDEN_KEYS 스캔이 edges.py route_*에만 국한 → gate/legality/rank_recovery/select_policy로 확대(현 누출 0, 회귀가드).

**Q-B 불변식② 검증 커버리지**
- `verify/verify_no_fw_subproc.py:24` — 정적 subprocess-0 검사가 core/만 스캔 → collector/ingest/replay 포함, backend.py+safeexec.py allowlist.
- 신규 유닛: `backend.py:52` is_read_only_argv(통과/거부 케이스), `backend.py:179` read_only 세마포어 분리, `driver.py:86` fresh thread_id·operator.add-1회누적, `correlate.py:20` 직접 유닛.

**Q-C collector 오탐 억제**
- `air_side.py:127` Packet_Loss value=100·band='warning' 계약위반(METRICS상 danger).
- METRICS band-range 미소비(`compute_trust`가 domain/weight만) — collector 컷오프 하드코딩.
- 미방출 metric(RTT/Signature_Verify_Fail/NAS_Cipher_Order) — 도메인 weight 예산 미충족.
- `mongo.py:99` dedupe 키 ts 없음 → 동일 IP 반복접속 영구억제.
- `sense.py:81` command 도메인 2 collector 충돌(한 collector 死 마스킹).

**Q-D config 죽은 표면 정리(안전방향이나 오해소지)**
- `recovery_priors.yaml:10` pfcp_firewall enforce_at=gcs_proxy — PFCP는 net_core, gcs_proxy 미지남 + epc_smf/upf가 role 아님 → 수정불가 오정합. operator-only 문서화 또는 upf role 추가.
- `recovery_priors.yaml` mongo_acl — 고아+web_backend 오정합+cellular 미검증 삼중데드. 제거 또는 3중배선.
- `act.py:71` reverse_container_for_ip 데드코드(OPER pause 컨테이너 미해석).
- 죽은 config: score_weights/rejected_types 하드코딩, loader.thresholds() fallback 비-미러, SEQ_SKEW_S 미사용.

**Q-E 잔여 테스트 회귀 잠금**
- `test_p4_response.py` _resolve_endpoints alias DISTINCT 가드, legality config_version/threat/signing 분기 미검증(관통 e2e는 step11 test_p7 추가로 일부 커버됨).

---

## 1. 해결 계획 (단계·방법·의존)

### Phase 0 — 서버 정리 (즉시, 대부분 operator 수동)
| 항목 | 방법 | 비고 |
|---|---|---|
| H1 | operator가 `!ssh ... "sudo docker rm -f reverent_euler"` 또는 세션 밖 실행 | 분류기 차단분, operator go 필요 |
| H2 | `bash ~/dah_exec/lib/discover.sh --fresh`로 재생성 or 원본 백업복원 | 자가치유(동적) |
| H3 | `read_mode.py`로 현재 모드 조회 → 필요시 STABILIZE 재설정 | read-only 우선 |

### Phase 1 — 프로덕션-필수 보완 (라이브 전, **워크플로우 구현+검증**)
의존순서: P4(self-DoS 선제) → P1(reap) → P3(pruning) → P2(런처, 앞 3개 흡수).
| 순 | 항목 | 수정 요지 | 검증 |
|---|---|---|---|
| 1 | **P4** stale-binding 방어 | response._resolve_endpoints가 target IP를 smf_table/최신 tun-scan으로 교차확인, 불일치시 inert. 재할당 IP DROP 차단 | 적대검증(self-DoS)+유닛 |
| 2 | **P1** R4 reap 분리 | `teardown()`/reap_labelled 가드를 `mode=='mock'`만으로(allow_live 무관). verify_leak0 A축을 allow_live=False read_only로도 커버 | verify_leak0+유닛 |
| 3 | **P3** checkpointer pruning | 매틱 `delete_thread(t-1)` 또는 bounded saver. 장기런 메모리 유계 | driver 다틱 메모리 유닛 |
| 4 | **P2** live_autorun 런처 | 예외안전 shutdown(collector stop/join/teardown, allow_live env, jsonl) 프로덕션 모듈 신설(스크래치패드 대체) | 기동/종료 누수-0 |
> 방법: 순차 워크플로우(각 단계 구현→적대검증 불변식②·self-DoS→pytest). Phase 1 완료 후 pytest·verify 재확인.

### Phase 2 — 배포 + 라이브 검증
| 순 | 항목 |
|---|---|
| 1 | D1 배포(11단계+Phase1) → D2 서버 pytest/verify |
| 2 | D3 라이브 A(게이트+A5 recon)→B(탐지)→C(결정 DRY) read-only 검증 |
| 3 | D3 D구간(자율 DROP 실집행+E4) — **operator 승인** → E복원·누수0 |

### Phase 3 — 품질 보완 (라이브 후, 워크플로우 일괄)
| 그룹 | 처리 |
|---|---|
| Q-A/Q-B | verify 스코프 확대 + 신규 유닛(정적가드·커버리지) |
| Q-C | collector 오탐 억제(Packet_Loss band·METRICS 소비·dedupe·도메인충돌) |
| Q-D | 죽은 config 정리(mongo_acl/pfcp_firewall/reverse_container 문서화 or 제거) |
| Q-E | 잔여 회귀테스트 |
> 라이브 검증 결과를 반영해 우선순위 조정. 안전방향(대부분 fail-closed)이라 라이브 후 처리 가능.

---

## 2. 권장 실행 순서 요약
```
Phase 0(서버정리, operator) → Phase 1(P4→P1→P3→P2, 워크플로우+검증)
→ Phase 2(배포·라이브 A~C, D는 승인) → Phase 3(품질보완 일괄)
```
**급소:** Phase 1의 P4(stale-binding)·P1(reap)은 자율 DROP을 라이브로 켜기 전에 닫아야 self-DoS/누수 리스크가 없다. Q(품질)는 fail-closed라 라이브 후로 미뤄도 안전.

---
*요약: 미해결 = [H]서버정리 3 + [P]프로덕션필수 4 + [D]배포·라이브 3 + [Q]품질보완 28(그룹 5). 계획 = Phase0 정리 → Phase1 필수보완(워크플로우) → Phase2 배포·라이브(D는 승인) → Phase3 품질일괄. self-DoS 인접 P4·P1은 라이브 자율DROP 활성 전 필수 선행.*
