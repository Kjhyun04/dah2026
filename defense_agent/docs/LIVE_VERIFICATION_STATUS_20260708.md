# MDG 라이브 검증 종합 상태 (2026-07-08)

> 대상 testbed: `<TESTBED-IP>` (인가된 격리 샌드박스, dahv2 Open5GS split-core).
> 이 문서 = 자율 DROP 방어 파이프라인의 **배포·라이브 검증 최종 상태 + 잔여 과제**. 검증 명세는 `mdg/live/AUTODROP_LIVE_VERIFY.md §G`, 품질 보류는 `docs/PHASE3_DEFERRED_20260708.md`.

## 0. 한 줄 결론
**MDG 자율 DROP 전 구간이 실서버에서 관통 검증됨** — 탐지(5762)→BACKDOOR_5762→backdoor_drop AUTO→legality 라이브 통과→실제 `iptables DROP` 집행→실 트래픽 차단→revert·누수0까지 실증. 유일 잔여는 **P4 SMF 교차확인 레이어**(이 split-core의 IMSI↔IP 로깅 한계, recon-only best-effort로 발화, 후속과제).

---

## 1. 이번 검증 라운드에서 수행한 작업 (2026-07-08)

### 1-A. Phase 3 품질 28건 (ultracode 4그룹) — 배포 완료
- G-A(verify_routing FORBIDDEN_KEYS 스코프를 gate/legality/rank_recovery/select_policy로 확대·회귀가드), G-C(mongo.py dedupe 시간버킷), G-D(config death-surface: pfcp_firewall/mongo_acl operator-only 주석, 죽은 키 문서화), G-B(신규 회귀테스트 `test_qb_regression.py` 19건).
- 결정론 scoring·자율DROP 경로 영향분(air_side band, sense.py liveness, 미방출 metric 등)은 **강행 대신 문서화-보류**(`PHASE3_DEFERRED_20260708.md`).
- **서버 배포 후 pytest 189 passed / 1 skipped / 0 failed**, 그래프 컴파일 OK.

### 1-B. attacker attach 환경복구 (근본수정, 영구)
- **근본원인**: attacker 전용 eNB `ran_enb2`의 ZMQ RF `fail_on_disconnect=false`(정상 `ran_enb`은 `true`). peer 끊김 시 동기식 REQ/REP 락스텝이 데드락된 소켓을 물고 미복구 → srsue "Attaching UE..." 영구정지, DL IQ Recv-Q 0.
- **수정**: `configs/ran/enb2.conf` `false→true`(백업 `enb2.conf.bak_phase3`) + `docker compose ... up -d --force-recreate --no-deps ran_enb2 attacker_ue`(두 서비스만 병렬 재생성 = 원 부팅 동시성 복원). **정상 ran_enb/uav_ue 미접촉 → 보호 UAV 무영향**.
- 결과: RACH→`Network attach successful`, attacker tun 확보(동적, 이 라운드 10.45.0.17). 진단이 처음 지목한 "MME 잔여 컨텍스트"는 오진 — MME는 clean(0세션은 4G 세션이 UPF에만 로깅되기 때문).

### 1-C. 무해 G1 — A5·C 라이브 관통 (실 DROP 없이)
- **스플릿 백엔드**: recon=`allow_live=True`(read-only tun-scan) / 집행 Backend=`allow_live=False`(DRY). 실 role_verified 위에서 결정경로만 관측, 실 DROP 원천차단.
- **A5 ✅**: role_verified{uav_ue:true, attacker_ue:true,...}, ip_map{attacker_ue:10.45.0.17} 라이브 동적 해석 (이중 operator-go 게이트 (a)).
- **C1 ✅**: correlate `BACKDOOR_5762` target=10.45.0.17, source 셀렉터 운반.
- **C2 ✅**: `nsenter_input_drop`, enforce_at=uav_ue, target=10.45.0.17, AUTO(operator_gate=false), MED·reversible.
- **C3 ✅ (역사적 blocker)**: legality가 라이브 role_verified 컨테이너키로 통과(인위주입 없이). 154/189 pytest green이어도 못 닫던 관문을 라이브로 닫음.
- **무해성 ✅**: `applied.confirmed=false` + uav_ue INPUT DROP 규칙 0.

### 1-D. D/E 실집행 — "진짜 자율 DROP" (operator `!`-run, allow_live=True)
- auto-mode 가드가 실 상태변경(DROP)을 자동 차단 → operator가 세션 `!`로 `d_fire.sh`(발화→검증→trap 무조건 revert) 직접 실행.
- **D2 ✅**: 그래프가 operator 개입 0으로 `iptables -I INPUT -s 10.45.0.17 -j DROP` 집행 → uav_ue netns에 `-A INPUT -s 10.45.0.17/32 -j DROP` 설치.
- **D3 ✅**: DROP 후 신규 5762 접속 = `TimeoutError`(차단). **D4 ✅**: UAV C2 HB(lo 14550) 정상, uav_ue tun 유지(self-DoS 0).
- **E1 ✅**: trap revert → INPUT `ACCEPT`만, 도달성 원복. **E2 ✅**: orphan proc 0. **E4 ✅**: 컨테이너 20 복원.
- 관측성 노트(비결함): `applied.confirmed=true` grep 미매치 — 실 규칙+D3 차단이 집행 증거, effect_confirm 사후틱 부족(max_iters=10) 추정.

---

## 2. 라이브 검증 최종 매트릭스

| 항목 | 상태 | 근거 |
|---|---|---|
| Phase 3 배포 (품질 28) | ✅ | 서버 pytest 189 passed |
| A5 role_verified (라이브) | ✅ | allow_live tun-scan, uav_ue·attacker_ue=True |
| C1 correlate BACKDOOR_5762+target | ✅ | run.jsonl incident target=10.45.0.17 |
| C2 backdoor_drop AUTO | ✅ | tool=nsenter_input_drop, enforce_at=uav_ue, operator_gate=false |
| C3 legality 라이브 통과 | ✅ | 결정 act 관통, provenance=verified |
| D2 실 자율 DROP 집행 | ✅ | 실 iptables 규칙 설치 |
| D3 실 트래픽 차단 | ✅ | 신규 5762 TimeoutError |
| D4 집행중 self-DoS 0 | ✅ | UAV HB 생존 |
| E1/E2/E4 revert·누수0·원복 | ✅ | INPUT ACCEPT 원복, proc 0, 20 컨테이너 |
| **P4 SMF 교차확인 (라이브)** | **◐ 미배선** | split-core IMSI↔IP 단일로그 부재 → recon-only 발화(finding) |
| C4 과잉개방 없음 (라이브 adversarial) | ◐ 부분 | 5762만 DROP 계획(관측), mongo/PFCP 라이브 미주입 |

---

## 3. 잔여 과제 (남은 사항)

### A. 라이브 검증 잔여
- **[후속] P4 SMF 교차확인 defense-in-depth**: `epc_upf`(F-SEID↔IP)+`epc_mme/smf`(IMSI) 멀티로그 상관 콜렉터 or Open5GS SMF 4G 세션 로깅 복구. 현재 recon-only best-effort(안전측)로 발화 중.
- **[선택] C4 라이브 adversarial**: mongo/PFCP만 주입해 자율DROP 무발화 라이브 확인(유닛·DRY 커버됨).

### B. Phase 3 문서화-보류 (calibration sign-off 대기 — `PHASE3_DEFERRED_20260708.md`)
- air_side Packet_Loss band(warning→danger), sense.py per-source liveness, 미방출 metric(RTT/Signature_Verify_Fail/NAS_Cipher_Order), thresholds fallback mirror. 전부 결정론 scoring 스칼라 이동이라 도메인 sign-off 후 적용.

### C. 예선 산출물 (마감 2026-07-10)
- 최종 보고서 작성/갱신(`report-generator`) — 본 라이브 실증 반영.
- 문서 마스킹 확인(ARIA키·서명키·실IP 반출 금지).

### D. 서버 하우스키핑 (낮음)
- `dah_exec/lib/targets.env` `ATTACKER_IP` stale(.13→현재 .17) — `discover.sh --fresh` 자가치유.
- `ran_enb2` fail_on_disconnect=true는 host 파일 영구 반영(:ro) → 재부팅 유지(해결).

---

## 4. testbed 최종 상태 (검증 후 완전 원복)
- 컨테이너 **20**, `uav_ue` INPUT `-P INPUT ACCEPT`(DROP 잔존 0), attacker attached(10.45.0.17), UAV HB 정상.
- 임시 산출물(`d_driver.py`/`d_fire.sh`/`g1_verify.py`/`d_out`/`g1_out`/배포 스테이징) 제거. 보존: `~/mdg`(배포코드)·`~/mdg_venv`·`enb2.conf.bak_phase3`.
- 전 과정 운영·보안 제약 준수: 실 상태변경(DROP)은 operator 승인 하 `!`-run + trap 무조건 revert, 키 반출 0, 문서 마스킹.

---
*변경 파일(로컬): `mdg/verify/verify_routing.py`, `mdg/collector/mongo.py`, `mdg/config/{recovery_priors.yaml,defaults.py,loader.py}`, `mdg/core/nodes/act.py`, `mdg/tests/test_qb_regression.py`, `docs/PHASE3_DEFERRED_20260708.md`(신규), `mdg/live/AUTODROP_LIVE_VERIFY.md §G`. 서버: `configs/ran/enb2.conf`(fail_on_disconnect=true). 메모리 3건.*
