# nsenter DROP 라이브 검증 명세 (SSH) — DROP 경로 관통·안전·불변식보존 검증

> ⚠ **정정(2026-07-09 · 5762 백도어 벡터 제거).** 본 명세는 원래 **5762 시리얼 백도어** 트리거의
> 자율 DROP(`WebProbe`→`Port_5762_State`→`BACKDOOR_5762` incident→`backdoor_drop` rtype,
> enforce_at=uav_ue)을 검증했다. 이 5762 탐지·복구 경로는 **코드에서 전량 제거**되었다
> (WebProbeCollector·Port_5762_State·BACKDOOR_5762·backdoor_drop·read_port_state tool·s3b_5762.sh).
> **★ `nsenter_input_drop` DROP 메커니즘 자체(2-엔드포인트 chokepoint⟂source 안전 assert·fail-closed
> inert·record_intent·revert·누수-0)는 존속**하며, 이제 이 도구를 참조하는 복구는
> `pfcp_firewall`(트리거 `PFCP_Delete_Attempt`→`PFCP_DELETE`/CR01, enforce_at **gcs_proxy**)·
> `mongo_acl`(트리거 `DB_Access`, enforce_at **web_backend**)이다. 단, `recovery_priors.yaml`대로
> **두 경로 모두 현재 operator-only/비자율(inert)**: PFCP는 correlate가 귀속 소스 없음→`target=""`
> fail-closed(자율 DROP 미발화)·gcs_proxy가 net_core PFCP를 chokepoint 못 함, mongo_acl은
> orphan(select_policy 후보 미방출). 즉 5762가 제공하던 **완전 자율(AUTO-tier 실발화) DROP은 제거**
> 되었고, DROP 메커니즘은 PFCP/mongo에 배선된 채 **operator-go**로 남는다.
> **아래 §0 상수는 현행 트리거(gcs_proxy/web_backend)로 갱신했으며, §A~§G의 관통·실집행 절차와
> 2026-07-08 실집행 기록은 제거된 5762 경로를 대상으로 한 원 절차로, nsenter DROP 메커니즘·안전·
> 불변식의 참조 구현이자 역사적 감사기록으로 보존한다**(감사 정본: `docs/LIVE_VERIFICATION_STATUS_20260708.md`).
>
> 대상: 실제 testbed(`<TESTBED-IP>`)에서 **nsenter DROP 경로가 관통·안전·불변식보존**임을 검증.
> 단위테스트로 닫을 수 없는 **라이브-전용 사항** 중심.
> 지위: DROP(상태변경)은 **operator 명시 승인** 하에서만. 기본 read-only/DRY. 2대 불변식·운영제약 우선.
>
> ⚠⚠ **이중 operator-go 게이트**: UE-pool source(attacker_ue) 검증이 **True가 되려면 recon이
> `allow_live`로 stage-2 tun 스캔을 실행**해야 함(부팅 inspect만으론 미검증→legality illegal→inert).
> 즉 DROP 집행엔 **(a) live recon 리졸브 + (b) 집행 allow_live 둘 다** operator-go 필요. fail-closed의 핵심.

## 0. 공통 상수·해석 (매 실행 런타임 재해석, 하드코드 금지)
| 항목 | 라이브 실측(예시, 동적) | 해석법 |
|---|---|---|
| UAV | uav_ue, tun `10.45.0.2`, netns `4026532572` | `docker exec uav_ue ip -4 addr show tun_srsue` |
| attacker | attacker_ue, tun `10.45.0.13`, cellular `10.44.0.31` | 동상, `-s` DROP 소스=tun IP |
| enforce chokepoint | **gcs_proxy**(pfcp_firewall)·**web_backend**(mongo_acl) — `recovery_priors.enforce_at` | `docker inspect -f {{.State.Pid}} <role>` |
| 공격도구 | `~/dah_exec/B_TM2_V3/pfcp_delete.py`(PFCP delete) · mongo 접속 유발 (via `lib/run.sh`) | targets.env 참조 |

**안전 assert(전 스텝 fail-closed):** `attacker_tun != uav_tun` · `enforce_pid>0` · DROP `-s`는 attacker_tun(≠UAV). 하나라도 실패 → abort.

---

## A. 배포·회귀 게이트 (read-only, 상태변경 0) — **GATE0**

| # | 검증사항 | DO | PASS 기준 |
|---|---|---|---|
| A1 | 11단계 코드 배포 | tar+scp `~/mdg` 갱신, pycache clear | 배포 완료 |
| A2 | 단위 회귀 무손상 | `~/mdg_venv/bin/python -m pytest ~/mdg/tests -q` | **154+ passed**(신규 관통테스트 포함), 0 failed |
| A3 | 불변식 정적검사 | `python -m mdg.verify.verify_graph/verify_routing/verify_no_fw_subproc/verify_grep0/verify_keys/verify_tools` | 전부 PASS(라우팅 결정론·노드 subprocess 0) |
| A4 | 그래프 컴파일 | `build_graph` import+compile | ImportError 0 |
| **A5** | **live recon 리졸브(이중게이트 a)** | `MDG_ALLOW_LIVE=1 recon_boot` → `role_verified` + `ip_map` 덤프 | **`role_verified[uav_ue]==True` ∧ `role_verified[attacker_ue]==True` ∧ `ip_map[attacker_ue]==10.45.0.13`** |

> 중단: A2/A3 실패 → 라이브 진입 금지, 워크플로우 교정 재실행.
> **A5는 C3(legality)·D2(발화)의 선행조건**: allow_live stage-2 tun 스캔이 uav_ue/attacker_ue를 verified로
> 만들지 못하면(부팅 inspect만) legality가 illegal→inert. A5 실패 시 C/D 진입해도 자율 DROP은 구조적 무발화.

---

## B. 탐지 경로 관통 (read-only) — 단위테스트 불가, 라이브 전용

기존엔 **WebProbe가 web_backend netns를 봐 5762 증거가 영원히 미방출**(감사 C). 배선 교정 후 라이브에서만 확인 가능.

### B1. [C] WebProbe가 uav_ue netns에서 5762를 실제로 관측하는가
- **DO:** attacker→uav:5762 단발 연결 유발 후(`serial5762.py 4`), MDG collector 1사이클(allow_live=False).
- **VERIFY:** `run.jsonl`에 `Port_5762_State: ESTAB_PRESENT`(band=danger, domain=command) 방출.
- **PASS:** 배선 전엔 0건이던 신호가 방출됨. **미방출 시 C 배선 미적용**(netns_prefix가 여전히 web_backend).
- **교차:** `nsenter --target <uav_ue pid> --net -- ss -tn state established '( sport = :5762 )'`로 ESTAB peer가 실제 10.45.0.13인지 확인(collector가 보는 것과 일치).

### B2. [①B] peer source 셀렉터가 evidence까지 운반되는가
- **DO:** 위 5762 ESTAB 상태에서 collector 방출 evidence 검사.
- **VERIFY:** `run.jsonl` evidence에 `source` 필드 == **`10.45.0.13`**(attacker tun). (배선 전엔 필드 자체 부재.)
- **PASS:** source==attacker_tun. 비었으면 → ingest.py envelope_to_ev 미배선(B) 또는 web.py peer 파싱 실패(①).
- **경계:** ss row가 tun(10.45.x)이 아니라 cellular(10.44.x) peer를 보이면 → DROP 대상 검증 실패로 이어짐(하단 C3 확인).

### B3. [G] idle에서 N3 볼륨이 PFCP danger로 날조되지 않는가 (self-DoS 오탐 제거)
- **DO:** **무공격 idle** 상태 MDG 다틱(6틱) 자율런(allow_live=False).
- **VERIFY:** `run.jsonl`에 `PFCP_Delete_Attempt`(danger) **0건**, network/session_network 도메인 baseline=normal/Green.
- **PASS:** 정상 데이터플레인 트래픽이 위험신호로 날조되지 않음. 날조되면 → 자율 DROP 활성 후 **오DROP self-DoS 위험** → A(legality) 열기 전 반드시 재수정.

---

## C. 결정 경로 관통 (read-only, allow_live=**False** DRY) — 계획만 확인, 무집행

allow_live=False라 Backend가 DRY 반환 → **그래프가 무엇을 DROP하려는지(계획)를 무집행으로 관찰**. 실 DROP 전 안전 검증.

### C1. [D/②] correlate가 BACKDOOR_5762 incident + target을 만드는가
- **VERIFY:** `run.jsonl` incident `kind==BACKDOOR_5762`, `target==10.45.0.13`. 다른 단일신호(mongo/RTT)는 여전히 `single-signal`(오라우팅 없음).
- **PASS:** 전용 kind 분리 + target 귀속. single-signal이 5762 DROP으로 오라우팅되면 D 실패.

### C2. [③/8/9] select_policy→rank_recovery→gate가 backdoor_drop을 AUTO로 선택하는가
- **VERIFY:** `run.jsonl` chosen_action: `rule/tool_id==nsenter_input_drop`, `enforce_at==uav_ue`, `target==10.45.0.13`, `risk==MED`, `reversible==true`; gate 판정 `tier2==AUTO`.
- **PASS:** feasibility(succ≥0.70) 통과 + AUTO 게이트. chosen_action=None이면 → priors 미등록(E) 또는 feasibility 탈락.

### C3. [A] legality가 라이브 worldstate에서 통과하는가 — **역사적 blocker**
- **VERIFY:** `run.jsonl` `legal_actions` **비어있지 않음** + 이 action이 decide→act로 라우팅(DRY effect_confirm까지 도달, 실집행은 DRY).
- **PASS:** enforce_at=uav_ue(컨테이너키)가 role_verified[uav_ue]=True로 동적검증 통과. **여전히 legal_actions=[]면 A(legality 동적바인딩) 미적용** — 이것이 4곳 수정만으론 안 되던 핵심 관문.
- **대조(F):** enforce_at을 일부러 역할별칭("uav")로 두면 pid_map.get("uav")=None → inert. 컨테이너키여야 함을 재확인.

### C4. [fail-closed 회귀] 의도 외 공격은 여전히 자율 DROP 안 되는가
- **DO:** mongo(A5) 또는 PFCP(A2) 공격만 주입(5762 없이), allow_live=False.
- **VERIFY:** mongo/PFCP에 대해 chosen_action이 nsenter_input_drop **아님**(mongo=고아/미검증 inert, PFCP=CR01 target 없음 inert). 즉 **5762 경로만** 열렸고 과잉개방 없음.
- **PASS:** 변경이 오직 5762 백도어에만 자율 DROP을 부여(최소개방). 다른 데서 DROP 계획이 나오면 self-DoS 표면 과다.

---

## D. 자율 DROP 실집행 + E4 (allow_live=**True**, operator 승인 — 유일 상태변경)

> **operator 서면 승인 하에서만.** 안전 assert 통과 + C1~C3 DRY 확인 후에만 진입.

### D1. 사전 도달성 baseline (read-only)
- **DO:** `nsenter --target <attacker pid> --net -- ping -c2 <uav_tun>` + 5762 TCP.
- **VERIFY:** attacker→uav **reachable**(E4 측정 대상 트래픽 성립). 미도달이면 E4 effect 측정 불가(V4 상황).

### D2. 그래프 자율 DROP 발화 (핵심)
- **DO:** 지속 5762 공격 배경 + MDG 자율런 `MDG_ALLOW_LIVE=1`(allow_live=True) 다틱.
- **VERIFY:**
  - `run.jsonl` `applied[nsenter_input_drop].confirmed==true` (record_intent 선기록 + 단일 subprocess 집행, 불변식②).
  - **실 규칙 설치:** `nsenter --target <uav_ue pid> --net -- iptables -S INPUT | grep '10.45.0.13.*DROP'` → 존재.
- **PASS:** 그래프가 operator 개입 없이 스스로 DROP 집행(record_intent→Backend 단일경로→effect_confirm). **이것이 "진짜 자율 DROP" 실증.**

### D3. ★E4 — 실 공격 트래픽 차단 (V4 미실증 항목)
- **DO:** DROP 설치 상태에서 attacker→uav ping/5762 재측정.
- **VERIFY:** ping/5762 **BLOCKED**(배선 전 reachable → 후 차단). uav_proxy 서명차단 카운터 증가 **정지**(주입 도달 중단) 또는 WebProbe ESTAB 소멸.
- **PASS:** 자율 DROP이 실 공격 트래픽을 실제로 끊음(E4 effect on live traffic).

### D4. self-DoS 0 (동시 확인)
- **VERIFY:** `nsenter --target <uav_ue pid> --net -- tcpdump -i lo -c3 udp port 14550` → UAV C2 HB 정상 캡처. DROP `-s`가 10.45.0.13(≠UAV 10.45.0.2)임 재확인.
- **PASS:** UAV C2 무영향. HB 소멸 시 **즉시 revert + abort**.

---

## E. 복원·누수-0·불변식 라이브 (read-only)

### E1. revert (필수)
- **DO:** `iptables -w -D INPUT -s 10.45.0.13 -j DROP` (자율 recovery가 revert하는지 또는 operator revert).
- **VERIFY:** 규칙 제거 → `iptables -S INPUT`에 10.45.0.13 **0건** · attacker→uav 도달성 **원복**.

### E2. 누수-0 (불변식② 라이브)
- **VERIFY:** 집행 전후 `docker ps -q | wc -l` **diff 0** · 잔존 tcpdump/nsenter proc **0** · `ss :5762` ESTAB 0(공격중단 후).
- **PASS:** 관측·집행 subprocess 자기종료 + R1~R6 reap, 사이드카 미생성.

### E3. 결정론(불변식①) 라이브 재현
- **DO:** 동일 evidence 시퀀스로 2회 자율런.
- **VERIFY:** `run.jsonl` {seq,node,patch} 시퀀스 바이트동일(라우팅 동일). LLM(orient/decide) advisory라 라우팅 무영향.

### E4. 최종 상태
- **VERIFY:** UAV 모드 원복(5762가 변경했으면), uav_ue INPUT=`-P INPUT ACCEPT`, 잔여 attack-tool 컨테이너 0, `MDG_ALLOW_LIVE` 해제.

---

## F. 검증 항목 ↔ 11단계 매핑 (어느 수정이 어디서 라이브 확인되는가)

| 라이브 검증 | 확인하는 단계 | 단위테스트로 닫히나? |
|---|---|---|
| B1 5762 증거 방출 | C(탐지netns) | ✗ 라이브 netns 전용 |
| B2 source==10.45.0.13 | ①(peer)·B(carrier) | 부분(파싱 유닛) + ✗ 실 peer 형식 |
| B3 N3 오탐 없음 | G | ✗ 라이브 UPF 카운터 전용 |
| C1 BACKDOOR_5762 target | D·② | 유닛 O + 라이브 target값 ✗ |
| C2 backdoor_drop AUTO | ③·8·9 | 유닛 O |
| C3 legality 통과 | **A** | ✗ **라이브 role_verified 컨테이너키 전용**(e2e 인위주입이 가리던 것) |
| C4 과잉개방 없음 | 전체 | 부분 |
| D2 자율 DROP 발화 | 관통 | ✗ 라이브 allow_live 전용 |
| D3 E4 실차단 | 관통 | ✗ 라이브 트래픽 전용 |
| D4/E2 self-DoS0·누수0 | 불변식② | ✗ 라이브 netns 전용 |
| E3 결정론 | 불변식① | 부분(verify_routing) + 라이브 재현 |

**핵심:** C3(legality)·B1(탐지netns)·B3(N3오탐)·D2·D3·D4는 **오직 라이브에서만** 관통 확인 가능 — 154 pytest가 green이어도 이들이 실패하면 자율 DROP은 무동작. 배포 후 이 순서(A→B→C→D→E)로 반드시 검증.

---

## G. 라이브 검증 실행 기록 (2026-07-08) — ⚠ 제거된 5762 경로의 역사적 기록

> ⚠ 아래 기록은 **제거된 5762 백도어 트리거**(BACKDOOR_5762/backdoor_drop, enforce_at=uav_ue)에
> 대한 2026-07-08 실집행 감사기록이다. 해당 자율 DROP 경로는 코드에서 제거되었으므로 현행 동작이
> 아니며, nsenter DROP 메커니즘·안전·불변식(2-엔드포인트·revert·누수-0)의 실증 provenance로만 보존한다.
> 현행 PFCP/mongo 트리거는 operator-go/inert(상단 정정 배너 참조).

### 완료 (배포+DRY)
- **A GATE0 ✅**: 서버 배포 후 pytest **170 passed·1 skipped**, verify graph(28)·routing(21)·no_fw_subproc(119)·leak0(16) PASS. langgraph-checkpoint **2.1.2**(≥2.0.25 → P3 pruning 활성).
- **B1/B2 탐지관통 ✅** (allow_live=False DRY): `mdg.live_autorun`가 recon으로 uav_ue pid 해석 → WebProbe가 uav_ue netns 5762 관측 → `Port_5762_State`(danger)+**`source=10.45.0.15`**(실 attacker tun) → correlate `BACKDOOR_5762` incident+**`target=10.45.0.15`**. 교차확인 attacker_ue tun=10.45.0.15 일치.
- **B3 N3 오탐 제거 ✅**: idle/공격 중 `PFCP_Delete_Attempt` 날조 0(G 수정 실증).

### 완료 (2026-07-08 추가: Phase3 배포 + 환경복구 + 무해 G1)
- **Phase 3(품질 28건) 배포 ✅**: 서버 pytest **189 passed·1 skipped·0 failed**(신규 회귀 `test_qb_regression.py` 19건 포함), 그래프 컴파일 OK. G-A(verify_routing 스코프 확대)·G-C(mongo dedupe 시간버킷)·G-D(config death-surface 문서화) 반영. 결정론 scoring 영향분은 `docs/PHASE3_DEFERRED_20260708.md`로 문서화-보류.
- **환경복구(attacker attach) ✅**: attacker 미어태치 근본원인 = `ran_enb2`의 ZMQ RF `fail_on_disconnect=false`(정상 `ran_enb`은 true). peer 끊김 시 데드락 소켓을 물고 미복구. 수정 = `enb2.conf` `fail_on_disconnect=false→true`(백업 `enb2.conf.bak_phase3`) + compose로 `ran_enb2`+`attacker_ue`만 병렬 force-recreate(`--no-deps`, 정상 ran_enb/uav_ue 미접촉). 결과 RACH→`Network attach successful. IP: 10.45.0.16→동적 10.45.0.17`. 블라스트 반경 attacker 경로 한정, 보호 UAV 무영향.
- **A5(UE-pool role_verified) ✅** (recon=allow_live=True read-only tun-scan): `role_verified{uav_ue:true, attacker_ue:true, ...}` 전부 True, `ip_map{attacker_ue:10.45.0.17, uav_ue:10.45.0.2}` 라이브 동적 해석. **이중 operator-go 게이트 (a) 실증**.
- **C1~C3 결정관통 ✅** (스플릿: recon=allow_live / 집행 Backend=allow_live=False DRY): 실 role_verified 위에서 `mdg`가 관통 —
  - C1: correlate `incidents=[{kind:BACKDOOR_5762, target:10.45.0.17, members:[Port_5762_State], score:1.0}]` (source 셀렉터 `10.45.0.17` 운반).
  - C2: act ledger `rule=backdoor_drop, tool_id=nsenter_input_drop, enforce_at=uav_ue, target=10.45.0.17, target_kind=ip, operator_gate=false(AUTO)`, decide `enforcement=auto, confidence=1.0`, risk=MED·reversible.
  - **C3(역사적 blocker) ✅**: 결정이 act까지 관통 + `provenance=verified` → legality가 **라이브 role_verified 컨테이너키로 통과**(e2e 인위주입 없이). 154/189 pytest가 green이어도 못 닫던 관문을 라이브로 닫음.
  - **무해성 교차확인 ✅**: `applied.backdoor_drop.confirmed=false·reverted=false` + `uav_ue INPUT = -P INPUT ACCEPT`만(10.45.0.17 DROP 규칙 0) → 실 상태변경 0. 종료 후 held-5762 teardown, 5762 ESTAB 소멸·MDG orphan proc 0(누수-0).

### 완료 (2026-07-08: D/E 실집행 — operator `!`-run, allow_live=True) ✅
operator가 `d_fire.sh`(발화→검증→trap 무조건 revert)를 세션 `!`로 직접 실행. attacker tun **10.45.0.17**.
- **D2 실 자율 DROP ✅**: MDG 그래프가 operator 개입 0으로 `nsenter --target <uav_ue pid> --net -- iptables -w -I INPUT -s 10.45.0.17 -j DROP` 집행 → uav_ue netns에 `-A INPUT -s 10.45.0.17/32 -j DROP` 설치 확인. (recon-only P4 best-effort; SMF 교차확인은 아래 finding으로 미배선.)
- **안전 ✅**: DROP `-s`=10.45.0.17(attacker) — UAV 10.45.0.2는 규칙에 없음(사전/사후 assert).
- **D3 실 트래픽 차단 ✅**: DROP 후 신규 attacker→uav:5762 = `TimeoutError`(차단). 배선 전 reachable→후 차단.
- **D4 self-DoS0 ✅**: DROP 중 UAV C2 HB(lo 14550) 정상 캡처, uav_ue tun 유지. UAV 무영향(DROP이 loopback HB 미접촉).
- **E1 revert ✅**: trap이 `iptables -D` → INPUT `-P ACCEPT`만, 도달성 `E1_OK_reachable_again` 원복.
- **E2 누수0 ✅**: orphan nsenter/iptables proc 0. **E4 ✅**: 컨테이너 20 복원, DROP 잔존 0.
- 관측성 노트(비결함): `applied.confirmed=true` 토큰 grep 미매치 — 실 규칙 설치+D3 실차단이 집행 결정 증거. effect_confirm 사후틱 부족 추정(max_iters=10).

### ★ finding: P4 SMF 교차확인 이 split-core(Open5GS)에선 미배선
- SmfSessionTable 콜렉터가 `epc_smf`를 tail하나, 이 코어의 4G 공격자 세션(IMSI002)은 **`epc_smf` 미로깅**(NRF 등록실패 반복). IMSI↔IP가 단일 로그에 없음: `epc_upf`=IPv4만(F-SEID, IMSI 없음)·`epc_mme`=IMSI만(IP 없음)·`epc_smf`=07/02 IMSI001만.
- 결과: `smf_table` present-empty면 P4가 **fail-closed(DROP 거부)** = 안전측. 라이브 실집행은 `epc_builder=None`(recon-only best-effort)로 발화 — recon 귀속(10.45.0.17→attacker_ue verified)이라 blind-drop 아님.
- 후속 과제(라이브 후): epc_upf(F-SEID↔IP)+smf/mme(F-SEID/IMSI) 멀티로그 상관 콜렉터 or Open5GS SMF 4G 세션 로깅 복구로 P4 defense-in-depth 완성.

### ★ 라이브 검증이 잡은 버그 2건 (단위테스트 불가, 검증된 방식으로 수정)
| 버그 | 근본원인 | 수정 |
|---|---|---|
| **B2 source=""** | `parse_ss_peer`가 5컬럼(`ESTAB 0 0 local peer`) 기대. 실제 `ss -H -tan state established`는 **State 컬럼 생략→4컬럼**(`Recv-Q Send-Q local peer`) → `len<5` 가드가 거부 | `web.py:57` `<5`→`<4` + 양포맷 회귀테스트 |
| **탐지 전무(mission_context만)** | `_SafeExecDocker._inspect`가 `docker inspect`에 `read_only=True` 미설정 → allow_live=False에서 DRY 강등 → recon pid 미해석 → netns collector inert | `live_autorun.py` inspect `read_only=True`(데몬읽기=read-only, resolve.py stage-1 정합). tun스캔(nsenter ip)은 operator-go 유지 |

> (구 기록 갱신) 이전에 "대기"였던 **A5·C(결정관통)**는 2026-07-08 무해 G1 스플릿으로 **완료**(위 블록). 남은 대기는 D/E 실집행뿐.

---
*요약: 자율 DROP 라이브 검증은 (A)회귀게이트→(B)탐지관통 read-only→(C)결정계획 DRY→(D)operator승인 실DROP+E4→(E)복원·누수0·결정론. C3(legality 라이브 통과)·B1(uav_ue netns 탐지)·B3(N3 오탐제거)·D3(E4 실차단)이 단위테스트 불가한 라이브 급소다. 이름(source/BACKDOOR_5762/backdoor_drop)은 배포 전 구현 실명칭으로 치환.*
