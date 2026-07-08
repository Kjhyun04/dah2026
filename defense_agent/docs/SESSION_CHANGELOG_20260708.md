# MDG 방어 에이전트 — 변경 이력 (2026-07-08 세션)

> 이 세션에서 MDG(Mission-centric Defense Gateway) 방어 AI 에이전트에 적용한 전체 변경 요약.
> 상세: `LIVE_VERIFICATION_STATUS_20260708.md`(라이브 실증), `CODE_REVIEW_20260708.md`(리뷰),
> `PHASE3_DEFERRED_20260708.md`(품질 보류), `mdg/live/AUTODROP_LIVE_VERIFY.md §G`(검증 기록).

## 1. Phase 3 — 품질 28건 (ultracode 4그룹)
- **G-A** `verify/verify_routing.py`: FORBIDDEN_KEYS 정적 스캔을 edges.py→gate/legality/rank_recovery/select_policy로 확대(불변식① 회귀가드, 제어흐름 조건만 스코프).
- **G-C** `collector/mongo.py`: dedupe 키에 시간버킷 추가(방출 스칼라 무변, 캐시키만). air_side band·sense.py liveness·미방출 metric은 결정론 scoring 영향분이라 문서화-보류.
- **G-D** `config/{recovery_priors.yaml,defaults.py,loader.py}`, `core/nodes/act.py`: pfcp_firewall/mongo_acl operator-only 주석, 죽은 키 문서화.
- **G-B** `tests/test_qb_regression.py`: 신규 회귀 19건(is_read_only_argv·read_only 세마포어·driver fresh thread_id·correlate BACKDOOR_5762·parse_ss_peer 4/5열).
- 결과: 로컬 pytest 188→189(서버) green.

## 2. attacker attach 환경복구 (testbed, 영구)
- 근본원인: attacker 전용 eNB `ran_enb2`의 ZMQ RF `fail_on_disconnect=false`(정상 enb=true) → 데드락 소켓 미복구.
- 수정: `enb2.conf` `false→true`(백업 `.bak_phase3`) + compose로 ran_enb2+attacker_ue만 병렬 재생성. 보호 UAV(별도 eNB) 무영향.

## 3. 라이브 검증 (서버 <TESTBED-IP>, 인가된 격리 샌드박스)
- **무해 G1**(recon=allow_live / 집행=DRY 스플릿): A5 role_verified·C1~C3 결정관통·legality 라이브 통과 실증(실 DROP 없이). 역사적 blocker C3 닫음.
- **D/E 실집행**(operator `!`-run, allow_live=True): 그래프가 스스로 `iptables -I INPUT -s <attacker> -j DROP` 집행(D2) → 신규 5762 TimeoutError 차단(D3) → UAV C2 HB 무영향(D4) → trap revert·누수0·원복(E1/E2/E4).
- finding: 이 Open5GS split-core에서 P4 SMF 교차확인은 IMSI↔IP 단일로그 부재로 미배선 → recon-only best-effort 발화(안전측, 후속과제).

## 4. 프롬프트 enrich (agent_v2 양식, ultracode)
- `mdg/llm/prompts/{orient,decide}.jinja` + `mdg/llm/{orient,decide}.py` _SYSTEM 4면을 agent_v2 양식으로 재구성: ROLE·GLOSSARY·READ-ONLY tool-tier context·OUTPUT FORMAT 규격·스키마정확 예시·DO NOT.
- 불변식 보존: advisory-only·edge-invisible·raise-only, 새 jinja 변수 0(화이트리스트 4/4), 예시 `extra="forbid"` 정확일치.

## 5. 코드리뷰 + medium 2건 수정 (agent_v2/OSS 참조, ultracode)
- 리뷰 20 findings(`CODE_REVIEW_20260708.md`), 안전 문서화 fix 적용·나머지 보류.
- **D-LLM-1** `llm/client.py`: `_emit_temperature`에 `_ACCEPT_SAMPLING` 허용목록 + 미지 Anthropic 모델 fail-safe omit(400 대신). 신규 forward-safe 테스트.
- **D-ERR-1** `collector/base.py`: heartbeat를 성공 tick에서만 갱신 → 에러 지속 collector를 Watchdog가 dead 마킹. 신규 테스트 3건(pytest+standalone).
- 결과: 로컬 pytest 192, 서버 193 green.

## 6. 배포
- Phase 3 + 프롬프트 + 코드수정 전부 서버 `~/mdg` 배포, 서버 pytest 193 passed/1 skipped 확인. testbed 런타임 무접촉(20 컨테이너, INPUT ACCEPT, attacker attached).

---
*운영·보안 제약 준수(전 과정): 인가된 격리 샌드박스 · read-only/가역 기본 · 실 상태변경(DROP)은 operator 승인 `!`-run + trap 무조건 revert · 키 반출 0 · 문서 IP 마스킹 대상.*
