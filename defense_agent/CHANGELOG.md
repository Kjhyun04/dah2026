# CHANGELOG — defense_agent (MDG)

## 2026-07-09 · 5762 시리얼 백도어 벡터 제거

### 제거 (코드 · 문서 정합)
- **5762 백도어 탐지·복구 전 경로 삭제**: `WebProbeCollector`(uav_ue:5762 ss ESTAB 관측) ·
  `Port_5762_State` 신호 · correlate `BACKDOOR_5762` incident · `backdoor_drop` recovery(rtype) ·
  레지스트리 `read_port_state` tool(**TOOL_COUNT 27→26**) · 라이브 스크립트 `live/s3b_5762.sh` ·
  campaign `A4_5762_backdoor` 시나리오. 남은 로스터 = **A1/A2/A3/A5/A6**(5공격).
- **★ 유지 — `nsenter_input_drop` DROP 메커니즘 존속**: AUTO-tier nsenter+iptables DROP 도구 자체와
  2-엔드포인트(chokepoint⟂source) 안전 assert·fail-closed inert·record_intent·revert(누수-0) 불변식은
  그대로 유지된다. 이제 이 도구를 참조하는 복구는 `pfcp_firewall`(enforce_at gcs_proxy,
  트리거 `PFCP_Delete_Attempt`→`PFCP_DELETE`/CR01)·`mongo_acl`(enforce_at web_backend,
  트리거 `DB_Access`)이다. 단, `recovery_priors.yaml` 주석대로 **두 경로 모두 현재 operator-only/
  비자율(inert)**: PFCP는 correlate가 귀속 소스 없음→`target=""` fail-closed(자율 DROP 미발화),
  mongo_acl은 orphan(select_policy가 후보로 미방출). 즉 5762가 제공하던 "자율 nsenter DROP"의
  트리거는 제거되었고, 메커니즘은 PFCP/mongo에 배선된 채 operator-go로 남는다.

## 2026-07-08 · 라이브 검증 · 품질강화 · 배포 스캐폴딩

### 라이브 검증 (서버 · 인가된 격리 샌드박스)
- **자율 DROP 전 구간 실서버 관통 검증**: 탐지(5762)→`BACKDOOR_5762`→`backdoor_drop` AUTO→
  legality 라이브 통과→실제 `iptables -I INPUT -s <attacker> -j DROP` 집행→신규 5762 TimeoutError 차단→
  보호 UAV C2 HB 무영향→trap revert·누수0·원복. (operator `!`-run, `allow_live=True` 창)
- **무해 G1**(recon=allow_live / 집행=DRY 스플릿): A5 role_verified·C1~C3 결정관통·legality 라이브 통과를
  실 DROP 없이 실증, 역사적 blocker C3 닫음.
- finding: 이 Open5GS split-core 는 IMSI↔IP 단일로그 부재로 **P4 SMF 교차확인 미배선** →
  recon-only best-effort 발화(안전측, 후속과제). 상세 `docs/LIVE_VERIFICATION_STATUS_20260708.md`.

### Phase 3 — 품질 28건 (ultracode 4그룹)
- **G-A** `verify/verify_routing.py`: FORBIDDEN_KEYS 정적 스캔을 edges.py→gate/legality/rank_recovery/
  select_policy 로 확대(불변식① 결정론 라우팅 회귀가드, 제어흐름 조건만 스코프).
- **G-B** `tests/test_qb_regression.py`: 신규 회귀 19건(is_read_only_argv·read_only 세마포어·driver fresh
  thread_id·correlate BACKDOOR_5762·parse_ss_peer 4/5열).
- **G-C** `collector/mongo.py`: dedupe 키에 시간버킷 추가(방출 스칼라 무변, 캐시키만).
- **G-D** `config/*` + `core/nodes/act.py`: pfcp_firewall/mongo_acl operator-only 주석, 죽은 키 문서화.
- 결정론 scoring·자율DROP 경로 영향분은 강행 대신 문서화-보류(`docs/PHASE3_DEFERRED_20260708.md`).

### 코드리뷰 + 프롬프트 (medium 2건 수정, ultracode)
- 리뷰 20 findings(`docs/CODE_REVIEW_20260708.md`), 안전 문서화 fix 적용·나머지 보류.
- **D-LLM-1** `llm/client.py`: `_emit_temperature` 에 `_ACCEPT_SAMPLING` 허용목록 + 미지 Anthropic 모델
  fail-safe omit(400 대신). 신규 forward-safe 테스트.
- **D-ERR-1** `collector/base.py`: heartbeat 를 성공 tick 에서만 갱신 → 에러 지속 collector 를 Watchdog 가
  dead 마킹. 신규 테스트 3건.
- 프롬프트 enrich: `llm/prompts/{orient,decide}.jinja` + `llm/{orient,decide}.py` _SYSTEM 을 agent_v2 양식
  (ROLE·GLOSSARY·READ-ONLY tool-tier·OUTPUT FORMAT·DO NOT)으로 재구성. 불변식 보존(advisory-only·
  edge-invisible·raise-only, 새 jinja 변수 0).

### 환경복구 (testbed, 영구)
- attacker 전용 eNB `ran_enb2` 의 ZMQ RF `fail_on_disconnect=false`(정상 enb=true) → 데드락 소켓 미복구.
  `enb2.conf` `false→true`(백업 `.bak_phase3`) + compose 로 ran_enb2+attacker_ue 만 병렬 재생성.
  보호 UAV(별도 eNB) 무영향.

### 배포 스캐폴딩 (GitHub 배포 대응 · 이번 커밋)
- **단일 셸 진입점 `dah.sh`**(`verify|test|campaign|autorun|live|viewer|status`) — `.env` 자동 로드 +
  `TESTBED=${TESTBED_USER}@${TESTBED_HOST}`/`SSH_KEY` export → `mdg/live/*.sh` 전달.
- **단일 게이트 러너 `verify.py`**(= `./dah.sh verify`) — `mdg/verify/*.py` 9 게이트를 `python -m` 으로
  발견·실행, PASS/FAIL 요약, 실패 시 nonzero. 오프라인·무해.
- `pyproject.toml`(`[project] name=defense_agent`, `mdg*` 패키지, `requires-python>=3.12`,
  langgraph·litellm·pydantic·jinja2·pyyaml·grpcio·httpx) + `.gitignore`(.venv·캐시·`live_out/`·`*_out/`·
  `run.jsonl`·runs·`.env*`·`*.pem`) + `.gitattributes`(LF) + `.editorconfig`.
- `README.md` / `QUICKSTART.md` — 2대 불변식·파이프라인·실행·`.env`·docs 포인터.

### 보안 (비밀·서버정보 외부화 — 감사 결과 0)
- `mdg/live/*.sh`: `SSH_KEY`/`TESTBED` baked-in 기본값 제거, `${SSH_KEY:?…}`/`${TESTBED:?…}`(미설정 시
  즉시 실패). `campaign/artifacts.py`: 호스트 라벨을 `MDG_TESTBED_LABEL` env 로(IP 미노출 `<testbed>` 기본).
- 감사: **git 추적 파일에 실제 테스트베드 IP·SSH user·`.pem` 경로·키값 0**.
- PS-8 유지: `viewer/app.py`·`ingest/server.py` 의 `127.0.0.1` 루프백 바인드는 관리평면 보안 불변식(wildcard 금지).

### 검증 기준선
- 로컬 `pytest mdg/tests` **192 passed / 2 skipped**(SKIP 2 = langgraph 의존 그래프-컴파일, 예상). 서버 193 green.
- `./dah.sh verify` **9/9 게이트 PASS**(오프라인). `./dah.sh campaign` `report.json`(`live_executions=0`) 확인.
