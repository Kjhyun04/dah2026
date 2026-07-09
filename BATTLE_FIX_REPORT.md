# AI 공방전 실행 수정 보고서 (2026-07-09)

> 목적: "AI 에이전트 공방전(공격→방어 탐지→방어 LLM 판단→복구)"이 가시적으로 실행되지 않던
> 문제를 3-전문가 진단(ultracode)으로 규명하고, 코드·문서·이미지·설정을 수정해 **E2E 실증**한 기록.

## 사용자 질문 답: "방어만 문제인가, 공격도 문제인가?"

**둘 다였습니다.** 3-전문가(AI개발자·UAV·4G) 만장일치. 인과 사슬:

```
[공격] 툴링 사이드카 이미지에 baked 스크립트 부재
  └ recon(docker exec <sidecar> dah_exec/…)이 스크립트를 못 찾아 reach 를 못 만듦
  └ → 주입 tool(serial5762 등)이 영영 non-runnable → recon/key-leak 무한루프
        ↓
[방어] 능동주입 트래픽이 없어 compute_impact 가 매 틱 Green→END 단락(설계상 정상)
  └ orient 미도달 → LLM 미발화
        ↓
[방어 LLM] 설령 orient 도달해도 침묵:
  └ has_api_key() 가 ANTHROPIC_API_KEY 만 확인 + models.yaml anthropic/ 직결
    + client 가 json_schema response_format 를 항상 전송(OpenRouter 경유 400)
```

## 근본원인 3종과 수정

### ① 방어 LLM provider drift (blocker) — 가용 키(OpenRouter)로 절대 발화 불가
- **원인**: `has_api_key()` 가 `ANTHROPIC_API_KEY` 만 확인, `models.yaml` 이 `anthropic/claude-*`
  직결 고정, `complete_structured` 가 모든 모델에 `json_schema response_format` 강제(OpenRouter→
  Anthropic 경유에서 400/타입위반), egress 도 `api.anthropic.com` 단독. → 가용 키가 OpenRouter 면
  `make_orient_llm/make_decide_llm` 이 항상 None → 결정론 폴백(무발화).
- **수정 (provider 하드코딩 제거 · env 선택)**:
  - `mdg/config/models.yaml`: 최상위 `api_key_env`(기본 OpenRouter, Anthropic 직결로 교체 가능)
    + 모델 slug 를 provider 별로 파라미터화 + `egress_allowlist` 에 `openrouter.ai:443` 추가 + 문서화.
  - `mdg/llm/client.py`: `has_api_key(api_key_env)` 가 설정된 env 를 읽음(ANTHROPIC 하드코딩 제거).
    `complete_structured` 는 `model.startswith("anthropic/")` 일 때만 response_format 첨부
    (openrouter/* 엔 생략 — `_parse_capped` 의 `model_validate_json` 이 authoritative 게이트라 안전).
  - `mdg/llm/orient.py`·`decide.py`: `has_api_key(cfg.get("api_key_env"))` 전달.
  - `.env.example`: `OPENROUTER_API_KEY` 추가 + anthropic 직결/openrouter 두 경로 안내.
- **검증**: `pytest` 269 passed·1 skipped(회귀 0), `./dah.sh verify` ALL GATES PASS,
  `make_orient_llm/make_decide_llm` 실호출 → ORIENT/DECIDE 유효 JSON 반환(OpenRouter).

### ② 공격 툴링 사이드카 이미지 부재 (blocker) — recon 이 reach 를 못 만듦
- **원인**: 공격 tool 은 `docker exec <sidecar> dah_exec/R4_UE_ENTRY/recon_ue_entry.sh` 로 **이미지에
  baked 된** 스크립트를 실행한다(`sidecar/air/Dockerfile`: `COPY exec/ /opt/dah/exec/`, `WORKDIR
  /opt/dah/exec`). 그런데 이 툴링 이미지가 **빌드되지 않았고**, 이전에 "이미지 부재" 회피로 config 를
  테스트베드 SITL 이미지 `dahv2/air`(스크립트 없음)로 바꿔버렸다. → 사이드카에 스크립트가 없어 recon 이
  아무 reach 도 산출 못 함(`kb_final.facts` 에 reach 전무) → 주입 tool 이 영영 안 열림.
- **수정**:
  - 툴링 이미지를 **`dahv2/air-tools`** 로 빌드(테스트베드 `dahv2/air` SITL 와 태그 충돌 회피).
    `./dah.sh build-tools` 서브커맨드 추가(pymavlink host 버전 핀, vendor placeholder 로도 5762 공방전 충분).
  - `configs/config.live.yaml`: `tools.image.air: dahv2/air-tools`.
  - `sidecar/air/exec/dah_exec/R4_UE_ENTRY/recon_ue_entry.sh`: tun point-to-point 대비 자기 인터페이스
    /24 도 스윕(UE-pool 피어 포함) — 견고성 보강.
  - `dah.sh campaign`: 기본 goal 을 `goal.land`(mode_set mode=9 LAND, 실주입 필수)로 전환.
- **검증**: 빌드 후 실제 캠페인 사이드카(`dah_tools_ue`)에서 recon 이 `uav5762@10.44.0.30` **identified**,
  `kb_final.facts` 에 `reach(uav5762)` 등 확립. 자율 캠페인이 **serial5762 ×5(5762 백도어 주입) +
  recon_defense·observe_mode·capture_downlink·peer_flood** 전 계층 능동공격 실행(이전엔 recon+key-leak 뿐).

### ③ 방어 탐지 타이밍 (관측 한계, 문서화)
- **현상**: 자율 캠페인의 `serial5762` 는 "단일연결·수명관리(포화 금지)"라 **연결이 매우 짧아**,
  방어 `WebProbe`(5s 주기 `ss` 스냅샷)가 `Port_5762_State=ESTAB_PRESENT` 를 놓친다 → Green 단락.
- **결론**: **지속 주입이면 방어가 정상 탐지**한다(아래 E2E 실증). 자율 캠페인의 브리프 주입까지
  잡으려면 (a) 방어 WebProbe 를 conntrack/SYN 기반으로 보강하거나 (b) serial5762 가 연결을 window
  동안 hold 하도록 조정해야 한다(후속). 최소 가시 공방전에는 지속 주입(`./dah.sh land`)으로 충분.

## E2E 공방전 실증 (2026-07-09, 라이브 테스트베드)

`./dah.sh land`(지속 5762 LAND 주입) + 방어 monitor(root·`MDG_ALLOW_LIVE=1`·OpenRouter LLM):

| 관측 | 결과 |
|---|---|
| 공격 5762 주입 | `uav_ue` netns **5762 ESTAB=1 유지** |
| 방어 탐지 | `Port_5762_State=ESTAB_PRESENT` → compute_impact non-Green |
| 방어 파이프라인 | `orient·select_policy·rank_recovery·decide·act·effect_confirm` **풀 도달** |
| 방어 LLM | 매 틱 **OpenRouter egress 포착**(orient/decide advisory 실발화) |
| 복구 | `act`(nsenter_input_drop@uav_ue = 5762 백도어 차단) → effect_confirm |

→ **"공격 5762 백도어 주입 → 방어 탐지 → orient/decide LLM 판단 → nsenter DROP 복구" 완결 실증.**

## 공방전 실행법 (감독관/재현)

```bash
# 0) 방어 LLM 키: defense_agent/.env 에 OPENROUTER_API_KEY 채움(또는 ANTHROPIC 직결 — models.yaml api_key_env)
# 1) 공격 툴링 이미지 빌드(1회):
cd attack_agent && ./dah.sh build-tools
# 2) 방어 monitor(root+LIVE+LLM):
cd defense_agent && sudo -E env INTERVAL=5 bash dah.sh monitor
# 3) 공방전:
#    (가시 실증) cd attack_agent && ./dah.sh land          # 지속 5762 LAND 주입 → 방어 탐지·복구
#    (자율 캠페인) ./dah.sh campaign                        # 자율 LLM 계획(serial5762 등 주입 실행)
# 4) 뷰어: 방어 http://127.0.0.1:8787 · 공격 http://127.0.0.1:8090 · 텔레메트리 :8080
```

## 변경 파일
- 방어: `mdg/llm/client.py`, `mdg/llm/orient.py`, `mdg/llm/decide.py`, `mdg/config/models.yaml`, `.env.example`
- 공격: `configs/config.live.yaml`, `dah.sh`(build-tools + goal.land 기본), `sidecar/air/exec/dah_exec/R4_UE_ENTRY/recon_ue_entry.sh`
- 신규 이미지: `dahv2/air-tools`(= `sidecar/air/Dockerfile` 빌드)

## 보안 불변식 유지
인가된 격리 샌드박스 · 가역/무해(nsenter DROP·docker 조작만, 컨테이너 stop 없음) · 키 서버 밖 반출 0
(문서 마스킹) · 실기체/실이동통신망 아님 · MDG key-free(서명은 gcs_c2 위임) · `MDG_ALLOW_LIVE=1`/
`MDG_OPERATOR_AUTO=1` 는 SITL/샌드박스 전용.
