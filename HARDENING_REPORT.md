# 방어 하드닝 · .env 이식성 수정 보고서 (2026-07-09)

> `BATTLE_FIX_REPORT.md`(공방전 성립)에 이어, 4개 조율 변경을 ultracode 4-전문가 설계 후 구현·검증.
> 결정 반영: **재이륙 복구 현행유지 · 5762 하드닝 토글 없음 · 감독관 .env 만으로 아무 플랫폼 · PFCP 필수 탐지·차단.**

## ① 감독관 편의 — .env 에 키+모델명만 채우면 아무 플랫폼에서 실행

방어·공격 LLM 을 provider 하드코딩 없이 **.env 파라미터**로 구동. litellm 이 모델 slug 접두
(`openrouter/` · `anthropic/` · `openai/` · `gemini/` …)로 provider 라우팅하고, 키 값을 **명시 주입**
하므로 하나의 키로 어떤 플랫폼이든 인증(관례 env 이름과 무관).

- 방어: `mdg/config/loader.py` `_apply_model_env()` 오버레이 + `mdg/llm/client.py` `resolve_api_key()` +
  `complete_structured(api_key=)` · orient/decide 가 스레딩. `response_format`(json_schema)은 `anthropic/*`
  에만 첨부(그 외 provider 는 생략, 로컬 `model_validate_json` 이 authoritative 게이트라 안전).
- 공격: `configs/config.live.yaml` `${LLM_MODEL:-…}`/`${LLM_API_KEY_ENV:-LLM_API_KEY}` 치환 +
  `core/common/llm.py`·`orchestrator.py`·`driver.py` api_key 스레딩.

**감독관 .env (키+모델만):**
```bash
# 방어(defense_agent/.env)
MDG_LLM_API_KEY=<키>          # provider 무관 값 1개
MDG_ORIENT_MODEL=<slug>       # 예) openrouter/anthropic/claude-sonnet-4.5 | openai/gpt-4o-mini | anthropic/claude-sonnet-4-5 | gemini/gemini-2.0-flash
MDG_DECIDE_MODEL=<slug>       # 예) openrouter/anthropic/claude-opus-4.1 | openai/gpt-4o
# 공격(attack_agent/.env)
LLM_MODEL=<slug>             # 예) openrouter/anthropic/claude-sonnet-4 | openai/gpt-4o
LLM_API_KEY=<키>
# (관례키 재사용 시: MDG_LLM_API_KEY_ENV / LLM_API_KEY_ENV 로 이름 지정, 예 OPENROUTER_API_KEY)
```
- 검증: `MDG_ORIENT_MODEL=openai/gpt-4o-mini MDG_DECIDE_MODEL=gemini/gemini-2.0-flash` → loader 가 정확 해석,
  `resolve_api_key` OK, **pytest 269 passed**. 공격 `LLM_MODEL=openai/gpt-4o` → config 치환 OK, **verify ALL GATES PASS**.
- 하위호환 주의: 공격 기본 키 이름이 `OPENROUTER_API_KEY`→`LLM_API_KEY` 로 바뀜. 기존 OpenRouter 키만
  쓰던 런북은 `LLM_API_KEY_ENV=OPENROUTER_API_KEY` 지정(또는 LLM_API_KEY 채움).
- 키 위생: 키 값은 in-process litellm `api_key` 인자로만 전달, State/JSONL/프롬프트/로그 미노출(PS-3), MDG key-free 유지.

## ② PFCP(delete/flood) 반드시 탐지 + 차단/복구

PFCP 단독 공격이 `distrust 36 < session_network floor 40` 이라 Green 으로 희석돼 미탐이던 것을 수정.

- `defaults.py`/`thresholds.yaml`: `PFCP_Delete_Attempt` weight **0.40→0.55** → danger distrust **49.5 ≥ floor 40
  → crit_floor 45 → Yellow → orient**. warning/critical 은 여전히 Green(오탐 방지).
- `correlate.py`: PFCP 를 전용 kind **`PFCP_DELETE`** 로 분류(단일신호 오분류 방지). ★보안: PFCP 는
  공격자 귀속 소스가 없으므로(Prometheus 집계=무IP, SMF 로그=피해자 tun-IP) **target=''** 로 fail-closed →
  pfcp_firewall 가 피해자 IP 를 DROP 하는 self-DoS 원천 차단.
- `select_policy.py`: `_INCIDENT_RECOVERY['PFCP_DELETE']=['pfcp_firewall']`(nsenter_input_drop, MED, 가역).
- `compute_impact.py`: CR01 동시-틱 상관(PFCP_Delete + Unauthorized_Command, 각 도메인 floor 미만이어도)
  발생 시 band 1단 bump(이번 틱 한정) → 2신호 CR01 이 Green 을 벗어나 orient.
- 검증: distrust **49.5 / floor 45**(수학), PFCP단독→`PFCP_DELETE` target='' + `pfcp_firewall` 매핑(흐름),
  5762→`BACKDOOR_5762` target=peer(대조), **pytest 269 passed**.

## ③ 5762 백도어 브리프 주입 확정 탐지 (토글 없음, 항상 on)

자율 `serial5762` 는 연결이 짧아 방어 `ss` 5s 스냅샷이 놓치던 것을, iptables 카운터로 결정론 포착.

- testbed `scripts/50-sitl-up.sh`: uav_ue netns 에 **DAH5762 관측 계수 체인** 설치(항상, DROP/REJECT 없음 →
  트래픽·공격성공 불변). `-p tcp --dport 5762 -j DAH5762`, `-i lo RETURN`(로컬 제외), `--syn -j NFLOG`
  (미지원 시 comment 폴백)로 SYN 카운트. 정상 5762 legit 없음(C2=14550 서명·GPS=14540 lo) → 순수 공격신호.
- 방어 `collector/web.py`: `iptables -n -v -x -L DAH5762` 로 SYN 카운터 읽어 델타 게이팅 → 브리프 연결도
  `Port_5762_State=ESTAB_PRESENT` 방출(source='' 탐지전용; 지속연결은 기존 ss 경로가 peer 제공).
- 방어 `safe_exec/backend.py`: `iptables` 를 읽기전용 관측자에 추가하되 **listing(-L/-S/-C)만 허용, mutating
  verb(-A/-F/-Z/-X 등, 결합 플래그 포함) 전량 거부** — read-only fast-path 신뢰경계 유지.
- 검증: 브리프 연결 3회 → **DAH5762 SYN pkts 0→3**, backend 허용 단위(listing True / -F,-Z,-A False),
  **E2E: monitor 가 카운터로 탐지 → orient·decide·rank_recovery·act·effect_confirm 풀 도달(LLM 에러 0)**.

## ④ ARIA 키 위생 — `--key-hex` argv 노출 제거

ARIA 마스터키가 프록시 `--key-hex ${ARIA_KEY_HEX}` argv 로 `docker inspect`/`ps` 에 노출(=공격 key-leak
승리요인 + forge_sign 위조서명 가능)이던 것을 **파일마운트 주입**으로 전환.

- `proxy/mav_aria_proxy.py`: `--key-hex` 없으면 `ARIA_KEY_FILE`(파일) → env `ARIA_KEY/ARIA_KEY_HEX` 순으로
  64hex 추출(`.mav-sign-key` 규약 정합). `--key-hex` 는 selftest/수동용만 유지.
- `compose/docker-compose.{uav,gcs}.yml`: `../.env-aria:/aria.key:ro` 마운트 + `ARIA_KEY_FILE=/aria.key`,
  command 에서 `--key-hex ${ARIA_KEY_HEX}` 제거. 두 프록시 동일 파일 → 동일 키(G4 왕복).
- `scripts/70-aria-up.sh`: 부분키 로그(`앞8`) → **sha256 지문**(비가역)만. dead `export ARIA_KEY_HEX` 제거
  (`80-web-up.sh` 도).
- 검증: 프록시 selftest ✅, 파일서 64hex 추출·32바이트 OK, 파일마운트 프록시 기동 시 **키 값이 docker
  inspect·ps args 에 미노출**(정밀 대조). ※이미 실행 중인 구 프록시는 다음 rebuild 시 교체.

## 검증 요약 (커밋 전, 문제 0)
| 영역 | 검증 | 결과 |
|---|---|---|
| 방어 회귀 | `pytest` | **269 passed, 1 skipped** |
| 방어 게이트 | `./dah.sh verify` | ALL GATES PASS |
| 방어 .env 다중 provider | loader/resolve (openai·gemini slug) | 정확 해석 |
| 공격 .env | config 치환 + verify | openai/gpt-4o 치환 · ALL GATES PASS |
| PFCP | 수학·흐름·self-DoS | 49.5/45 · PFCP_DELETE→pfcp_firewall · target='' |
| 5762 NFLOG | 카운터·backend·E2E | 0→3 · listing만 허용 · orient 풀 도달 |
| ARIA | selftest·파일읽기·무키 | ✅ · inspect/ps 키 미노출 |

## 변경 파일 (27)
- 방어: `mdg/config/{loader,models.yaml,defaults,thresholds.yaml}` · `mdg/llm/{client,orient,decide}` ·
  `mdg/core/nodes/{correlate,select_policy,compute_impact}` · `mdg/safe_exec/backend` · `mdg/collector/web` · `.env.example`
- 공격: `configs/config.live.yaml` · `core/common/llm` · `core/{orchestrator,driver}` · `.env.example` · `dah.sh` · `sidecar/…/recon_ue_entry.sh`
- testbed: `proxy/mav_aria_proxy` · `compose/docker-compose.{uav,gcs}.yml` · `scripts/{50-sitl-up,70-aria-up,80-web-up}`

## 보안 불변식 유지
가역/무해(관측 계수·나열만 추가, DROP/REJECT 신규 없음) · 키 서버밖 반출 0(문서 지문/마스킹) ·
MDG key-free · LLM edge-invisible(결정론 제어, api_key 는 전송 인증만) · 실기체/실이동통신망 아님.
