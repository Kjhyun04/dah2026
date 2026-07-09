# attack_agent — QUICKSTART (한 장 요약)

> 흩어진 명령·파일이 많아 보이지만, **실제로 쓰는 건 런처 하나(`dah.sh`)** 입니다.
> 아래만 알면 됩니다. 상세는 [README.md](./README.md) / [docs/DEPLOY_VERIFY_RUNBOOK.md](./docs/DEPLOY_VERIFY_RUNBOOK.md).

---

## 0. 정신모델 (딱 이거)

```
run.py = 에이전트 본체 (플래그로 offline/live 전환)
  └ run_live_gate5.py = run.py(캠페인) + 감독 동시  ← 헤드라인
  └ run_supervisor_standalone.py = 감독만 (netns 분리용)
  └ verify_*.py (8개) = 1회성 무결성 게이트 (평소 실행 X)
dah.sh = 위 전부를 감싼 단일 런처
```

## 1. 접속 · 환경

```bash
ssh -i "C:\Users\user\.ssh\<KEY>.pem" ubuntu@<TESTBED_IP>     # 키=<KEY>.pem
cd ~/attack_agent
# 웹 대시보드 볼 때만: ssh -i ...<KEY>.pem -L 8080:127.0.0.1:8080 ubuntu@<TESTBED_IP>
```

.env 에 키+모델 slug 만 채우면 됩니다 (그 외 기본값은 dah.sh 가 자동 주입):
- `LLM_MODEL` + `LLM_API_KEY` — 아무 플랫폼(OpenRouter/Anthropic/OpenAI/Gemini). 예) `LLM_MODEL=openrouter/anthropic/claude-sonnet-4`. 관례키 재사용 시 `LLM_API_KEY_ENV=OPENROUTER_API_KEY`
- `ARIA_KEY` — `testbed/.env-aria`에서 자동 로드 (감독 복호)
- ★ 캠페인 전 1회 `./dah.sh build-tools` (툴링 사이드카 이미지 dahv2/air-tools 빌드)

## 2. 런처 한 방 (`./dah.sh <명령>`)

| 명령 | 하는 일 | 내부적으로 |
|---|---|---|
| `./dah.sh verify` | 11개 게이트 전부 PASS/FAIL | verify.py(11게이트) |
| `./dah.sh recon` | 정찰만 (오프라인·무해) | `run.py --config configs/config.testbed.yaml --goal goals/goal.testbed.yaml` |
| `./dah.sh campaign` | **라이브 캠페인 + 감독** (헤드라인) | 내장 2-프로세스 오케스트레이션(nsenter 감독 + 캠페인) |
| `./dah.sh viewer` | 뷰어 3패널 (8090) | `viewer.server` |
| `./dah.sh status` | 컨테이너 + 드론 상태 | docker ps + 5762 readback |

**가장 흔한 흐름:** `./dah.sh verify` → `./dah.sh campaign` → `./dah.sh viewer`

## 3. 파라미터 파일 — 뭘 고르나 (변형은 무시해도 됨)

| 종류 | 실제 쓰는 것 | 변형(참고) |
|---|---|---|
| config | **`configs/config.live.yaml`** (라이브·서버) | `configs/config.testbed.yaml`(오프라인 베이스), `configs/config.example.yaml`(빈 템플릿) |
| goal | **`goals/goal.example.yaml`** (캠페인 기본 · mode_set mode=4 GUIDED 능동주입) | `goals/goal.p4.yaml`(서명우회 mode=5), `goals/goal.testbed.yaml`(정찰). `GOAL=` 오버라이드 |
| models | **`configs/models.yaml`** (모델 라우팅·1개면 충분) | — |

> config는 `테스트베드 접속·vantage·타깃 이름`, goal은 `공격 목표·방어 시드·계층 scope`만 담습니다. 하드코딩 0 — 값은 전부 여기서 주입.

## 4. 산출물 (뷰어·보고서용)

- `run_live.jsonl` — 에이전트 액션 로그
- `evaluation_live.json` — 감독 ground-truth 판정
- `supervisor_live.jsonl` — 뷰어 통신 프레임
- 자동 백업: `runs/archive_<timestamp>/`

## 5. 검증 파일이 왜 8개인가 (안심용)

평소 실행에는 **하나도 필요 없습니다.** 코드 무결성을 증명하는 CI 게이트이고, `./dah.sh verify` 한 줄로 전부 돕니다. 보고서 6장의 "검증 PASS" 증거일 뿐, 실행 경로가 아닙니다.

| 게이트 | 증명하는 것 |
|---|---|
| verify_p0 | 22 tool 계약·타입·legality |
| verify_p2 | recon 폐루프·실행 글루 |
| verify_grep0 | 공격 core ⟂ 감독 완전분리 |
| verify_viewer | 뷰어 read-only·redact·3패널 |
| verify_models | role→model 라우팅 |
| verify_bindings | registry exec 바인딩 |
| verify_parsers | raw→모델 파서 |
| verify_hygiene | 인코딩·위생 |
