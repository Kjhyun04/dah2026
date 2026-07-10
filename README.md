# DAH 2026 — 4G UAV C2 공방 (테스트베드 + 공격/방어 AI 에이전트)

인가된 격리 SITL 샌드박스 전용. 실기체·실이동통신망 대상 금지.
시크릿(ARIA·서명키·API 키)은 저장소에 없음 — `.env`(gitignore)로 주입한다.

## 구성
- `testbed/` · `testbed-split/` : 격리 4G UAV C2 테스트베드 (Open5GS + srsRAN + ArduPilot SITL + ARIA)
- `defense_agent/` : 자율 방어 에이전트 (11노드 결정론 파이프라인 + LLM advisory)
- `attack_agent/` : 자율 공격 에이전트 (닫힌 22 tool + LLM 계획 + 독립 감독)

---

## 실행 방법 (새 인스턴스, git clone 부터)

### 0) 클론 + 시스템 준비
```bash
git clone https://github.com/Kjhyun04/dah2026 ~/dah2026
bash ~/dah2026/testbed/scripts/00-server-setup.sh     # docker + SCTP + TUN + venv 등
# ★ 반드시 재로그인 (docker 그룹 활성화): exit → 다시 ssh 접속
```

### 1) 테스트베드 기동 (원-커맨드)
```bash
bash ~/dah2026/testbed-split/bringup.sh --check       # (선택) 비파괴 사전검증
bash ~/dah2026/testbed-split/bringup.sh               # 이미지 빌드 + 19 컨테이너 + 키 자동생성
docker logs -f gcs_c2                                  # 2~3분 양방향 C2 확인 후 Ctrl-C
```

### 2) 방어 에이전트
```bash
cd ~/dah2026/defense_agent
python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
./dah.sh verify && ./dah.sh test                       # ALL GATES PASS + 256 passed / 2 skipped
cp .env.example .env                                   # ↓ LLM 키/모델 채움 (비우면 결정론 폴백=안전)
sudo -E bash dah.sh monitor                            # 자율 감시 (netns 관측이라 sudo -E)
#   다른 창(뷰어): bash dah.sh viewer live_out/monitor/run.jsonl   → 127.0.0.1:8787
```

### 3) 공격 에이전트 (자율 공방전)
```bash
cd ~/dah2026/attack_agent
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
./dah.sh verify                                        # 11 게이트 PASS
./dah.sh build-tools                                   # ★ 캠페인 전 1회: 툴링 사이드카 이미지 빌드
cp .env.example .env                                   # ↓ LLM 키/모델 채움
./dah.sh campaign                                      # 자율 공방 (최대 200s — 끝까지 둘 것, Ctrl-C 금지)
#   다른 창(뷰어): bash dah.sh viewer   → 127.0.0.1:8090
```

---

## LLM 키 설정 (`.env`)
키 1개 + 모델 slug 만 채우면 아무 플랫폼(Anthropic/OpenRouter/OpenAI/Gemini)에서 동작한다.
★ 값은 `=` 바로 뒤에 공백 없이 붙여 쓴다(공백은 bash sourcing 오류).

Anthropic 직결 (예: 모두 Sonnet)
```bash
# defense_agent/.env
ANTHROPIC_API_KEY=sk-ant-...
MDG_LLM_API_KEY_ENV=ANTHROPIC_API_KEY
MDG_ORIENT_MODEL=anthropic/claude-sonnet-4-5
MDG_DECIDE_MODEL=anthropic/claude-sonnet-4-5
MDG_ORIENT_FALLBACK=
MDG_DECIDE_FALLBACK=
MDG_ALLOW_LIVE=1

# attack_agent/.env
LLM_MODEL=anthropic/claude-sonnet-4-5
LLM_API_KEY_ENV=ANTHROPIC_API_KEY
ANTHROPIC_API_KEY=sk-ant-...
TESTBED_HOST=127.0.0.1
```
OpenRouter 경유(기본): `api_key_env=OPENROUTER_API_KEY`, slug = `openrouter/anthropic/claude-sonnet-4.5`
(점 표기는 OpenRouter용, 하이픈 표기 `claude-sonnet-4-5`는 Anthropic 직결용)

---

## 뷰어 접속 (노트북에서 SSH 터널)
뷰어는 서버의 `127.0.0.1`에만 열려 있으므로, 노트북에서 터널을 연다.
```bash
ssh -i <키.pem> -L 8787:127.0.0.1:8787 -L 8090:127.0.0.1:8090 -L 8080:127.0.0.1:8080 ubuntu@<서버IP>
# 브라우저:  방어 http://localhost:8787 · 공격 http://localhost:8090 · 텔레메트리 http://localhost:8080
```

---

## 주의사항
- `00-server-setup.sh` 직후 **반드시 재로그인**(docker 그룹). 안 하면 bringup 이 연쇄 실패한다.
- `campaign` 은 최대 200초 자율 루프다. 화면이 조용해도 `runs/gate5_camp.log` 에 진행 중이니 **Ctrl-C 로 일찍 끊지 말 것**. `wc -l run_live.jsonl` 이 늘면 8090 뷰어가 채워진다.
- 시크릿은 인스턴스 내에서 자동 생성(`.mav-sign-key`·`.env-aria`)되어 컴포넌트 간 키가 일치한다. 방어 에이전트는 key-free(서명은 gcs_c2 위임).
- 키를 비우면 방어 LLM(advisory)은 결정론 폴백으로 침묵하며, 코어는 안전하게 동작한다.
