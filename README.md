# DAH 2026 — 4G UAV (테스트베드 + 공격/방어 AI 에이전트)

시크릿(ARIA·서명키·API 키)은 저장소에 없음 — `.env`(gitignore)로 주입한다.

## 구성
- `testbed/` · `testbed-split/` : 테스트베드
- `defense_agent/` : 방어 에이전트 
- `attack_agent/` : 공격 에이전트 

---

## 실행 방법 (새 인스턴스, git clone 부터)

### 0) 클론 + 시스템 준비
```bash
git clone https://github.com/Kjhyun04/dah2026 ~/dah2026
bash ~/dah2026/testbed/scripts/00-server-setup.sh     # docker + SCTP + TUN + venv 등
# 반드시 재로그인 (docker 그룹 활성화): exit → 다시 ssh 접속
```

### 1) 테스트베드 기동 
```bash
bash ~/dah2026/testbed-split/bringup.sh --check       # (선택)사전검증
bash ~/dah2026/testbed-split/bringup.sh               # 이미지 빌드 + 19 컨테이너 + 키 자동생성
```

### 2) 방어 에이전트
```bash
cd ~/dah2026/defense_agent
python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"
./dah.sh verify && ./dah.sh test                       
cp .env.example .env                                  
sudo -E bash dah.sh monitor                            
#   다른 창(뷰어):
 cd ~/dah2026/defense_agent
 bash dah.sh viewer live_out/monitor/run.jsonl   → 127.0.0.1:8787
```

### 3) 공격 에이전트 (자율 공방전)
```bash
cd ~/dah2026/attack_agent
python3 -m venv .venv && . .venv/bin/activate && pip install -e .
./dah.sh verify                                        
./dah.sh build-tools                                  
cp .env.example .env                                   
./dah.sh campaign                                      
#   다른 창(뷰어):
cd ~/dah2026/attack_agent
bash dah.sh viewer   → 127.0.0.1:8090
```

---

## LLM 키 설정 (`.env`)
키 1개 + 모델 slug 만 채우면 아무 플랫폼(Anthropic/OpenRouter/OpenAI/Gemini)에서 동작한다.
 값은 `=` 바로 뒤에 공백 없이 붙여 쓴다.

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
