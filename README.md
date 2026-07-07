# DAH 2026 — 방산 AI 사이버보안 (공격 에이전트 + 테스트베드)

인가된 격리 UAV C2 테스트베드에서 **계획된 공격 시나리오를 자동 수행하는 공격 AI 에이전트**와 그 대상 **격리 테스트베드** 소스.

## 구성
| 디렉터리 | 내용 | 실행 |
|---|---|---|
| **`attack_agent/`** | 공격 자동수행 AI 에이전트 (4계층·닫힌 23 tool·독립 감독) | `cd attack_agent&& pip install -e .&& ./dah.sh verify` |
| **`testbed/`** · **`testbed-split/`** | 격리 4G UAV C2 테스트베드(EPC+srsRAN+SITL+ARIA) | 패키지를 `~/`에 전개 후 `bash ~/testbed-split/bringup.sh` (2-스텝 배포·상세 `testbed/README.md`) |

## ⚠️ 범위 · 안전
- 인가된 CTF/공모전 **샌드박스(SITL 시뮬)** 전용. 실 이동통신망·운용 UAV 대상 금지.
- **시크릿(ARIA·서명키·API키)은 저장소에 없음** — `.env`(gitignore)로 외부 주입. `.env.example` 참고.
- 배포 패키지(`dah-testbed-deploy.tgz`, 시크릿 동봉)는 비공개 전송 전용(저장소 미포함).
