# sidecar/pfcp — `dahv2/pfcp-poc` 툴링 사이드카 (B 계층 · 골격)

> 오프라인 골격 · 테스트베드 무접속 · 실제 `docker build`/scp/배포는 **통제단계**에서 수행.
> 근거: doc13(연결·vantage) · doc14(타깃식별) · doc18(구현결정) · doc19(누수-안전 R1~R6).

## 1. 정체

B 계층(코어망 PFCP · 측면이동)의 scapy 기반 PoC 툴링을 baked 한 **장수 사이드카**.
`pfcp_delete` · `pfcp_flood` · `pivot_exploit` · `learn_seid`(recon_session) ·
`capture_s1u`(S1-U 캡처) 를 host 실행기가 `docker exec` 로 구동한다(registry `sidecar="core"`).

## 2. 실행 전제 (netns/네트워크 공유 + `docker exec`)

- **금지(하드):** `docker run --rm` 단명 사이드카 · ENTRYPOINT 자동실행 · SSH.
  대신 장수 사이드카(CMD `sleep infinity`) + `docker exec`(doc13 §2, 종료계약).
- **공유 실행 모델:** `air` 사이드카의 `tools_ue` 가 `--network container:attacker_ue`
  로 rogue UE 의 **netns 를 공유**하듯, 사이드카는 대상 컨테이너를 오염시키지 않고
  네트워크 시야만 공유한 채 `docker exec` 로만 작업을 받는다.
- **★ 이 사이드카의 vantage(doc13 §3·doc14 §3):** 네트워크 시야는 **`net_core`(pivot 후)**.
  pivot 전에는 net_core 격리(✗)이며, `tools_core` 는 pivot 성공 후 net_core 에 접속한다.
  공격 **원점 foothold 는 `attacker_ue`**(pivot 은 attacker_ue → dual-homed pivot →
  net_core 경로). pivot 미기동 시 T2 측면이동은 봉쇄(doc14 §5).
  - 정직성 노트: 상위 지시의 "netns 공유(attacker_ue)"는 **공격 원점/실행 계약**을 뜻하고,
    실제 이 사이드카가 **접속하는 net 은 net_core** 다(doc13 §3 실측). 배치 방식(attacker_ue
    netns 공유 vs net_core 접속)은 통제단계 확정 필요 — decisions 참조.

## 3. 누수-안전 불변식(R1~R6)이 이미지에 요구하는 것

| 불변식 | 이미지 제공 | 실행기(host) 책임 |
|--------|-------------|-------------------|
| **R1** in-container timeout + JOB 마커 kill | `coreutils`(timeout) · `util-linux`(setsid) · `procps`(pkill) | `docker exec $SC sh -c "exec -a $JOB setsid timeout … <script> > /tmp/out.$JOB 2>&1"` · 회수=`pkill -KILL -f $JOB` |
| **R2** 라벨 + teardown + reap | 이미지 라벨 `org.dah.image=dahv2/pfcp-poc` | 컨테이너 라벨 `dahv2.owner=agent`,`dahv2.run_id=$RUN` · pivot 동적 사이드카도 동일 라벨→일괄 reap |
| **R3** preflight | scapy 설치 · 핀(ARG) | init 이 사이드카 안에서 scapy import·버전 정합 확인 |
| **R5** reaper 백스톱 | `iproute2`(ss) · `procps`(pkill) | JOB 마커 기반 백스톱 종료 |
| **R6** 비밀 stdin | (B 계층 PoC 는 소비 비밀 없음 — 해당 시 stdin 규약) | vault→stdin(argv/평문 env 금지) |

> **PIPE 데드락 회피:** 출력은 컨테이너 내부 파일(`/tmp/out.$JOB`)로 리다이렉트 후
> 파일/스트림으로 읽는다(PIPE 캡처 금지). `capture_s1u` 는 tcpdump→오프라인 파싱(doc18 G-b).

## 4. exec 채움 (★ 통제단계에서만)

`exec/` 는 비워 두고 참조만 한다. `docker build` 전에 통제단계에서 read-only scp 로 채운다.
`exec/README.md` 의 경로 계약(core_exec/…) 참조.

## 5. build (참고 · 통제단계 명령, 여기서 실행하지 않음)

```bash
# 통제단계에서 exec/ 를 scp 로 채운 뒤:
docker build -t dahv2/pfcp-poc ./sidecar/pfcp
```

- `config.tools.image.pfcp = dahv2/pfcp-poc`(옵션 — B 계층 pivot 시나리오에서만).
- pivot(net_core) 은 동적 사이드카 예외(doc18 C7): 부트스트랩이 아니라 pivot 성공 후 기동,
  단 R2 라벨은 동일하게 부여하여 teardown/reap 에 함께 걸린다.

## 6. 정직성 노트

- 이 디렉터리는 **골격(Dockerfile + 채움 계약)** 만 담는다. PFCP 공격 스크립트 자체는
  여기서 생성하지 않는다(오프라인 · 통제단계).
- scapy 버전 핀·vantage 배치·pivot 사이드카 수명은 통제단계 검증 대상.
