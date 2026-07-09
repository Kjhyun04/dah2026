# sidecar/ — 툴링 사이드카 이미지 정의 (오프라인 골격)

> 이 디렉터리는 **이미지 정의(Dockerfile)와 vendor/exec 채움 계약**만 담는다.
> 이 워크플로우는 **완전 오프라인 · 테스트베드 무접속** — 어떤 에이전트도 SSH/scp/
> `docker build`/배포를 하지 않는다. 실제 build/채움/기동은 별도 **통제단계**에서 수행.

## 이미지 2종

| 이미지 | 디렉터리 | 계층 | vantage(sidecar) | 도구 | config 키 |
|--------|----------|------|------------------|------|-----------|
| `dahv2/air-tools` | `air/` | A · D | `tools_ue`(`--network container:attacker_ue`) · `tools_sgi`(net_sgi) | pymavlink + OpenSSL(ARIA, vendored) | `tools.image.air`(필수) — `./dah.sh build-tools`. SITL `dahv2/air` 와 태그 구분 |
| `dahv2/pfcp-poc` | `pfcp/` | B | `tools_core`(net_core, pivot 후) | scapy | `tools.image.pfcp`(옵션) |

> `host` vantage(C 계층: `docker inspect`·`/sign.key`)와 `core`(pivot) 는 doc13 §2~§3 참조.
> `sidecar="host"` 도구(key_extract 등)는 사이드카 이미지가 없다(호스트 자체).

## 공통 계약 (doc09 종료계약 · doc19 R1~R6)

- **장수 사이드카 + `docker exec`**: 모든 이미지 CMD = `sleep infinity`. 이미지는 실행
  주체가 아니며, host 실행기가 `docker exec` 로만 baked 스크립트를 구동한다.
- **금지(하드):** `docker run --rm` 단명 사이드카 · ENTRYPOINT 자동 공격실행 · SSH ·
  넓은 grep 기반 kill · PIPE 캡처 · 5762 다중연결.
- **R2 라벨:** 이미지는 `org.dah.image` 정체 라벨만 갖는다. 런타임 회수 라벨
  (`dahv2.owner=agent`, `dahv2.run_id=$RUN`)은 실행기가 `docker create/run --label` 로 부여.
- **vendor/exec 슬롯:** 각 하위 README 의 "채움" 절 참조 — 통제단계 read-only scp 로만 채운다.

각 이미지 상세는 `air/README.md` · `pfcp/README.md` 참조.
