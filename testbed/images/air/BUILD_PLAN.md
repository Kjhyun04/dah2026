# 이미지 빌드 계획 (P1에서 실행)

3종 이미지 확보:

1. **Open5GS EPC** — upstream 이미지/compose 태그 **pin**(4G, IMS/osmo 제외). MME `ciphering_order/integrity_order`에 EEA2/EIA2 반영.
2. **srsRAN_4G** — `srsenb`/`srsue`, 릴리스 태그 빌드, **ZMQ 활성**. eNB EEA2/EIA2 우선.
3. **air (SITL + ARIA)** — 이 디렉토리 `Dockerfile`(P1 작성):
   - base `ubuntu:22.04`
   - ArduPilot **Copter 4.x** (arducopter SITL 바이너리)
   - `python3` + `pymavlink`
   - OpenSSL `libcrypto` (**ARIA 포함** — mav_aria_proxy 용)
   - `mavlink-router` (평문 fan-out)

**P1 검증:** `docker images` 3종 존재 · `mav_aria_proxy.py --selftest`(ARIA-256 KAT 통과) · `arducopter --help` · libcrypto ARIA 가용.
