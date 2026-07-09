"""aria_gcm — VENDOR SLOT PLACEHOLDER (통제단계에서 교체됨).

이 파일은 **자리표시자(placeholder)** 일 뿐 실제 ARIA 구현이 아니다.
이 워크플로우는 테스트베드 무접속이므로 실제 벤더 코드를 fetch/생성하지 않는다.

통제단계(control stage)에서 read-only scp 로
    testbed/proxy/mav_aria_proxy.py  ->  이 파일(aria_gcm.py)
의 `AriaGCM` 클래스 + ARIA 봉투 파서만 추출(doc18 D8: 전체복사 아님, 원본 경로·해시 주석)
하여 **덮어쓴다**. 원본 = ctypes 로 OpenSSL libcrypto(EVP, aria-256-gcm)를 호출하는
종단 암호 프록시의 GCM 래퍼.

R3 preflight 규약
-----------------
init 의 R3 preflight 는 사이드카 안에서
    python3 -c "import aria_gcm; assert not getattr(aria_gcm,'__DAH_VENDOR_PLACEHOLDER__',False)"
를 확인한다. 아래 sentinel 이 True 인 동안(=아직 placeholder)에는 preflight 가 실패하고
해당 계층 실행이 봉쇄된다(정직성: 채워지지 않은 vendor 로는 실행 불가).

봉인 계약(통제단계 채움 시 이 인터페이스를 만족해야 함, 참고용)
--------------------------------------------------------------
    class AriaGCM:
        def __init__(self, key: bytes) -> None: ...      # 32B ARIA-256 키
        def seal(self, plaintext: bytes) -> bytes: ...   # VER‖nonce(12)‖CT‖TAG(16)
        def open(self, envelope: bytes) -> bytes: ...    # 검증 후 평문
"""

# R3 preflight sentinel — 실제 벤더 코드로 교체되면 이 심볼은 사라진다.
__DAH_VENDOR_PLACEHOLDER__ = True


def _refuse(*_args, **_kwargs):
    raise NotImplementedError(
        "aria_gcm 은 placeholder 다. 통제단계에서 testbed/proxy/mav_aria_proxy.py "
        "의 AriaGCM 을 read-only scp 로 채워야 한다(R3 preflight 가 이를 강제)."
    )


class AriaGCM:  # noqa: D401 - placeholder; 실제 구현은 통제단계 vendor 로 교체
    """placeholder AriaGCM — 생성/사용 즉시 NotImplementedError."""

    def __init__(self, *_args, **_kwargs):
        _refuse()

    seal = _refuse
    open = _refuse
