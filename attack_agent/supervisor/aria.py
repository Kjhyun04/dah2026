"""supervisor.aria — ARIA-256-GCM 복호 vendor (감독 전용·복호 방향만 사용).

★ COPIED VERBATIM from testbed/proxy/mav_aria_proxy.py — KCMVP 검증모듈 교체 지점 = AriaGCM.
  재구현 금지(doc18 D8). 감독은 encrypt() 미사용(완전 수동). unwrap 만 사용.
  원본: /home/ubuntu/testbed/proxy/mav_aria_proxy.py (AriaGCM + C2Cipher).
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
from ctypes import (
    POINTER,
    byref,
    c_char_p,
    c_int,
    c_void_p,
    create_string_buffer,
)

GCM_SET_IVLEN = 0x9
GCM_GET_TAG = 0x10
GCM_SET_TAG = 0x11


class AriaGCM:
    """OpenSSL EVP_aria_256_gcm AEAD (verbatim). 감독은 decrypt 만 사용."""

    def __init__(self):
        L = self._load(); self.L = L
        L.EVP_CIPHER_CTX_new.restype = c_void_p
        L.EVP_CIPHER_CTX_free.argtypes = [c_void_p]
        L.EVP_aria_256_gcm.restype = c_void_p
        for f in (L.EVP_EncryptInit_ex, L.EVP_DecryptInit_ex):
            f.restype = c_int; f.argtypes = [c_void_p, c_void_p, c_void_p, c_char_p, c_char_p]
        for f in (L.EVP_EncryptUpdate, L.EVP_DecryptUpdate):
            f.restype = c_int; f.argtypes = [c_void_p, c_char_p, POINTER(c_int), c_char_p, c_int]
        for f in (L.EVP_EncryptFinal_ex, L.EVP_DecryptFinal_ex):
            f.restype = c_int; f.argtypes = [c_void_p, c_char_p, POINTER(c_int)]
        L.EVP_CIPHER_CTX_ctrl.restype = c_int
        L.EVP_CIPHER_CTX_ctrl.argtypes = [c_void_p, c_int, c_int, c_void_p]
        if not L.EVP_aria_256_gcm():
            raise RuntimeError("EVP_aria_256_gcm 미지원 — libcrypto ARIA-GCM 확인")

    @staticmethod
    def _load():
        for n in ("libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so", ctypes.util.find_library("crypto")):
            if not n:
                continue
            try:
                return ctypes.CDLL(n)
            except OSError:
                continue
        raise RuntimeError("libcrypto 로드 실패")

    def decrypt(self, key, blob):  # nonce(12)||ct||tag(16) -> pt or None
        if len(blob) < 12 + 16:
            return None
        iv, ct, tag = blob[:12], blob[12:-16], blob[-16:]
        L = self.L; ctx = L.EVP_CIPHER_CTX_new()
        try:
            L.EVP_DecryptInit_ex(ctx, L.EVP_aria_256_gcm(), None, None, None)
            L.EVP_CIPHER_CTX_ctrl(ctx, GCM_SET_IVLEN, 12, None)
            L.EVP_DecryptInit_ex(ctx, None, None, key, iv)
            out = create_string_buffer(len(ct) + 16); ol = c_int(0)
            L.EVP_DecryptUpdate(ctx, out, byref(ol), ct, len(ct)); pt = out.raw[:ol.value]
            L.EVP_CIPHER_CTX_ctrl(ctx, GCM_SET_TAG, 16, tag)
            fin = create_string_buffer(16); fl = c_int(0)
            if L.EVP_DecryptFinal_ex(ctx, fin, byref(fl)) != 1:
                return None  # 인증 실패(변조/타키) → 조용히 폐기(프록시와 동일 규율)
            return pt + fin.raw[:fl.value]
        finally:
            L.EVP_CIPHER_CTX_free(ctx)


VER = b"\x01"


class C2Cipher:
    def __init__(self, key):
        self.key = key
        self.a = AriaGCM()

    def unwrap(self, blob):
        if len(blob) < 1 or blob[0:1] != VER:
            return None
        return self.a.decrypt(self.key, blob[1:])


def load_key(env_name: str) -> bytes:
    """소유자 ARIA 키를 env(hex)에서 로드(감독 프로세스 내에서만). 32바이트 강제.

    ★ 소유자 특권 — 공격 agent 에는 절대 주지 않는다(완전분리). 값은 이 프로세스 밖으로 안 나감.
    """
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        raise RuntimeError(f"supervisor: ARIA key env {env_name!r} 미설정")
    try:
        key = bytes.fromhex(raw)  # 값(키)은 에러 메시지에 절대 미노출
    except ValueError:
        raise RuntimeError(f"supervisor: ARIA key env {env_name!r} not valid hex") from None
    if len(key) != 32:
        raise RuntimeError(f"supervisor: ARIA key len={len(key)} != 32")
    return key


__all__ = ["AriaGCM", "C2Cipher", "load_key", "VER"]
