#!/usr/bin/env python3
# mav_aria_proxy — MAVLink C2를 국산암호 ARIA-256-GCM(AEAD)으로 감싸는 UDP 프록시 쌍.
#   [SITL]--평문--(uav_proxy)==ARIA-GCM 암호문(셀룰러)==(gcs_proxy)--평문--[GCS]
#   datagram = VER(0x01) || nonce(12, 패킷별 랜덤) || CT || TAG(16)   (MAVLink 메시지 1:1)
#   AEAD 인증 실패(변조/오키) → 조용히 폐기. KCMVP 검증모듈 교체 지점 = AriaGCM 1개.
#   사용:
#     자가검증:  python3 mav_aria_proxy.py --selftest
#     UAV측:  --plain-listen 127.0.0.1:14550 --cipher-listen 0.0.0.0:14555 --cipher-peer <GCS>:14555 --key-hex <64hex>
#     GCS측:  --plain-listen 127.0.0.1:14556 --plain-peer 127.0.0.1:14550 --cipher-listen 0.0.0.0:14555 --key-hex <64hex>
import sys, os, socket, select, argparse, ctypes, ctypes.util
from ctypes import c_void_p, c_char_p, c_int, POINTER, byref, create_string_buffer

# ── ARIA-256-GCM via OpenSSL libcrypto (ctypes) ─────────────────────────────
GCM_SET_IVLEN = 0x9; GCM_GET_TAG = 0x10; GCM_SET_TAG = 0x11
class AriaGCM:
    """OpenSSL EVP_aria_256_gcm AEAD. (KCMVP 검증모듈 교체 지점)"""
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
            if not n: continue
            try: return ctypes.CDLL(n)
            except OSError: continue
        raise RuntimeError("libcrypto 로드 실패")

    def encrypt(self, key, pt):                          # -> nonce||ct||tag
        L = self.L; iv = os.urandom(12); ctx = L.EVP_CIPHER_CTX_new()
        try:
            L.EVP_EncryptInit_ex(ctx, L.EVP_aria_256_gcm(), None, None, None)
            L.EVP_CIPHER_CTX_ctrl(ctx, GCM_SET_IVLEN, 12, None)
            L.EVP_EncryptInit_ex(ctx, None, None, key, iv)
            out = create_string_buffer(len(pt) + 16); ol = c_int(0)
            L.EVP_EncryptUpdate(ctx, out, byref(ol), pt, len(pt)); ct = out.raw[:ol.value]
            fin = create_string_buffer(16); fl = c_int(0)
            L.EVP_EncryptFinal_ex(ctx, fin, byref(fl)); ct += fin.raw[:fl.value]
            tag = create_string_buffer(16); L.EVP_CIPHER_CTX_ctrl(ctx, GCM_GET_TAG, 16, tag)
            return iv + ct + tag.raw[:16]
        finally:
            L.EVP_CIPHER_CTX_free(ctx)

    def decrypt(self, key, blob):                        # nonce(12)||ct||tag(16) -> pt or None
        if len(blob) < 12 + 16: return None
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
            if L.EVP_DecryptFinal_ex(ctx, fin, byref(fl)) != 1: return None   # 인증 실패
            return pt + fin.raw[:fl.value]
        finally:
            L.EVP_CIPHER_CTX_free(ctx)

VER = b"\x01"
class C2Cipher:
    def __init__(self, key): self.key = key; self.a = AriaGCM()
    def wrap(self, pt):   return VER + self.a.encrypt(self.key, pt)
    def unwrap(self, blob):
        if len(blob) < 1 or blob[0:1] != VER: return None
        return self.a.decrypt(self.key, blob[1:])

# ── 자가검증 (roundtrip + 변조탐지 + 타키거부) ───────────────────────────────
def selftest():
    print("[selftest] ARIA-256-GCM 가용성...")
    c = C2Cipher(os.urandom(32)); print("           ✓ EVP_aria_256_gcm OK")
    print("[selftest] AEAD roundtrip + 변조/타키...")
    msg = b"\xfd\x09..HEARTBEAT..MAVLINK C2 payload " * 3
    blob = c.wrap(msg); assert c.unwrap(blob) == msg, "roundtrip 실패"
    t = bytearray(blob); t[20] ^= 0x01; assert c.unwrap(bytes(t)) is None, "변조 미탐지!"
    assert C2Cipher(os.urandom(32)).unwrap(blob) is None, "타키 복호 허용됨!"
    print("           ✓ roundtrip OK · 1비트 변조/타키 → 폐기 OK")
    print("[selftest] ✅ 전체 통과 — ARIA-GCM C2 프록시 사용 가능"); return 0

# ── UDP 양방향 암호 릴레이 (MAVLink 메시지 1:1, 패킷별 nonce) ────────────────
def _make_verifier():
    import os
    kf = os.environ.get("MAV_SIGN_KEYFILE")
    if not (kf and os.path.exists(kf)): return None
    from pymavlink import mavutil
    key = bytes.fromhex(open(kf).read().strip())
    v = mavutil.mavlink.MAVLink(None); v.robust_parsing = True
    v.signing.secret_key = key; v.signing.link_id = 0; v.signing.timestamp = 0
    v.signing.allow_unsigned_callback = lambda m, msgId: False
    return v

def _sig_ok(v, pt):
    try:
        try: v.buf = bytearray(); v.buf_index = 0
        except Exception: pass
        msgs = v.parse_buffer(pt) or []
    except Exception:
        return False
    if not msgs: return False
    return all(m.get_type() != 'BAD_DATA' for m in msgs)

def hostport(s): h, p = s.rsplit(":", 1); return (h, int(p))
def run_proxy(a):
    key = bytes.fromhex(a.key_hex.strip())
    if len(key) != 32: print("[proxy] ✗ --key-hex 32바이트(64hex) 필요", file=sys.stderr); return 2
    cph = C2Cipher(key)
    verifier = _make_verifier(); sigdrop = 0
    if verifier is not None:
        print("[proxy] 🔒 MAVLink2 서명 강제 ON (무서명/오서명/리플레이 → SITL 폐기)", flush=True)
    plain = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); plain.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); plain.bind(hostport(a.plain_listen))
    ciph  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); ciph.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); ciph.bind(hostport(a.cipher_listen))
    # plain-peer는 콤마로 다중 지정 가능(fan-out: gcs_c2 + web_backend). 없으면 학습.
    plain_peers = [hostport(x) for x in a.plain_peer.split(",")] if a.plain_peer else None
    learned_pp = None
    cp = hostport(a.cipher_peer) if a.cipher_peer else None
    print("[proxy] plain=%s(peers=%s) cipher=%s(peer=%s) ARIA-256-GCM" % (a.plain_listen, plain_peers, a.cipher_listen, cp), flush=True)
    up = dn = drop = 0
    while True:
        r, _, _ = select.select([plain, ciph], [], [])
        for s in r:
            if s is plain:                               # 평문 → 암호화 → 셀룰러
                data, addr = plain.recvfrom(65535)
                if plain_peers is None: learned_pp = addr
                if cp is None: continue
                ciph.sendto(cph.wrap(data), cp); up += 1
            else:                                        # 암호문 → 복호 → 평문측(fan-out)
                blob, addr = ciph.recvfrom(65535)
                if a.cipher_peer is None: cp = addr
                pt = cph.unwrap(blob)
                if pt is None: drop += 1; continue
                if verifier is not None and not _sig_ok(verifier, pt):
                    sigdrop += 1
                    if sigdrop <= 20 or sigdrop % 50 == 0:
                        print("[proxy] ⛔ 서명검증 실패 → SITL 차단 (누적 %d)" % sigdrop, flush=True)
                    continue
                dests = plain_peers if plain_peers else ([learned_pp] if learned_pp else [])
                for pp in dests:
                    try: plain.sendto(pt, pp)
                    except OSError: pass                 # 한 peer 실패가 전체를 죽이지 않게
                dn += 1

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--plain-listen"); ap.add_argument("--plain-peer", default=None)
    ap.add_argument("--cipher-listen"); ap.add_argument("--cipher-peer", default=None)
    ap.add_argument("--key-hex")
    a = ap.parse_args()
    if a.selftest: sys.exit(selftest())
    if not (a.plain_listen and a.cipher_listen and a.key_hex): ap.error("--plain-listen/--cipher-listen/--key-hex 필요")
    sys.exit(run_proxy(a))

if __name__ == "__main__": main()
