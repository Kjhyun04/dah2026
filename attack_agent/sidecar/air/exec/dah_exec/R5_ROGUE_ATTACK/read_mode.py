#!/usr/bin/env python3
"""recon_defense — 방어 자세 probe (RECON·RO·sgi vantage). 파서 계약: {"signing": ...}.

sgi vantage(net_sgi)에서 오라클(:14556)을 자체 discover(연결 서브넷 스윕)해 HEARTBEAT 를
read-only 로 읽어 도달을 확인한다. 서명(signing)은 공격자-관측만으로 수동 판정 불가 →
"unknown"(정직·12 §9 D18: 첫 blocked 주입에서 lazy 학습). 상태변경 0(read only).
"""
import ipaddress
import json
import socket
import subprocess

ORACLE_PORT = 14556


def connected_subnets():
    out = subprocess.run(["ip", "-o", "-4", "route", "show", "scope", "link"],
                         capture_output=True, text=True, timeout=5).stdout
    nets = []
    for ln in out.splitlines():
        tok = ln.split()
        if tok and "/" in tok[0]:
            try:
                nets.append(ipaddress.ip_network(tok[0], strict=False))
            except ValueError:
                pass
    return nets


def tcp_up(ip, port, t=0.3):
    s = socket.socket(); s.settimeout(t)
    try:
        s.connect((str(ip), port)); s.close(); return True
    except Exception:
        return False


def main() -> int:
    found = False
    for net in connected_subnets():
        for ip in list(net.hosts())[:30]:
            if tcp_up(ip, ORACLE_PORT):
                found = True
                break
        if found:
            break
    # signing 은 수동 관측 불가 → unknown(정직). 오라클 도달 여부만 로깅 목적.
    print(json.dumps({"signing": "unknown", "oracle_reachable": found}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
