#!/bin/sh
# recon_reach — 공격자 vantage 자체 스윕→분류 (RECON·RO·12 §5). 하드코딩 0: 자기 라우팅
# 테이블의 연결 서브넷을 스윕한다. stdout = 파서 계약 JSON(recon.build_recon_result):
#   {"reach":[<ReachTarget>@ip:port,...], "identified":[<ReachTarget>,...], "unauth":[...]}
# 포트→역할 분류: 5762=uav5762(+HEARTBEAT sysid=1∧quad→identified), 14555=gcs14555,
#   14556=gcs14556, 8080=web8080, 27017=mongo. read-only(TCP connect + uav 1-HEARTBEAT).
exec python3 - "$@" <<'PY'
import json, socket, subprocess, ipaddress, sys

PORT_ROLE = {5762: "uav5762", 14555: "gcs14555", 14556: "gcs14556",
             8080: "web8080", 27017: "mongo"}
# 14555(ARIA cipher)·14556(평문 오라클)은 **UDP** MAVLink 포트 → TCP connect 는 RST(refused)
#   를 받지만 그건 **호스트 도달을 증명**(패킷 왕복 성공). UDP 서비스 존재로 간주(도달).
#   TCP 서비스(5762 SITL·27017 mongo·8080 web)는 connect open 만 도달로 인정.
UDP_MAVLINK = {14555, 14556}

def connected_subnets():
    """자기 라우팅의 scope link /24(하드코딩 아님)를 discover."""
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

def probe(ip, port, t=1.5):   # UE 터널(srsue) 경유 경로는 느림 → 넉넉한 connect 타임아웃
    """반환: 'open'(TCP 서비스) | 'refused'(호스트 도달·TCP 포트 닫힘) | 'unreach'(타임아웃/무경로)."""
    s = socket.socket(); s.settimeout(t)
    try:
        s.connect((str(ip), port)); s.close(); return "open"
    except ConnectionRefusedError:
        return "refused"
    except Exception:
        return "unreach"

def uav_hb(ip, port, t=6.0):
    """5762 HEARTBEAT 1개 → (sysid,type). 실패 None. RO."""
    try:
        from pymavlink import mavutil
        m = mavutil.mavlink_connection(f"tcp:{ip}:{port}")
        hb = m.wait_heartbeat(timeout=t); m.close()
        if hb is not None:
            return hb.get_srcSystem(), int(hb.type)
    except Exception:
        pass
    return None

# 동시 스윕(타임아웃 견고): (ip,port) 전량 concurrent probe → 역할별 첫 도달만 채택.
from concurrent.futures import ThreadPoolExecutor

targets = []
for net in connected_subnets():
    for ip in list(net.hosts())[:32]:  # 유계 스윕(.1-.32: SGi web=.20 포함)
        for port in PORT_ROLE:
            targets.append((ip, port))

found = {}  # role -> "ip:port" (첫 도달)
with ThreadPoolExecutor(max_workers=64) as ex:  # I/O 바운드 → 병렬 확대(타임아웃 여유)
    futs = {ex.submit(probe, ip, port): (ip, port) for ip, port in targets}
    for fut in futs:
        ip, port = futs[fut]
        role = PORT_ROLE[port]
        if role in found:
            continue
        st = fut.result()
        # TCP 서비스=open · UDP MAVLink=open|refused(호스트 도달 증명)
        if st == "open" or (port in UDP_MAVLINK and st == "refused"):
            found[role] = f"{ip}:{port}"

reach = [f"{role}@{addr}" for role, addr in found.items()]
# SGi 서비스(gcs/web) 중 하나라도 닿으면 coarse reach(sgi) 도 방출(recon_defense precond).
if any(r in found for r in ("gcs14555", "gcs14556", "web8080")):
    reach.append("sgi")
identified = []
if "uav5762" in found:
    ip, port = found["uav5762"].split(":")
    hb = uav_hb(ip, int(port))
    if hb and hb[0] == 1 and hb[1] == 2:  # sysid=1 ∧ QUADROTOR
        identified.append("uav5762")

print(json.dumps({"reach": reach, "identified": identified, "unauth": []}))
PY
