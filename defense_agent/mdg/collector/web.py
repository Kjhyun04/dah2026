"""WebProbeCollector — 5762 ss-only, pool=1 (backdoor 탐지).

타깃 container의 netns에 합류하여 ``ss`` 만 실행하고(ss-only 제약) 포트 5762(ArduPilot
backdoor)를 검사한다. 5762에서 established 연결이 하나라도 있으면 danger 신호다
(Port_5762_State = ESTAB_PRESENT); ESTAB 없는 LISTEN은 정상.

pool=1 (G4): 5762의 ss는 전용 PrioritySemaphore(1)로 직렬화되어 probe가 절대 fan-out/
경합하지 않는다. probe는 safe-exec Backend를 통해 사이클당 정확히 한 번의 ss 호출을
발행한다(불변식2.).
"""
from __future__ import annotations

from typing import Optional

from ..config import defaults as D          # P4 단일 설정원: 포트는 INPUT_SPEC["ports"] 에서만 정의
from ..safe_exec.backend import ExecRequest, PrioritySemaphore
from .base import BaseCollector


def _ss_argv(netns_prefix: list[str], port: int) -> list[str]:
    # -H 헤더 없음, -t tcp, -a all, -n numeric; backdoor 포트로 필터.
    return list(netns_prefix) + [
        "ss", "-H", "-tan", "state", "established", f"( sport = :{port} or dport = :{port} )",
    ]


def parse_ss_established(stdout: str, port: int) -> int:
    """포트를 참조하는 ESTAB 행을 센다. ``ss -H`` 는 이미 established로 필터하지만,
    필터 차이에 견고하도록 포트 토큰을 여전히 확인한다."""
    if not stdout:
        return 0
    tok = f":{port}"
    n = 0
    for ln in stdout.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        if tok in ln and ("ESTAB" in ln or "estab" in ln or ln[0].isdigit() or "." in ln.split()[0]):
            n += 1
    return n


def parse_ss_peer(stdout: str, port: int) -> str:
    """``port`` 를 참조하는 첫 ESTAB 행에서 peer source IP를 추출한다.

    ss 행(``ss -H -tan state established``): ``state`` 필터는 State 열을 생략하므로,
    실제 행은 4열 ``<Recv-Q> <Send-Q> <local>:5762 <peer>:<port>`` 이다(5열 형태인
    ``ESTAB 0 0 <local> <peer>`` 가 아님). 어느 경우든 local/peer ``addr:port`` 는 마지막
    두 whitespace 토큰이며; peer는 포트가 ``port`` 가 아닌 엔드포인트다. peer IP를
    반환하거나, 파싱 실패 시 ""(fail-closed).
    """
    if not stdout:
        return ""
    tok = f":{port}"
    for ln in stdout.splitlines():
        ln = ln.strip()
        if not ln or tok not in ln:
            continue
        parts = ln.split()
        if len(parts) < 4:                   # Recv-Q Send-Q local peer (State 열은 필터로 제거됨)
            continue
        # peer=parts[-1], local=parts[-2]; 포트가 port가 아닌 엔드포인트를 고른다.
        for addr in (parts[-1], parts[-2]):
            ip, sep, p = addr.rpartition(":")
            if not sep or not ip or p == str(port):
                continue
            return ip.strip("[]")            # IPv6 대괄호가 있으면 제거
    return ""


def _iptables_argv(netns_prefix: list[str], chain: str) -> list[str]:
    """EXACT 카운터로 read-only 리스팅. short 플래그를 분리(-n -v -x -L)하여
    backend.is_read_only_argv가 -L 리스팅 verb를 인식하고 mutating verb가 없도록 한다."""
    return list(netns_prefix) + ["iptables", "-n", "-v", "-x", "-L", chain]


def parse_dah5762_syn_count(stdout: str) -> int:
    """DAH5762 chain의 SYN 카운팅 규칙의 SYN 패킷 카운터(pkts, col0), ``DAH5762_SYN`` 마커
    (NFLOG --nflog-prefix 또는 --comment)로 식별. chain 부재 / read 실패 -> -1 (inert).
    chain은 있으나 아직 SYN 행 없음 -> 0. ``-x`` 아래서 pkts는 항상 col0."""
    if not stdout:
        return -1                                          # chain 부재 / read 실패 -> inert
    for ln in stdout.splitlines():
        if "DAH5762_SYN" in ln:                            # SYN 카운팅 규칙
            parts = ln.split()
            if parts and parts[0].isdigit():
                return int(parts[0])                       # pkts col0 (exact, -x)
    return 0 if "DAH5762" in stdout else -1                # chain은 있으나 SYN 행 없음 -> 0


class WebProbeCollector(BaseCollector):
    source_id = "web_5762_probe"
    domain = "command"

    def __init__(self, *args, container: str = "uav_ue", port: int = D.INPUT_SPEC["ports"]["backdoor"],
                 netns_prefix: Optional[list[str]] = None,
                 semaphore: Optional[PrioritySemaphore] = None, **kw):
        super().__init__(*args, **kw)
        self.port = port
        # None => inert (ip-netns-exec 폴백 없음); canonical prefix는 recon이 주입.
        self.netns_prefix = netns_prefix
        self._sem = semaphore or PrioritySemaphore(1)     # pool=1, ss-only
        self._syn_seen = 0                                # DAH5762 SYN 카운터 high-water (delta 게이트)

    def collect(self) -> list[dict]:
        if self.backend is None or self.netns_prefix is None:
            return []                                      # inert: netns 타깃 미해석
        out: list[dict] = []

        # (1) 지속 연결 경로 — ss ESTAB 스냅샷. peer IP를 담는다(점유된 backdoor에 대한
        #     실제 nsenter DROP 복구의 droppable 귀속 타깃).
        argv = _ss_argv(self.netns_prefix, self.port)
        with self._sem:                                    # pool=1 직렬화
            res = self.backend.run(ExecRequest(argv=argv, timeout_s=5.0, read_only=True))
        if not res.dry_run and parse_ss_established(res.stdout, self.port) > 0:
            peer = parse_ss_peer(res.stdout, self.port)    # 파싱 실패 시 "" (fail-closed)
            out.append({
                "metric": "Port_5762_State", "value": "ESTAB_PRESENT", "band": "danger",
                "domain": "command", "channel": "port_5762_read", "confidence": 0.90,
                "source": peer,                            # peer IP = 귀속 selector (droppable)
            })

        # (2) 짧은 연결 경로 — DAH5762 SYN 카운터(결정론적; 5s ss 스냅샷이 놓치는 sub-poll
        #     연결을 잡음). Delta-게이트: 직전 poll 이후 NEW SYN만 방출. source=''(집계
        #     카운터에는 peer 없음) => 탐지 전용 — 짧은 연결은 이미 사라져 DROP할 대상이
        #     없지만, 파이프라인은 여전히 orient/decide에 도달한다(LLM 개입). ss가 아직
        #     플래그하지 않았을 때만 방출(peer 행 우선).
        cargv = _iptables_argv(self.netns_prefix, "DAH5762")
        with self._sem:
            cres = self.backend.run(ExecRequest(argv=cargv, timeout_s=5.0, read_only=True))
        if not cres.dry_run:
            cnt = parse_dah5762_syn_count(cres.stdout)
            if cnt >= 0:
                if cnt < self._syn_seen:                   # 카운터 reset (testbed/netns 재시작)
                    self._syn_seen = 0
                if cnt > self._syn_seen:
                    self._syn_seen = cnt
                    if not out:
                        out.append({
                            "metric": "Port_5762_State", "value": "ESTAB_PRESENT", "band": "danger",
                            "domain": "command", "channel": "port_5762_syn_count", "confidence": 0.90,
                            "source": "",                  # 집계 카운터 -> droppable peer 없음
                        })
        return out
