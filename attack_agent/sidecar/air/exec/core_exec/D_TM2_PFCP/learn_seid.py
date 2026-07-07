#!/usr/bin/env python3
"""recon_session (PROBE): learn PFCP F-SEID from observed PFCP traffic.

Contract (single-line JSON): {"seid": str|null, "sessions": int}
This probe is read-only and conservative: if no trustworthy PFCP signal is
captured, it emits {"seid": null, "sessions": 0}.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        n = int(raw)
    except ValueError:
        return default
    return max(lo, min(hi, n))


def _iter_layers(pkt: object, max_hops: int = 128) -> Iterable[object]:
    cur = pkt
    for _ in range(max_hops):
        if cur is None:
            break
        yield cur
        nxt = getattr(cur, "payload", None)
        if nxt is cur:
            break
        cur = nxt


def _collect_seids_from_packets(packets: Iterable[object], pfcp_mod: object) -> set[int]:
    ie_fseid = getattr(pfcp_mod, "IE_FSEID", None)
    if ie_fseid is None:
        return set()

    out: set[int] = set()
    for pkt in packets:
        for layer in _iter_layers(pkt):
            if not isinstance(layer, ie_fseid):
                continue
            seid = getattr(layer, "seid", None)
            if isinstance(seid, int) and seid > 0:
                out.add(seid)
    return out


def _learn_seids() -> set[int]:
    try:
        from scapy.all import sniff, rdpcap  # type: ignore[import-not-found]
        from scapy.contrib import pfcp as P  # type: ignore[import-not-found]
    except Exception:
        return set()

    pcap = os.environ.get("PFCP_PCAP", "").strip()
    if pcap:
        p = Path(pcap)
        if p.is_file():
            try:
                return _collect_seids_from_packets(rdpcap(str(p)), P)
            except Exception:
                return set()

    iface = os.environ.get("PFCP_IFACE", "eth0").strip() or "eth0"
    count = _env_int("PFCP_SNIFF_COUNT", default=60, lo=1, hi=5000)
    timeout_s = float(_env_int("PFCP_SNIFF_TIMEOUT", default=20, lo=1, hi=300))
    bpf = os.environ.get("PFCP_BPF", "udp port 8805").strip() or "udp port 8805"

    try:
        packets = sniff(
            iface=iface,
            filter=bpf,
            count=count,
            timeout=timeout_s,
            store=True,
        )
    except Exception:
        return set()
    return _collect_seids_from_packets(packets, P)


def main() -> int:
    seids = sorted(_learn_seids())
    payload = {
        "seid": (hex(seids[0]) if seids else None),
        "sessions": len(seids),
    }
    print(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
