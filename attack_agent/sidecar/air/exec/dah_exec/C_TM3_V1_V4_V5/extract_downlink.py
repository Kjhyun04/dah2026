#!/usr/bin/env python3
"""capture_downlink (COLLECT): 짧은 다운링크 캡처 시도 후 pcap artifact 보고."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile


def emit(artifacts: list[str], values: dict[str, str]) -> None:
    print(json.dumps({"artifacts": artifacts, "values": values, "nonce_collision": None}))


def main() -> None:
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        emit([], {})
        return

    timeout_s = os.environ.get("TIMEOUT_S", "4")
    pkt_count = os.environ.get("PKT_COUNT", "20")
    with tempfile.NamedTemporaryFile(prefix="downlink_", suffix=".pcap", delete=False) as tf:
        pcap_path = tf.name

    try:
        # GCS 관련 포트 트래픽(14555/14556) 중심으로 짧게 수집.
        cmd = [
            "timeout",
            timeout_s,
            tcpdump,
            "-i",
            "any",
            "-nn",
            "-s0",
            "-c",
            pkt_count,
            "udp and (port 14555 or port 14556)",
            "-w",
            pcap_path,
        ]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        size = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0
        if size > 0:
            emit(["pcap"], {"pcap_bytes": str(size)})
        else:
            emit([], {})
    finally:
        try:
            os.remove(pcap_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
