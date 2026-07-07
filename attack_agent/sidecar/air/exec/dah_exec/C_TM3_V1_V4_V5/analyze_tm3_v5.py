#!/usr/bin/env python3
"""nonce_scan (COLLECT): 입력 바이너리에서 12-byte nonce 재사용 징후를 보수적으로 탐지."""

from __future__ import annotations

import json
import os
from pathlib import Path


def detect_collision(buf: bytes, win: int = 12, limit: int = 1_000_000) -> bool:
    if len(buf) < win * 2:
        return False
    seen: set[bytes] = set()
    data = buf[:limit]
    for i in range(0, len(data) - win + 1):
        key = data[i : i + win]
        if key in seen:
            return True
        seen.add(key)
    return False


def candidate_files() -> list[Path]:
    out: list[Path] = []
    for env_key in ("INPUT_FILE", "CIPHERTEXT_FILE", "PCAP_FILE"):
        v = os.environ.get(env_key)
        if v:
            out.append(Path(v))
    out += [
        Path("ciphertext.bin"),
        Path("ciphertext"),
        Path("input.bin"),
        Path("capture.pcap"),
    ]
    # 중복 제거
    uniq = []
    seen = set()
    for p in out:
        s = str(p)
        if s not in seen:
            uniq.append(p)
            seen.add(s)
    return uniq


def main() -> None:
    found_file: Path | None = None
    collision = False
    for p in candidate_files():
        if p.exists() and p.is_file():
            try:
                data = p.read_bytes()
            except OSError:
                continue
            found_file = p
            collision = detect_collision(data)
            break

    artifacts: list[str] = []
    values: dict[str, str] = {}
    if found_file is not None:
        artifacts.append("ciphertext")
        values["source"] = str(found_file)
        values["bytes"] = str(found_file.stat().st_size)

    print(json.dumps({"artifacts": artifacts, "values": values, "nonce_collision": collision}))


if __name__ == "__main__":
    main()
