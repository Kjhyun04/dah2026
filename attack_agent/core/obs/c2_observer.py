"""Passive host-side observer for UDP C2 cadence (default-off optional module).

The observer is non-intrusive:
- no packet transmit
- best-effort passive sampling via tcpdump
- emits only derived numeric notes (no untrusted payload passthrough)
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
import time


class C2Observer:
    """Sample UDP port traffic rate and gap hints for planner context."""

    def __init__(
        self,
        *,
        port: int = 14555,
        iface: str = "any",
        sample_s: int = 2,
        gap_s: int = 8,
        quiet_pps: float = 0.5,
        tcpdump_bin: str = "tcpdump",
        max_packets: int = 400,
    ) -> None:
        self._port = max(1, int(port))
        self._iface = iface.strip() or "any"
        self._sample_s = max(1, int(sample_s))
        self._gap_s = max(1, int(gap_s))
        self._quiet_pps = max(0.0, float(quiet_pps))
        self._tcpdump = tcpdump_bin.strip() or "tcpdump"
        self._max_packets = max(10, int(max_packets))
        self._last_seen_ts: float | None = None
        self._fatal_note: str | None = None
        self._probed_bin = False

    async def sample_notes(self) -> list[str]:
        """Return compact deterministic observer notes for prompt context."""
        if self._fatal_note is not None:
            return [self._fatal_note]

        if not self._probed_bin:
            self._probed_bin = True
            if shutil.which(self._tcpdump) is None:
                self._fatal_note = f"obs.error=tcpdump_not_found({self._tcpdump})"
                return [self._fatal_note]

        try:
            count, err = await self._capture_count()
        except Exception as exc:  # noqa: BLE001
            self._fatal_note = f"obs.error={type(exc).__name__}"
            return [self._fatal_note]

        if err is not None:
            self._fatal_note = err
            return [self._fatal_note]

        now = time.time()
        if count > 0:
            self._last_seen_ts = now

        pps = count / float(self._sample_s)
        notes = [f"obs.udp_{self._port}.pps={pps:.2f}"]
        if pps <= self._quiet_pps:
            notes.append(f"obs.c2_quiet=true(th={self._quiet_pps:.2f})")

        if self._last_seen_ts is not None:
            gap = now - self._last_seen_ts
            if gap >= self._gap_s:
                notes.append(f"obs.c2_gap_s={gap:.1f}(th={self._gap_s})")
        return notes

    async def _capture_count(self) -> tuple[int, str | None]:
        argv = [
            self._tcpdump,
            "-n",
            "-l",
            "-i",
            self._iface,
            "udp",
            "port",
            str(self._port),
            "-c",
            str(self._max_packets),
        ]
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        count = 0
        try:
            async with asyncio.timeout(self._sample_s):
                while True:
                    line = await proc.stdout.readline()  # type: ignore[union-attr]
                    if not line:
                        break
                    count += 1
        except TimeoutError:
            pass
        finally:
            if proc.returncode is None:
                with contextlib.suppress(Exception):
                    proc.terminate()
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(proc.wait(), timeout=0.8)
            if proc.returncode is None:
                with contextlib.suppress(Exception):
                    proc.kill()
                    await proc.wait()

        if proc.returncode not in (None, 0) and count == 0:
            err_raw = b""
            with contextlib.suppress(Exception):
                err_raw = await proc.stderr.read()  # type: ignore[union-attr]
            err_txt = err_raw.decode("utf-8", "ignore").strip().lower()
            if "permission denied" in err_txt:
                return 0, "obs.error=tcpdump_permission_denied"
            return 0, "obs.error=tcpdump_failed"
        return count, None


__all__ = ["C2Observer"]
