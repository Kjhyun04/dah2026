"""verify_parsers.py - V2-D21 raw->model parser verification.

Default run validates parser behavior offline for all 22 ToolSpec entries.
Optional live run (`--live`) executes a safe PROBE subset on testbed and
verifies parse_output on real stdout.
"""

from __future__ import annotations
_import_sys=__import__('sys'); _import_os=__import__('os')
from pathlib import Path as _Path
_REPO=_Path(__file__).resolve().parents[1]
if str(_REPO) not in _import_sys.path: _import_sys.path.insert(0,str(_REPO))
_import_os.chdir(_REPO)  # cwd=repo root -> cwd-relative paths resolve

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core import driver as D  # noqa: E402
from core.common.config import load_config  # noqa: E402
from core.common.results import CollectResult, InjectResult, ReconResult, _ResultBase  # noqa: E402
from core.common.types import ToolKind  # noqa: E402
from core.modules.backends import ExecOutput  # noqa: E402
from core.modules.recon import parse_probe_json, parse_sessions, parse_signing  # noqa: E402
from core.modules.registry import REGISTRY, get_spec  # noqa: E402
from core.modules.resolve import (  # noqa: E402
    parse_br_addr,
    parse_heartbeat,
    parse_inspect_networks,
    target_ip_fields,
)
from core.modules.safeexec import make_runner_factory, parse_output  # noqa: E402
from core.modules.tool_wrap import Err, Ok  # noqa: E402

_FAILS: list[str] = []


def _check(name: str, cond: bool, detail: str = "") -> None:
    mark = "PASS" if cond else "FAIL"
    if not cond:
        _FAILS.append(name)
    print(f"[{mark}] {name}{(' - ' + detail) if detail else ''}")


def _expect_ok(name: str, v: Any) -> Any:
    if isinstance(v, Ok):
        return v.value
    if isinstance(v, Err):
        _check(name, False, getattr(v.error, "error", "Err"))
        raise RuntimeError(name)
    _check(name, False, f"unexpected result container: {type(v).__name__}")
    raise RuntimeError(name)


def _expect_kind_result(spec_kind: ToolKind, parsed: _ResultBase) -> bool:
    if spec_kind == ToolKind.PROBE:
        return isinstance(parsed, ReconResult)
    if spec_kind == ToolKind.COLLECT:
        return isinstance(parsed, CollectResult)
    if spec_kind == ToolKind.INJECT:
        return isinstance(parsed, InjectResult)
    return False


OFFLINE_FIXTURES: dict[str, dict[str, Any]] = {
    # RECON
    "recon_reach": {
        "reach": ["net_core@10.50.0.1:0", "uav5762@10.45.0.10:5762"],
        "unauth": ["mongo"],
        "identified": ["uav5762"],
        "signing": "off",
    },
    "recon_defense": {"signing": "on"},
    "recon_session": {"seid": "0xA01B", "sessions": 4},
    "capture_downlink": {
        "artifacts": ["ciphertext", "pcap"],
        "values": {"ciphertext": "AABBCCDDEEFF"},
    },
    "observe_mode": {"observed_mode": 4},
    # A
    "serial5762": {"accepted": True, "signed": False, "effect": {"mode": "5"}},
    "s1u_capture": {"artifacts": ["ciphertext", "pcap"], "values": {"pcap": "long-blob"}},
    # B
    "subdb_dump": {
        "artifacts": ["k_opc", "imsi"],
        "values": {"k_opc": "0011223344556677", "imsi": "450081234567890"},
    },
    "subdb_canary": {"accepted": True, "effect": {"subscriber_written": "true"}},
    "pfcp_delete": {"accepted": True, "effect": {"c2": "disrupted"}},
    "pfcp_flood": {"accepted": True, "effect": {"c2": "disrupted"}},
    "pivot_exploit": {"accepted": True, "effect": {"reach": "net_core"}},
    # C
    "key_extract": {"artifacts": ["aria_key"], "values": {"aria_key": "DEADBEEF0011"}},
    "signkey_leak": {"artifacts": ["sign_key"], "values": {"sign_key": "ABCDEF123456"}},
    "nonce_scan": {"artifacts": ["pcap"], "nonce_collision": True},
    # D
    "oracle": {
        "accepted": False,
        "signed": True,
        "blocked_by": "signing",
        "effect": {"mode": "5"},
    },
    "webcmd": {"accepted": True, "signed": True, "effect": {"mode": "4"}},
    "forge_sign": {"accepted": True, "signed": True, "effect": {"mode": "5"}},
    "forge_aria": {"accepted": False, "blocked_by": "signing"},
    "replay": {"accepted": False, "blocked_by": "timestamp"},
    "peer_flood": {"accepted": True, "effect": {"c2": "disrupted"}},
    "forceland": {"accepted": True, "effect": {"mode": "9"}},
    "naive": {"accepted": False, "blocked_by": "baseline"},
}


def run_offline() -> None:
    print("=" * 70)
    print("A. parse_output coverage (23 tools)")
    print("=" * 70)

    reg_ids = set(REGISTRY.keys())
    fix_ids = set(OFFLINE_FIXTURES.keys())
    _check("fixture covers all registry ids", reg_ids == fix_ids, f"registry={len(reg_ids)} fixture={len(fix_ids)}")

    for tool_id in sorted(REGISTRY.keys()):
        spec = get_spec(tool_id)
        payload = OFFLINE_FIXTURES[tool_id]
        out = ExecOutput(
            returncode=0,
            stdout=json.dumps(payload, ensure_ascii=False),
            latency_ms=17,
            killed=False,
            timed_out=False,
        )
        parsed = _expect_ok(f"{tool_id}: parse_output Ok", parse_output(spec, out))
        _check(
            f"{tool_id}: kind->result model",
            _expect_kind_result(spec.kind, parsed),
            f"kind={spec.kind} model={type(parsed).__name__}",
        )
        _check(f"{tool_id}: latency_ms copied", parsed.latency_ms == 17)
        _check(f"{tool_id}: killed copied", parsed.killed is False)

        if isinstance(parsed, CollectResult):
            vals = payload.get("values", {})
            if isinstance(vals, dict):
                for k, raw in vals.items():
                    masked = parsed.values.get(str(k), "")
                    _check(f"{tool_id}: masked value present({k})", bool(masked))
                    _check(f"{tool_id}: raw not leaked({k})", str(raw) != masked)

        if isinstance(parsed, InjectResult):
            if not parsed.accepted:
                _check(f"{tool_id}: effect empty when not accepted", parsed.effect == {})
            bb = payload.get("blocked_by")
            if isinstance(bb, str):
                if bb in {"signing", "auth", "no_effect", "timestamp", "baseline"}:
                    _check(f"{tool_id}: blocked_by propagated", parsed.blocked_by == bb)
                else:
                    _check(f"{tool_id}: blocked_by filtered", parsed.blocked_by is None)

    print()
    print("=" * 70)
    print("B. parser edge behavior")
    print("=" * 70)
    # killed/timed_out should force accepted=False on INJECT.
    inj = get_spec("serial5762")
    out_killed = ExecOutput(
        returncode=124,
        stdout=json.dumps({"accepted": True, "effect": {"mode": "5"}}),
        latency_ms=999,
        killed=True,
        timed_out=True,
    )
    parsed_killed = _expect_ok("inject killed parse ok", parse_output(inj, out_killed))
    _check("inject killed -> accepted false", isinstance(parsed_killed, InjectResult) and parsed_killed.accepted is False)
    _check("inject killed flag copied", parsed_killed.killed is True)

    # invalid json should fallback to conservative defaults.
    for tid in ("recon_reach", "capture_downlink", "webcmd"):
        spec = get_spec(tid)
        bad = ExecOutput(returncode=0, stdout="{not-json", latency_ms=1)
        parsed = _expect_ok(f"{tid}: invalid-json parse ok", parse_output(spec, bad))
        _check(f"{tid}: invalid-json kind mapping", _expect_kind_result(spec.kind, parsed))

    print()
    print("=" * 70)
    print("C. recon/resolve parser helpers")
    print("=" * 70)
    _check("parse_signing(on)", parse_signing("ON") == "on")
    _check("parse_signing(fallback)", parse_signing("weird") == "unknown")
    _check("parse_sessions(non-negative)", parse_sessions("7") == 7)
    _check("parse_sessions(fallback=0)", parse_sessions(-1) == 0 and parse_sessions("x") == 0)
    _check("parse_probe_json(object only)", parse_probe_json("{}") == {} and parse_probe_json("[]") == {})

    networks = parse_inspect_networks(
        json.dumps(
            {
                "net_sgi": {"IPAddress": "10.10.0.5"},
                "net_cellular": {"IPAddress": "10.20.0.8"},
                "bad": {"IPAddress": "not-ip"},
            }
        )
    )
    _check("parse_inspect_networks ipv4 filter", networks == {"net_sgi": "10.10.0.5", "net_cellular": "10.20.0.8"})
    _check("parse_br_addr extract first ipv4", parse_br_addr("tun_srsue UNKNOWN 10.45.0.3/16") == "10.45.0.3")

    hb_ok = parse_heartbeat('{"sysid":1,"type":2}')
    hb_bad = parse_heartbeat('{"sysid":255,"type":6}')
    _check("parse_heartbeat uav signature", hb_ok.is_uav is True)
    _check("parse_heartbeat non-uav", hb_bad.is_uav is False)
    _check(
        "target_ip_fields extracts only known placeholders",
        target_ip_fields("{oracle_ip}:14556 mode {mode} via {cipher_ip}") == ("oracle_ip", "cipher_ip"),
    )


async def run_live(config_path: str, backend_kind: str, tool_ids: list[str]) -> None:
    print()
    print("=" * 70)
    print("D. live parse measurement (safe subset)")
    print("=" * 70)

    cfg = load_config(config_path)
    mgr = D.build_sidecar_manager(cfg)
    backend = D.build_backend(
        cfg,
        kind=backend_kind,
        workdir=_ROOT / ".cache_verify",
        mgr=mgr,
    )
    mgr.bind_backend(backend)
    resolver = D.build_resolver(cfg, backend)
    runner_factory = make_runner_factory(
        backend=backend,
        timeout_s=cfg.run.termination_timeout,
        preflight=(backend_kind != "mock"),
        resolver=resolver,
    )

    try:
        # ensure only sidecars required by requested tools
        need = sorted(
            {
                get_spec(tid).exec_binding.sidecar
                for tid in tool_ids
                if get_spec(tid).exec_binding.sidecar != "host"
            }
        )
        for sidecar in need:
            if sidecar in mgr.kinds:
                ensured = await mgr.ensure(sidecar)
                if isinstance(ensured, Ok):
                    _check(f"ensure sidecar:{sidecar}", True)
                else:
                    # Existing sidecars outside our ownership labels can still be runnable.
                    detail = ""
                    if isinstance(ensured, Err):
                        detail = getattr(ensured.error, "error", "Err")
                    print(f"[WARN] ensure sidecar:{sidecar} skipped - {detail or 'non-fatal'}")
            else:
                _check(f"sidecar available:{sidecar}", False, f"known={mgr.kinds}")

        for tid in tool_ids:
            spec = get_spec(tid)
            runner = runner_factory(spec)
            parsed = _expect_ok(f"live {tid}: runner ok", await runner())
            _check(
                f"live {tid}: model type",
                _expect_kind_result(spec.kind, parsed),
                type(parsed).__name__,
            )
            _check(f"live {tid}: latency captured", getattr(parsed, "latency_ms", 0) >= 0)
            if isinstance(parsed, ReconResult):
                _check(f"live {tid}: signing domain", parsed.signing in {"on", "off", "unknown"})
    finally:
        mgr.bind_backend(backend)
        await mgr.teardown()
        await backend.teardown()


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="V2-D21 parser verification (offline + optional live-safe)."
    )
    p.add_argument(
        "--live",
        action="store_true",
        help="Run live-safe parser checks after offline checks.",
    )
    p.add_argument(
        "--config",
        default="configs/config.testbed.yaml",
        help="Input config path for live run (default: config.testbed.yaml).",
    )
    p.add_argument(
        "--backend",
        default="local",
        choices=["local", "ssh", "mock"],
        help="Backend kind for live run.",
    )
    p.add_argument(
        "--live-tools",
        default="recon_reach,recon_defense,recon_session",
        help="Comma-separated live tool ids (safe subset recommended).",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    run_offline()

    if args.live:
        ids = [x.strip() for x in args.live_tools.split(",") if x.strip()]
        # default policy: safe PROBE-only; override allowed explicitly.
        if not ids:
            _check("live tools not empty", False)
        else:
            for tid in ids:
                _check(f"live tool exists:{tid}", tid in REGISTRY)
            if all(tid in REGISTRY for tid in ids):
                asyncio.run(run_live(args.config, args.backend, ids))

    print()
    if _FAILS:
        print(f"FAIL ({len(_FAILS)}): {', '.join(_FAILS)}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
