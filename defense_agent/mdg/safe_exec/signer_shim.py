"""signer_shim — operator-gate token binding (PS-9) + KEY-FREE signed-mode emitter (P3-Q1 / C-2).

C-2 SoD resolution (locked): MDG holds NO uplink-signing key on ANY path. The false premise —
"the operator-gate must co-locate with the signing key" — is dropped: ``uav_proxy`` already
ENFORCES uplink signing on the drone side and ``gcs_c2`` already signs with its own key. So
MDG's autonomous (act) path never needs a signing key (the only AUTO response is the netns
DROP). The operator-gate here issues an AUTHORIZATION token, not a signature.

This module provides two things:

  1. Command-bound OperatorRequest (PS-9). The token is an HMAC over
     ``(decision_id, command_digest, nonce, expiry)`` — so a CAPTURED approval cannot authorize
     a DIFFERENT command (its command_digest differs → the HMAC no longer verifies). The nonce
     is single-use and issue/consume timestamps are MONOTONIC (replay + continuity).

  2. A KEY-FREE signed-mode emitter. ``emit_signed`` NEVER opens or references any signing-key
     path: with allow_live=False it computes ONLY the command_digest (token material); a live
     promotion DELEGATES to the gcs_c2 out-of-band signing endpoint (operator-go 유보) over an
     authenticated channel — re-mounting the key is FORBIDDEN (E11 non-proliferation).

Secret hygiene (PS-3 / PS-5 #3): the operator-gate HMAC key lives in THIS module's process
memory ONLY — never MDGState, replay JSONL, or the checkpointer. It is a SEPARATE secret from the
uplink-signing key. No signing-key path literal and no key file read appear here (the emitter is
statically key-free — verify_signer_no_keyopen).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
import warnings
from dataclasses import dataclass, field
from typing import Optional

from .backend import ExecRequest  # single-spawn owner request type (불변식②); NO subprocess here

# --- key-free emitter binding: the SoD contract in one place (load-bearing comment) --------- #
# MDG delegates the actual signature to the container that already holds the key. We name the
# delegate endpoint but NEVER a key path — the emitter must remain key-free.
GCS_SIGN_DELEGATE = "gcs_c2"          # out-of-band signer (already holds its own key)
# The signed-correction sender is AUTHORED here as an asset (assets/gcs_signed_correct.py) but is
# DEPLOYED INTO gcs_c2 by the mainloop (docker cp) — MDG only names the in-container path and the
# recovery (mode, altitude) parameters. The signing key stays INSIDE gcs_c2: this module never names
# a key path and never reads a file (verify_signer_no_keyopen).
GCS_SIGNED_SENDER = "/gcs_signed_correct.py"   # sender path INSIDE gcs_c2 (mainloop deploys it)
_RECOVERY_MODE = "GUIDED"             # the flight mode that accepts the 30 m reposition (S2 return)
_RECOVERY_ALT_M = 30                  # home/hover relative altitude (arducopter --home=...,30)
# Backend spawn hard deadline for the gcs_c2 signed sender (R1). LOAD-BEARING INVARIANT: this MUST
# exceed the sender's worst-case blocking budget with margin, or Backend._spawn SIGKILLs the process
# group MID-SEQUENCE and the S2 physical return truncates silently (GUIDED set but the 30 m reposition
# never issued). gcs_signed_correct.py bounds its worst case to
#   HEARTBEAT_TIMEOUT_S + 2*(POS_TIMEOUT_S + SETTLE_S) = 5 + 2*(2+1) = 11s  (+ small connect overhead).
# 30s leaves >2.5x headroom for heartbeat delay / lossy-UDP jitter after a command-hijack (contended
# uplink) while still bounding a truly hung sender. Keep in lockstep with the asset's budget constants.
_DELEGATE_TIMEOUT_S = 30.0


def _canonical(*parts: object) -> bytes:
    """Deterministic canonical byte-join for digest/HMAC (order-fixed, NUL-separated)."""
    return b"\x00".join(str(p).encode("utf-8") for p in parts)


def command_digest(intent) -> str:
    """sha256 hex over the command's identifying fields (KEY-FREE — no secret involved).

    Binds decision_id|rule|tool_id|config_version|sorted(params)|target|target_kind|enforce_at. Two
    different commands (or the same command scoped to a DIFFERENT source OR enforcement selector,
    P4-Q1/P4-2) yield different digests, so a captured approval minted for one cannot verify against
    another — operator approval is scoped to (command, source, enforcement chokepoint). (The
    dispatch-resolved live src_ip binding is operator-go RESERVED: src_ip is only resolved on the
    AUTO netns-DROP path, not at escalate.)
    """
    params = getattr(intent, "params", None) or {}
    if isinstance(params, dict):
        params_repr = ";".join(f"{k}={params[k]}" for k in sorted(params))
    else:
        params_repr = str(params)
    blob = _canonical(
        getattr(intent, "decision_id", ""),
        getattr(intent, "rule", ""),
        getattr(intent, "tool_id", ""),
        getattr(intent, "config_version", ""),
        params_repr,
        getattr(intent, "target", ""),
        getattr(intent, "target_kind", ""),
        getattr(intent, "enforce_at", ""),
    )
    return hashlib.sha256(blob).hexdigest()


@dataclass
class OperatorRequest:
    """The command-bound request the operator approves (NON-secret; goes to the ledger)."""
    decision_id: str
    command_digest: str
    nonce: str
    expiry: float          # absolute deadline (issued_ts + ttl_s)
    issued_ts: float


class OperatorGate:
    """Issues/verifies command-bound operator approvals (PS-9). Holds the HMAC key in process
    memory ONLY (never State). nonce single-use + monotonic timestamps prevent replay.

    KEY BOOTSTRAP (P4-Q2, locked): ``key=None`` is the NORMAL MDG-runtime posture, NOT a
    degraded mode. The autonomous path (escalate) calls ONLY ``issue()`` (key-free), so the MDG
    process needs NO approval secret — a compromised MDG then has NO material to forge a
    self-approval (sign()/verify() share ``self._key``: verify-capable == forge-capable, so
    holding the key inside MDG would let MDG self-approve and bypass the whole PS-9 binding).
    ``verify()`` returning fail-closed under key=None is therefore an INTENDED contract
    (structural "runtime cannot self-approve"), not a bug.

    Provisioning of a real key is OUT-OF-BAND and lives in the operator/verifier trust domain
    (tmpfs 0400 secret file, operator-go RESERVED, PS-5) — it does NOT flow through MDG. ``key``
    may be injected for that verifier-domain deployment or unit tests. The env fallback
    ``MDG_OPERATOR_GATE_KEY`` is DEV/replay ONLY (it is exposed via ``docker inspect`` Config.Env,
    a PS-1 leak surface) and emits a warning; production keys never arrive via env.
    """

    _ENV_KEY = "MDG_OPERATOR_GATE_KEY"

    def __init__(self, key: Optional[bytes] = None, clock=None, ledger=None):
        if key is None:
            env = os.environ.get(self._ENV_KEY)
            if env:
                # DEV/replay ONLY — env is visible in `docker inspect` Config.Env (PS-1 surface).
                # Production provisions via a tmpfs 0400 secret in the operator/verifier domain
                # (operator-go RESERVED, PS-5); MDG runtime stays key-free (key=None).
                warnings.warn(
                    "OperatorGate key read from env MDG_OPERATOR_GATE_KEY (DEV/replay only; "
                    "docker inspect exposes Config.Env). Production provisions the key via a "
                    "tmpfs 0400 secret in the operator/verifier domain, not MDG env (PS-5).",
                    stacklevel=2,
                )
                key = env.encode("utf-8")
        self._key: Optional[bytes] = key            # process-memory only, never State (PS-3)
        self._clock = clock
        # PS-9 anti-replay is durable when a secret-free operator-ledger is injected (P4-Q3):
        # the token is NEVER persisted; only the consumed-nonce set survives a reboot so a
        # captured-but-unexpired token cannot be replayed after a crash.
        self._ledger = ledger
        seed = set()
        if ledger is not None:
            try:
                seed = set(ledger.recover_on_boot())
            except Exception:
                seed = set()
        self._seen_nonces: set[str] = seed           # single-use enforcement (durable if ledger)
        self._last_issue_ts: float = 0.0             # monotonic issue continuity
        self._last_consume_ts: float = 0.0           # monotonic consume continuity

    def _now(self, now: Optional[float] = None) -> float:
        if now is not None:
            return float(now)
        if self._clock is not None:
            return float(self._clock.now())
        return time.time()

    # -- issue (KEY-FREE: building the request needs no key) --------------- #
    def issue(self, intent, *, nonce: str, ttl_s: float, now: Optional[float] = None,
              digest: Optional[str] = None) -> OperatorRequest:
        """Mint a command-bound OperatorRequest. Timestamp continuity: issue ts is clamped to be
        monotonic (never earlier than the last issue), so a stale clock cannot rewind the series.
        """
        t = self._now(now)
        if t < self._last_issue_ts:                  # continuity: no rewind
            t = self._last_issue_ts
        self._last_issue_ts = t
        dg = digest if digest is not None else command_digest(intent)
        req = OperatorRequest(
            decision_id=getattr(intent, "decision_id", ""),
            command_digest=dg, nonce=nonce, expiry=t + float(ttl_s), issued_ts=t,
        )
        # P4-Q3: durably mint the nonce lifecycle (ISSUED receipt — secret-free, NO token).
        self._record(req, verdict="ISSUED", consumed_ts=None)
        return req

    # -- durable secret-free receipt (P4-Q3; token is NEVER persisted) ----- #
    def _record(self, req: OperatorRequest, *, verdict: str, consumed_ts) -> None:
        if self._ledger is None:
            return
        try:
            self._ledger.record(decision_id=req.decision_id, command_digest=req.command_digest,
                                 nonce=req.nonce, expiry=req.expiry, verdict=verdict,
                                 issued_ts=req.issued_ts, consumed_ts=consumed_ts)
        except Exception:
            # ledger write must not crash the gate; anti-replay still holds in memory this run.
            pass

    # -- sign / verify (KEY required) ------------------------------------- #
    def sign(self, req: OperatorRequest) -> str:
        """Operator-side HMAC token over the FULL binding. Requires the key (else '' fail-closed)."""
        if self._key is None:
            return ""
        mac = hmac.new(self._key,
                       _canonical(req.decision_id, req.command_digest, req.nonce, req.expiry),
                       hashlib.sha256)
        return mac.hexdigest()

    def verify(self, req: OperatorRequest, token: str, *, now: Optional[float] = None,
               expected_digest: Optional[str] = None) -> tuple[bool, str]:
        """Verify a command-bound approval (PS-9). Rejects: no key, wrong/absent token, expired,
        replayed nonce, non-monotonic consume ts, and (if given) a command_digest mismatch — so a
        captured token minted for command A cannot authorize command B.

        On success the nonce is marked seen and the consume-ts advances (single-use + continuity).
        """
        if self._key is None:
            return False, "no operator-gate key (fail-closed)"
        if expected_digest is not None and not hmac.compare_digest(req.command_digest, expected_digest):
            return False, "command_digest mismatch (captured token bound to a different command)"
        t = self._now(now)
        if t > req.expiry:
            return False, "expired (TTL elapsed)"
        if t < self._last_consume_ts:                # continuity: consume ts must be monotonic
            return False, "non-monotonic timestamp (replay/continuity violation)"
        if req.nonce in self._seen_nonces:
            return False, "nonce already consumed (replay)"
        expected = self.sign(req)
        if not expected or not hmac.compare_digest(expected, token or ""):
            return False, "HMAC mismatch (unauthorized / tampered binding)"
        # Record the GRANTED receipt (fsync) BEFORE returning True so an actuation-then-crash
        # cannot re-approve the same nonce on reboot (P4-Q3 — token itself is NOT persisted).
        self._seen_nonces.add(req.nonce)
        self._last_consume_ts = t
        self._record(req, verdict="GRANTED", consumed_ts=t)
        return True, "approved"


# --------------------------------------------------------------------------- #
# KEY-FREE signed-mode emitter — NEVER opens any signing-key path (verify_signer_no_keyopen)
# --------------------------------------------------------------------------- #
@dataclass
class SignerEmit:
    ok: bool
    dry_run: bool
    command_digest: str
    delegate: str = GCS_SIGN_DELEGATE
    note: str = ""
    extra: dict = field(default_factory=dict)


def _recovery_mode_alt(intent) -> tuple[str, int]:
    """Resolve the (mode, relative-altitude-m) recovery parameters MDG hands to the gcs_c2 sender.

    These are NOT secrets and NOT a raw actuation payload — the actual signed MAVLink command is
    built and signed INSIDE gcs_c2 (which holds the key). Defaults are the S2 physical-return
    contract (GUIDED + 30 m home/hover). An Intent may override via ``params`` (mode/alt) if present;
    a malformed alt falls back to the 30 m default (fail-safe to the home altitude)."""
    params = getattr(intent, "params", None) or {}
    if isinstance(params, dict):
        mode = str(params.get("mode", _RECOVERY_MODE)) or _RECOVERY_MODE
        raw_alt = params.get("alt", _RECOVERY_ALT_M)
    else:
        mode, raw_alt = _RECOVERY_MODE, _RECOVERY_ALT_M
    try:
        alt = int(raw_alt)
    except (TypeError, ValueError):
        alt = _RECOVERY_ALT_M
    return mode, alt


def _delegate_argv(mode: str, alt: int) -> list[str]:
    """The single Backend-spawn argv: ``docker exec gcs_c2 python3 <sender> <mode> <alt>``.

    MDG passes ONLY the recovery mode + altitude. It never passes, names, or opens a key — the sender
    (already inside gcs_c2) reads gcs_c2's own key and signs there (E11 non-proliferation)."""
    return ["docker", "exec", GCS_SIGN_DELEGATE, "python3", GCS_SIGNED_SENDER, mode, str(alt)]


def emit_signed(intent, backend=None) -> SignerEmit:
    """Emit a signed-mode correction command WITHOUT MDG ever holding a key.

    allow_live=False (default / operator-go 유보): compute ONLY the command_digest (the token
    material) and return a DRY result — NO spawn, NO file access (unchanged legacy behaviour).

    allow_live=True (operator-approved live promotion): DELEGATE the signature to ``gcs_c2`` (which
    already holds its own key) by triggering, through the SOLE subprocess owner ``Backend.run``
    (불변식②, a single spawn site), ``docker exec gcs_c2 python3 <sender> <mode> <alt>``. The sender
    signs INSIDE gcs_c2 and pushes DO_SET_MODE GUIDED + a 30 m relative-altitude return to the SITL
    over the already-trusted gcs_c2 signing path. This function never opens, reads, or names a
    signing-key path (verify_signer_no_keyopen); it only builds an argv and hands it to Backend.run.
    """
    dg = command_digest(intent)
    live = bool(getattr(backend, "allow_live", False))
    if not live:
        return SignerEmit(ok=True, dry_run=True, command_digest=dg,
                          note="operator-go 유보: key-free digest only; sign delegated to gcs_c2 "
                               "(no signing key held, E11 non-proliferation)")
    # Live promotion: authorization must have been operator-approved (OperatorGate.verify). The
    # signature is issued by the gcs_c2 delegate out-of-band; MDG only triggers it via the single
    # Backend spawn and never re-mounts the key. A missing/invalid backend fails inert (no spawn).
    if not callable(getattr(backend, "run", None)):
        return SignerEmit(ok=False, dry_run=True, command_digest=dg,
                          note="live emit requested but no Backend spawn owner supplied (inert)")
    mode, alt = _recovery_mode_alt(intent)
    argv = _delegate_argv(mode, alt)
    res = backend.run(ExecRequest(argv=argv, timeout_s=_DELEGATE_TIMEOUT_S, reversible=False))
    return SignerEmit(ok=bool(getattr(res, "ok", False)),
                      dry_run=bool(getattr(res, "dry_run", False)),
                      command_digest=dg,
                      note=(f"delegate to {GCS_SIGN_DELEGATE} signed sender via Backend spawn "
                            f"(docker exec {GCS_SIGN_DELEGATE} python3 {GCS_SIGNED_SENDER} "
                            f"{mode} {alt}; key stays in {GCS_SIGN_DELEGATE}, E11): "
                            f"{getattr(res, 'note', '')}"),
                      extra={"mode": mode, "alt": alt, "argv": argv})
