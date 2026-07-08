# MDG Code Review — 2026-07-08

Scope: `C:\Users\user\Desktop\dah\dah_defense\mdg` (MDG defense agent).
Baseline at review time: local pytest **188 passed, 2 skipped**; `verify/` gates green.
Reference conventions: **agent_v2** (README/QUICKSTART/CHANGELOG + `llm.py` envelope + `make_runner` wrap) and the repo's own **OSS/LangGraph** framework decision (deterministic routing + leak-0 hand-held; rest OSS).

Two UNBREAKABLE invariants frame every finding below:
- **불변식①** Deterministic control flow — `edges.py` read ONLY numeric/bool; orient/decide LLM is ADVISORY-ONLY and EDGE-INVISIBLE.
- **불변식②** Leak-0 — single subprocess site (`safe_exec/backend._spawn`); no added spawns.

Every item in this review was checked against: *can this break a test, or touch the determinism path / DROP path / scoring / schema?* Only items proven **non-behavioral and test-neutral** were applied; everything else is DEFERRED with a documented rationale (no forcing).

---

## Summary

| Status | Count | Dimensions |
|--------|-------|-----------|
| **Applied** (safe, non-behavioral) | 3 | config-loader (2), structure-docs (1) |
| **Deferred** (behavioral / judgment) | 18 | llm-layer (5), config-loader (2), errors-failsafe (6), structure-docs (5) |

All 3 applied fixes re-verified post-edit: loader imports clean, `verify_no_fw_subproc` PASS (119 checks), full suite still **188 passed / 2 skipped**.

---

## APPLIED — safe, non-behavioral (comment/docstring only)

### A1 · config-loader · medium · `mdg/config/loader.py:1` (module docstring)
**Finding:** The deterministic scoring pipeline bypasses `loader.thresholds()` and reads `defaults.py` constants directly, so most of the loader's returned payload and the thresholds.yaml scoring section are effectively dead — retuning the "canonical" YAML silently no-ops. The loader docstring ("Prefers the canonical *.yaml files") and defaults.py ("the values the deterministic scoring pipeline reads") are contradictory and mislead an operator into thinking editing thresholds.yaml recalibrates scoring.

**Verification:** grep-confirmed the only live consumers of `thresholds()` are `recon.py:62-63` (rtt_baseline_ms/rtt_mdev_ms), `evidence.py:45` (evidence_ttl_s), `client.py:66` (llm_response_max_bytes). No consumer reads severity_factor/band_map/metrics/trust_bands/impact_bands/low_confidence_threshold/seq_window/ts_skew_s/correlation_rules/driver back through the loader — those are imported directly from `defaults` by scoring.py / compute_trust.py / correlate.py / intent_ledger.py / ingest/verify.py / driver.py / bundle.py.

**Fix applied:** Added a `Q-D-4 DOCUMENTATION-ONLY` block to the loader module docstring naming exactly which keys are live-read via the loader vs. read from `defaults.py`, and stating explicitly NOT to wire the loader into scoring (that would move calibration onto the YAML surface → 불변식① determinism-path change). **No code path changed.**

### A2 · config-loader · low · `mdg/config/loader.py:63` (`channel_quality()`)
**Finding:** The entire `channel_quality` config subsystem (`loader.channel_quality()`, `defaults.CHANNEL_QUALITY`, `channel_quality.yaml`) has zero consumers. Evidence confidence actually comes from the ingest payload, so retuning these priors has no effect. The YAML header claiming it is "compute_confidence의 avg_quality 입력" is inaccurate.

**Verification:** grep-confirmed `loader.channel_quality()` is never called and `CHANNEL_QUALITY` is never read. `SensorEv.confidence` is set in `collector/ingest.py` from `p.get('confidence', 0.9)`; `compute_trust.py` derives avg_q from those per-evidence confidences, never from the channel priors.

**Fix applied:** Added a `Q-D-4 DOCUMENTATION-ONLY` marker comment above `channel_quality()` noting no live consumer within mdg (mirroring the repo convention for `SEQ_SKEW_S` and `score_weights`). Did **not** delete the file/constant/function or change any numeric prior.

### A3 · structure-docs · low · `mdg/verify/verify_no_fw_subproc.py:3` (module docstring)
**Finding:** Docstring overclaimed that `safe_exec/backend.py` is "The ONLY module permitted to import subprocess", but `safe_exec/safeexec.py:29` also imports subprocess, and the gate's `_core_files()` only walks `core/` — so the gate does not actually forbid subprocess outside `core/`. (Already flagged in BUILD_REPORT P1.)

**Verification:** grep-confirmed `import subprocess` at `backend.py:19` **and** `safeexec.py:29`; `_core_files()` walks `CORE` only. Gate re-run post-edit: **PASS, 119 checks.**

**Fix applied:** Reworded the docstring — nodes/core modules never spawn; the gate scans **only** `core/*`; on the single-spawn path `backend.py` owns the primary spawn and `safeexec.py` holds the R1~R6 teardown/reap primitives on that same path; the positive assertion checks only that backend.py owns the import, not a whole-tree "only importer" proof. Added pointer to `CODE_AUDIT_20260708:45` for the separate (behavioral) scan-root-widening option. **Docstring-only; no scan logic changed.**

---

## DEFERRED — behavioral or judgment (not auto-applied)

### Dimension: llm-layer (`mdg/llm/client.py`)

#### D-LLM-1 · medium · line 36 — `_REJECT_SAMPLING` hardcoded denylist — ✅ RESOLVED (2026-07-08)
**FIX:** added `_ACCEPT_SAMPLING` allowlist (sonnet-4-5, haiku-4-5); `_emit_temperature` now returns False for reject family, True for known-accept family, and — the fail-safe — False for any UNKNOWN Anthropic model (a future opus-4-9/sonnet-6 now OMITS temperature instead of 400-and-dies), True for non-Anthropic providers. New test `test_emit_temperature_forward_safe_for_unknown_and_nonanthropic`; existing `test_emit_temperature_gate` 6 cases unchanged. pytest 192 green.

Original: Any future reject-sampling Anthropic family not listed (e.g. a new opus-4-9 / sonnet-6 / haiku-5 that 400s on `temperature`) would get `temperature=0` emitted → HTTP 400 → that model silently falls to the deterministic fallback with no operator-visible signal. Correct for the 3 currently-configured models and covered by `test_emit_temperature_gate`; `drop_params=True` is a partial second net. **Why deferred:** editing the classifier touches the determinism/temperature path. Recommend documenting the models.yaml ↔ `_REJECT_SAMPLING` coupling only. *(See claude-api skill for the current Anthropic model temperature-support matrix before any future edit.)*

#### D-LLM-2 · medium · line 123 — per-attempt `timeout_s` in fallback loop
The hand-rolled `for model in models` loop applies `timeout=timeout_s` PER attempt, so the configured 2-model chain can block up to ~2×timeout_s (~10s), contradicting the module's own "5s deadline is real" framing; no outer wall deadline wraps the node (none in `graph.py`). Latency-only, not correctness (routing stays deterministic — always falls back on final failure). **Why deferred:** enforcing a shared remaining-budget (deduct elapsed per iteration) or softening the docstring is a behavioral timing change.

#### D-LLM-3 · medium · line 113 — litellm telemetry not explicitly disabled
`litellm.telemetry`/callbacks are not explicitly disabled at this single litellm surface, in tension with the **PS-4 egress allowlist** (`api.anthropic.com:443` only). Defense-in-depth gap; modern litellm telemetry is largely no-op so severity is bounded. **Why deferred:** setting `litellm.telemetry = False` at import adds global config → behavioral; verify against pinned litellm version first.

#### D-LLM-4 · low · line 140 — non-string `content` assumption
`resp["choices"][0]["message"]["content"]` assumes dict-subscripting + string content; litellm/Anthropic can return a list of content blocks or `None`, which flows into `_parse_capped` where `raw.encode(...)` raises `AttributeError`. Fails safe (caught by per-model except → fallback) so no correctness break, but the byte-cap DoS bound is bypassed for non-string content and it diverges from agent_v2 (`raw.model_dump()` into an `extra='ignore'` envelope). **Why deferred:** normalizing content is a parse-path behavioral change.

#### D-LLM-5 · low · line 115 — scalar-string `fallback` mishandled
`[role_cfg.get("model")] + list(role_cfg.get("fallback", []) or [])` splits a scalar-string `fallback` into per-character model ids (`list('anthropic/...')`), each erroring through the whole loop before the deterministic fallback. models.yaml currently declares `fallback` as a list → no live impact. **Why deferred:** coercing a str to a single-element list changes model-list construction.

### Dimension: config-loader

#### D-CFG-1 · medium · `loader.py:23` — `_try_yaml` guards only the import
`_try_yaml` guards only the pyyaml import, not `open()`/`yaml.safe_load()`. A present-but-malformed/unreadable YAML raises (`YAMLError`/`OSError`) and propagates through every `@lru_cache` accessor, aborting recon/scoring instead of falling back to `defaults.py`. The advertised graceful fallback only triggers on pyyaml-absent or file-absent. **Why deferred:** this is a deliberate fail-safe vs. fail-closed decision — EITHER wrap open/safe_load returning `None` (fail-safe onto constants) OR document malformed config as intentionally fatal. Either way it's an error-path behavioral change; leave as a documented decision.

#### D-CFG-2 · low · `mission_profile.yaml:37` — `bootstrap`/`ntp` keys with no mirror
`mission_profile.yaml` lines 37-38 (`bootstrap:{...}`, `ntp:{...}`) exist only in the YAML; `defaults.MISSION_PROFILE` omits both, and no reader references them (grep-confirmed) — a pyyaml-path-only asymmetry. Harmless today, but a future `profile['bootstrap']` reader would `KeyError` only on the pyyaml-absent path. (`ntp.max_skew_ms=200` is also the origin of the already-documented-dead `SEQ_SKEW_S`.) **Why deferred:** mirroring the keys into defaults or annotating them touches the config surface; do not change values.

### Dimension: errors-failsafe

#### D-ERR-1 · medium · `collector/base.py:103` — erroring collector keeps heartbeat fresh — ✅ RESOLVED (2026-07-08)
**FIX:** `tick_once` refreshes `_last_hb` ONLY on a non-raising cycle (moved out of `finally`); `run()` no longer refreshes the heartbeat on the exception path. A quiet tick (`collect()->[]`) is still a success and beats; a persistently-erroring collector now goes stale and the Watchdog (G7) marks it dead + emits `sensor_loss`. New tests: `test_collector_heartbeat_withheld_on_error`, `test_quiet_collector_keeps_beating`, `test_watchdog_marks_erroring_collector_dead` (pytest + standalone). pytest 192 green.

Original: A collector whose `collect()` raises every cycle still refreshes `_last_hb` (finally at line 94 + except at line 103), so the **Watchdog (G7)** never marks it dead — a persistently-failing vantage is indistinguishable from a healthy quiet one, and `self.errors` is read by nobody. **Why deferred:** the "quiet tick still alive" semantics should not extend to the exception path — fix needs a separate last-success timestamp or a watchdog error-rate factor. Behavioral liveness change; `test_p1_engine` exercises heartbeat.

#### D-ERR-2 · medium · `core/nodes/effect_confirm.py:25` — injected `observe(rule)` unguarded
`effect_confirm` calls `bool(observe(rule))` with no exception guard, unlike sibling advisory nodes `orient.py:36-40` / `decide.py:28-33` which wrap their injected callables and fall back deterministically (**G6**). A raising `observe` (parse/backend fault) propagates out of the node and aborts the whole driver tick. The fail-safe `None` case already degrades to "unconfirmed → re-observe next tick"; a raising `observe` should degrade the same way. **Why deferred:** error-path change on a graph node; could interact with graph-parity tests.

#### D-ERR-3 · medium · `safe_exec/backend.py:151` — spawn `Popen` outside try/except
The single `subprocess.Popen(req.argv, ...)` spawn site (line 151) is constructed before the `try:` guarding `communicate()`; the finally-reap only runs if Popen already succeeded. Every INTERNAL failure returns an `ExecResult` (timeout→124), but a spawn `OSError`/`PermissionError` (missing iptables/nsenter/tcpdump binary) leaks uncaught. On the read-only observer path it's absorbed by `BaseCollector.run`, but on the **act DROP/actuation path** `def_tool_wrap` catches ONLY `CRSError` (`defresult.py:64`), so a Popen `OSError` bypasses the "every tool returns DefResult, no exception leak" contract and crashes the tick. agent_v2's `make_runner` wraps `backend.run` in `except Exception → Err`. **Why deferred:** this is on the live-verified actuation path — recommend catching spawn `OSError` → `ExecResult(ok=False, code=127, note='spawn failed')`, but do not modify under this pass.

#### D-ERR-4 · low · `safe_exec/signer_shim.py:208` — GRANTED receipt swallow
`OperatorGate.verify()` commits in-memory anti-replay state (adds nonce to `_seen_nonces`, advances `_last_consume_ts`) and returns `(True,'approved')` even when the durable GRANTED receipt write fails, because `_record` swallows all ledger exceptions (lines 170-172). On reboot `_seen_nonces` is reseeded only from `ledger.recover_on_boot()`, which won't contain this nonce — re-opening the replay window within the token TTL, contradicting the documented crash-durable single-use guarantee. **Why deferred:** operator-gate/signing path (§9-B), not the DROP path — consider failing closed when the durable write can't persist; document only.

#### D-ERR-5 · low · `core/nodes/sense.py:36` — `_drain` bare `except Exception: break`
`_drain` catches generic `Exception` and breaks, silently abandoning the rest of the queued envelopes for that tick with no counter — unlike `base.py push()` which increments `self.drops` on `queue.Full`. `queue.Empty` is the only expected exception; a transient non-Empty fault stops the drain mid-queue and discards still-pending verified evidence invisibly. **Why deferred:** narrow to `Empty` only (let unexpected errors surface) or count abandoned envelopes — behavioral.

### Dimension: structure-docs

#### D-DOC-1 · medium · `mdg/BUILD_REPORT.md:1` — no README/QUICKSTART/CHANGELOG at mdg root
Unlike agent_v2 (which standardizes all three as the operational entry point), mdg's only root docs are BUILD_REPORT.md, DESIGN_DECISIONS.md and LIVE_VERIFICATION.md — none give a clone/install/run entry path. **Verified additive-only:** no `verify/` or `tests/` gate enumerates `.md` files or a required-doc manifest, so new doc files cannot break the baseline. **Why deferred:** authoring accurate operational content (module map, how to run pytest + `verify/` gates, the 2 invariants) is a judgment task, not a mechanical edit.

#### D-DOC-2 · low · `DESIGN_DECISIONS.md:73` — stale `검증:` gate pointers
The locked contract's `검증:` pointers reference `tests/verify_*.py`, but the suite lives in `verify/`, and several named gates were never built (`verify_no_sock_in_core`, `verify_ingest_hmac`, `verify_seq_persist`, `verify_bind_iface`, `verify_viewer_auth`, `verify_egress_allowlist`, `verify_no_key_in_image`, `verify_replay_leak0`). Actual gates: `verify/verify_{graph,routing,grep0,keys,tools,models,no_fw_subproc,leak0,d11_collector_disjoint}.py` (+ `tests/verify_injection_gate.py`, `tests/verify_parsers.py`); `verify_replay_leak0`→`verify_leak0`. **Why deferred:** DESIGN_DECISIONS.md is a locked contract — do NOT rewrite locked sections; add a short errata/reconciliation note instead. No gate cross-checks these references, so nothing breaks.

#### D-DOC-3 · low · `DESIGN_DECISIONS.md:349` — non-existent module paths
PS-8 points the FastAPI viewer at `mdg/verifier/viewer.py`, but it ships at `mdg/viewer/app.py` (`verifier/` is the separate replay-only trust root) — a plain naming drift. `safe_exec/docker_backend.py` (layout line 34, PS-1 line 226) is unbuilt but the contract already acknowledges it as "미생성/미래 (D-2 잔여)" — a documented deferral. **Why deferred:** fold both into the same errata note; keep locked text intact.

#### D-DOC-4 · low · `tools/registry.py:113` — dangling `exec='safe_exec.docker_backend'`
`docker_pause` (line 113) and `docker_net_disconnect` (line 116) declare `exec='safe_exec.docker_backend'`, but no such module exists (`resolve.py:96` calls it "the future safe_exec/docker_backend.py"). Never spawned today — both are operator-go/OPER-tier (Backend defaults `allow_live=False`) and `verify_tools` doesn't require the module to import. **Why deferred:** `registry.py` exec/tier strings are load-bearing for the schema and OPER routing; a trailing "exec target unimplemented — operator-go" comment should be reviewed, not mechanically applied.

#### D-DOC-5 · low · `docs/CODE_AUDIT_20260708.md:56` — stale dead-code claim
The audit lists "act.py:71 `reverse_container_for_ip` 데드코드", but this is stale: `act.py` never calls `reverse_container_for_ip` (live in `targets/resolve.py`, exercised by `test_p2_recon.py`), and `act.py:83-89` now carries an explicit Q-D-3 comment rebutting the claim (its OPER pause branch intentionally does not resolve the container). **Why deferred:** editing a dated audit report is a judgment call — leave as historical record with a one-line "RESOLVED/stale" annotation, or drop the item.

---

## Post-change verification

| Check | Result |
|-------|--------|
| `python -c "import mdg.config.loader"` | OK (`channel_quality()`, `thresholds()` non-None) |
| `python mdg/verify/verify_no_fw_subproc.py` | **[PASS] 119 checks** |
| `python -m pytest mdg/tests -q` | **188 passed, 2 skipped** (unchanged from baseline) |

All three applied fixes are comment/docstring-only — no scoring scalar, no routing edge, no schema field, no spawn site, and no DROP-path logic was touched. 불변식① and 불변식② preserved.
