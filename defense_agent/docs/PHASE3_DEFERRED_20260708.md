# PHASE3 DEFERRED — Concern group Q-C (collector false-positive suppression)

Date: 2026-07-08
Scope: MDG defense agent (`dah_defense/mdg`). Records the items in Q-C that were
**DOCUMENT-DEFERRED** because a code change would alter a NUMERIC SCORING scalar or a
band-range consumed by `compute_trust` / `compute_impact` / the conditional edges
(`edges.route_after_impact`, `edges.route_after_decide`) / `rank_recovery` / the
autonomous-DROP decision. Per the Q-C HARD GUARDRAIL these must NOT be applied as code;
they need calibration / domain sign-off first.

Baseline at time of writing: `pytest mdg/tests` = **169 passed / 2 skipped** (unchanged
by the one applied fix, item 2 — mongo dedupe time-bucket).

---

## Q-C-1 (DEFERRED) — `mdg/collector/air_side.py:~127` Packet_Loss band='warning' vs METRICS 'danger'

**Contract violation (real):** `AirTelemetryTap.collect()` emits, on a silent cross-tap,
`{"metric":"Packet_Loss","value":100,"band":"warning"}`. Per `config/defaults.py`
`METRICS["Packet_Loss"]` the value 100 falls in the **danger** range `[21,100]`
(bands: normal `[0,1]`, warning `[2,5]`, critical `[6,20]`, danger `[21,100]`). So the
emitted band is contract-wrong; the contract-correct band is `danger`.

**Why DEFERRED (band value IS a routing scalar — exact downstream trace):**

`warning -> danger` changes the E7 severity/deviation the scoring pipeline consumes:
- `config/defaults.py BAND_MAP`: `warning = {severity: medium(0.3), dev: 0.4}` →
  `danger = {severity: critical(1.0), dev: 1.0}`.
- `scoring.domain_penalty`: communication contribution `w·sev·dev` with weight 0.30:
  warning `0.30·0.3·0.4 = 0.036` → danger `0.30·1.0·1.0 = 0.30`.
- `compute_trust`: communication `trust_score = 100·(1 − conf·penalty)`; with the
  plaintext_mavlink_tap confidence ≈0.95 this moves communication trust from ≈96.6 to
  ≈71.5 (distrust ≈3.4 → ≈28.5).
- `compute_impact`: `distrust[communication]` (mission_weight 30) feeds
  `scoring.overall_impact` weighted_mean = Σ w·distrust / Σw → raises `overall` →
  `score_impact` → `impact.band` (Green/Yellow/Red).
- `edges.route_after_impact` reads `impact.band`: `Green → __end__`, else `→ orient`.
  A large communication-distrust jump can flip a tick Green→Yellow, i.e. it changes a
  **conditional-edge routing scalar** (ends-before-LLM vs enters orient).

It does NOT touch the command domain / BACKDOOR_5762 DROP path (that path is
`Port_5762_State → correlate → select_policy`, independent of communication trust). But
the guardrail bars ANY routing-scalar change, and `impact.band` is one. Correlate also
uses the band: `severity_factor(band)` sets the single-signal Incident `score`
(warning 0.3 → danger 1.0), another scored scalar.

**Disposition:** DEFER. Requires comms-domain calibration sign-off (does the band cut
250 / impact-band recalibration hold?) before flipping. NOT a pure false-positive fix.

---

## Q-C-3 (DEFERRED) — `mdg/core/nodes/sense.py:~80-84` command domain has 2 collectors; one death can mask the sibling

**Conflict (identified):** The command domain has **two** collectors with distinct
source_ids and non-overlapping metrics:
- `AirCommandTap` (`source_id="air_command_tap"`, metric `Unauthorized_Command`)
- `WebProbeCollector` (`source_id="web_5762_probe"`, metric `Port_5762_State`, the
  BACKDOOR_5762 detector).

`collector/__init__.py build_source_domains()` maps BOTH source_ids → the single key
`"command"`. The watchdog emits `sensor_loss` carrying `value=source_id` (per-collector),
but `sense()` collapses it to the **domain**:
- loss: `dead.add(source_domains[value])` → either collector's death adds `"command"`.
- clear: `else: dead.discard(ev.domain)` → any LIVE command evidence discards `"command"`.

Two masking failure modes follow from the **domain-granular** dead set vs **per-collector**
liveness:
1. **Live sibling erases a dead detector.** If `web_5762_probe` (the 5762 detector) dies
   but `air_command_tap` emits a live `Unauthorized_Command` the same tick, the `else`
   branch `dead.discard("command")` clears the dead mark → `compute_trust` treats command
   as present-and-healthy, hiding that the backdoor detector is blind.
2. **Order-dependence within a tick.** If a `sensor_loss` (add) and a live command
   evidence (discard) for `"command"` arrive in the same drain, the final dead state
   depends on evidence iteration order (add-then-discard vs discard-then-add).

**Why DEFERRED (fix changes a routing scalar — exact trace):** The only real fix is to
track liveness **per source_id** and mark the domain dead only when ALL its collectors are
dead (or keep a per-source dead set consumed by `compute_trust`). That changes
`worldstate.dead_domains` semantics, which flows:
`sense (dead set) → compute_trust` (`if dom in dead: continue` drops the domain's TrustObj)
`→ compute_impact` PRESENT-set (`if t is None: continue`; excluding a domain changes the
weighted_mean denominator Σw) `→ impact.band → edges.route_after_impact`. So any change to
which collectors mark `"command"` dead changes `impact.band` in a collector-death scenario
— a **conditional-edge routing scalar**. DEFER per HARD GUARDRAIL.

**BACKDOOR_5762 DROP is NOT affected either way** (safety note): the autonomous-DROP path
reads `evidence`/`incidents` directly (`Port_5762_State → correlate BACKDOOR_5762 →
select_policy backdoor_drop → nsenter_input_drop`), never `dead_domains`/`compute_trust`.
So the item-3 defer criterion "changes detection routing for BACKDOOR_5762" is NOT met by
the fix; it is deferred solely because it changes the `compute_impact` routing scalar.

**Disposition:** DEFER. Needs a per-source liveness design + impact-band re-verification
(present-set denominator behavior on a partial command-collector death) with sign-off.

---

## Q-C-4 (DEFERRED) — unemitted metrics RTT / Signature_Verify_Fail / NAS_Cipher_Order (domain weight budget unmet)

**Verified unemitted (grep of `mdg/collector/`):** no collector emits any of
`RTT`, `Signature_Verify_Fail`, `NAS_Cipher_Order`. They exist only in
`config/defaults.py METRICS` (and mirror `thresholds.yaml`) plus docs:
- `RTT` — `{domain: communication, weight: 0.20}` — referenced by `RTT_BASELINE_MS`
  priors and the prototype design, but NO active-probe collector emits it (network.py
  polls Prometheus counters only; no RTT/loss probe wired).
- `Signature_Verify_Fail` — `{domain: command, weight: 0.20}` — the uav_proxy signing
  drop-log SOURCE is D-2 un-wired (see `compute_trust.py` header note: "actuation-observation
  SOURCE … is D-2 un-wired -> operator-go deferred").
- `NAS_Cipher_Order` — `{domain: communication, weight: 0.15, once: True}` — no NAS-log
  collector emits it (`mme_log`/`smf_session` do not).

**Consequence:** the per-domain weight budgets in `METRICS` are not fully realized — the
communication domain sum (Packet_Loss 0.30 + RTT 0.20 + NAS_Cipher_Order 0.15) and the
command domain sum (Unauthorized_Command 0.35 + Signature_Verify_Fail 0.20 +
Port_5762_State 0.45) are only partially emitted. This is a **calibration / domain sign-off**
question (does trust scoring assume the full weight budget?), NOT a collector bug.

**Why DEFERRED (not a code change):** Inventing emitters would (a) fabricate signals not
backed by a wired live SOURCE — the opposite of false-positive suppression — and (b) add
new scored contributions to `compute_trust` (routing-affecting). The correct action is the
existing operator-go wiring of the D-2 signing collector and an active RTT/loss probe,
under domain calibration, not a Q-C code edit.

**Disposition:** DEFER (calibration / domain sign-off). No emitter invented.

---

## Q-D — Concern group Q-D (config dead-surface cleanup)

Date: 2026-07-08. All Q-D changes are **comment/documentation only** — zero value, tier, or
routing-scalar change. Grep verified every rtype/key before touching it. Baseline unchanged.

### Q-D-1 (DOCUMENTED, not removed) — `recovery_priors.yaml` pfcp_firewall enforce_at=gcs_proxy
LIVE rtype (`select_policy._INCIDENT_RECOVERY["CR01"]` + `test_p1_engine`/`test_p4_response`/
`verify_d11`). enforce_at=gcs_proxy is an unresolvable PFCP chokepoint (PFCP=net_core; gcs_proxy
never carries it; epc_smf/upf are log-tail containers, not resolvable roles). Chose option (a)
DOCUMENTATION (inline operator-only comment). Option (b) adding a `upf` role was REJECTED: its
response_tool `nsenter_input_drop` is AUTO-tier, so a newly-resolvable chokepoint would widen the
autonomous DROP surface through an unverified path. gcs_proxy resolves (verified), so the plan is
not inert, but a gcs_proxy-netns DROP does not chokepoint a net_core PFCP flow → ineffective no-op,
never a mis-DROP. No change to backdoor_drop.

### Q-D-2 (DOCUMENTED, not removed) — `recovery_priors.yaml` mongo_acl triple-dead
Orphan (no `_INCIDENT_RECOVERY` kind → never selected) + web_backend role-mismatch (Mongo 27017 on
RAN/cellular bridge) + unverified inter-container DROP (E4 br_netfilter absent). NOT removed: the
string `"mongo_acl"` is referenced by `test_p4_response.py:123` (absent-rule example) and mirrored
in `defaults.py RECOVERY_PRIORS`, so removal would break a test. Marked operator-only inline.

### Q-D-3 (DOCUMENT-DEFER) — `act.py` reverse_container_for_ip "dead code"
No such reference exists in `act.py` (grep-confirmed); the function is live only in
`targets/resolve.py` + `test_p2_recon`. The OPER pause path intentionally does not resolve the
pause-target container (docker_pause is operator-go), so resolution is correctly absent, not dead.
Added a clarifying comment; wiring resolution into the OPER branch is an operator-tooling concern.

### Q-D-4 (DOCUMENTATION-ONLY) — score_weights / SEQ_SKEW_S / thresholds() non-mirror
- `recovery_priors.yaml score_weights {0.6/0.4}`: unused (no reader); scoring.recovery_score
  hardcodes the split. Commented as documentation-only; numbers untouched.
- `defaults.py:145 SEQ_SKEW_S`: unused (no reader); anti-replay uses SEQ_WINDOW + TS_SKEW_S.
  Commented as a documented calibration note; value untouched.
- `loader.thresholds()` fallback: intentionally a non-mirrored subset of `thresholds.yaml`;
  harmless because every consumer carries its own `.get(default)` / `defaults.py` fallback
  (evidence_ttl_s, llm_response_max_bytes, rtt_*). Commented; no key added (adding one would put a
  value on the fallback path = a calibration change → deferred).

---

## APPLIED (for the record) — Q-C-2 `mdg/collector/mongo.py` dedupe time-bucket

NOT deferred; applied. The dedupe key changed from bare `remote` to
`f"{remote}|{floor(clock.now()/dedupe_window_s)}"` (default window 60s, using the
collector's injected `BaseCollector.clock`). This re-emits a re-connecting RAN-side IP
after the window instead of suppressing it permanently, while preserving intra-window
overlap dedupe and the 4096 bounded-cache DoS cap. Emitted scalars
(metric/value/band/domain/weight/confidence) are unchanged, so no routing scalar moves.
Baseline stays 169 passed / 2 skipped (existing `test_mongo_collector_dedupe` still green:
two identical lines in one cycle share the bucket → 1 emission).
