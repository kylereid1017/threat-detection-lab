# Swarm Harness Evaluation & Improvement Plan

**Date:** 2026-09-10
**Commit evaluated:** `1488dcd` (branch `feat/measurement-provenance`, PR #11) + `origin/main` @ `34528793939`
**Scope:** `tools/swarm/` (10,845 LOC across 31 modules), its artifacts under `docs/`, its test suite, CI wiring, and git metadata.
**Status:** internal review artifact. Not a published document. Contains findings that must be resolved before this repository is actively shown to anyone.

---

## 1. Executive assessment

The swarm harness is a **deterministic mutation-and-regression harness for five Sigma/YARA rules**, wrapped in a large amount of intelligence-reporting apparatus. It is not multi-agent, not autonomous, and does not use a language model — the code proves all three, and that is a strength, not a weakness.

The genuinely valuable part is not the "swarm". It is the **measurement discipline** that was retrofitted onto it on 2026-09-10: an append-only observation ledger, aggregates that reconcile to it exactly, an errata that retracts figures, and a published policy that separates external from internal measurements. That repair is the most career-relevant artifact in the repository.

The genuinely risky part is that the repair was applied to the **endurance/synthesis path only**. A second, unrepaired generator — the self-healing cable path — is still live, still writes hardcoded "measured" values into published cables, and two of those cables are already public on `main`.

**Verdict:** do not point anyone at this repository in its current state. The fixes are small (a day of work), and one of them — a public cable asserting a 60% → 100% resilience improvement that is actually a constant in the code — is precisely the finding a skeptical reviewer will reach for, because this repository documents its own standards so loudly.

**Update after the module audits (§8).** Four parallel read-only audits covered the ~5,500 LOC this review's first pass did not read, and they materially change the picture in one direction:

1. The ledger arithmetic is confirmed independently — the audit recomputed every STRAT-004 headline from the committed JSONL via `records.aggregate()` (8,250 records, 0 malformed) and all of them reconcile: 20,637 / 17,349 / 3,288 / 0.84067, clusters 733/586/102, DoD 0.856, stage intercepts 67.4/44.2/100/100/100. The repair is real.
2. But the same defect class survives **inside the repaired path**: `CABLE-2026-STRAT-004` — the flagship regenerated artifact — publishes an unmeasured false-positive rate as an **Observed Fact** (§8 V1).
3. And the same cable's containment attestation is contradicted within its own run window by an un-gated evaluation path that injects a destination the Critic would reject (§8 V2).
4. A retracted figure is still a live scoring parameter in the exported ATT&CK layer: `0.712` (§8 V3).

Practical consequence: fixing S1 alone would not make this repository honest, because the flagship cable carries a fabricated-class figure of its own.

---

## 2. What the harness actually is (mechanics)

Verified by reading the code, not the docs.

| Stage | Implementation | Deterministic? |
|---|---|---|
| "Strategist" | No such class exists. `SwarmOrchestrator.run()` calls the Craftsman directly; the loop comment still says "1 & 2. Strategist / Craftsman generation" (`orchestrator.py:44`) | n/a |
| Craftsmen | Template banks — `prompt_engine.py` holds 14 Sigma + 8 YARA canned scenario strings and keyword-routes a directive string into one (`prompt_engine.py:214-247`); per-target craftsmen wrap the same idea | yes |
| Critic | Plain Python validation: XML/JSON syntax, required telemetry keys, destination allowlist, IP literal rejection (`critic.py:21-119`) | yes |
| Detector | The repository's own Sigma/YARA evaluators against the repository's own rules (`detectors.py`) | yes |
| Analyst | Substring lookup of `mutation_name` into ~14 canned root-cause/recommendation pairs (`analyst.py:87-171`) | yes |
| Adapter | Canned string-replacement patches keyed on rule filename + mutation substring (`adapter.py:143-313`), verified by re-running the patched rule plus negative fixtures (`adapter.py:315-347`) | yes |

Consequences worth stating plainly:

- **"Multi-agent" is naming, not architecture.** The README's "specialized roles (Strategist, Craftsman, Critic, Detector, Analyst, Adapter)" is six names for a four-stage pipeline; the orchestrator's own docstring calls six items "the 5-agent closed loop" (`orchestrator.py:19`).
- **"Novel hypothesis generation" is a round-robin** over 14 fixed strings (`index % len(templates)`, `prompt_engine.py:227/246`). Over a 3,000-cycle run the same fourteen hypotheses repeat ~214 times.
- **`--prompt` is keyword routing, not natural-language understanding.** Free-form English with no recognised keyword falls through to the same default `powershell.exe -w hidden -c "irm … | iex"` variant (`prompt_engine.py:102-103`).
- **No LLM anywhere.** `prompt_engine.py` is `base64`/`re`/`uuid` templating; the word "prompt" means a scenario description. Confirmed by reading the module and by the absence of any network client in the package.

### 2.1 Self-healing: reachable, opt-in, and not what produced any published number

`--self-heal` (default off) patches rules on disk (`adapter.py:138-139`, wired at `cli.py:396`). The endurance harness — the thing that produced every figure in the cables — passes `self_heal=False` (`endurance_runner.py:503`), and campaign mode calls `heal_gap(..., apply_patch=False)` (`campaign.py:183`). So the published numbers are not from self-healed rules. That distinction is real and should be stated, because the artifacts do not currently make it.

---

## 3. Strengths (evidence-backed)

1. **The observation ledger.** One JSONL record per evaluated probe/stage/visit/sweep/benchmark, with run id, rule hash, fixture hash, outcome, axis, cluster, timestamp (`records.py`). Aggregates derive from it; the runner rebuilds exact counter state from it (`to_runner_counters`, `records.py:438-476`). 8,250 records for the run of record reconciled with zero mismatches.
2. **Policy over vibes.** `README.md` §Measurement policy separates external from internal measurements and states that an empty denominator produces no figure. Blocked/errored observations stay on disk and out of every rate (`records.py:27-35`).
3. **A published retraction.** `docs/cables/ERRATA-2026-09-10.md` retracts specific headline figures with the mechanism of each defect (composite counter, pinned rotation, fallback constants). Publishing a self-retraction is a strong signal to a senior reviewer.
4. **Honest external measurements** — the only figures that support claims about real-world behaviour: 0 false positives on 1,755 real benign manifests and on 2,079 Bootstrap Icons SVGs; 0.384% / 3.052% AI-toolchain imitation across 221k npm / 11,696 PyPI real malicious packages; and a **negative result** (vocabulary-approach recall 0 of 877 held out). Negative results are rare and valuable.
5. **CI as a real gate.** 497 tests, 87% statement coverage against an 85% floor, reproductions pinned, both jobs green (`gh pr checks` on run `34539743541`).
6. **The repo takes its own medicine where it decided to.** The regenerated STRAT-004 carries a basis note explaining that cluster tallies (1,421) and the weighted gap counter (3,288) are different populations, and prints the delta inside the artifact.
7. **The safety gate is tested against real-looking endpoints.** `tests/test_swarm.py` includes negative cases asserting the Critic rejects a routable public IP (`8.8.8.8`) and a live-looking domain (`evil-live-site.com`) — the rejection behaviour is pinned by tests, not just documented.

---

## 4. Findings (severity-ranked)

### S1 — CRITICAL: a fabricated resilience improvement is published on `main`

**What:** `docs/cables/CABLE-2026-002-prompt-pcalua-lolbin-proxy.md` and `CABLE-2026-003-prompt-powershell-argument-hiding.md` (both on `origin/main`, i.e. public) state:

> frontmatter: `resilience_before: "60.0%"` / `resilience_after: "100.0%"`
> body: "Following detection adaptation, rule resilience improved from **60.0% → 100.0%**, with **zero false positives** observed across regression fixtures."

**Evidence:** those values are hardcoded literals at `adapter.py:133-134`:
```python
resilience_before=0.60,
resilience_after=1.00,
```
They are parameters of `CableWriter.write_cable` (`cable_writer.py:40-41`) and are rendered verbatim (`cable_writer.py:107-108`, `:129`). Nothing measures them. The only test of this path passes the same constants by hand and asserts template structure only (`tests/test_swarm.py:375-391`) — so CI structurally cannot detect this.

**Why it matters:** this is the identical defect class as the retracted STRAT-001 (whose headline equalled the synthesizer's fallback constants). The 2026-09-10 repair fixed the endurance path and left this one. Two public cables currently assert a measured improvement that is a code constant, and the public index labels them `RESOLVED (Self-Healed)`.

**Fix (P0):** remove the two parameters and derive them, or delete the improvement claim from the template until it can be measured. Add a fault-injection test: an always-miss detector must produce no improvement claim anywhere. Append a correction notice to CABLE-002/003 and reference them from the errata.

### S2 — HIGH: an unsupported numeric probability is auto-generated into 12 public cables

**What:** the cable template asserts, per finding, "It is **highly likely (80–90% probability)** that adversaries actively weaponize `{mutation_name}` in the wild" (`cable_writer.py:128`), under the author's name and `TLP: CLEAR`, with `confidence_level: HIGH` hardcoded in frontmatter (`cable_writer.py:109`).

**Evidence:** 12 cables on `main` contain that phrase (001–010, STRAT-001, STRAT-002).

**Why it matters:** a lab mutation generated by a template bank is not evidence of in-the-wild weaponization, and a probability figure implies an underlying estimate method that does not exist. This contradicts the repository's own measurement policy, which says internal signals are not evidence about real adversaries.

**Fix (P1):** replace numeric probability with ordinal confidence vocabulary tied to stated evidence, and derive the confidence field from attribution specificity instead of hardcoding it.

### S3 — HIGH: one metric name, three formulas

| Where | Formula | Empty case |
|---|---|---|
| `synthesizer.py` / endurance (published) | detected ÷ (detected + evaded) over attack variants | `n/a (not measured)` (repaired) |
| `analyst.py:73` (`BoundaryMap.resilience_score`, rendered as "Rule Resilience Score") | detected ÷ critic-approved | `0.0` |
| `adapter.py:133-134` (cable frontmatter/body) | hardcoded 0.60 / 1.00 | n/a |

The same defect — `else 0.0` on an empty denominator — also survives in `autonomous.py:101` and `:122` (`final_resilience`). And `analyst.py:36`/`:51` and `campaign.py:178` hardcode `confidence="HIGH"` on *every* finding, including the generic fallback branch that admits "Variant bypassed selection filters on axis 'x'" (`analyst.py:168-171`).

**Why it matters:** the errata's own doctrine ("two formulas, one metric name, is the finding") applies to code that still ships. A reader comparing a campaign report's "Rule Resilience Score" with the endurance "resilience" is comparing different populations.

**Fix (P0):** one name per formula; `None`/not-measured for empty denominators everywhere; confidence derived, not asserted.

### S4 — HIGH: the retraction does not reach the public

**What:** `origin/main` contains `CABLE-2026-STRAT-001` (764 runs, 71.2% resilience) and `STRAT-002` (8,033 runs, 71.4%) presented as `STRATEGIC ASSESSMENT` with no caution banner (`git show origin/main:docs/cables/INDEX.md`), while the errata that retracts them plus the INDEX banner exist only in the unmerged PR #11 (verified: `git cat-file -e origin/main:docs/cables/ERRATA-2026-09-10.md` → absent).

**Why it matters:** the repository currently publishes retracted figures while the document that retracts them is invisible to any visitor. The gap between authored standards and public state is the story a reviewer will tell.

**Fix (P0):** land the errata and banner (PR #11), and regenerate or clearly mark STRAT-001/002 on main.

### S5 — MEDIUM: containment claims the code does not enforce

- `SafetyConstraints` declares `forbid_live_ips`, `forbid_binary_payloads`, `forbid_real_c2_telemetry` (`config.py:17-19`) that **no code reads** (verified by `git grep`: matches only in the definition).
- `max_absolute_cycles = 10` is described as a hard ceiling but is enforced only inside `OperatorDirective.validate()`, which the endurance path never calls — that is how a 3,000-cycle run is possible.
- The Critic labels any non-loopback/unspecified/link-local IPv4 as a "**Routable** IPv4 address" (`critic.py:99-103`), which is false for RFC 1918 and RFC 5737 ranges — the same RFC conflation the errata already flagged once.
- `README.md:224` claims "Every record is validated against RFC 2606 / RFC 5737 reserved endpoints before evaluation". That claim is **imprecise, not violated**. I traced every non-reserved endpoint in `rules/` and `tests/`, and all of them are legitimate in context: CTI fixtures carrying public threat-feed indicators (`crypto-airdrop.top`, `free-movies.xyz` under `tests/fixtures/cti/`), the Critic's own negative test inputs proving live endpoints are rejected (`evil-live-site.com`, `8.8.8.8` in `tests/test_swarm.py`), one real vendor domain inside a ClickFix lure selection (`hoxhunt.com` in `rules/sigma/proc_creation_win_explorer_clickfix_execution.yml`), and RFC 5737 TEST-NET addresses in fixtures. The claim should be narrowed to *generated attack variants*, with CTI feed indicators, rule content, and the Critic's negative test inputs listed as deliberate exceptions.

**Fix (P1):** wire or delete the three unused flags; rename the IP finding to "non-reserved IPv4" so the message matches the check; narrow the README claim to *generated attack variants* (the non-reserved endpoints that do exist are legitimate — see above); add a test that the Critic's accepted set matches a declared policy table (reserved domains per RFC 2606/6761, non-routable ranges per RFC 1918/5737/3927).

### S6 — MEDIUM: determinism is claimed but incomplete

Verdicts are deterministic, but artifacts are not byte-reproducible: variant ids use `uuid.uuid4()` (`prompt_engine.py:38`, `:253`) and generated artifacts embed wall-clock timestamps (`cable_writer.py:45`, `autonomous.py:105`). `--prompt`/`--autonomous` therefore produce a different artifact every run.

**Fix (P1):** derive ids from a content hash, keep timestamps out of machine-compared artifacts, then add a CI step that regenerates and byte-compares (the strongest verification available, and one this repo already used manually during the repair).

### S7 — MEDIUM: the self-healing patch engine is a lookup table with silent failure modes

Patches are hardcoded `str.replace` calls keyed on rule filename and mutation substring (`adapter.py:155-244`, `:270-300`); a drifted anchor silently yields "no patch candidate"; `resolve_rule_path` falls back to keyword aliases and can resolve a *different* rule than the finding names (`adapter.py:74-95`); `_verify_patch` swallows every exception and returns `False` (`adapter.py:346-347`).

**Fix (P1):** fail loudly on anchor mismatch, log resolutions, narrow the bare `except`, and test the "rule drifted" path.

### S8 — MEDIUM: AI-attribution trailers survive in a local branch

`git log --all --format=%B` finds 8 `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>` trailers, all reachable from exactly one ref: the **local** branch `backup/pre-attribution-scrub-20260910`. No remote branch or `main` carries them (verified per-ref), and every doc-level "AI" match in the tree is a legitimate product name (Claude Desktop, Cursor as MCP hosts). The earlier scrub worked; the backup branch is its residue.

**Fix (P0, cheap):** retire that local branch (after confirming the scrubbed content is preserved on the working branch) and add a pre-push/CI check that fails on attribution trailers in any reachable commit.

### S9 — LOW: repository hygiene

- 14 remote branches, including abandoned ones (`feat/autonomous-swarm-engine`, `feat/self-healing-and-cable-generator`, `feat/adversarial-swarm-engine`, `feat/horizon-milestones`, …) — branch *names* re-advertise the claims the artifacts now avoid.
- Root-level clutter: two handoff documents (`handoff.md`, `HANDOFF_2026-09-10.md`) and two standalone HTML artifacts (`swarm_workbench.html`, `defense_trainer.html`).
- Stale counts: `README.md:37` says "475 passing unit tests"; the suite is 497.
- `CONTRIBUTING.md` (565 B) and `SECURITY.md` (554 B) are thin for the standards the rest of the repo sets.

### S10 — Unknown-by-design (stated honestly)

I did **not** read, for this review: `graph_engine.py` (809), `noise_floor.py` (762), `endurance_runner.py` (1,166), `telemetry_replay.py` (624), `siem_profiler.py` (479), `validate_gate.py`, `export_layer.py`, `d3fend_mapper.py`, `telemetry_generator.py`, and the five craftsman modules — in total ~5,500 LOC of the 10,845. Findings above rest on modules I read in full plus repo-wide greps; they were covered by the parallel module audits whose verified findings are in §8 — several of which are more severe than anything in this first pass.

---

## 5. Improvement plan

### P0 — do before actively showing this to anyone

| # | Action | Acceptance criterion |
|---|---|---|
| 1 | Derive or delete `resilience_before/after`; correct CABLE-002/003; reference them from the errata | No artifact asserts a metric change that is not recomputable from recorded evaluations; a fault-injected always-miss detector yields no improvement claim |
| 2 | Land the errata + INDEX banner (PR #11) | `git grep` for the retracted figures on `origin/main` returns errata/archive context only |
| 3 | De-claim code identity: package/CLI/docstrings/section titles (`Intelligence Engine`, `multi-agent`, `Agent N`, `autonomous`, `self-healing`) | Repo-wide grep for that vocabulary in code, CLI help, and docs returns zero; the claim-discipline test covers code strings as well as cables |
| 4 | One formula per metric name; no `else 0.0`; derived confidence | Tests pin `n/a (not measured)` for every empty denominator; no hardcoded `confidence="HIGH"` |
| 5 | Retire the trailer-bearing local branch; add a CI guard | All-refs attribution scan is clean and enforced |

### P1 — next increment

6. Replace templated numeric probability with evidence-tied ordinal confidence (extends the claim-discipline test to the heal and campaign cable templates).
7. Determinism completion: content-hashed ids, no wall-clock in compared artifacts, regenerate-and-byte-compare CI step.
8. Safety honesty: wire or delete the unused flags, fix the "Routable" label, scope README:224, add the policy-table test.
9. Harden the patch engine: loud failure on anchor drift, narrowed exception handling, resolution logging.
10. Coverage: `endurance_runner.py` 79% → resume/stop/finish/error paths, plus the fault-injection contract from P0-1 as a suite-level test.

### P2 — later

11. Hygiene: retire stale branches; move handoffs and HTML into `docs/`; refresh counts; thicken `CONTRIBUTING.md`/`SECURITY.md`; adopt issue → branch → PR → CI for doc-heavy changes.
12. Refresh `docs/swarm/architecture.md` (still titled "Adversarial Swarm Intelligence Engine", still "5 Agent Roles"); keep its good habit of presenting measurement history as explicit cycles (initial mapping → tuning → re-measurement).
13. Evidence strategy: extend *external* measurement rather than more synthetic axes — score the rules against public labelled telemetry with per-rule precision/recall, documented exclusions, and a simple baseline. That is what converts the swarm from a self-referential signal into supporting tooling.

---

## 6. Sharing assessment

**Is it safe?** Yes. A targeted scan found no credentials, no employer/customer references, no live payloads, and no non-redistributable data (corpora are public, gitignored, and hash-pinned by committed lockfiles). The only "real" indicators are inert strings inside rules and benign fixtures.

**Is it ready?** Not today. Five specific things:

1. **A public cable asserts a fabricated 60% → 100% improvement** (S1). This is the finding a reviewer will find, and it cheapens everything else.
2. **The flagship regenerated cable publishes an unmeasured false-positive rate as an "Observed Fact"** (§8 V1) — "0.00% (95% Wilson CI [0.00%, 65.76%])" over a two-event corpus, where the numerator was never counted. This is the worst single item to leave standing, because it sits in the artifact the repair produced and therefore undercuts the repair narrative itself.
3. **The retraction is invisible on `main`** (S4) while the retracted figures are published there — so a visitor sees the numbers, not the correction. And the retraction banner itself is one cable-generation run away from silent deletion (§8 V4).
4. **The containment attestation in that same cable is contradicted inside its own run window** (§8 V2) — an un-gated path injects a destination the Critic rejects.
5. **The code, CLI, and architecture doc still promise autonomy that does not exist** (S2 naming, §2 mechanics). A reviewer who follows the "Adversarial Swarm Intelligence Engine" label and finds a 14-template round-robin will discount the real work alongside it.

**Who it is worth showing, once P0 lands, and how:**

- **Detection-engineering hiring managers / senior peers:** lead with the **external measurements** (0 FP on 1,755 manifests; the 233k-package imitation study; the published negative result) and the **measurement-provenance discipline** (ledger, errata, denominator policy). That combination is rare and it is the strongest signal in the repo.
- **Writers/researchers:** the errata is a genuinely good technical-writing sample — a self-audit with named defect classes. Few candidates can show one.
- **Agent-security / MCP audience:** the capability-composition work (`tools/agent_graph/`, the MCP population study, `tools/agent_audit.py`) is the most novel, least replicated material and the most likely to be cited. It also has the strongest external grounding.
- **Nobody:** the swarm as a headline. Present it as what it is — a deterministic internal regression harness with a fixed scenario bank — and its honest scope becomes a credibility asset rather than a liability. Do not lead with "swarm", "autonomous", or "self-healing".

**Sequencing recommendation:** merge PR #11 (P0-2), do P0-1, -3, -4, -5, then re-run this review's checks (`git grep` for the retracted figures, the banned vocabulary, attribution trailers, and artifact reconstruction). Roughly a day. After that, the repository is credibly shareable, and the story — "I built a detection lab, found my own metrics were fabricated, built the ledger that proves the rest, and published the retraction" — is a stronger one than a clean first draft ever would have been.

---

## 7. Annex — evidence index

| Finding | Evidence |
|---|---|
| S1 fabricated improvement | `adapter.py:133-134`; `cable_writer.py:107-108,129`; `docs/cables/CABLE-2026-002…md:9,10,31`; `:003…md:9,10`; `tests/test_swarm.py:375-391` |
| S2 templated probability | `cable_writer.py:128,109`; 12 files on `origin/main` matched by `git grep -c '80–90% probability'` |
| S3 metric formulas | `analyst.py:73,36,51`; `autonomous.py:101,122`; `campaign.py:178`; `adapter.py:133-134` |
| S4 retraction not public | `git show origin/main:docs/cables/INDEX.md`; `git cat-file -e origin/main:docs/cables/ERRATA-2026-09-10.md` |
| S5 safety mismatch | `config.py:17-19` (unused); `config.py:41`; `critic.py:99-103`; `README.md:224` |
| S6 determinism | `prompt_engine.py:38,253`; `cable_writer.py:45`; `autonomous.py:105` |
| S7 patch engine | `adapter.py:143-244,270-300,315-347,74-95` |
| S8 attribution | `git log --all --format=%B` → 8 trailers, all reachable only from `refs/heads/backup/pre-attribution-scrub-20260910` |
| S9 hygiene | `git ls-remote --heads origin` (14 branches); repository root listing; `README.md:37` vs suite count 497 |
| Mechanics (§2) | `orchestrator.py:19,44-45`; `prompt_engine.py:102-103,214-247,227,246`; `analyst.py:87-171`; `critic.py:21-119`; `endurance_runner.py:503`; `campaign.py:183` |
| V1–V13 (module audits) | see §8 — each row carries its own evidence and verification status |

---

## 8. Annex B — module-audit findings

Four parallel read-only audits (one per module cluster) covered the ~5,500 LOC the first pass skipped: graph/detection core, the runner and benchmarks, the evidence/reporting layer, and the role model plus safety gates. Each returned file:line evidence; every item below that was cheap to verify was re-checked and marked, and the rest are marked audit-reported. Two of the four — evidence/reporting and roles/safety — were read in full and supply most of the table; the other two were read in summary form, and their headline items are noted here: `GraphEngine.__init__` hand-wires the whole rule estate (2 YARA + 8 Sigma detectors + 2 correlation rules) and `to_workbench_dict` bakes SVG canvas geometry into the engine (`graph_engine.py:199-257`, `:152-186`); four campaign graphs are hand-built with fixed nodes; `noise_floor.py:678-680` carries a `_bulk_match` column-mismatch fallback; and both audits independently flagged the same `uuid4`/unseeded-`random` determinism caveat as S6. The audits also recomputed the run-of-record aggregates from the ledger by executing `records.aggregate()` read-only — all STRAT-004 headline figures reconcile (see §1, update note).

| ID | Sev | Finding | Evidence | Verification |
|---|---|---|---|---|
| V1 | **Critical** | The flagship regenerated cable publishes an **unmeasured** FP rate as an Observed Fact. `empirical_fp_rate` is hardcoded to `0.0` whenever the corpus is not marked benign, and the Wilson CI is computed from a count of zero; the synthesizer prints it without checking `is_benign`. The fabricated `0.0` also makes the replay report's FP gate unconditionally PASS. | `telemetry_replay.py:594-595`, `:357`; `synthesizer.py:485,496-500`; `CABLE-2026-STRAT-004…md:150` | **verified** |
| V2 | High | The Critic is **not applied on every evaluation path**, and the containment claim is window-wide. `graph_engine.py` never references `SwarmCritic` and injects `"/usr/bin/curl https://example.com"` — a destination the Critic rejects — while endurance suites increment `critic_approved` for campaign/DAG/replay/noise events without gating. The cable states "Destinations were restricted to RFC 2606 reserved TLDs…" as an Observed Fact whose evidence counts only gated sparring probes. | `graph_engine.py:643` (+ zero critic refs); `endurance_runner.py:513,577,678,724`, `:817-839`; `synthesizer.py:462-467`; `CABLE-2026-STRAT-004…md:149` | **verified** |
| V3 | High | A **retracted figure is a live scoring parameter**: `pinned_resilience` defaults to `0.712` (the withdrawn STRAT-001 headline) and is blended into every non-correlation technique score in the exported ATT&CK Navigator layer. | `export_layer.py:33,54,120,158` | **verified** |
| V4 | High | The **retraction banner can be silently erased**: INDEX rebuilds keep only lines matching `| [CABLE-`/`| CABLE-`, dropping everything else — including the `> [!CAUTION]` block. One `--self-heal` cable or campaign cable deletes the only public qualifier on the retracted figures. | `cable_writer.py:232-244,266-277` vs `docs/cables/INDEX.md:5-7` | **verified** |
| V5 | High | The **"closed feedback loop" edge is dead code**: the orchestrator computes and passes `adapter_feedback`, but no craftsman reads `feedback` (it appears only in signatures and the ABC docstring). Variation is cycle-indexed template selection. | `orchestrator.py:39-48,80-82`; `craftsmen/*.py:15,22,24` | **verified** |
| V6 | Medium | The main endurance entry point **always starts a repo-wide local file server**: loopback-bound, but serving `directory=str(ROOT)` (the whole repository), default-on, and `--no-server` exists only in the module's own CLI — `tools.swarm.cli --endurance` never passes it. | `endurance_runner.py:19,87,331-343,1138`; `cli.py:168-172` | **verified** |
| V7 | Medium | The **"Mordor" telemetry fixtures are hand-styled, not upstream slices**: `mordor_schtasks_persistence.jsonl` is two records with 2026 timestamps, sequential fake GUIDs (`{A1B2C3D4-0002-…}`), `VICTIM-HOST-01.corp.example`, and truncated payloads (`JABvACAAPQA...`, `<Task>...</Task>`). The manifest hash pins the local file, and the acquisition tool verifies against that same manifest after downloading upstream bytes onto the fixture path (circular; `--force` clobbers before failing). | fixture content read; `tools/telemetry_manifest.json`; `acquire_telemetry.py:115,121` (circularity per audit) | **verified (content)**; audit-reported (circularity) |
| V8 | Medium | Replay metric definitions are underpowered and over-labelled: "Alert Latency" is an offset from the corpus's first timestamp, not detection time; five report rows carry a hardcoded `PASS`; correlation hits never enter the benign FP numerator; on attack corpora all rule hits are auto-labelled "True Positive"; `window_seconds` is accepted and never used; "Cryptographically verified replay" is printed while nothing cryptographic happens; and the committed artifact leaks an absolute `rule_path` despite `_repo_relative` existing (a regression of the "drop stale absolute paths" cleanup). | `telemetry_replay.py:343,350-353,359`, `:27-41`; committed `telemetry_replay.json` line 17 | **verified** (PASS rows, latency, crypto line, abs path); audit-reported (window no-op, correlation exclusion) |
| V9 | Medium | The SIEM empirical **calibration correlation is invalid as constructed**: each profile's complexity score is paired with the same per-rule SQLite latency, but there are 1–3+ profiles per rule (one per backend), so Pearson `r` runs over duplicated, cross-backend pairs; strength thresholds are hardcoded (0.7/0.4); and the report asserts "the dominant driver is leading-wildcard matching" unconditionally without computing contributions. | `siem_profiler.py:448-465`, `:469`, `:227` | **verified** (thresholds, unconditional claim); audit-reported (pairing) |
| V10 | Medium | Legacy fallback paths can still fabricate when no ledger exists: proportional cluster allocation from cable metadata, `intercepted` defaulting to `True`, DoD defaulting to `0.8`, and a boundary-history denominator that includes Critic-blocked probes. | `synthesizer.py:109,111`, `:315-349`; `endurance_runner.py:1039-1043` | **verified** (`:109,111`); audit-reported (rest) |
| V11 | Medium | **Silent ledger-append failure**: `_emit` swallows `OSError` with a warning, so a disk error leaves in-memory counters diverging from the ledger; a later resume then reports fewer evaluations than the state claimed. | `endurance_runner.py:781-786` | **verified** |
| V12 | Medium | The D3FEND artifact asserts that **all** countermeasure identifiers "have been verified against the published MITRE D3FEND ontology", while the module's own notes scope verification to a subset and a reachable `extended` mapping branch exists. | `d3fend_mapper.py:315`, `:121` (docstring contradiction per audit) | **partially verified** |
| V13 | Low | Literal prose numbers remain in the strategic template: "likely (55–80% probability)" (disclosed as an inference, which is the right way to ship a judgment), "tune a single rule to 99% coverage… closing the final 20%… The empirical data proves this is counterproductive" (a causal claim no experiment in this repo tests), and a hardcoded `CABLE-2026-` prefix in `ref_range`. | `synthesizer.py:545`, `:676`, `:128-132` | **verified** |

### Additions to the plan (§5)

**P0 additions (before sharing):**

| # | Action | Acceptance criterion |
|---|---|---|
| 6 | Gate the telemetry Observed Fact on `is_benign`; never publish a rate whose numerator was not counted; reprint STRAT-004 with the corrected row | No artifact states an FP rate for a non-benign corpus; the replay report's FP verdict cannot PASS on an unmeasured rate |
| 7 | Route the DAG path through the Critic (preferred) or scope the containment claim to gated sparring probes and name the un-gated path in the artifact | A grep of any published containment claim resolves to evidence covering every path in the same run window |
| 8 | Remove the pinned `0.712` from the layer exporter (derive per-run, or refuse to score) | No exported artifact encodes a withdrawn measurement as a constant |
| 9 | Preserve non-row content in INDEX (or keep the caution banner in the header template) + a test that it survives an INDEX update | Updating the index cannot delete the retraction banner |

**P1 additions:**

| # | Action | Acceptance criterion |
|---|---|---|
| 10 | Replay honesty: rename "Alert Latency" to what it measures, derive every PASS/REVIEW from measured values, include correlation hits in the benign FP numerator, wire or delete `window_seconds`, drop the "cryptographically verified" line, make `rule_path` repo-relative | Report contains no verdict that is not computed from the measurement it judges |
| 11 | SIEM: one observation per rule (single backend) for the correlation, or drop it; compute the driver claim instead of asserting it | Calibration pairs are independent; driver attribution is derived |
| 12 | Fixture provenance: derive fixtures from upstream with a recorded recipe and verify upstream→fixture, or relabel them as hand-styled synthetic and stop calling them Mordor; fix the acquire path so it verifies before overwriting | No fixture is described as authentic without a reproducible derivation |
| 13 | Ledger durability: fail loudly or mark the run degraded on append failure | An append failure cannot silently desynchronise counters from the ledger |
| 14 | Make D3FEND/export assertions match their verification state | Artifact wording scoped to what was actually verified |
| 15 | Wire or delete `forbid_live_ips`, `forbid_binary_payloads`, `forbid_real_c2_telemetry`, `require_operator_approval`; extend the Critic to scheme-less/UNC/encoded destinations, or document the gap | No class docstring claims enforcement that no code performs |

