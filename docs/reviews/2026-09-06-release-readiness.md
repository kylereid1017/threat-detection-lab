# Release-readiness and career-portfolio review

**Date:** 2026-09-06  
**Target:** local working tree of `threat-detection-lab`, not just committed HEAD (`50a83b6`).  
**Verdict:** promising research and engineering material; **not ready to release as dependable security tools or validated population findings**. Repair trustworthiness before expanding scope.

## Executive assessment

The valuable idea is not an autonomous swarm with more campaigns. It is **helping defenders understand what their tools can actually see, what an agent can actually reach, and which change measurably reduces exposure**.

Two products merit focused investment:

1. **Agent configuration exposure review:** a local-first, read-only tool that explains risky combinations, evidence, unknowns, and verified mitigations.
2. **Detection readiness checker:** a tool that tells operators why a rule cannot run on their telemetry and proves the diagnosis with a replayable example.

The current breadth obscures these contributions. The roadmap began with “one defensible artifact” but became a chronological list of completed features. Several “DONE” items fail their operational meaning. A simulated detector hit is not containment; a name resemblance is not malice; a package description is not a reachable data-flow path; passing tests do not establish those distinctions.

**Strong foundations worth keeping:** readable Python modules, inert test fixtures, pinned local data snapshots, explicit limitations in several detection notes, external-corpus experiments, separate confidence/relevance concepts, and willingness to publish negative results. Those are useful career signals after the problems below are addressed.

## Verification and boundaries

- Repository `.venv/Scripts/python.exe`: **Python 3.14.3; 414 tests passed** in the direct run. The shell's default Python was a different 3.11 environment without YARA/pySigma; that initial import failure was an environment mismatch, not a source-code failure.
- Disposable-copy reproduction: **414 passed**, but the configured coverage gate **failed: 74% versus required 85%**, exit code 2. This is local reproduction of the workflow commands, not a claim about a new remote CI run or Ubuntu/Python 3.12.
- Independent regression specifications: **9 tests, 9 assertion failures**, all reproduced defects rather than import errors. Run `docs/reviews/reproduce_review.py` using the repository interpreter. Kept outside `tests/` intentionally until fixes are undertaken.
- Recomputed composition summary: **336 configurations; 80 modeled closures; 26 composed; 54 single-package**. Both configuration-snapshot hashes matched their lockfile.
- Read-only population CLI: **2,500 records; 300 manifests; 84 name-similarity flags; 210 advisory-name leads**. Triage output differed from the paper: **11 targeted / 147 unverified**, not 12 / 146.
- CTI fixture CLI completed: **45 records, 74 unique indicators, 15 queued**, with output directed to Temp. This is still internal fixture evidence.
- Node execution compared the shipped browser analysis with Python; headless Chrome confirmed inert DOM code execution through analyzer input. The browser helper failed to start, so an isolated local Chrome process was used instead; no configuration secrets were entered.
- No package payloads were downloaded or executed. No fixes, commits, pushes, or publication performed. Review adds documentation, evidence, and reproduction specifications only.
- **Important side effect discovered:** the baseline test suite writes actual `docs/swarm/results` files. The initial direct test run therefore was not read-only. In a disposable copy, before/after hashes confirmed changes to `endurance_run.log`, `endurance_state.json`, and `telemetry_replay.json`. Other aggregate writes also exist. The original tree was already dirty; no reset or speculative restoration was attempted. Treat affected live generated outputs as test-contaminated until regenerated from trustworthy evidence.
- Parallel independent reviewers failed on provider credits. Findings here come from direct inspection and execution, not their incomplete summaries.

Machine-readable evidence: [2026-09-06-evidence.json](2026-09-06-evidence.json). Source hashes identify the reviewed Python files. This is a prioritized audit, not an exhaustive security certification or a fresh validation of every historical cable, YARA corpus, or cited incident.

## Release blockers: confirmed bugs and broken contracts

### R01 — Swarm can report successful defenses when every detector misses — High

**Locations:** `tools/swarm/graph_engine.py:605-687,741-757`; `:535-548`.

Several branches return literal `True`, `(not evasive) or res.detected`, or `res.detected or True`. Compensating controls report successful ESF/eBPF/correlation/audit results without invoking those controls.

**Reproduction:** replaced every actual detector on a GraphEngine instance with an inert always-miss test double, then walked the supply-chain, cloud, and agent graphs with all primary stages marked evasive. **All three still reported containment.** Returned detection nodes are recorded in the evidence JSON.

Also, `contained=intercepted` makes any alert imply containment; MTTD comes from fixed stage offsets, not response-system timing.

**Required repair:** distinguish `simulated`, `evaluated`, `unsupported`, `error`, `detected`, and `contained`. Unimplemented controls must report unknown, never success. If retained as teaching animation, explicitly label hypothetical interventions and exclude them from measured results. Test that an always-miss engine cannot claim an interception.

### R02 — Published-looking counts are allocated from constants — High

**Locations:** `tools/swarm/endurance_runner.py:570-592,656-686`; `tools/swarm/synthesizer.py:167-182,295-309`.

- Endurance history splits total probes/gaps **65% Sigma / remainder YARA**, not by detector observations. Ten aggregate probes and three gaps yield fabricated per-target results of 6/4 probes and 1/2 gaps.
- With zero observations, metrics default to **71.4% resilience, 91% DoD, 100% containment, 25 seconds MTTD**.
- `_cluster_evasions([], 1000)` produces **382/268/209/141** gaps with no incident evidence. The cable headings present these proportions as forensic cluster analysis.

**Required repair:** append-only per-observation records carrying run ID, rule hash, fixture hash, outcome, axis and timestamp; derive every aggregate from them. Preserve unclassified/failed cases. Empty denominators produce null/not measured. Reissue affected cables with correction notices; do not merely add another general “synthetic” caveat. Fabricated category allocation is not an internal measurement either.

### R03 — “Remove to break every chain” can be wrong — High

**Locations:** `tools/agent_graph/composition.py:159-167,172-193`; `artifact_template.html:278-300,426-429`.

The algorithm finds only **minimum-size** closures, then treats their intersection as critical to **all** closures. It omits larger, inclusion-minimal alternatives.

**Reproduction:** A supplies all legs; B supplies private data; C supplies ingress and egress. Analyzer recommends A, yet removing A leaves B+C closed. The same leave-one-out check found **11 false removal recommendations in the actual stored corpus**.

**Required repair:** enumerate inclusion-minimal closures, or verify each suggested removal directly. Explain whether a suggestion removes one server instance, every instance of a package, or a specific capability. Add property tests: every mitigation advertised as breaking all paths must do so under the model. The 80/26 headline counts themselves reproduced; the critical-package rankings and mitigation claims do not follow.

### R04 — Analyzer input becomes executable HTML — High

**Locations:** `tools/agent_graph/artifact_template.html:398-445,539-555`; `export_artifact.py:253-255`.

Package/evidence strings enter `innerHTML` and inline event-handler attributes without escaping. The exported JSON also enters an HTML script element without safe script-context encoding.

**Reproduction:** an isolated, CDN-free copy of the actual page received an inert image-error marker through `addWorkingServer`. Headless Chrome returned `data-review-canary="1"`: arbitrary input executed script. This was a local marker only, not data theft.

The page promises that nothing is sent anywhere but loads an unpinned third-party script from `cdn.tailwindcss.com` at line 7. This does **not** prove exfiltration; it makes the privacy trust boundary much larger than the wording suggests.

**Required repair:** use text nodes and registered listeners, safe JSON embedding, locally bundled assets, restrictive CSP, and a no-network test. Do not ask strangers to paste sensitive configurations before this is fixed.

### R05 — Browser/Python parity and configuration identity are broken — High

**Locations:** `export_artifact.py:104-120,125-139,216-225`; `artifact_template.html:229-255`; `marginal.py:205-210,296-301`.

Browser taxonomy omits Python's dependency-scope and install-hook inference. Executing both engines on identical server inputs produced **9 capability-state discrepancies, including 4 closure-classification discrepancies**.

Separately, repository name is used as configuration identity. **336 configurations have only 332 identifiers**; four browser payload associations are overwritten when a repository contains multiple config files. The marginal analysis also keys prior results by this nonunique identifier.

**Required repair:** stable identity containing repository, path, revision and relevant configuration fingerprint; shared inference specification with cross-runtime behavioral tests; no duplicate dictionary keys. Export parity must compare outcomes, not merely assert that taxonomy data was embedded.

### R06 — Auditor confuses floating, unsupported and clean configurations — High

**Locations:** `tools/agent_audit.py:173-209,246-279,314-343,395-414`.

Reproduced zero-findings/hardened outcomes for:

- `demo@^1.0.0` and `demo@next` with scripts disabled: both treated as exact pins.
- `uvx --from demo demo`: `--from` is incorrectly sufficient proof of pinning.
- A pinned `uvx` advisory fixture: `==version` remains in the lookup key, so the hit is missed.
- Unsupported input schema, malformed server entry, and a remote-only entry.
- Broad Windows home-directory argument `C:\Users\kyler`.

**Required repair:** one tested runner/parser model shared across acquisition, audit and UI; explicit supported/unsupported/invalid status and coverage denominator. Exact version, integrity verification, auto-confirmation and script policy are separate facts. Never equate no findings with “follows hardening baseline.”

### R07 — Audit output can copy secrets; advisory identity is underspecified — High

**Locations:** `agent_audit.py:130-145,194,240,246-279`; `agent_watchdog.py:44-52,96,109-125`.

An inert connection-string secret in args was copied verbatim into finding metadata. Detection of secrets in environment maps does not redact command arguments.

Both advisory lookups use bare names, losing ecosystem and affected-version context. A watchdog input with `groq-mcp`, ecosystem npm, and arbitrary version `999.0.0` is called confirmed malicious using the PyPI case's advisory. This input is a counterexample, not an assertion about a real npm package. Historical compromise is not evidence that every version remains malicious.

**Required repair:** redact at the output boundary; retain ecosystem, normalized name, versions/ranges, advisory status, source and observation date. Where the identities-only dataset cannot establish version applicability, report “historical advisory match; applicability unknown,” not an automatic quarantine or rotate-all-credentials instruction.

### R08 — Watchdog does not consume the acquisition schema — High

**Locations:** `agent_watchdog.py:142-183,224-277`; `acquire_agent_registry.py:165-190`.

Acquisition nests fields under `manifest`, while watchdog reads top-level `bin/scripts/dependencies` and `has_oidc`. An identical inert record scores **55 flattened versus 0 in acquisition shape**. Its CLI reads a finite JSONL file or built-in demo; it does not implement a real-time registry subscription, checkpoint, retry or freshness loop.

**Required repair:** normalize at one boundary and add acquisition-to-alert integration tests. Position this as an offline triage evaluator until durable monitoring actually exists. Heuristic points are not calibrated maliciousness probabilities.

### R09 — Sandbox policy is not the enforcement contract — High

**Locations:** `agent_sandbox/launcher.py:48-94,102-151`; `policy.py:39-47,54-92`.

Generated Linux plan says “restricted to hosts” but contains no enforcement for `net_allowed_hosts`; macOS permits all outbound networking when enabled. Linux ignores `allow_child_processes` and does not enforce denied credential subpaths inside allowed roots. The macOS exec policy explicitly allows `/bin/sh`, not the requested general Node/Python executable.

These are **generated-plan/code findings**, not a demonstrated Linux/macOS escape: this host is Windows. The Windows no-confinement disclaimer is appropriate, but the roadmap calls the overall feature implemented isolation.

**Required repair:** unsupported policy requirements must fail closed. Release enforcement only after OS-specific integration tests use harmless canaries to prove forbidden reads, writes, children and destinations are denied. Until then call this a policy/launch-plan prototype, not a protective sandbox.

### R10 — Correlation semantics can combine unrelated events and miss valid chains — High

**Locations:** `swarm/evaluator.py:139-257`; `models.py:187,211-237`; `telemetry_replay.py:567-587`.

Direct evaluator ignores `group_by`. Two stages from different computers correlated despite `group_by=['Computer']`. Replay pre-groups by Computer, reducing that specific cross-host case, but still ignores declared user/process/cloud-identity grouping.

Greedy chain selection also misses valid assignments: unordered stages with candidates at times 0 or 100 seconds for stage A and 101 seconds for stage B, window 10, return no match despite the valid 100/101 pair. Ordered overlapping stage candidates at equal timestamps can fail similarly.

**Required repair:** implement grouping and valid window/matching semantics with adversarial fixtures, including absent entity keys, repeated stages, timestamp ties and out-of-order arrival. Do not silently reinterpret unsupported Sigma correlation types.

### R11 — Durability scorer does not prove required-field dependency — High for research validity

**Locations:** `brittleness/metrics.py:258-289,313-320`; `docs/brittleness/README.md:88-95`.

Dependency inference searches for literal `" or "` in the condition rather than evaluating Sigma Boolean semantics. A rule using `1 of by_*`, with Image OR CommandLine alternatives, gets command-line dependence **1.0** and “cannot fire” wording, while the actual compiled rule matches with an empty command line.

**Required repair:** use the Sigma condition AST and controlled missing-field evaluation. Until recalculated, retract the precise “33.5% cannot fire without command-line capture” conclusion as unvalidated heuristic output. The scoring rubric also favors this repo's own custom prerequisites field; disclose that comparison design. A process-creation logsource does not uniquely imply Windows Security 4688 policy: Sysmon and EDR are different telemetry paths.

### R12 — CTI output violates identity and exchange semantics — Medium/High

**Locations:** `cti/models.py:101-116`; `sources.py:247-252`; `emit.py:29-38,58,74-77,124-153`.

- Full URL paths/query values are lowercased, changing case-sensitive observables. Reproduced `CaseSensitive?Key=ABC` becoming `casesensitive?key=abc`.
- Existing bundle ID `bundle--cti-2026-09-05` is not a UUID-based STIX identifier.
- DNS candidate rules include full URL strings in `QueryName`, which DNS events do not contain.
- Pattern/YAML interpolation is not appropriately escaped for arbitrary observable strings.

**Required repair:** typed canonicalization, STIX library/validator round-trip, pattern validation, and distinct hostname-versus-URL rule generation. Valid JSON alone is not STIX conformance. No external STIX validator was installed during this audit; UUID failure is independently reproducible.

### R13 — CT enrichment confuses observation with registration and co-hosting with linkage — Medium/High

**Locations:** `cti/sources.py:35-81,147-167`; `cti/graph.py:23-37,82-107`.

A certificate dating from 2020 still becomes `recently_registered=True`. Certificate validity is not domain-registration time. `unrelated-a.co.nz` and `unrelated-b.co.nz` both become `co.nz`. Two unrelated domains sharing only an issuer form a cluster; the fanout cutoff does not protect small samples from shared CAs/ASNs.

**Required repair:** pinned Public Suffix List, separate registration/issuance/observation timestamps, and strong-edge candidate clustering. Keep weak issuer/ASN relationships explorable, but do not promote them to campaign evidence or generated detection scope on their own.

### R14 — Tests mutate evidence; current quality gate is not green — High

**Locations:** `tests/test_endurance_runner.py:17-66`; `endurance_runner.py:126-137,267-268,612-686`; `.github/workflows/detection-validation.yml:20-23,42-48`.

Tests instantiate the real output paths, execute a run and create/delete the actual stop-signal file. This can also interfere with another running session. The disposable-copy coverage result was **74%**, below the workflow's **85%** requirement. Some modules with very high statement coverage still have the semantic bugs above.

**Required repair:** dependency-inject all output/state paths; isolate every test; assert the working tree is unchanged; add behavioral and integration tests rather than lowering the floor or celebrating a larger test count. Validate supported Python/OS environments separately.

## Dataset interpretation: corrections required before promotion

### Composition study

The 80/336 and 26/336 counts reproduce **under the current heuristic**, not as verified exploit paths.

- **“Lower bound” is unjustified.** Precision below one means invented capabilities can increase closures, while missed capabilities reduce them. The net bias is unknown. Low recall does not establish a lower bound, nor does a selected GitHub example corpus establish the direction of real-world prevalence bias. See `composition.py:303-306`, research note lines 82-85 and 138-140, and handoff lines 49-51.
- Filesystem writes map directly to exfiltration (`capabilities.py:132`); dependencies and credential-key names do not prove agent-callable tools, attacker-controlled inputs, reachable private resources or allowed destinations. Rename the finding **potential capability co-occurrence**, pending reachability analysis.
- Correct acquisition flow: **1,387 fetched → 112 without server entries → 1,275 with entries → 761 without resolved registry packages → 514 resolvable → 178 duplicates removed → 336 retained**. The discard is about 59.7% of configs containing entries. `178/1275` is not the duplicate fraction among resolvable configs; that is `178/514`, about 34.6%. Label denominators, do not silently replace them.
- Dedup fingerprints ignore wiring even though wiring changes inferred capabilities (`config_corpus.py:254-256,304-315`). Two otherwise identical configs with/without a credential are collapsed. This is not merely template deduplication.
- Parser drops pinned `uvx demo==1.2.3`; interprets an npm `--registry` URL as the package; collects all manifests from npm and strips version provenance. Unresolved transport/runner identities require explicit accounting.
- Validation is not the same as a locked holdout. The published JSON reports 23 scored labels; running the verifier against the retained composition manifests resolves 20 and gives P=.7692/R=.5455, not .7333/.5323. This is a **different-input reproduction gap**, not proof the historical arithmetic is false. Preserve and hash the exact validation manifests, annotation basis, revision, and role in model selection. The verifier also omits configuration wiring, while the population analysis includes it.
- Co-installation is a cross-sectional affinity heuristic, not evidence of an observed future installation or a calibrated probability. “Grounded flips,” “true catalysts,” and “in reality” overstate the counterfactual. Zero pair support means unobserved in this sample, not impossible. Raising support from 2 to 3 does not itself validate a community or threshold.

### Agent population study

- **78/300 (26%)** includes packaging/build hooks. Only **8/300 (2.67%)** in the same snapshot declare nonempty `preinstall/install/postinstall` scripts. These are narrower manifest counts, not the complete runtime attack surface. npm documents different conditions for `prepare`, `prepack`, and consumer installation; the 26% headline cannot be interpreted as all firing during normal registry installation.[3]
- A `bin` entrypoint is not evidence of unvetted execution, absent isolation, or hostile intent. Name similarity is not proof of impersonation; 84 flags are review candidates, not 84 established attacks.
- Population timing uses npm search `date` (`acquire_agent_registry.py:71`, `evaluate_agent_population.py:176-184`), not a stored first-publication history. That does not establish births or exponential ecosystem growth. Fetch/verify creation timestamps before claiming 509 new packages in August. Correct the announced MCP launch date from November 20 to **November 25, 2024**.[4]
- External/internal classification is `len(all_packages) >= 50` (`evaluate_agent_population.py:620`). Fifty inert synthetic rows were labeled EXTERNAL. Registry totals remain hardcoded even for synthetic input (`:212-217`). Missing YARA rules yield an apparently measured zero-match result (`:255-260,334`). Provenance and evaluation completeness must be explicit inputs, not inferred from sample size.
- The forensic classifier uses name lists and substrings such as `test/demo/canary`, and a string fragment of an advisory ID to infer history (`:461-472`). These are not independently verified forensic labels. Unknown removals must not acquire invented removal reasons.
- OIDC/trusted-publisher metadata absence does not demonstrate absence of all provenance, universal static-token use, or account-takeover susceptibility. Single-maintainer/download concentration are descriptive proxies, not measured compromise risk or proof that a power-law model fits.
- The sample limitations section is useful but contradicts the “exhaustive census,” “first population study,” and operationally universal executive claims. Earlier large-scale MCP research already evaluated 1,899 servers.[5] Keep novelty narrow and comparison-backed.

### Relevance and telemetry studies

`evaluate_relevance_recall.py:301-313` measures malicious-name recall with an AI reference inventory, while `:326-344` measures benign false positives using a different inventory built from half a local dependency tree. **61.6% recall at 2.56% FPR is not a single fixed-policy operating point.** Recompute both under the same inventory and threshold, then report sampling limitations. Label creation and detection share string-similarity assumptions; external inputs do not make the labels independent.

“Recall equals inventory coverage” is not established: the table itself reports 522/848 at full inventory coverage. Inventory is one limiting input, not the only mechanism failure. A registry ratio in selected advisory data does not by itself determine where an organization should spend analyst time.

`telemetry_coverage.py` measures tags and heuristic logsource classes, not operational detection coverage. It groups process access and PowerShell script logs under `endpoint_process`, while the paper calls the category process creation. Replace “zero public coverage” with **zero matching technique tags in the specified corpus revision** until semantic review of nearby rules is complete. Do not submit an upstream gap claim based on the stronger wording.

## Product direction: useful, understandable, technically deep

### Flagship: Agent Exposure Review

**Plain-English promise:** “Before you connect another AI tool, see what sensitive information the combined setup might expose—and what change actually reduces that exposure.”

Keep it local and read-only. Integrate audit and composition around a shared typed model rather than launching another standalone scanner. Differentiate on verified cross-tool configuration changes, not “first MCP security tool.” MCP-Scan already documents installed-server inspection, tool pinning and cross-server checks; compare capabilities explicitly instead of claiming nobody else can see combinations.[1]

The frontier-worthy progression is **configuration-aware, tool-level reachability and mitigation validation**:

1. Identify exact ecosystem/package/version/server instance and configuration scopes.
2. Model tool inputs/outputs, authentication, tenant, allowed filesystem paths, destinations and approval requirements.
3. Distinguish latent package ability from agent-exposed capability and attacker-reachable paths.
4. Show the smallest evidence-backed path and its assumptions.
5. Offer scope reduction, read-only tokens, destination restrictions or separation into agents—not only package removal.
6. Validate the proposed change against harmless local canary scenarios, including a positive control proving the harness can observe the path when allowed.

Do not autonomously execute arbitrary collected servers to gain tool metadata. Start with reviewed, pinned public declarations and independently authored inert protocol doubles. Real-package execution requires a separate explicit isolation and provenance decision.

**Evaluation:** adjudicated labels at server-version/configuration level, repo/template/time-aware splits, precision/recall for reachable paths, unknown rate, mitigation correctness, task utility retained, and review burden. Freeze the benchmark before tuning. Compare with a name/description baseline and an existing scanner on shared scope. No headline efficacy target should be chosen after seeing the results.

### Second product: Detection Readiness Checker

**Plain-English promise:** “Is this rule quiet because nothing happened—or because your logs cannot support it?”

Make the core a prerequisite and missing-field analyzer, not a speculative universal “durability score.” Ingest a rule plus a sanitized telemetry schema/sample; explain required fields, viable alternatives, source mappings and deployment parameters; show a working positive event and a representative legitimate lookalike. Add an explicit telemetry-loss test and native backend parity. This can become a useful CI report before it becomes a new specification.

Start with one endpoint rule and one cloud rule. For cloud, “bulk retrieval” currently has no aggregation threshold (`aws_cloudtrail_model_weight_bulk_retrieval.yml:42-61`); call it a suspicious-object-access tripwire or actually implement and validate the temporal/volume policy. Separate S3 data events from management-plane telemetry and map copy source/destination fields deliberately.

### Keep supporting work in its proper role

| Component | Recommendation |
|---|---|
| Swarm | Keep as deterministic mutation/replay harness and teaching simulator; stop marketing simulated controls as measured defenses. Disable autonomous rule promotion until trustworthy independent gates exist. |
| CTI pipeline | Keep as a supporting triage/provenance module after typed identity, schema and clustering repairs; do not add more feeds yet. |
| Registry watchdog | Merge its useful checks into the flagship; do not sell a finite-file evaluator as a monitoring service. |
| Sandbox | Defer public protective claims until an OS integration suite proves enforcement. |
| Population/composition papers | Preserve experiments and negative results; reissue narrow, reproducible reports after corrections. |
| Upstream RFCs | Pause submission. Demonstrate an interoperable working implementation and correct the supporting measurements first. |
| Historical generated cables | Preserve with provenance/correction notices; move repetitive run logs out of the primary visitor journey. |

## A newcomer should not need the glossary before seeing value

Use progressive disclosure, not watered-down engineering:

- **First screen:** question answered, who it helps, one safe example, one primary action, current limitations.
- **Finding card:** what was observed → why it might matter → what is unknown → recommended change → what the recheck demonstrated.
- **Technical expansion:** exact config path, inference source, package/version, policy edges, raw records, limitations, test ID and reproduction command.
- Replace “marginal precipice” with “one capability not yet evidenced”; “chain closed” with “potential path identified”; “chain open” with “no complete path identified—coverage incomplete” where appropriate.
- Unknown/unsupported must not be green. Display analyzed/total servers and unresolved entries beside the verdict.
- The current UI uses much 9–11 px text; calculated contrast against its panel is about **4.20:1 for muted text and 2.08:1 for subtle text**. Increase body text, strengthen contrast, label inputs explicitly, provide keyboard controls and a text/table alternative to the graph. Automated contrast calculations are not a full accessibility audit.
- Keep jargon available in tooltips and a short glossary: ingress = information coming in; egress = information leaving; telemetry = security-relevant records; provenance = where evidence came from.
- Example result wording: **“Potential exposure: this setup combines file access with a web-connected tool. We have not verified whether the tool can send file contents to an arbitrary destination. Restrict the file root and destination policy, then recheck.”** No invented probability or accusation.

## Career advancement: evidence of ownership, not feature count

The frontier threat-intelligence role reviewed asks for production-quality engineering, intelligence that changes detections/hunts, clear concise writing, and public contributions—not just research dashboards.[2] This repository can support that story, but cannot substitute for incident ownership, collaboration or threat expertise.

A compelling portfolio demonstration is: **“I found the measurement was wrong, isolated the cause, corrected the model, proved the repair, and helped another person use the result.”**

Use one short case study showing threat hypothesis → source evidence → detection/exposure path → failure discovered → tested correction → decision enabled → remaining limits. Add a short demonstration and a reproducible report. Seek an independent maintainer/security practitioner review and newcomer usability sessions using public or synthetic data. Record actual feedback and changed behavior; do not invent adoption or impact statistics.

Suggested release sequence and acceptance criteria are in [2026-09-06-next-release.md](2026-09-06-next-release.md).

## Sources

[1] https://invariantlabs.ai/blog/introducing-mcp-scan
[2] https://job-boards.greenhouse.io/anthropic/jobs/5195705008
[3] https://docs.npmjs.com/cli/v11/using-npm/scripts
[4] https://www.anthropic.com/news/model-context-protocol
[5] https://arxiv.org/abs/2506.13538
