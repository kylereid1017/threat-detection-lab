# Next release: earn trust before adding scope

Companion to [the release-readiness review](2026-09-06-release-readiness.md). Recommendations only: none of these repairs or releases has been performed.

## Product decision

**Primary:** local-first Agent Exposure Review, combining config audit and composition analysis.  
**Secondary:** Detection Readiness Checker, proving telemetry prerequisites.  
**Support:** inert mutation/replay harness, versioned public-data research, CTI normalization.  
**Defer:** additional campaigns, automated healing/promotion, generalized sandbox claims, new feeds, and upstream specification submissions.

This is a sequencing decision, not a judgment that the other work was wasted. Existing modules become shared infrastructure rather than competing front doors.

## Gate 1 — Trust repair

Before using any output to recommend a security action:

- [ ] Every claimed measured hit comes from an executed detector, with simulated/unsupported/error outcomes kept separate.
- [ ] Per-detector and per-axis totals reconcile to raw observation records; no fixed-ratio allocations or nonzero empty-data defaults.
- [ ] Every recommended removal passes a leave-one-out recheck, including alternative closures of different sizes.
- [ ] Analyzer inputs render as text; script-context embedding is safe; browser runs with local assets and a restrictive network policy.
- [ ] Runner parsing distinguishes exact versions, ranges, tags, URLs, option values, ecosystem and server instances.
- [ ] Unsupported or invalid input yields incomplete/invalid, not hardened/allow.
- [ ] Findings redact secrets, and advisory matches retain ecosystem/version applicability rather than asserting present malice.
- [ ] Watchdog consumes the acquisition schema and reports unknown metadata separately.
- [ ] Correlation honors rule grouping and finds valid time-window assignments.
- [ ] STIX round-trips through an independent validator; URL identity and DNS output are correct.
- [ ] Tests cannot write run artifacts or stop another session; current coverage requirement passes on the supported CI matrix.
- [ ] Review reproductions move into behavioral regression tests as each defect is fixed.

**Proof:** red-before/green-after results for each defect, independent review, clean test side-effect check, and exact rule/code hashes. Do not silently lower the coverage floor to make the release green.

## Gate 2 — Research repair

- [ ] Pin exact acquisition, annotation, taxonomy and evaluation inputs and preserve cohort exclusions.
- [ ] Recompute findings and regenerate JSON, HTML, research prose and roadmap summaries from a single versioned result.
- [ ] Deduplicate at the intended unit while preserving capability-relevant wiring and scopes.
- [ ] Python/browser outcomes agree across the complete available corpus and malformed/unknown cases.
- [ ] Remove unsupported lower-bound, first-ever, exhaustive-census, real-world-containment and intent claims.
- [ ] Separate install hooks from packaging hooks, publication updates from creation, and similarity flags from adjudicated imitations.
- [ ] Measure recall and false positives using the same frozen inventory/policy; keep label origin and sampling bias visible.
- [ ] Report technique-tag coverage as tag coverage unless a semantic review establishes more.
- [ ] Reissue affected historical reports with correction notes, not silent edits.

**Proof:** a stranger can regenerate the reported tables from permitted public snapshots, without private data or untrusted package execution. A snapshot hash verifies content; it does not recreate missing input files or prove the labels.

## Gate 3 — One useful flagship workflow

Target one user question: **“What changes if I add this tool to my current agent?”**

Required flow:

1. Load a safe example or local config; show what was and was not parsed.
2. Explain each potential path using concrete tools, resources and assumptions.
3. Compare before/after configuration, not only a context-free score.
4. Offer a capability restriction or separation strategy.
5. Recheck and show exactly which modeled paths remain.
6. Export a redacted report with evidence and limitations.

Start with a reviewed, pinned subset of tool declarations. Do not imply that description/dependency inference establishes exploitability. Treat scoped filesystem access, destination restrictions, identity boundaries, read-only permissions and approvals as first-class modeling inputs.

**Proof:** independent test cases include both potential exposures and ordinary configurations that must not receive alarmist findings. Unknown coverage remains visible. Mitigation tests use inert canaries and retain legitimate-task utility checks.

## Gate 4 — Accessible release

- [ ] README leads with the problem, safe example, one start action and a truthful status—not a catalog of internal modules.
- [ ] Plain-language findings precede raw evidence and technical details.
- [ ] Normal-size readable text, adequate contrast, labeled inputs, keyboard operation and non-graph output.
- [ ] Offline demo runs without third-party scripts or private credentials.
- [ ] A beginner can identify the problem and next action; a practitioner can inspect the exact assumptions and reproduce the result.
- [ ] Versioned package/CLI interface, supported environments, error codes, security policy, changelog and release notes.
- [ ] Human review confirms public-data/redistribution and employment-IP boundaries.
- [ ] Remote visibility, release scope and owner approval are explicit before publishing.

**Proof:** record genuine external feedback, a short demo, the release artifact, and successful clean-environment execution. Do not claim production readiness or ecosystem-wide precision from a small usability test.

## Maintenance and scope budget

Keep the existing roadmap as history, but add a small active section with **Verified / Experimental / Blocked / Deferred**, linking to evidence. “DONE” should mean the acceptance criterion was verified, not merely that a file exists.

Finish one reviewable product increment at a time. A correct config parser, one defensible mitigation, and a transparent failure report demonstrate more engineering judgment than another campaign animation.
