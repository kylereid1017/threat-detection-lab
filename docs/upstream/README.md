# Upstream contributions, prepared

Two contributions to SigmaHQ, both produced by measurement rather than opinion, and both
ready to submit. **Neither has been submitted.** Opening a pull request or an issue is an
action under the repository owner's own identity and is theirs to take.

## 1. A telemetry prerequisites block for the Sigma specification

**Status:** proposal drafted, see `SIGMA_TELEMETRY_PREREQUISITES.md`.

**The evidence.** Measured across 3,144 public Sigma rules
(`docs/brittleness/README.md`):

| Measurement | Result |
|---|---|
| Rules that cannot fire without command-line capture | 31.0% |
| Mean documentation gap, driven by absent prerequisites | 0.603 |

Windows command-line auditing is not on by default. Nearly a third of the corpus depends on it, and
almost no rule says so. When the policy is absent those rules validate, deploy, alert on
nothing, and look healthy. An operator cannot distinguish a quiet rule from a blind one.

*Figures re-measured 2026-09-10 under the repaired Sigma condition semantics; the earlier
33.5% was the pre-repair scorer's output (see `docs/brittleness/README.md`, re-derivation
section).*

A Sigma rule can express what it matches. It has no way to express what must be true for it to
match anything. The proposal adds an optional block covering the channel, the audit policy,
the required fields, and the degradation mode, so a deployment can check its own coverage
mechanically.

**Why this rather than another rule.** The corpus has three thousand rules and no way to know
which of them have gone blind. A convention is worth more than an addition.

## 2. Cloud control-plane rules for techniques with no public coverage

**Status:** rules exist and are tested; they need reformatting to SigmaHQ conventions before
submission, and the environment-specific placeholders need to become documented parameters.

**The evidence.** Measured across the same corpus
(`docs/brittleness/TELEMETRY_COVERAGE.md`):

| Technique | Name | Rules in SigmaHQ |
|---|---|---|
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | 0 |
| T1530 | Data from Cloud Storage | 0 |
| T1610 | Deploy Container | 0 |
| T1651 | Cloud Administration Command | 0 |
| T1538 | Cloud Service Dashboard | 0 |

A sixth, T1567.002 (Exfiltration to Cloud Storage), has thirteen rules and none of them read a
control plane.

Instance metadata credential theft is the standard pivot from a compromised workload into
cloud identity. Cloud storage collection is how large data leaves. Both have zero rules in the
corpus most detection programmes start from.

`rules/sigma/cloud/` covers T1552.005, T1530, T1567.002, T1611, T1609, and T1078.004 at the
control plane.

**What has to happen before submission.** Honestly, more than reformatting:

- The VPC ranges and pipeline role allowlists in these rules are placeholders. Upstream they
  must become clearly marked parameters with documented defaults, or the rules are wrong by
  default for everyone.
- These rules have fixture coverage and no false-positive measurement against real CloudTrail
  data. That should be stated in the pull request rather than discovered by a reviewer.
- SigmaHQ has conventions on identifiers, filenames, tagging, and status values that this
  repository does not follow exactly.

Submitting a rule with placeholder ranges and no false-positive measurement would be worse
than not submitting it. The coverage gap is real; the rules are not yet a gift.

## 3. Model Context Protocol: Tool Execution Telemetry & Capability Specification

**Status:** proposal drafted, see `MCP_TELEMETRY_AND_CAPABILITY_SPECIFICATION.md`.  
**Target:** `modelcontextprotocol/specification` (Anthropic / Linux Foundation).

**The evidence.** Measured across a preliminary survey of 2,500 packages in npm and PyPI (`docs/research/agent-execution-layer-population-study.md`):

| Measurement | Result | Scope / Context |
|---|---|---|
| Packages declaring CLI entrypoints (`bin`) | **58.7%** | Preliminary manifest sample ($n=300$) |
| Packages declaring install-time lifecycle hooks | **26.0%** | Preliminary manifest sample ($n=300$) |
| Compound imitation lures targeting official tooling | **3.20%** | 95.2% of flagged imitations ($n=2,500$) |
| Single-maintainer account concentration | **82.95%** | Surveyed corpus ($n=2,000$) |
| Packages lacking OIDC Trusted Publishing | **83.45%** | Surveyed corpus ($n=2,000$) |

Agent execution layers have no telemetry convention, no capability manifest, and ambient host privilege inheritance by default. This proposal defines a standardized audit telemetry stream (`mcp.tool_call` schema) with parent/child PID binding, argument/output hashing, and declarative capability sandboxing for agent tool servers.


## Sequence I would suggest

1. Open the Sigma specification proposal as an issue first. It is self-contained, it carries a
   measurement, and it does not depend on anyone accepting a rule.
2. Submit the MCP Telemetry & Capability RFC to the Model Context Protocol discussion forum/issue tracker. It positions Kyle directly in front of the Anthropic protocol authors with empirical numbers nobody else has collected.
3. Submit rules one at a time, starting with T1552.005, which is the clearest gap and the
   least environment-coupled.
