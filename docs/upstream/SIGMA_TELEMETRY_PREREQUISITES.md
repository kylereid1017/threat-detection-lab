# Proposal: an optional `telemetry_prerequisites` block for Sigma rules

**Status:** draft, not submitted.
**Target:** SigmaHQ specification discussion.

## Problem

A Sigma rule expresses what it matches. It has no way to express what must be true for it to
match anything.

That gap has an operational consequence. A rule whose required telemetry is absent behaves
identically to a rule whose adversary is absent: it validates, it converts to a backend query,
it deploys, and it produces no alerts. An operator has no mechanical way to distinguish a
quiet rule from a blind one, and the failure is silent in the direction that matters.

The clearest instance is Windows command-line capture. Recording process command lines in
event 4688 requires the "Include command line in process creation events" policy, which is not
enabled by default. A rule matching on `CommandLine` without that policy has a recall of zero
while appearing healthy.

## Evidence

Measured across the SigmaHQ corpus at revision `272daf82bf77`, 3,144 rules, using a static
analyzer published at `tools/brittleness/` in the repository this proposal comes from:

| Measurement | Result |
|---|---|
| Rules that cannot fire without command-line capture | 33.5% (1,053 rules) |
| Rules reading endpoint process telemetry | 50.9% |
| Rules in the most fragile band that read process creation | 189 of 192 |

The method and its limitations are documented alongside the numbers, and the analyzer runs
against any corpus so the figures can be reproduced or disputed.

## Proposal

Add an **optional** top-level block. Optional matters: it must not invalidate any existing
rule, and adoption should be incremental.

```yaml
telemetry_prerequisites:
    channel: Microsoft-Windows-Sysmon/Operational or Security
    event_id: 1 (Sysmon) or 4688 (Security)
    audit_policy: >-
        Audit Process Creation (Success) under Detailed Tracking, with
        'Include command line in process creation events' enabled.
    required_fields:
        - Image
        - CommandLine
        - ParentImage
    degradation_mode: >-
        Without command-line auditing, CommandLine is empty, every selection
        depending on it fails, and recall falls to zero while the rule continues
        to validate and deploy normally.
```

### Fields

| Field | Type | Purpose |
|---|---|---|
| `channel` | string | Where the events come from |
| `event_id` | string | Which event types populate the rule's fields |
| `audit_policy` | string | Configuration that must be enabled |
| `required_fields` | list | Fields without which the rule cannot fire |
| `degradation_mode` | string | What happens, observably, when the above is missing |

`degradation_mode` is the field that carries the value. The others describe a dependency.
That one describes the failure, in the terms an operator will actually encounter it.

## What this enables

- **Automated coverage checks.** A deployment can compare `required_fields` against the fields
  its pipeline actually populates and report which rules are inert, before an incident does.
- **Honest triage of a rule that never fires.** Today that is ambiguous. With a declared
  degradation mode it becomes checkable.
- **Better rule review.** A rule author who has to write down how their rule goes blind will
  sometimes notice the rule should read a different telemetry layer instead.

## What this is not

- Not a replacement for `falsepositives`, which describes noise when the rule works. This
  describes silence when it does not.
- Not machine-validated logic. The block is documentation with enough structure to be parsed.
  Verifying that a rule's stated prerequisites are correct is out of scope.
- Not mandatory. Existing rules remain valid, and a partial block is better than none.

## Prior art considered

`logsource` names the telemetry family but not its configuration: `category:
process_creation` is true whether or not command-line auditing is enabled. `fields` lists what
to display in an alert, not what is required to match. `falsepositives` covers the opposite
failure. No existing field expresses the dependency, which is why rules that have it document
it in prose, inconsistently, or not at all.

## Adoption path

1. Agree the field names.
2. Add the block to a small number of high-dependency rules as worked examples, starting with
   the command-line-dependent process creation rules where the gap is widest.
3. Add an optional linter check that warns when a rule reads `CommandLine` and declares no
   prerequisites. Warn only; never fail a build on a documentation field.

## Reference implementation

Every rule in `rules/sigma/` of the originating repository carries this block, and its test
suite fails if a rule is added without one. Measured documentation gap for that corpus is
0.053 against 0.603 for SigmaHQ, which is the entire difference between the two corpora on
that dimension and the reason this proposal exists.
