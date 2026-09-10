# CTI collection and enrichment pipeline

Turns raw feed records into a prioritized analyst queue, an infrastructure graph,
and operational artifacts: a STIX 2.1 bundle, a SIEM lookup table, and draft
detection rules for human review.

    python -m tools.cti.cli --snapshots tests/fixtures/cti/snapshots --out docs/cti/results
    python -m tools.cti.cli --score anthropic-careers.invalid

## What problem it solves

A general feed is mostly irrelevant to any specific organization. Commodity
phishing, unrelated botnet infrastructure, and generic malware hashes bury the
handful of indicators that matter to the environment being defended. Sorting by
the source's own severity does not help, because the source does not know what
is being defended.

The pipeline scores every observable against one specific threat model: an
organization whose crown jewels are model weights, training compute, and
researcher identity, and whose staff are targeted through recruitment lures and
developer supply chain compromise.

## Stages

| Stage | Module | What it does |
|---|---|---|
| Collect | `sources.py` | Normalizes Certificate Transparency entries, package registry publications, and a malicious URL feed into one indicator model |
| Deduplicate | `models.py` | Merges the same observable across sources, keeping the strongest confidence and the earliest sighting, and recording corroboration |
| Score | `relevance.py` | Assigns a relevance score with a stated reason for every point awarded |
| Pivot | `graph.py` | Draws edges on shared certificates, addresses, and packages, and clusters campaigns |
| Emit | `emit.py` | Writes STIX with expiries, a SIEM lookup table, and candidate Sigma drafts |

## Design decisions worth arguing with

**Confidence and relevance are separate axes.** Confidence is how sure we are
the indicator is what the source claims. Relevance is how much it matters here.
A high-confidence commodity phishing domain and a low-confidence lookalike of an
AI research organization are not comparable on one number, and collapsing them
is how a queue becomes noise.

**Every indicator expires.** Time-to-live is derived from indicator type and
confidence. Hosting addresses expire in weeks, registered domains in months,
file hashes effectively never. The defaults encode how quickly each class of
infrastructure is recycled. They are policy, not measurement, and a deployment
should replace them with values from its own observed decay.

**The scorer is explicit, not learned.** Every point is attributable to a named
rule and appears in the output as a sentence. A learned model over a corpus this
size would be unjustifiable, and an unexplainable priority queue is one analysts
stop trusting after the first bad week. The cost is that the term lists are
maintenance, and a lure using vocabulary outside them scores zero.

**Pivoting refuses high-fanout attributes.** An attribute value shared by more
than twenty-five indicators is treated as common infrastructure rather than as a
campaign link. Without that guard, clustering on a large cloud provider's
autonomous system number connects everything to everything, and the resulting
"campaign" is a hosting provider.

**Generated rules are marked unsupported.** Drafts carry an explicit banner, a
false-positive section that says the behavior is unmeasured, and a retirement
date. A generated rule that has not been evaluated against a noise floor is a
hypothesis. Shipping it as anything else degrades the detections the pipeline
exists to feed.

**Collectors read snapshots, not live feeds.** Behavior that depends on what a
feed returned today cannot be regression tested and cannot be reproduced by a
reader. Acquisition is a separate step: fetch, pin the hash, then run.

## Measured behavior

Run over the fixture snapshots in `tests/fixtures/cti/snapshots`:

| Measurement | Result |
|---|---|
| Records read | 45 |
| Raw indicators extracted | 86 |
| Unique after deduplication | 74 |
| Reached the triage queue | 15 |
| Queue reduction | 79.7% of unique indicators dropped |
| Campaign clusters discovered | 5 |
| Labeled relevant indicators recovered | 15 of 15 |
| Labeled commodity indicators leaked into the queue | 0 |

**This is an internal measurement.** The fixtures and their labels were authored
in this repository, so the result says the scorer behaves as designed on cases
the design anticipated. It is not evidence of performance on real feed traffic,
where the vocabulary is wider, the noise is heavier, and the interesting cases
are the ones nobody thought to write a fixture for. Treat the reduction figure as
a workload statement, not an accuracy claim: it says how much smaller the queue
became, not whether what left the queue deserved to.

An external measurement would require a snapshot of real feed traffic with
independent labels. That does not exist here yet, and until it does, no claim
about real-world precision is supportable.

## Known gaps

- **No live acquisition.** There is no fetch step with a pinned hash, so the
  snapshots are hand-built rather than captured. That is the next piece.
- **Passive DNS and JA4 pivoting are absent.** The graph pivots on certificate
  fingerprints, autonomous system numbers, and package linkage. Resolution
  history and TLS client fingerprints are named in the roadmap and not built.
- **The term lists are the whole scorer.** Coverage is exactly as wide as the
  vocabulary in `relevance.py`. A campaign using unfamiliar branding scores zero
  and is dropped silently, which is the failure mode to watch.
- **No feedback loop from detection outcomes.** Indicators that produced real
  detections should raise the weight of the signals that surfaced them. Nothing
  currently closes that loop.
