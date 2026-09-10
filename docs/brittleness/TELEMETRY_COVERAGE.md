# Telemetry-layer coverage mapping

Where a detection corpus's coverage actually sits, per ATT&CK technique.

    python -m tools.telemetry_coverage --git-corpus https://github.com/SigmaHQ/sigma \
        --path-prefix rules/ --label SigmaHQ

## The question

A technique count is not a coverage measure. Twelve rules for a technique, all reading
process creation, cover exactly one execution path. An adversary performing the same
technique through a cloud SDK, an API call, or a language runtime produces nothing any of the
twelve can see, and the corpus still reports the technique as covered.

This mapping classifies every rule's log source into a telemetry layer and asks, per
technique, which layers the coverage sits on.

The layer ordering is the point. An adversary chooses their own command line. They do not
choose what the cloud control plane records about an API call they made.

## Results: SigmaHQ

Corpus revision `272daf82bf77`, 3,144 rules, 390 techniques.

| Telemetry layer | Rules | Share |
|---|---|---|
| Endpoint, process | 1,602 | 50.9% |
| Endpoint, other | 1,009 | 32.1% |
| Cloud control plane | 272 | 8.6% |
| Network | 128 | 4.1% |
| Application | 112 | 3.6% |
| Identity provider | 21 | 0.7% |

**Eighty-three percent of the public corpus reads endpoint telemetry, and half of it reads
process creation specifically.** Cross-referenced with the durability benchmark in this
directory, that is also the layer where 189 of the 192 most fragile rules live. The corpus is
concentrated on its least durable layer.

**One hundred forty-nine of 390 techniques are covered by rules on a single layer.** For each
of those, one telemetry gap removes the coverage entirely.

## The gap that matters for a frontier AI lab

Five techniques central to model theft and cloud compromise have **no rules at all** in the
public corpus:

| Technique | Name | Rules in SigmaHQ |
|---|---|---|
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | 0 |
| T1530 | Data from Cloud Storage | 0 |
| T1610 | Deploy Container | 0 |
| T1651 | Cloud Administration Command | 0 |
| T1538 | Cloud Service Dashboard | 0 |

A sixth, T1567.002 (Exfiltration to Cloud Storage), has thirteen rules and **none of them
read a control plane**. Coverage sits on endpoint file events, process creation, and network
telemetry. An adversary calling the storage API from inside a workload is unobserved by all
thirteen.

These are not obscure techniques. Instance metadata credential theft is the standard pivot
from a compromised workload into cloud identity, and cloud storage collection is how model
weights leave. The public corpus, which is the default starting point for most detection
programmes, has nothing for either.

## Results: this repository

| Measurement | SigmaHQ | threat-detection-lab |
|---|---|---|
| Rules | 3,144 | 15 |
| Control-plane share | 8.6% | 33.3% |
| Techniques with zero control-plane coverage, from the list above | 6 | 0 |

The cloud rules in `rules/sigma/cloud/` cover T1552.005, T1530, T1567.002, T1611, T1609, and
T1078.004 at the control plane. Four of those are techniques the public corpus does not cover
at all.

This is a coverage claim, not a quality claim. Fifteen rules against three thousand is not a
comparison, and the durability benchmark separately shows these rules are average on
brittleness. What the comparison supports is narrower and still worth saying: **the gap in
public detection content for cloud credential and storage techniques is real, measurable, and
these rules sit in it.**

## Limitations

- **Layer classification is heuristic**, derived from Sigma log source fields. A corpus using
  unusual log source conventions will be classified imperfectly.
- **A missing technique tag reads as missing coverage.** Rules that detect a technique without
  tagging it are invisible here, so the zero counts above are an upper bound on the gap rather
  than a certainty.
- **Rule count is not detection quality.** A technique with thirty rules may be covered worse
  than one with two.
- **Control-plane coverage is not automatically better.** It is harder for an adversary to
  avoid, which is a different property from being more accurate.
- **One revision, one point in time.** The revision is pinned in the report.
