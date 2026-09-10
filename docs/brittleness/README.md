# Detection rule durability benchmark

A static analyzer that scores Sigma rules for the dependencies that quietly make them stop
working, and a measurement of the public SigmaHQ corpus against it.

    python -m tools.brittleness.cli --rules rules/sigma --label "threat-detection-lab"
    python -m tools.brittleness.cli --git-corpus https://github.com/SigmaHQ/sigma \
        --path-prefix rules/ --label SigmaHQ

## Why this exists

A rule can be correct today and worthless next quarter, and the usual cause is not a logic
error. It is a dependency the rule never declared: the command-line spellings it enumerates,
the parent process it assumes, the audit policy it needs but does not name. None of that
appears in a test suite built from fixtures the rule author also wrote, because the fixtures
encode the same assumptions.

Nobody publishes a durability metric for detection content. SigmaHQ ships thousands of rules
with no measure of how brittle any of them are, and no deployment can tell from a rule
whether it has gone blind. This is an attempt at that measure.

It is an instrument, not a detection, which is why it runs against corpora this repository
did not write.

## How rules are read

Public rule corpora are thousands of files full of live command-line strings and download
cradles. Checking one out onto a workstation running endpoint protection risks a partial
corpus: files get quarantined mid-analysis and the resulting measurement is wrong in a
direction nobody notices. That is not hypothetical here, since this repository already lost a
documentation file to exactly that.

The analyzer bare-clones the corpus and streams contents out of git object storage through
`git cat-file --batch`. No rule text is written to the filesystem. Files listed and files read
are both reported, so a corpus that does go short says so.

For the run recorded here: 3,144 listed, 3,144 read, 0 unreadable.

## Dimensions

| Dimension | Question | Weight |
|---|---|---|
| `commandline_dependence` | Can the rule fire at all without command-line capture? | 0.25 |
| `literal_enumeration` | How many literal spellings is it betting on? | 0.20 |
| `lineage_dependence` | Does it require one specific parent process? | 0.20 |
| `substring_reliance` | What share of matches are substrings of attacker-chosen text? | 0.15 |
| `environment_coupling` | Does it carry literals that must be replaced per deployment? | 0.10 |
| `documentation_gap` | Does it declare its telemetry prerequisites and false positives? | 0.10 |

The weights are policy, not measurement. They encode a judgment that a rule which cannot fire
at all under a plausible telemetry gap is worse off than one that merely enumerates a lot of
strings. They are exported in every report so they can be argued with.

## Results: SigmaHQ

Corpus revision `272daf82bf77`, 3,144 rules.

| Measurement | Result |
|---|---|
| Composite mean | 0.306 |
| Durable | 1,868 rules |
| Conditional | 1,084 rules |
| Fragile | 192 rules (6.1%) |
| Cannot fire without command-line capture | 33.5% of rules |
| Requires a specific parent process | 5.7% of rules |

### Fragility is almost entirely a process-creation phenomenon

Of the 192 rules in the fragile band, 189 read process creation telemetry.

| Log source of fragile rules | Count |
|---|---|
| windows/process_creation | 172 |
| linux/process_creation | 11 |
| macos/process_creation | 6 |
| windows/network_connection | 2 |
| windows/file_event | 1 |

This is the strongest result in the run and it is not a statement about rule authors. It is a
statement about the layer. Process creation is where an adversary has the most freedom to
choose the text a rule matches on, so rules that live there accumulate enumeration and
lineage assumptions in a way that rules reading structured control-plane events do not.

The operational reading: a detection programme weighted toward process creation is more
exposed to spelling changes than its rule count suggests, and coverage measured in rules is
not coverage measured in durability.

### One third of the corpus depends on a policy setting it does not mention

33.5% of rules cannot fire without command-line capture. That capture is not on by default on
Windows; it requires a specific audit policy. When it is absent, those rules validate cleanly,
deploy cleanly, alert on nothing, and look healthy.

`documentation_gap` averages 0.603 across the corpus, driven almost entirely by the absence of
declared telemetry prerequisites. Most rules do declare false positives. Almost none declare
what has to be switched on for them to see anything.

## Results: this repository

| Measurement | SigmaHQ | threat-detection-lab |
|---|---|---|
| Rules scored | 3,144 | 15 |
| Composite mean | 0.306 | 0.306 |
| Fragile | 6.1% | 2 of 15 |
| Command-line bound | 33.5% | 20.0% |
| `documentation_gap` mean | 0.603 | 0.053 |

The composite means being identical is a coincidence of two small differences cancelling, not
a finding. The honest read is that **this repository's rules are average against the public
corpus on durability**, better than average on stated telemetry dependencies, and no better on
the mechanics of matching.

The analyzer independently ranked the macOS developer credential rule as the most fragile rule
in this repository, which matches the hand analysis in
`docs/detections/macos-developer-credential-theft.md`, written before the analyzer existed.
Two independent routes to the same conclusion is weak evidence the instrument works. It is not
validation.

## The upstream contribution this suggests

The gap between the two corpora is not rule quality. It is that this repository declares
`telemetry_prerequisites` on every rule and the public corpus has no convention for it.

A Sigma rule can say what it matches. It cannot say what has to be true for it to match
anything, so an operator cannot distinguish a quiet rule from a blind one. A standard optional
block covering the channel, the audit policy, the required fields, and the degradation mode
would let a deployment check its own coverage automatically.

That is a proposal worth taking to SigmaHQ, and it is more useful than another rule.

## Limitations

- **Static analysis only.** The analyzer reads rule text. It does not execute rules, does not
  know their true positive rate, and cannot tell a fragile rule that catches real intrusions
  from a durable rule that catches nothing.
- **Brittleness is not badness.** A high score means a rule carries dependencies that can go
  unmet. Some of those rules are worth their fragility.
- **The bands are thresholds on a weighted sum**, and both the weights and the cut points are
  judgment. Changing them changes the counts.
- **Enumeration is counted, not evaluated.** Forty precise literals and forty sloppy ones score
  the same.
- **One revision, one point in time.** Rerunning against a later revision will give different
  numbers, and the corpus is pinned in the report for that reason.
