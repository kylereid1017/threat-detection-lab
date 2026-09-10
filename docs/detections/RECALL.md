# Recall against real malicious packages

External validation of the CTI relevance scorer against 232,729 confirmed-malicious
packages published by the OpenSSF `malicious-packages` project. Machine-readable results:
`evaluation-relevance-recall.json`.

    python tools/acquire_malicious_corpus.py --ecosystem npm
    python tools/evaluate_relevance_recall.py --ecosystem npm --benign-corpus <dir>

## What was acquired, and what deliberately was not

The corpus is **package identities and advisory identifiers only**. No package contents,
archives, or payloads are downloaded, written, or extracted. The acquisition tool clones the
dataset index with `--filter=blob:none --no-checkout`, so git fetches commits and trees and
no file contents at all.

This is a real constraint on what can be measured here, and it is worth stating rather than
hiding. A recall measurement for the **manifest content** rule
(`developer_malicious_package_hooks.yar`) would require a corpus of real malicious
`package.json` and `setup.py` files, which means a corpus of live malware. That belongs in an
isolated analysis environment, not on a workstation. Until such an environment exists, the
manifest rule has a measured false-positive rate and **no recall figure**, and no recall
figure is claimed for it.

What is measured here is the relevance scorer, which operates on package names, and whose
inputs are therefore inert.

| Ecosystem | Confirmed-malicious packages |
|---|---|
| npm | 221,033 |
| PyPI | 11,696 |

## Landscape finding

A malicious package was labeled as targeting the AI toolchain if its name imitates a real,
published AI or machine-learning package, by substring or by edit distance.

| Ecosystem | AI-toolchain imitations | Share of all malicious packages |
|---|---|---|
| PyPI | 357 | 3.052% (CI 2.756% to 3.380%) |
| npm | 848 | 0.384% (CI 0.359% to 0.410%) |

**AI-toolchain imitation is roughly eight times more concentrated in PyPI than in npm.**
That matches where machine-learning tooling actually lives, and it has a direct operational
consequence: a team protecting AI researchers should weight Python registry monitoring far
above npm. Weighting them equally, which is the default in most feed configurations, spends
most of the analyst budget in the wrong ecosystem.

## The measurement that mattered

The original scorer worked by matching a hand-written vocabulary of brand terms. Internal
fixture tests reported it recovering 15 of 15 labeled relevant indicators.

Against real data, with the reference list split so that recall is measured only on names
the scorer was never given:

| Ecosystem | Vocabulary recall, full label | Vocabulary recall, held out |
|---|---|---|
| npm | 5.1% | **0 of 789** |
| PyPI | 73.9% | **0 of 88** |

Zero, in both ecosystems. The fixtures were authored alongside the scorer and measured its
vocabulary rather than its mechanism. This is the clearest available demonstration of why a
measurement produced by the same repository that wrote the thing being measured cannot be
trusted: the internal number was 100%, and the external number was 0%.

## The fix, and why it is a different kind of thing

Adding the held-out names to the vocabulary would have raised the score and changed nothing.
Substring matching cannot, even in principle, catch imitation of a name it does not hold.

The mechanism that generalizes does not need to know which brand is being imitated. It needs
to know which names are **worth** imitating, and the operational source for that is the
organization's own dependency inventory. You protect what you actually install. A package one
edit away from something in your lockfiles is a candidate confusion attack whether or not
anyone thought to add it to a list, and a package one edit away from something nobody uses is
not worth an analyst's attention.

`tools/cti/protected_names.py` builds that registry from manifests and checks two imitation
forms: a near miss of the whole name, and a protected name sitting inside a compound.

With the vocabulary branches switched off entirely, so that only the inventory branch can
score:

| Ecosystem | Vocabulary, held out | Inventory mechanism | 95% CI |
|---|---|---|---|
| npm | 0.0% | **61.6%** | 58.2% to 64.8% |
| PyPI | 0.0% | **27.2%** | 22.8% to 32.0% |

## The cost, stated

Recall is not free. Measured against real published packages the registry was not given, by
splitting the benign set into a simulated inventory half and an unseen control half:

| Measurement | Result |
|---|---|
| False-positive rate, inventory branch, unseen benign packages | 2.56% (CI 1.56% to 4.19%) |
| False-positive rate, vocabulary branches, all benign | 0.00% |

The vocabulary approach was precise because it almost never fired. The inventory approach
fires roughly once per forty unseen benign packages. That is workable for a human triage
queue and unacceptable for a blocking control, and it should be deployed accordingly.

## Three defects the measurement exposed

None of these were visible in the fixture tests. All three were found by measuring against
real names and then asking why a number moved.

**The registry reused a URL normalizer.** `relevance.normalize` splits on `/` and keeps the
first segment, which is correct for hosts and actively wrong for scoped packages:
`@eslint/object-schema` reduced to `eslint`, so every ESLint plugin in the ecosystem matched
a protected name. This alone produced two thirds of the false positives, taking the rate from
2.56% to 7.69%.

**The pipeline was rewarding packages for its own formatting.** Package indicators are built
as `<ecosystem>:<name>`, and the scorer then awarded a supply-chain point for the string
containing `npm` or `pypi`. Every package in the population got the same inflation, which is
invisible in aggregate and quietly moved compound matches over the triage threshold. The
apparent recall before this was found was not real.

**Homoglyph folding was suppressing the attack it exists to catch.** Excluding exact matches
on the normalized form meant `l0dash` folded to `lodash`, matched the real dependency, and
was discarded as genuine. The exclusion now runs on the literal name. A unit test caught this
one before any measurement did.

## The compound tradeoff, measured rather than assumed

A protected name sitting inside a longer unknown name is a weaker signal than a misspelling,
because ecosystem conventions legitimately embed tool names in dependents. The question is
whether it should reach the analyst queue on its own. Both settings were measured:

| Compound weight | npm recall | False-positive rate |
|---|---|---|
| 0.25, below the triage threshold | 1.9% | 1.03% |
| 0.40, above the triage threshold | 61.6% | 2.56% |

Roughly sixty points of recall for one and a half points of false positives. For a queue a
human reads, that trade is worth taking, and the higher weight is the shipped default. For a
blocking control it is not, and lowering the weight removes compounds from the queue without
touching anything else.

## The operating characteristic

Recall is bounded by inventory coverage, and the bound is exact.

| Simulated inventory coverage | Recall on imitations of covered names | Recall on imitations of uncovered names |
|---|---|---|
| 0% | not applicable | 0 of 848 |
| 25% | 19 of 26 | 0 of 822 |
| 50% | 32 of 128 | 0 of 720 |
| 75% | 320 of 573 | 0 of 275 |
| 100% | 522 of 848 | not applicable |

Recall on imitations of names outside the inventory is zero at every level. This is the
useful thing to tell a deployment team, and it is more actionable than any single aggregate
number: the detection's coverage is exactly the completeness of the dependency inventory
supplied to it, which is an input the defender controls. Improving this detection is a
software-bill-of-materials problem, not a tuning problem.

The non-monotonic middle rows are a sampling artifact of which names each random coverage
draw happened to include, not a property of the mechanism.

## Known limitations

- **The AI toolchain reference list is curated here.** The population is external; the label
  is internal. A malicious package imitating an AI tool absent from that list is counted as a
  true negative when it is really a miss, which biases every recall figure upward.
- **The label is more generous than the detector.** The label counts any substring
  containment; the detector requires a whole-name near miss or an exact component match.
  Names such as `datasetsgraphviz` are labeled and not caught.
- **The benign control is a local dependency tree**, not a representative sample of registry
  publications. The false-positive rate would differ on a real publication feed.
- **No recall figure exists for the manifest content rule**, for the reason given above.
- **Nothing here measures whether a flagged package is actually malicious.** It measures
  whether the scorer surfaces packages that imitate the AI toolchain. Those are different
  questions and only the second one is answered.
