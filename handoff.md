# Handoff: agent capability composition

> 2026-09-10: test count 479 → **545**, statement coverage 86% → **87% over `tools/`**. The
> honesty-pass session added tests and republished figures for the *swarm* programme; see
> [HANDOFF_2026-09-10.md](HANDOFF_2026-09-10.md) for that handoff. **This file's
> composition-programme measurements below were NOT re-verified by that session.**

Updated 2026-09-06 after verifying the release-readiness work. **545 tests passing, statement
coverage 87% over `tools/`.** Keep both green.

## Verification status of the release-readiness work

All four gates verified independently rather than taken on trust: reproductions 9/9, coverage
87% against an 85% floor, the suite mutates nothing under `docs/swarm/results/` (hash-compared
before and after), the artifact is self-contained with the CDN removed, and the taxonomy embedded
in the page matches the Python source exactly.

Three correctness defects were found in the flagship Exposure Review **by running it**, all of
which shipped while the suite was green. Modeled paths listed the whole taxonomy instead of the
capabilities each closure actually held. The mitigation recheck was hardcoded to report success
and could not express failure. Directory scoping advice was gated on the `private_data` leg, so it
was offered to tools with no filesystem arguments. All three are fixed and pinned by
`ExposureReviewCorrectnessTests`. Roadmap entry 37 has the detail.

**Lesson worth carrying: run the deliverable before believing it.** The tests, the coverage floor,
and the walkthrough were all green while the flagship told operators a mitigation worked when it
did not.

## Where this sits

The programme is measuring a claim: **the exfiltration hazard in agent toolchains is a property
of the installed set, not of any package in it.** A filesystem server is ordinary. A web-fetch
server is ordinary. A server that posts outward is ordinary. Assembled in one agent they can read
private data, ingest text an attacker planted, and send the result out. Nothing is wrong with any
package, so nothing flags it.

The framing is Simon Willison's "lethal trifecta" and is credited as his throughout. The
measurement is ours.

**Hard constraint from Kyle, unchanged: nothing may depend on access to Abnormal systems, data, or
detection content.** Public data only.

## What is built and measured

`tools/agent_graph/` holds the whole thing.

| Module | Role |
|---|---|
| `capabilities.py` | Static capability taxonomy over the three legs, with graded evidence |
| `composition.py` | Closure detection, minimal closures, critical packages |
| `marginal.py` | Distance-to-closure, marginal flip simulation, co-installation graph |
| `config_corpus.py` | Acquisition of real configs and the manifests they reference |
| `verification.py` + `labels.json` | Ground-truth scoring of the taxonomy |
| `export_artifact.py` + `artifact_template.html` | The runnable analyzer |

Corpus: 1,387 configuration files retrieved from public repositories, 1,275 containing server
entries, **336 unique server sets** after collapsing 178 duplicates, 380 distinct packages
referenced, 205 resolving to an npm manifest. Nothing executed, no payloads downloaded.

Headline results, all published in `docs/detections/evaluation-agent-composition.json` and written
up in `docs/research/agent-capability-composition.md`:

| Measurement | Value |
|---|---|
| Configurations closing a chain | 80 of 336 (23.8%) |
| Closed by a single package | 54 |
| **Closed only by composition** | **26** |
| Minimal closure size, every composed case | 2 packages |
| Open configs one leg short | 68 (26.6% of open, 20.2% of all) |
| Of those, missing private data | 42 |

**The taxonomy is verified and it is not very accurate.** Precision 0.733, recall 0.532 against 23
independently labelled servers. An earlier version of this handoff called every rate a lower bound.
That was wrong and the research document has since been corrected: recall of 0.53 biases downward,
but precision of 0.73 biases upward, and because the two error modes pull in opposite directions
these are estimates of potential capability co-occurrence, not strict bounds in either direction.
Keep that phrasing.

**The verification falsified the original design.** Declared dependencies were assumed the
strongest evidence; measured, admitting the package description improved precision *and* recall
together, because agent servers are thin wrappers whose dependency sets say nothing about their
purpose. The default moved. The failed assumption is documented in `capabilities.py` rather than
deleted, and that write-up is part of what makes this work credible.

## Next: six modifications to the marginal analysis

`marginal.py` is implemented and running. It already reports rates alongside raw counts and derives
communities by connected components rather than pre-labelling them, both of which were right. These
six are what a review found, in priority order.

### 1. The counterfactual assumes uniform mixing, and the fix is in the same file

`compute_marginal_closure_contributions` adds package X to every open configuration lacking it.
That treats every package as equally plausible in every configuration. Nobody adds a Postgres
server to a design-tooling config.

The co-installation graph built alongside it is exactly the data that corrects this, but the two
are currently parallel outputs. **Join them.** Report the unweighted figure as an upper bound on
marginal risk, and a co-installation-weighted figure as the realistic one. This is the largest
available improvement and it needs no new data.

### 2. Distance-to-closure is the metric most damaged by recall of 0.53

If half of real capabilities are missed, configurations measured as one leg short may already be
closed. The distribution is therefore biased toward openness in a **known direction**, which means
the 26.6% figure is probably overstated rather than uncertain in both directions.

Two changes. Carry the measurement-error caveat explicitly into the marginal section of the
research document, in the corrected both-directions form rather than as a lower bound.
Then run the distance distribution across evidence thresholds and publish it as a sensitivity band
rather than a point estimate. The `min_tier` plumbing already supports this, so it is cheap.

### 3. Use the deduplicated corpus for co-installation, and I was wrong about this earlier

An earlier handoff said to use the pre-deduplication set of 1,275 because duplicates carry signal
about which templates propagate. That is wrong for this purpose. A template copied into two hundred
forks would dominate every edge weight, and the resulting communities would be forks of one
repository rather than installation practice.

The code takes the deduplicated 336, which is correct. Keep it. If the propagation signal is
wanted, report template prevalence separately rather than as edge weight.

### 4. `min_support=2` is too low for 336 configurations

A pair seen twice is noise. Connected-components clustering over noisy edges tends to collapse into
one giant component plus singletons, which then gets presented as a finding. Raise the threshold,
and publish the component size distribution so that failure mode is visible if it happens.

### 5. Rank the headline table by composed contribution

The sort key is `flips_total` first, which puts single-package closers on top. Those flip
everything and are the uninteresting answer. Composed flips are the research contribution and
belong in the primary ranking, with total as a secondary column.

### 6. Language precision

Prefer "one capability leg short" over "one package away". The two are equivalent only under the
uniform-mixing assumption that item one removes. The JSON already reports both denominators
(`share_of_open` and `share_of_total`), so make sure the prose does too; 68 of 256 open and 68 of
336 total will otherwise be read interchangeably.

## After those, the open questions worth pursuing

- **Ingress reachability tiers.** Content an anonymous internet user can plant is a different
  exposure from content only a colleague can plant, and the model currently treats them the same.
  This is the single biggest modelling gap and the research suggests three natural tiers:
  internet-open with no relationship required, requires org membership or a share, and requires
  prior compromise or an indirect path such as a log line.
- **Tool-level rather than server-level capability resolution.** Would need the protocol's own tool
  declarations rather than package metadata.
- **Escalation primitives as a separate dimension.** Some write capabilities are categorically
  worse: creating a webhook endpoint or an alerting contact point establishes a durable outbound
  channel that fires without the agent, and code-deployment tools outlive the session. These are
  not the same as ordinary writes and the taxonomy currently flattens them.
- **Longitudinal re-run.** The acquisition is reproducible from the hash-pinned lockfile, so the
  same measurement over time shows whether the ecosystem is trending toward or away from closure.

## Disciplines, non-negotiable

Learned the hard way across three programmes. Do not relearn them.

1. **Never download package payloads.** Identities, manifests, and configuration files only.
   Defender on this machine is aggressive and has quarantined a documentation file before.
2. **Defang command-line examples in prose.** Defender signature 2147925971 fires on intact cradle
   strings in markdown.
3. **Declare every measurement external or internal.** External means data this repository did not
   author. A previous programme found a scorer measuring 15 of 15 internally and 0 of 877
   externally.
4. **Never publish a third party as malicious on a name match.** Every package named in the outputs
   so far is behaving exactly as documented, and the write-ups say so explicitly. A closure is a
   capability statement, never an accusation.
5. **Do not let the swarm generate synthetic configurations.** The entire value of this measurement
   is that the configurations are real. Synthetic ones would measure the generator, which is the
   failure this repository has already documented twice.
6. **Record what was discarded.** 761 configurations were dropped because no server entry resolved
   to a registry package; that number belongs in the write-up, not in a comment.

## Prior art, so it is not rediscovered

Ecosystem-scale measurement of agent tool servers already exists and must keep being cited: Hasan
et al. on server security and maintainability across 1,899 servers, MCPTox on tool poisoning
against live servers, **Huang et al. on over-privileged tool capabilities** which is the closest
work and audits file, network, and execution axes, and MCPZoo on scanner reliability across tens of
thousands of servers.

None of them measure capability **co-occurrence across an installed set**. That is the only
novelty claimed and the claim should stay that narrow.

One correction to carry: `langchain-core-mcp` appeared in an earlier handoff as a lead. Research
could not verify it against any primary source. **Drop it** and do not name it anywhere.

## Environment notes

- Windows 11, Python 3.14, `yara` 4.5.4. Suite: `python -m unittest discover -s tests`.
- Regenerate everything: `python -m tools.agent_graph.export_artifact`.
- Single test module takes a dotted path: `python -m unittest tests.test_agent_graph`, not a file
  path.
- `subprocess` output from `gh` must be captured as bytes and decoded UTF-8. `text=True` uses the
  Windows ANSI code page and dies on real API responses.
- Windows git cleanup needs a chmod-on-error handler; `shutil.rmtree` fails on read-only objects
  under `.git`. Working implementation in `tools/acquire_malicious_corpus.py`.
- GitHub code search is authenticated through the `gh` CLI and rate limited to ten requests a
  minute; the acquisition paces itself at 6.5 seconds between pages.
- Large corpora are gitignored, lockfiles are committed, and everything is reproducible from them.
- Other agent sessions may be open on this repository. Check `git status` before assuming a
  change is yours.
- **The repo now has real committed history** (`main` @ `9b79436`, 11 merged PRs; the swarm honesty
  pass is on `fix/swarm-honesty-pass`). An earlier revision of this file said "nothing is committed"
  — that described the Sep 4–6 state and is retired. Check `git log`/`git status` yourself; do not
  trust a handoff doc on repository state.

## Earlier programmes, for context

Recorded in `PORTFOLIO_ROADMAP.md` entries 25 through 31 and in the Obsidian vault at
`C:\GILA VAULT\01_Threat_Intelligence`.

- External validation against 232,729 real malicious packages. AI-toolchain imitation is roughly
  eight times more concentrated in PyPI than npm.
- A relevance scorer measuring 0 of 877 held-out recall, replaced with an inventory-derived
  mechanism reaching 61.6% on npm at a 2.56% false-positive rate.
- A durability benchmark over 3,144 public SigmaHQ rules: 189 of the 192 most fragile read process
  creation, and a third of the corpus depends on Windows command-line auditing that is off by
  default and almost never declared.
- Five cloud techniques with zero rules in the public corpus, including instance metadata
  credential theft.
- An unsubmitted upstream package in `docs/upstream/`: a Sigma telemetry prerequisites proposal
  that is ready, and cloud rules that are deliberately not, because they carry placeholder network
  ranges and no false-positive measurement.
