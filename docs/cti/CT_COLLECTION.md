# Live Certificate Transparency collection

The acquisition half of the CTI pipeline: a network-facing tool that queries public
Certificate Transparency logs and writes a dated, hash-pinned snapshot the offline pipeline
then reads.

    python tools/acquire_ct_snapshot.py --out corpus/ct --window-days 90
    python -m tools.cti.cli --snapshots corpus/ct --summary-only

Acquisition talks to the network. Analysis never does. That split is what makes a published
result reproducible, because the analysis can be re-run against the exact bytes that produced
it. The pipeline documentation described this split before anything implemented it; this
closes that gap.

## What the output is, and is not

Every row is a certificate that exists. **Nothing in a snapshot establishes that any domain
is malicious.** Most matches for a brand term are the brand's own infrastructure, its
customers, or unrelated software that happens to share a word. Scored output is a queue for
human verification. The acquisition lock file carries that statement so it travels with the
data.

## First run

Ninety-day window, queried on the relevance vocabulary's brand terms.

| Measurement | Result |
|---|---|
| Unique certificates retrieved | 137 |
| Unique DNS names | 114 |
| Indicators after deduplication | 101 |
| Registrable-domain clusters | 10 |

## Finding one: querying by brand makes the scorer redundant

Queue reduction was **0.0%**. Every indicator reached the triage queue.

That is not a scorer failure. It is a selection effect, and it is worth stating plainly
because it is easy to mistake for success. The collection query was `%brand%`, so every
result contains a brand term by construction, and the scorer's brand branch then fires on all
of them. Relevance scoring adds nothing when the collection query has already done the
filtering.

The scorer earns its place when collection is broad and scoring narrows it, which is the
firehose case: consuming a full CT stream and deciding what matters. Against a targeted
crt.sh query, collection is the filter and the score is decoration.

The measurement to want here is the one this run cannot produce: precision against a broad
sample. That needs a streaming CT client rather than term queries, and it is not built.

## Finding two: the useful analytic is the pivot, not the score

With scores uninformative, the value came from clustering names by registrable domain. Ten
clusters formed. The fanout guard rejected two attributes as common infrastructure: a widely
used certificate authority (82 names) and a legitimate vendor's own apex (57 names).

The pattern worth an analyst's time appeared immediately: **one registrable domain hosting
subdomains that lexically impersonate two different AI brands.** On `elitefinstats.com`, the
snapshot contains `chat--openai--com.elitefinstats.com` and `huggingface--co.elitefinstats.com`.
The double-hyphen convention renders a brand's fully qualified domain as a single subdomain
label, so a browser address bar shows a familiar string well before the real registrable
domain.

Stated precisely, because the distinction matters: this is a factual observation about public
Certificate Transparency records. It is **not** a determination that the domain is malicious.
That would require resolving the names, examining content, and checking registration and
hosting, none of which this tool does. It is a candidate, and it is the kind of candidate a
brand-term query exists to surface.

Two brands imitated under one apex is a stronger signal than either name alone, which is the
argument for pivoting at all. A single lookalike is a data point. A shared apex is a
structure.

## Limitations

- **Term queries, not a stream.** Coverage is exactly the query list. A campaign imitating a
  brand outside the vocabulary is not collected at all, which is the same coverage ceiling
  measured in `docs/detections/RECALL.md`.
- **crt.sh is one view of CT**, is a free community service, and is rate limited here to one
  query every two seconds for that reason.
- **Registrable domain is approximated** from a short hand-maintained suffix list rather than
  the Public Suffix List. A missing suffix over-clusters, and the fanout guard then discards
  the cluster, so the failure mode is a lost pivot rather than a fabricated campaign.
- **No resolution, no content, no registration data.** Everything downstream of the
  certificate record is unbuilt, and that is most of what verification requires.
- **The 90-day window is a parameter, not a finding.** Widening it changes every count above.
