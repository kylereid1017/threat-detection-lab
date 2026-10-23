# EG2 link triage: validating on production data

**Status:** proposal, 2026-10-10. Nothing here has been run on production data.
**Audience:** an engineer, or a coding agent working for one, inside an organization that has
approved testing this on its own data. Each section gives an agent enough to act on.

The study in this folder used public data only (Phishpedia and a 2026 public screenshot
benchmark). It shows that reading the page behind a link closes most of the gap a text-only
"System One" model leaves on links. Public data can't say how much this adds to a production
detection stack, or how often it false-alarms on real benign traffic. This document lists the
tests that would, in order, with the data each needs and the guardrails each must follow.

---

## 0. Rules for any agent running this

1. **Approval first.** Don't query any production data until a named owner has approved the
   specific test (Section 3). Record the approval (who, when, scope) in the plan file.
2. **Pre-register.** For each test, write a plan file with the question, the sample, the arms and
   the pass/fail criteria. Commit it to the organization's own repository *before* pulling or
   scoring any data. Records are append-only. Aggregates are recomputed from records. Misses are
   reported as misses. Anything decided after seeing data is labeled post-hoc. The plans in
   `tools/eg2_triage/PLAN*.md` are the template.
3. **Read-only.** No writes to production systems, no automated actions on mail, no changes to
   live verdicts. The page score is a shadow signal until a go decision.
4. **Data stays inside.** Work in an internal fork of this repository, on approved
   infrastructure. Never commit production data, results, screenshots, URLs or identifiers to the
   public repository. Only aggregate results leave the approved environment, and only with the
   data owner's sign-off.
5. **Follow every privacy control in Section 4.** None of them is optional.

---

## 1. Discovery: answer these before designing anything

The public study compared page readers against a link-only model. Production systems may
already fetch or render link destinations, so the real baseline has to be established first.
Write the answers to `DISCOVERY.md` in the internal fork, with a source (doc, code path, table)
for each.

| # | Question | Why it matters |
|---|---|---|
| D1 | Does the stack fetch, crawl or render link destinations today? At delivery, at click, or both? | Sets the baseline. If pages are already rendered, this proposal is a new *reader* for existing artifacts, which is much cheaper. |
| D2 | If so, what is stored per link: final URL, redirect chain, HTML, visible text, screenshot? For how long? | Decides whether tests can replay history (cheap) or must render prospectively (slower). |
| D3 | What ground truth exists for links: analyst dispositions, user reports, remediation outcomes, later confirmed campaigns? How noisy is each? | Labels for every test below. The public study found two thirds of one dataset's "phishing" labels showed no phishing; check label quality the same way (Section 2, test V0). |
| D4 | What does the System One model (the production counterpart of Jev) see for a link today, and can its input take extra context such as page text? | Test V3, the cheapest upgrade path. |
| D5 | What share of delivered links point at shared hosts (site builders, cloud hosting, file sharing, shorteners)? Use `SHARED_HOSTS` in `tools/eg2_triage/battery_a_urls.py` as the starting list. | Sizes the problem and the render budget. |
| D6 | Is there approved GPU capacity, and is any third-party vision-LLM vendor approved for page images? | Decides which readers are allowed in Section 2. |
| D7 | Who owns approval for each data source, and what retention and residency rules apply? | Section 4. |

If D6 says no third-party LLM is approved for page images, run the EG2 and page-text arms only.
They carry most of the public result (Battery T: page text alone took the link reader from 37.5%
to 91.0% on trusted-host phishing).

---

## 2. Tests, in priority order

Each test names the public result it would confirm or overturn. "Public" figures are from
`results-*.json` in this folder.

### V0 · Label audit (do this first; one day)

- **Public result:** 16 of 24 audited "phishing" pages in the 2026 benchmark showed no phishing
  (`AUDIT-A-PHISH.json`).
- **Internal test:** draw 100 labeled-phishing and 100 labeled-benign links at random from each
  label source in D3. Two analysts label each rendered page blind to the source label: visible
  phishing, fraud, dead or parked, benign. Report agreement and each source's error rate.
- **Why it comes first:** every later number depends on these labels.

### V1 · Incremental catches over the current stack (the decisive test)

- **Public result:** page readers caught 94–99% of 387 trusted-host phishing sites; the
  link-only reader caught 37.5% (`results-x.json`).
- **Internal test:** a 4-week read-only shadow run. Render (or reuse renders of) a sample of
  delivered links on shared hosts. Score each page with the arms below, alongside the current
  production verdict. Adjudicate every disagreement.
- **Arms:** current production verdict (baseline); System One model with link + page text (V3);
  EG2 URL + screenshot with a head trained on internal labels (V4); vision LLM, if approved; EG2
  with the LLM on the least-certain 20% (V5).
- **Primary metric:** confirmed phishing caught by an arm and missed by production, per week.
- **Sample size:** about 400 confirmed phishing links per host group gives about ±5-point intervals
  on recall.

### V2 · False alarms on benign pages on the same hosts (the biggest public gap)

- **Public result:** false alarms were measured only on a 2026 set of ordinary legitimate sites,
  not on benign pages hosted on the shared hosts where the phishing lives. This is the main
  weakness an engineer will point to.
- **Internal test:** sample benign links on shared hosts (delivered, never reported, sender and
  recipient with an established history), stratified by host. Score with every arm.
- **Sample size:** with zero false alarms in *n* pages, the 95% upper bound is about 3/*n*. Bounding
  false alarms below 0.01% needs about 30,000 adjudicated benign pages. Below 0.1% needs about
  3,000.
- **Report:** false-alarm rate per arm, per host, and on login, signup and payment pages
  separately (the public "hard negative" slice).

### V3 · Page text into the System One model (cheapest path)

- **Public result:** Battery T (`results-t.json`). Link + OCR'd page text: 91.0% caught vs 37.5%
  link only, with fewer false alarms (9.1% vs 10.7%). All four criteria passed.
- **Internal test:** replicate with the production System One model. Compare three text sources:
  OCR of the screenshot (as public), visible DOM text if D2 says HTML is stored, and both. Keep
  the public truncation (first 2,000 characters) unless the plan says otherwise.
- **Why it matters:** it needs no vision model and no new serving stack, only a new input field.

### V4 · Labels needed, and drift over time

- **Public result:** about 25 labels per class reached 98% caught at threshold 0.5; 150 per class
  lifted catches at ≤1% false alarms from 65% to 78% (`results-l.json`).
- **Internal test:** the same learning curve on internal labels (10 / 25 / 50 / 100 / 150 / all per
  class, 20 draws each). Add a **time split**: train on months 1–2, test on month 3. Public data
  had no time dimension.
- **Group** cross-validation by registered domain (as public) and also by tenant, so one
  organization's pages never appear in both train and test.

### V5 · Calibrated gate between EG2 and the LLM

- **Public result:** the registered band (0.1–0.9) sent 99% of pages to the LLM because EG2's raw
  scores are poorly calibrated (G-a MISS). Post-hoc, the LLM on the 20% least-certain pages gave
  99.6% caught and 1.8% false alarms (`POSTHOC-G.json`).
- **Internal test:** fit Platt or isotonic calibration on a held-out month, then pre-register the
  gate as "LLM on the least-certain *k*%" with *k* fixed in the plan. Report catches, false alarms
  and LLM share. This turns the post-hoc design into a registered one.

### V6 · Brand impersonation with no training

- **Public result:** 31 brands described in one line of text; "looks like brand X, not on X's
  domain" scored ROC-AUC 0.956 and caught 78% at 0.9% false alarms (`results-n.json`).
- **Internal test:** use the organization's list of most-impersonated brands and their official
  domains, including the protected organizations' own brands where policy allows. Report per
  brand. This is also the explanation analysts see.

### V7 · Kits and render savings

- **Public result:** 66% of phishing pages sat in multi-domain kits, 91.5% brand-pure; the
  largest was 147 pages on 21 domains (`results-k.json`).
- **Internal test:** cluster internal renders the same way (cosine distance 0.10). Report the share
  of phishing in kits, kits seen across several tenants, and the render and inference saved by
  "one verdict per kit". Compare kit first-seen time with first detection.

### V8 · Explanations analysts trust

- **Public result:** a fixed rule over seven page questions caught 82% of trusted-host phishing at
  0% false alarms, and 99.4% of LLM flags carried a reason (`results-q.json`). The 40-page
  accuracy check was labeled by an AI assistant, not a person.
- **Internal test:** map the seven questions to the analysts' own justification categories. Two
  analysts answer them on 120 pages (60 phishing, 60 benign) blind to model output. Report
  per-question accuracy. This replaces the AI-labeled audit with a human one.

### V9 · Cloaking, delayed arming and robustness

- **Public result:** ordinary image changes flipped ≤1% of EG2's catches (`results-r.json`); an
  overlaid "verified safe" banner fooled neither reader (`results-i.json`); a white-box pixel
  attack on EG2's public weights flipped 70% at 8/255 (`results-w.json`).
- **Internal test:** for a sample of links, render at delivery and again at +1 h and +24 h, and
  from two network egress profiles if available. Report how often the page changes class (a
  benign page that turns malicious, or a phishing page that goes blank for the crawler). Report
  how often EG2 and the LLM disagree on pages that changed. Don't generate attacks; measure what
  attackers already do.

### V10 · Cost and latency at production scale

- **Public result:** EG2 4.0 s per page on a 12-thread desktop CPU, fp32; URL text alone 93 ms;
  GPU untested (`timing-solo.json`). Haiku 5.5 $0.16 per 1,000 pages at list price, 2.5 s median.
- **Internal test:** benchmark EG2 on the approved GPU class: throughput at batch 16/64/256, p50
  and p99 latency, and bf16 vs fp32 agreement (fp16 produced NaNs on CPU; check before relying
  on it). Measure render cost per page in the existing sandbox. Report cost per 1,000 links for
  each arm and for the gated design, at the D5 volumes.

---

## 3. Approvals checklist (one per test)

- Data owner for each source in D3, with scope (tables, date range, fields).
- Privacy or legal review of Section 4 for this test.
- Security sign-off on the render sandbox if new renders are needed.
- Vendor approval before any page image goes to a third-party model.
- Named adjudicators and their time budget.

---

## 4. Privacy and safety requirements

**What the public study found.** About 15 of 987 public phishing screenshots show a targeted
person's email address pre-filled in a login form. Phishing links often carry the recipient's
address in the query string, fragment or path, sometimes base64-encoded, so the kit can pre-fill
it. Production renders will show this more often than the public data does. Legitimate pages
show staff names and contact addresses.

**Requirements.**

1. **Strip recipient identifiers before rendering.** Remove or replace email addresses, names and
   tenant identifiers found in the URL (plain, percent-encoded or base64) with a neutral
   placeholder. Log only that a substitution happened. Measure in V1 whether this changes
   verdicts. Kits that key on the address may render differently.
2. **Isolated renderer.** No cookies, no stored credentials, no single sign-on session, no form
   submission, no downloads executed. Fresh profile per render. Egress through the approved
   detonation network only.
3. **One-time links.** Rendering can consume single-use tokens (password resets, magic links,
   invitations). Exclude known single-use patterns, and prefer reusing renders the stack already
   makes (D1) over new ones.
4. **Redact page text before it leaves the renderer.** Mask email addresses, phone numbers,
   payment card numbers and government ID patterns in OCR or DOM text before storage, before
   the System One model and before any LLM.
5. **Third-party models.** Page images and text go to an external model only if that vendor is
   approved for this data with zero-retention terms. Otherwise run EG2 (self-hosted) and the
   page-text arm only.
6. **Records hold ids, not content.** Store link ids, hashes, scores, verdicts and adjudications.
   Keep screenshots and page text in the governed store with its normal retention, referenced by
   id.
7. **Outputs.** Only aggregate tables leave the approved environment. Example pages shown in any
   deck are chosen from public data, or reviewed and redacted by the data owner.

---

## 5. Go / no-go (agree before V1 starts)

- **Go** if the shadow run shows confirmed incremental catches per week that the detection team
  considers material, and false alarms on shared-host benign pages are bounded at a level the
  team accepts (V2), at a cost per 1,000 links inside budget (V10).
- **No-go** if incremental catches are negligible, or false alarms can't be bounded, or cloaking
  (V9) hides most phishing from the renderer.
- Agree these thresholds with the detection team in writing before the run starts.
- Either way, publish the result internally as registered, misses included.

---

## 6. For the agent: porting the harness

The harnesses in `tools/eg2_triage/` read public corpora through small loader functions. To run
on internal data, add one adapter and point the batteries at it. Don't edit the public loaders.

**Adapter contract.** One function returning a list of items:

```python
@dataclass
class LinkItem:
    key: str            # stable id for the link (no raw URL in records)
    url: str            # after recipient-identifier stripping (Section 4.1)
    image_path: Path | None   # screenshot, if rendered
    page_text: str | None     # redacted OCR or DOM text (Section 4.4)
    label: int | None         # 1 phishing, 0 benign, None unlabeled
    label_source: str         # which D3 source
    host: str                 # lower-cased hostname
    seen_at: datetime         # delivery time, for time splits
    tenant_hash: str          # for grouped CV; never the tenant's name
```

**Where each battery loads data** (replace these calls with the adapter):

| Test | Script | Public loader to replace | Notes |
|---|---|---|---|
| V1, V2 | `battery_a_urls.py`, `battery_x_crossdataset.py` | `load_sample()`, `load_x()` | EG2 input for URL + screenshot is `{"text": PREFIX + url + " <|image|>", "image": [path]}` with `PREFIX = "task: classification \| query: url: "`; fp32, normalized embeddings, logistic head (`lr()`). |
| V3 | `battery_t_pagetext.py` | `a_items()`, `x_items()`, `load_ocr()` | Swap `clients.jev_system_one` for the production System One client; keep the state templates in `PLAN-addendum-T-pagetext.md`. |
| V4 | `battery_lgnk.py --l` | `a_data()` | Add a time split and tenant grouping. |
| V5 | `battery_lgnk.py --g`, `--g-posthoc` | `a_data()`, `load_vlm_map()` | Add calibration before the gate. |
| V6 | `battery_lgnk.py --n` | `BRANDS` | Replace with the organization's brand and official-domain list. |
| V7 | `battery_lgnk.py --k` | `load_x()` | Cluster on internal embeddings. |
| V8 | `battery_q_questions.py` | `a_legit_items()`, `load_x()` | Questions are in `QUESTIONS`; map them to the analysts' categories in the plan. |
| V9 | `battery_r_robust.py` | `chosen()` | Re-render schedule replaces synthetic transforms. |
| V10 | `timing_solo.py` | — | Run on the target GPU. |
| All | `stats_util.py` | — | Wilson intervals, McNemar, bootstrap, TPR at fixed FPR, calibration error. Reuse as is. |

**Environment notes.**

- Model: `google/embeddinggemma-2` (Apache-2.0), loaded with `sentence-transformers`. Pass
  `config_kwargs={"audio_config": None}` to skip the audio tower.
- fp16 produced NaNs on CPU; the study used fp32. Verify bf16 on GPU against fp32 before use.
- One image costs about 280 tokens; URL + screenshot took 4.0 s on CPU. Don't run several image
  jobs on one CPU at once.
- The vision-LLM harness (`battery_v_vlm.py`) asks for JSON by instruction with stop sequences.
  On an approved direct API, use structured output instead and log the change as a deviation.
  Claude Haiku 5.5 accepts no temperature setting other than its default.
- Python's `hash()` is randomized per process. Never use it for seeded sampling.

**Deliverables back to the requester.** `DISCOVERY.md`, one plan file per test (committed before
data), append-only records in the governed store, a `results-V*.json` per test, and a one-page
summary with the go / no-go table filled in.
