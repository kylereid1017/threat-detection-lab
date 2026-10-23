# Jev Email Triage — Experiment Plan (pre-registered)

**Date:** 2026-09-17 · **Status:** design frozen before any data collection.
**Model under test:** Jev (`jev-latest` → `jev-1.13.0`), TypeSafe AI System One.
**Baselines:** DeepSeek V4.1 Flash; Claude Haiku 4.5 (full corpus); Claude Sonnet 5 (subset).

All thresholds, labels, corpus composition, and success criteria below were fixed
**before** running any model over any email. Results will be reported against this
plan; deviations get an explicit note in the report.

---

## 1. Question

Can Jev classify email (Safe / Gray / Spam / Attack) fast and cheaply enough to sit in
front of a heavier LLM in a triage cascade — and with what measured effectiveness?

Sub-questions:
- (a) Accuracy of Jev alone vs LLM baselines on the same inputs and labels.
- (b) Is Jev's `confidence` a usable gate (calibration)?
- (c) Cascade economics: what fraction of traffic can Jev auto-decide at a
  safety-constrained operating point, and what do cost and latency become?

## 2. Labels (inclusion rules)

| Label | Definition | Included | Excluded |
|---|---|---|---|
| `safe` | Wanted, legitimate mail the recipient would expect: personal, transactional, internal, subscribed newsletters. | Normal correspondence, receipts, notifications, subscribed content. | Anything solicited-but-unwanted (→ spam/gray). |
| `gray` | Real ambiguity — a reasonable analyst would neither auto-trust nor auto-block: unsolicited but plausible outreach, unknown-list bulk mail, legitimate-looking mail with anomalies (sender/brand mismatch, unexpected attachment, urgency from unknown party). | Cold outreach, plausible vendor mail, inbox oddities. | Clear bulk commercial junk with no malice (→ spam); clear deception (→ attack). |
| `spam` | Unsolicited bulk/promotional mail with no malicious intent. | Marketing blasts, get-rich schemes, retail promos to non-subscribers. | Mail carrying deception or payloads (→ attack). |
| `attack` | Intent to harm or defraud: credential phishing, invoice/BEC fraud, malware lures, extortion, QR phishing, tech-support scams. | Inert/defanged representatives. | Live URLs or payloads (never collected). |

Note on `gray` vs `spam`: gray requires *unresolvable* ambiguity for a typical analyst;
habitual junk does not qualify.

## 3. Corpus composition (target 200; balanced 4 × 50)

| Source | Label | N | Notes |
|---|---|---|---|
| Apache SpamAssassin public corpus (`easy_ham`) | safe | 25 | Real-world mail (2002–2003). |
| Synthetic (inert) | safe | 25 | Modern-style, varies by subtype. |
| Apache SpamAssassin public corpus (`hard_ham`) | gray | 25 | Legitimate but spam-looking — the ambiguity band. **Primary mapping; sensitivity run treats them as `safe`** (both reported). |
| Synthetic (inert) | gray | 25 | Cold outreach / anomalies. |
| Apache SpamAssassin public corpus (`spam`) | spam | 25 | Real-world bulk mail (2002–2003). |
| Synthetic (inert) | spam | 25 | Modern-style junk. |
| Synthetic (inert) + 10 hand-authored | attack | 50 | Six subtypes (credential phish, invoice fraud, malware lure, extortion, QR phish, tech-support scam). All indicators defanged (`.example`/`.invalid` domains, `192.0.2.0/24`, `hxxp://`). |

**Exclusions (pre-registered):** messages that fail RFC822 parsing, empty text bodies,
>100 KB, or non-English-dominant. Every exclusion is recorded with a reason in the
corpus manifest. Dedupe by normalized-body SHA-256 before sampling; sampling seed fixed
at sampling time and recorded.

**Input normalization (identical for all models):** one text block per email built from
`From`, `Reply-To` (if present), `Subject`, and the plain-text body. Headers beyond these
are excluded (no `Received` chains — defense against trivially deciding on relay hops).
Synthetic emails carry an equivalent header set. Attachments are represented only by
filename mentions in the body text.

## 4. Fixed model contracts

### Jev (one call per email, 3 questions — parallel batch)

```json
{
  "disposition": {"type": "choice", "instructions": "Classify this email...",
    "criteria": {"safe": "...", "gray": "...", "spam": "...", "attack": "..."}},
  "deception_present": {"type": "noul", "instructions": "Does the email attempt to deceive the recipient..."},
  "requests_credentials_or_payment": {"type": "noul", "instructions": "..."}
}
```
Reported label = `disposition.choice`; gate = `disposition.confidence`.

### LLM baselines (identical prompt for all LLMs; frozen)

System: classify into exactly one of safe/gray/spam/attack; output strict JSON
`{"label": str, "confidence": 0.0-1.0}`; no prose. No chain-of-thought requested
(default settings; DeepSeek thinking mode off — `"thinking": {"type": "disabled"}` is
set explicitly so the comparison is non-reasoning vs non-reasoning).

## 5. Metrics (pre-declared)

- Accuracy overall; per-class recall and precision **with raw counts**; full confusion
  matrices per model.
- Calibration: Jev disposition accuracy by confidence decile; auto-decide error rates
  across a confidence sweep (0.00→1.00 in 0.05 steps).
- Latency: wall-clock per call, p50 / p95 (measured at the harness, so it includes
  network — noted as such).
- Cost: measured token usage × vendor list prices (below), USD per 1,000 emails.

## 6. Cascade policy (pre-registered shape, threshold picked from the sweep)

```
c = Jev confidence for disposition
if disposition == "attack" and c >= T_block   -> auto-quarantine (attack)
elif disposition == "safe" and c >= T_auto    -> auto-deliver (safe)
else -> escalate to LLM triage
```
Operating point chosen by the **safety constraint first**: `T` such that
auto-decided-and-wrong rate ≤ 2% of auto-decided traffic, maximizing auto-decide share
subject to that. Escalation cost charged at measured LLM token usage for the same
emails (simulated from the recorded LLM runs — not re-called).

## 7. Success criteria (targets, not claims)

1. Attack recall ≥ 0.90 at the chosen operating point.
2. Jev cost ≤ $0.001 per email (expected ≈ $0.0004–0.0006 at ~700–900 input tokens).
3. Cascade ≥ 60% of traffic auto-decided with ≤ 2% wrong on the auto-decided set.
4. Cascade total cost ≤ 20% of pure-LLM cost on the same traffic at equal accuracy
   (equal-accuracy comparison uses the measured LLM results, not assumed ones).

A miss on (1) or (3) is a headline finding, not a failure to hide.

## 8. Pricing (vendor list prices, accessed 2026-09-17)

| Model | Input /MTok | Output /MTok | Source |
|---|---|---|---|
| Jev (`jev-latest`) | $0.042 | $0.00 (free) | typesafe.ai |
| DeepSeek V4.1 Flash | $0.15 off-peak / $0.30 peak | $0.60 / $1.20 | api-docs.deepseek.com/quick_start/pricing |
| Claude Haiku 4.5 | $1.00 | $5.00 | platform.claude.com/docs/en/about-claude/pricing |
| Claude Sonnet 5 | $2.00 | $10.00 | same |
| Claude Opus 5 | $5.00 | $25.00 | same |
| Claude Fable 5.1 | $10.00 | $50.00 | same |

DeepSeek peak = 01:00–04:00 and 06:00–10:00 UTC Mon–Fri. Runs record timestamps so the
correct tier is applied.

## 9. Known limitations (declared up front)

- Synthetic attacks are machine-generated (DeepSeek) plus 10 hand-authored cases;
  generation bias inflates or deflates measured effectiveness in unknown direction.
  **Synthetic accuracy is not evidence of real-world efficacy** and will not be
  presented as such.
- Public spam corpora are 2002–2003-era; modern mail (auth, HTML-only, tracking) is
  underrepresented. Subtype mix ≠ 2026 inbox mix.
- Single-run measurements; no repeated-run variance study.
- No employer or private data is used anywhere in this experiment.

## 10. Raw-record schema (append-only, one row per model × email)

`run_id, seq, ts_utc, model, email_id, label_true, label_pred, confidence,
 raw_answer, latency_ms, input_tokens, output_tokens, error`

Aggregates are computed from these records only; every figure in the report must be
recomputable from the committed record files.
