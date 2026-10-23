# EG2 Triage — errata

**2026-10-09 · Commit hashes after a history clean-up.** Unpushed commits were rewritten to
remove a superseded dashboard file and an organisation name. Content and author dates are
otherwise unchanged. Frozen plans that cite old hashes map as follows:

| Cited in | Old hash | New hash | Commit |
|---|---|---|---|
| `PLAN-addendum-A-urls.md` | `d1aa508` | `6c45a24` | URL & multimodal screenshot benchmark (the original, unregistered run) |
| — | `61bf6b3` | `8602a99` | Pre-registration of Batteries A and D |
| — | `eea09b1` | `2442792` | Pre-registration of Batteries V and X |
| — | `d07edbd` | `3a62bf2` | Pre-registration of the Haiku 5.5 arm |

The two dashboard-only commits (`a0ef05f`, `2eb7c64`) no longer exist; that file is
superseded by the registered re-runs. `ead9e00` and `39c3986` are unchanged.

**2026-10-09 · Haiku 5.5 arm: two mislabeled record fields (no effect on any result).** In
`battery_v_vlm.py` the per-observation `model` field is a constant (`claude-haiku-4-5`), and the
`run_meta` line's `price_per_mtok` is a constant (`[1.0, 5.0]`), on every arm. For the `_h55`
arms both are wrong. The fields that carry the truth are correct and are what the scorer uses:

- `served_model` is `anthropic/claude-haiku-5.5` on every `_h55` observation (as returned by the
  transport), and `anthropic/claude-haiku-4.5` on every Haiku 4.5 observation.
- `cost_usd` / `billed_cost_usd` equal the published list price for each model: Haiku 4.5 at
  $1 / $5 per million tokens, Haiku 5.5 at $0.10 / $0.50 (prompts up to 100k tokens). Example:
  1,039 input + 25 output tokens on Haiku 5.5 = $0.0001164, as recorded.

Records stay append-only and are not rewritten. Read `served_model`, not `model`, to tell the arms
apart.

**2026-10-09 · Post-hoc routing view.** `posthoc_route.py` re-reads the A / V / X records (no new
model calls) and splits each page reader's results by what Jev said about the link. Its
"reader decides all" rows reproduce the registered X and V numbers exactly, which checks the
join. Output: `docs/research/eg2-url-benchmark/POSTHOC-ROUTE.json`, labeled post-hoc.

**2026-10-09 · Haiku 5.5 did not run at temperature 0.** The harness sends `temperature: 0.0` on
every arm. Claude Haiku 5.5 (released 2026-10-07) accepts no sampling setting other than its
default; on the direct API a temperature of 0 returns a 400. The transport returned normal
answers, so the setting was evidently dropped and the `_h55` arms ran at default sampling, with
adaptive thinking at the default effort. Haiku 4.5 did run at temperature 0. Repeatability
check (post-hoc, `posthoc_route.py`): Battery R's unaltered run re-asked Haiku 5.5 about 100 X
pages a few hours after the X run, and all 100 verdicts matched (82 of 100 probabilities
identical, the largest difference 0.10). Those 100 are pages EG2 flagged, so they are mostly
clear-cut; borderline pages may vary more.

**2026-10-09 · Battery W strict-threshold count, and the spend tracker.** Two scoring fixes, both
before any figure was published:

- `results-w.json` first counted a T2 "flip" for every page whose lowest score fell below T2,
  including 3 of the 20 pages that already sat below T2 before the attack. T2 flips are now counted
  only among the 17 pages that started above T2 (all 17 fell below it). The 0.5 count is unchanged
  (all 20 pages start at or above 0.5): 14 of 20.
- `battery_v_vlm.spent()` sums only `records/vlm-*.jsonl`, so it does not see the `q-h-*` and
  `adv-i-*` Haiku records added by Batteries Q and I. Total logged Haiku cost across all records was
  $4.31, under the $5 cap. Any future Haiku arm should either use a `vlm-` file prefix or extend
  `spent()`.

**2026-10-10 · Battery W deviation text named the wrong run size.** The deviation string in
`battery_iw_robust.py` was written before the run settled and said "15 steps on 30 pages". The run
used 12 steps on 20 pages, as the `steps` and `n` fields of the `adv-w.jsonl` run_meta line and
the 20 records show. The string is now built from the run settings and `results-w.json` was
re-scored. The record's run_meta line keeps the old text (records are append-only); its `steps`
and `n` fields are correct. No figure changed.

**2026-10-10 · OCR records contain email addresses.** `records/ocr-a.jsonl` and `ocr-x.jsonl`
hold the visible text of every screenshot. About 15 of the 987 Phishpedia pages show a targeted
person's email address pre-filled in a login form, and some legitimate pages show staff contact
addresses. These files must not be published as-is: redact addresses before any commit, or keep
them out of the repo.
