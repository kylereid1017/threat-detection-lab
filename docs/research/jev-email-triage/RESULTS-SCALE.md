# Jev Email Triage - Scale Battery Results

Generated: 2026-09-17T20:09:10.798734+00:00 - recomputed from raw records only (jev-scale-20260917T184615Z.jsonl, sha256 397880fab6da0614...).

Plan: `tools/jev_triage/PLAN-addendum-scale.md` - registered operating point T=0.30.

Readings (post-hoc interpretation): `SCALE-READINGS.md`; conjunction arm: `CONJUNCTION-ARM-SCALE.md`.

## Reconciliation

| run | observations | errors | clean ids | expected | ok |
|---|---|---|---|---|---|
| jev-scale-20260917T184615Z.jsonl | 18324 | 10 | 18314 | 18314 | PASS |

## Registered criteria (A7)

| id | criterion | actual | result |
|---|---|---|---|
| C1 | attack recall >= 0.90 (aggregate attack partition) | 0.4801666666666667 | MISS |
| C2 | auto-delivered true attacks at registered T=0.30 == 0 | 1301 | MISS |
| C3 | auto-decide share >= 50% at <= 2% auto-decided exact-label error (T=0.30) | {"auto_coverage": 0.6084416293545921, "auto_error_rate": 0.18083101498698734} | MISS |
| C4 | cost <= $0.001/email | 4.320508856612428e-05 | PASS |
| C5 | latency p50 <= 350 ms and p95 <= 1000 ms | {"p50": 220.3, "p95": 349.4} | PASS |
| C6 | every attack miss at confidence < 0.50 | {"max_miss_confidence": 1.0, "miss_count": 6238} | MISS |

## Model summary

| run | model | n scored | unresolved errors | accuracy | p50 ms | p95 ms | $/email | $/1k |
|---|---|---|---|---|---|---|---|---|
| jev-scale-20260917T184615Z.jsonl | jev-latest | 18314 | 0 | 0.599 | 220 | 349 | 0.000043 | 0.0432 |

### Confusion - jev-latest

| true \ pred | safe | gray | spam | attack |
|---|---|---|---|---|
| safe | 3536 | 238 | 76 | 7 |
| gray | 192 | 4 | 46 | 3 |
| spam | 9 | 12 | 1672 | 519 |
| attack | 1334 | 550 | 4354 | 5762 |

| class | support | tp | precision | recall |
|---|---|---|---|---|
| safe | 3857 | 3536 | 0.697 | 0.917 |
| gray | 245 | 4 | 0.005 | 0.016 |
| spam | 2212 | 1672 | 0.272 | 0.756 |
| attack | 12000 | 5762 | 0.916 | 0.480 |

## Per-source accuracy

| source | n | accuracy |
|---|---|---|
| ceas_08 | 7203 | 0.163 |
| ling | 445 | 0.775 |
| nazario | 1523 | 0.891 |
| nigerian_5 | 3274 | 0.987 |
| spamassassin_easy_ham | 2472 | 0.882 |
| spamassassin_easy_ham_2 | 1385 | 0.979 |
| spamassassin_hard_ham | 245 | 0.016 |
| spamassassin_spam | 471 | 0.762 |
| spamassassin_spam_2 | 1296 | 0.747 |

## Attack recall by source

| source | attack support | recalled | recall |
|---|---|---|---|
| ceas_08 | 7203 | 1175 | 0.163 |
| nazario | 1523 | 1357 | 0.891 |
| nigerian_5 | 3274 | 3230 | 0.987 |

## Calibration (confidence decile vs accuracy)

| bucket | n | accuracy |
|---|---|---|
| 0.0-0.1 | 2 | 0.000 |
| 0.1-0.2 | 125 | 0.240 |
| 0.2-0.3 | 610 | 0.292 |
| 0.3-0.4 | 1427 | 0.359 |
| 0.4-0.5 | 1537 | 0.381 |
| 0.5-0.6 | 1581 | 0.388 |
| 0.6-0.7 | 1793 | 0.363 |
| 0.7-0.8 | 2226 | 0.368 |
| 0.8-0.9 | 2333 | 0.552 |
| 0.9-1.0 | 6757 | 0.935 |

## Two-branch threshold sweep (Jev only; escalated rows take Jev's own label)

| threshold | auto % | auto err % | missed attacks | final acc | $/1k |
|---|---|---|---|---|---|
| 0.00 | 62.0 | 18.17 | 1334 | 0.599 | 0.0432 |
| 0.05 | 62.0 | 18.17 | 1334 | 0.599 | 0.0432 |
| 0.10 | 62.0 | 18.17 | 1334 | 0.599 | 0.0432 |
| 0.15 | 62.0 | 18.14 | 1332 | 0.599 | 0.0432 |
| 0.20 | 61.8 | 18.11 | 1326 | 0.599 | 0.0432 |
| 0.25 | 61.4 | 18.14 | 1317 | 0.599 | 0.0432 |
| 0.30 | 60.8 | 18.08 | 1301 | 0.599 | 0.0432 |
| 0.35 | 59.6 | 17.70 | 1252 | 0.599 | 0.0432 |
| 0.40 | 57.5 | 17.25 | 1186 | 0.599 | 0.0432 |
| 0.45 | 55.7 | 16.75 | 1128 | 0.599 | 0.0432 |
| 0.50 | 53.9 | 16.09 | 1067 | 0.599 | 0.0432 |
| 0.55 | 52.1 | 15.52 | 1017 | 0.599 | 0.0432 |
| 0.60 | 50.2 | 14.46 | 920 | 0.599 | 0.0432 |
| 0.65 | 48.4 | 13.40 | 817 | 0.599 | 0.0432 |
| 0.70 | 46.0 | 11.59 | 640 | 0.599 | 0.0432 |
| 0.75 | 43.0 | 8.34 | 368 | 0.599 | 0.0432 |
| 0.80 | 40.0 | 5.44 | 160 | 0.599 | 0.0432 |
| 0.85 | 37.2 | 3.59 | 44 | 0.599 | 0.0432 |
| 0.90 | 33.8 | 2.50 | 5 | 0.599 | 0.0432 |
| 0.95 | 28.7 | 1.96 | 3 | 0.599 | 0.0432 |
| 1.00 | 13.8 | 1.94 | 1 | 0.599 | 0.0432 |

Auto-decided misroute decomposition (counts):

| threshold | attack->safe | safe->attack | spam->attack | spam->safe | gray->attack | gray->safe |
|---|---|---|---|---|---|---|
| 0.00 | 1334 | 7 | 519 | 9 | 3 | 192 |
| 0.05 | 1334 | 7 | 519 | 9 | 3 | 192 |
| 0.10 | 1334 | 7 | 519 | 9 | 3 | 192 |
| 0.15 | 1332 | 6 | 519 | 8 | 3 | 192 |
| 0.20 | 1326 | 4 | 519 | 8 | 3 | 191 |
| 0.25 | 1317 | 4 | 518 | 7 | 3 | 191 |
| 0.30 | 1301 | 3 | 516 | 6 | 2 | 187 |
| 0.35 | 1252 | 3 | 491 | 6 | 1 | 177 |
| 0.40 | 1186 | 3 | 451 | 4 | 1 | 173 |
| 0.45 | 1128 | 3 | 412 | 4 | 1 | 161 |
| 0.50 | 1067 | 3 | 363 | 3 | 1 | 151 |
| 0.55 | 1017 | 3 | 319 | 2 | 1 | 139 |
| 0.60 | 920 | 2 | 282 | 2 | 1 | 123 |
| 0.65 | 817 | 2 | 252 | 2 | 0 | 115 |
| 0.70 | 640 | 1 | 225 | 2 | 0 | 108 |
| 0.75 | 368 | 1 | 186 | 1 | 0 | 101 |
| 0.80 | 160 | 1 | 148 | 1 | 0 | 89 |
| 0.85 | 44 | 1 | 123 | 1 | 0 | 76 |
| 0.90 | 5 | 1 | 100 | 1 | 0 | 48 |
| 0.95 | 3 | 0 | 83 | 0 | 0 | 17 |
| 1.00 | 1 | 0 | 48 | 0 | 0 | 0 |

## Secondary arm: cheap-LLM comparator on the common subset (A8.1)

Comparator run: `deepseek-deepseek-flash-20260917T185653Z.jsonl` - common subset n=2000

| model | accuracy | attack recall | attack support | p50 ms | p95 ms | $/1k |
|---|---|---|---|---|---|---|
| jev | 0.472 | 0.292 | 1310 | 222 | 364 | 0.0425 |
| deepseek-flash | 0.421 | 0.181 | 1310 | 833 | 1093 | 0.1026 |

## Attack misses (6238 total; listed by confidence, highest first)

| email_id | source | predicted | confidence |
|---|---|---|---|
| scale-08914 | nigerian_5 | safe | 1.000 |
| scale-15138 | ceas_08 | spam | 0.990 |
| scale-11398 | ceas_08 | spam | 0.980 |
| scale-15510 | ceas_08 | spam | 0.980 |
| scale-17495 | ceas_08 | spam | 0.980 |
| scale-17626 | ceas_08 | spam | 0.980 |
| scale-12094 | ceas_08 | spam | 0.970 |
| scale-14757 | ceas_08 | spam | 0.970 |
| scale-14767 | ceas_08 | spam | 0.970 |
| scale-14864 | ceas_08 | spam | 0.970 |
| scale-15008 | ceas_08 | spam | 0.970 |
| scale-16284 | ceas_08 | spam | 0.970 |
| scale-10758 | ceas_08 | spam | 0.960 |
| scale-10798 | ceas_08 | safe | 0.960 |
| scale-11234 | ceas_08 | spam | 0.960 |
| scale-11259 | ceas_08 | spam | 0.960 |
| scale-11695 | ceas_08 | spam | 0.960 |
| scale-12089 | ceas_08 | safe | 0.960 |
| scale-13015 | ceas_08 | spam | 0.960 |
| scale-13401 | ceas_08 | spam | 0.960 |
| scale-13438 | ceas_08 | spam | 0.960 |
| scale-13716 | ceas_08 | spam | 0.960 |
| scale-14117 | ceas_08 | spam | 0.960 |
| scale-15460 | ceas_08 | spam | 0.960 |
| scale-15464 | ceas_08 | spam | 0.960 |
| scale-16064 | ceas_08 | spam | 0.960 |
| scale-16132 | ceas_08 | spam | 0.960 |
| scale-16334 | ceas_08 | spam | 0.960 |
| scale-17566 | ceas_08 | spam | 0.960 |
| scale-11100 | ceas_08 | spam | 0.950 |
| scale-11561 | ceas_08 | spam | 0.950 |
| scale-11646 | ceas_08 | spam | 0.950 |
| scale-11999 | ceas_08 | spam | 0.950 |
| scale-12014 | ceas_08 | spam | 0.950 |
| scale-12492 | ceas_08 | spam | 0.950 |
| scale-12552 | ceas_08 | spam | 0.950 |
| scale-12648 | ceas_08 | spam | 0.950 |
| scale-12793 | ceas_08 | spam | 0.950 |
| scale-13100 | ceas_08 | spam | 0.950 |
| scale-13562 | ceas_08 | spam | 0.950 |
| scale-13676 | ceas_08 | spam | 0.950 |
| scale-14285 | ceas_08 | spam | 0.950 |
| scale-14751 | ceas_08 | spam | 0.950 |
| scale-14923 | ceas_08 | spam | 0.950 |
| scale-15143 | ceas_08 | spam | 0.950 |
| scale-15665 | ceas_08 | spam | 0.950 |
| scale-15736 | ceas_08 | spam | 0.950 |
| scale-15811 | ceas_08 | spam | 0.950 |
| scale-15851 | ceas_08 | spam | 0.950 |
| scale-15935 | ceas_08 | spam | 0.950 |
| scale-16571 | ceas_08 | spam | 0.950 |
| scale-16708 | ceas_08 | spam | 0.950 |
| scale-16726 | ceas_08 | spam | 0.950 |
| scale-17472 | ceas_08 | spam | 0.950 |
| scale-17590 | ceas_08 | spam | 0.950 |
| scale-17675 | ceas_08 | spam | 0.950 |
| scale-10877 | ceas_08 | spam | 0.940 |
| scale-11583 | ceas_08 | spam | 0.940 |
| scale-12372 | ceas_08 | spam | 0.940 |
| scale-12760 | ceas_08 | spam | 0.940 |
| scale-12878 | ceas_08 | spam | 0.940 |
| scale-12956 | ceas_08 | spam | 0.940 |
| scale-12987 | ceas_08 | spam | 0.940 |
| scale-13143 | ceas_08 | spam | 0.940 |
| scale-13366 | ceas_08 | spam | 0.940 |
| scale-13592 | ceas_08 | spam | 0.940 |
| scale-13921 | ceas_08 | spam | 0.940 |
| scale-14038 | ceas_08 | spam | 0.940 |
| scale-14135 | ceas_08 | spam | 0.940 |
| scale-14251 | ceas_08 | spam | 0.940 |
| scale-14519 | ceas_08 | spam | 0.940 |
| scale-14537 | ceas_08 | spam | 0.940 |
| scale-14599 | ceas_08 | spam | 0.940 |
| scale-14684 | ceas_08 | spam | 0.940 |
| scale-14691 | ceas_08 | spam | 0.940 |
| scale-15065 | ceas_08 | spam | 0.940 |
| scale-15070 | ceas_08 | spam | 0.940 |
| scale-15179 | ceas_08 | spam | 0.940 |
| scale-15375 | ceas_08 | spam | 0.940 |
| scale-15584 | ceas_08 | spam | 0.940 |
| scale-15586 | ceas_08 | spam | 0.940 |
| scale-15830 | ceas_08 | spam | 0.940 |
| scale-15990 | ceas_08 | spam | 0.940 |
| scale-16055 | ceas_08 | spam | 0.940 |
| scale-16137 | ceas_08 | spam | 0.940 |
| scale-16437 | ceas_08 | spam | 0.940 |
| scale-16477 | ceas_08 | spam | 0.940 |
| scale-16483 | ceas_08 | spam | 0.940 |
| scale-16556 | ceas_08 | spam | 0.940 |
| scale-16737 | ceas_08 | spam | 0.940 |
| scale-16749 | ceas_08 | spam | 0.940 |
| scale-16751 | ceas_08 | spam | 0.940 |
| scale-16833 | ceas_08 | spam | 0.940 |
| scale-17074 | ceas_08 | spam | 0.940 |
| scale-17279 | ceas_08 | spam | 0.940 |
| scale-17596 | ceas_08 | spam | 0.940 |
| scale-17636 | ceas_08 | spam | 0.940 |
| scale-07734 | nigerian_5 | spam | 0.930 |
| scale-08042 | nigerian_5 | spam | 0.930 |
| scale-10677 | ceas_08 | spam | 0.930 |

## Sensitivity: hard_ham relabeled as safe (pre-registered)

| accuracy | gray recall | safe recall |
|---|---|---|
| 0.609 | n/a | 0.909 |

## Auxiliary signals (mean noul value by true label)

| label | n | deception_present | credentials_or_payment |
|---|---|---|---|
| safe | 3857 | 0.069 | 0.018 |
| gray | 245 | 0.204 | 0.109 |
| spam | 2212 | 0.670 | 0.343 |
| attack | 12000 | 0.684 | 0.275 |

## Deviations and errata

- A9 stopping rule invoked once: TypeSafe returned 'model_unavailable' (HTTP 503) for all calls from email ~1,246 onward (2026-09-17). The battery was stopped, a recovery watchdog was started, and it resumed the run via --resume once the service recovered; all 10 errored observations were retried to clean rows (raw error rows remain in the ledger as record).
- A8.1 comparator arm: DeepSeek returned HTTP 402 (insufficient balance) for a block of subset rows mid-run (2026-09-17). The arm was completed via --resume after a balance top-up; all 1,388 errored rows were retried to clean observations (raw error rows remain in the ledger as record).

## Provenance

- records `deepseek-deepseek-flash-20260917T185653Z.jsonl` sha256 `28f59600b11bbf106a07cea006c7d95dec79aa0c8647c4fc6c700e79c1859c1a` | gz `deepseek-deepseek-flash-20260917T185653Z.jsonl.gz` sha256 `717a71a5ce0a9ae8bdc2e3fec192b81d53ba25a223189b944576a0f4ab6fab3f`
- records `jev-scale-20260917T184615Z.jsonl` sha256 `397880fab6da06141808b9a4bc6c12d0914c0b92737a89f211e1e0d13cfadb16` | gz `jev-scale-20260917T184615Z.jsonl.gz` sha256 `970e771531478948c23f9e059428327a47d70d6b52de8880cd48f310826faee1`
- corpus: `corpus/email/scale/scale-corpus.jsonl` sha256 `ede15ebe5eef62e465fd0184e792c520a3c7b75c279c87ccc9b746f44234343a`
- scale manifest input hashes: `{"scale-normalized.jsonl": "ede15ebe5eef62e465fd0184e792c520a3c7b75c279c87ccc9b746f44234343a"}`
- recompute: `python tools/jev_triage/score_scale.py`
