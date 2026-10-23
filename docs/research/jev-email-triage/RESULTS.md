# Jev Email Triage — Results

Generated: 2026-09-17T15:43:32.991697+00:00 · recomputed from raw records only.

## Reconciliation

| run | observations | errors | clean ids | expected | ok |
|---|---|---|---|---|---|
| deepseek-deepseek-flash-20260917T143754Z.jsonl | 200 | 0 | 200 | 200 | PASS |
| jev-20260917T143754Z.jsonl | 200 | 0 | 200 | 200 | PASS |
| portal-anthropic_claude-fable-5_1-20260917T153601Z.jsonl | 61 | 1 | 60 | 60 | PASS |
| portal-anthropic_claude-haiku-4_5-20260917T145522Z.jsonl | 200 | 0 | 200 | 200 | PASS |
| portal-anthropic_claude-opus-5-20260917T151012Z.jsonl | 233 | 33 | 200 | 200 | PASS |
| portal-anthropic_claude-sonnet-5-20260917T145915Z.jsonl | 206 | 6 | 200 | 200 | PASS |

## Model summaries

| run | model | n scored | errors | accuracy | p50 ms | p95 ms | $/email | $/1k |
|---|---|---|---|---|---|---|---|---|
| deepseek-deepseek-flash-20260917T143754Z.jsonl | deepseek-flash | 196 | 0 | 0.740 | 894 | 1113 | 0.000098 | 0.0983 |
| jev-20260917T143754Z.jsonl | jev-latest | 196 | 0 | 0.653 | 224 | 369 | 0.000041 | 0.0414 |
| portal-anthropic_claude-fable-5_1-20260917T153601Z.jsonl | anthropic/claude-fable-5.1 | 59 | 1 | 0.746 | 5029 | 7902 | 0.009096 | 9.0964 |
| portal-anthropic_claude-haiku-4_5-20260917T145522Z.jsonl | anthropic/claude-haiku-4.5 | 196 | 0 | 0.724 | 1074 | 2061 | 0.000782 | 0.7818 |
| portal-anthropic_claude-opus-5-20260917T151012Z.jsonl | anthropic/claude-opus-5 | 196 | 33 | 0.745 | 3176 | 8474 | 0.005823 | 5.8234 |
| portal-anthropic_claude-sonnet-5-20260917T145915Z.jsonl | anthropic/claude-sonnet-5 | 196 | 6 | 0.704 | 2533 | 5850 | 0.002063 | 2.0630 |

### Confusion — deepseek-flash (deepseek-deepseek-flash-20260917T143754Z.jsonl)

| true \ pred | safe | gray | spam | attack |
|---|---|---|---|---|
| safe | 41 | 2 | 7 | 0 |
| gray | 20 | 14 | 11 | 5 |
| spam | 2 | 0 | 41 | 3 |
| attack | 0 | 1 | 0 | 49 |

| class | support | tp | precision | recall |
|---|---|---|---|---|
| safe | 50 | 41 | 0.651 | 0.820 |
| gray | 50 | 14 | 0.824 | 0.280 |
| spam | 46 | 41 | 0.695 | 0.891 |
| attack | 50 | 49 | 0.860 | 0.980 |

### Confusion — jev-latest (jev-20260917T143754Z.jsonl)

| true \ pred | safe | gray | spam | attack |
|---|---|---|---|---|
| safe | 44 | 6 | 0 | 0 |
| gray | 29 | 12 | 5 | 4 |
| spam | 1 | 3 | 29 | 13 |
| attack | 2 | 5 | 0 | 43 |

| class | support | tp | precision | recall |
|---|---|---|---|---|
| safe | 50 | 44 | 0.579 | 0.880 |
| gray | 50 | 12 | 0.462 | 0.240 |
| spam | 46 | 29 | 0.853 | 0.630 |
| attack | 50 | 43 | 0.717 | 0.860 |

### Confusion — anthropic/claude-fable-5.1 (portal-anthropic_claude-fable-5_1-20260917T153601Z.jsonl)

| true \ pred | safe | gray | spam | attack |
|---|---|---|---|---|
| safe | 15 | 0 | 0 | 0 |
| gray | 9 | 3 | 2 | 1 |
| spam | 0 | 0 | 11 | 3 |
| attack | 0 | 0 | 0 | 15 |

| class | support | tp | precision | recall |
|---|---|---|---|---|
| safe | 15 | 15 | 0.625 | 1.000 |
| gray | 15 | 3 | 1.000 | 0.200 |
| spam | 14 | 11 | 0.846 | 0.786 |
| attack | 15 | 15 | 0.789 | 1.000 |

### Confusion — anthropic/claude-haiku-4.5 (portal-anthropic_claude-haiku-4_5-20260917T145522Z.jsonl)

| true \ pred | safe | gray | spam | attack |
|---|---|---|---|---|
| safe | 43 | 3 | 4 | 0 |
| gray | 20 | 19 | 3 | 8 |
| spam | 3 | 6 | 33 | 4 |
| attack | 0 | 3 | 0 | 47 |

| class | support | tp | precision | recall |
|---|---|---|---|---|
| safe | 50 | 43 | 0.652 | 0.860 |
| gray | 50 | 19 | 0.613 | 0.380 |
| spam | 46 | 33 | 0.825 | 0.717 |
| attack | 50 | 47 | 0.797 | 0.940 |

### Confusion — anthropic/claude-opus-5 (portal-anthropic_claude-opus-5-20260917T151012Z.jsonl)

| true \ pred | safe | gray | spam | attack |
|---|---|---|---|---|
| safe | 49 | 1 | 0 | 0 |
| gray | 27 | 15 | 3 | 5 |
| spam | 3 | 3 | 33 | 7 |
| attack | 0 | 1 | 0 | 49 |

| class | support | tp | precision | recall |
|---|---|---|---|---|
| safe | 50 | 49 | 0.620 | 0.980 |
| gray | 50 | 15 | 0.750 | 0.300 |
| spam | 46 | 33 | 0.917 | 0.717 |
| attack | 50 | 49 | 0.803 | 0.980 |

### Confusion — anthropic/claude-sonnet-5 (portal-anthropic_claude-sonnet-5-20260917T145915Z.jsonl)

| true \ pred | safe | gray | spam | attack |
|---|---|---|---|---|
| safe | 37 | 4 | 8 | 1 |
| gray | 10 | 14 | 20 | 6 |
| spam | 3 | 0 | 38 | 5 |
| attack | 0 | 1 | 0 | 49 |

| class | support | tp | precision | recall |
|---|---|---|---|---|
| safe | 50 | 37 | 0.740 | 0.740 |
| gray | 50 | 14 | 0.737 | 0.280 |
| spam | 46 | 38 | 0.576 | 0.826 |
| attack | 50 | 49 | 0.803 | 0.980 |

## Sensitivity: hard_ham relabeled as safe (pre-registered)

| run | accuracy | gray recall | safe recall |
|---|---|---|---|
| deepseek-deepseek-flash-20260917T143754Z.jsonl | 0.827 | 0.560 | 0.773 |
| jev-20260917T143754Z.jsonl | 0.750 | 0.440 | 0.853 |
| portal-anthropic_claude-fable-5_1-20260917T153601Z.jsonl | 0.881 | 0.500 | 0.958 |
| portal-anthropic_claude-haiku-4_5-20260917T145522Z.jsonl | 0.796 | 0.640 | 0.800 |
| portal-anthropic_claude-opus-5-20260917T151012Z.jsonl | 0.847 | 0.520 | 0.947 |
| portal-anthropic_claude-sonnet-5-20260917T145915Z.jsonl | 0.750 | 0.560 | 0.613 |

## Per-source accuracy

| run | source | n | accuracy |
|---|---|---|---|
| deepseek-deepseek-flash-20260917T143754Z.jsonl | hand_authored | 10 | 0.900 |
| deepseek-deepseek-flash-20260917T143754Z.jsonl | spamassassin_easy_ham | 25 | 0.720 |
| deepseek-deepseek-flash-20260917T143754Z.jsonl | spamassassin_hard_ham | 25 | 0.000 |
| deepseek-deepseek-flash-20260917T143754Z.jsonl | spamassassin_spam | 22 | 0.864 |
| deepseek-deepseek-flash-20260917T143754Z.jsonl | synthetic | 114 | 0.868 |
| jev-20260917T143754Z.jsonl | hand_authored | 10 | 0.700 |
| jev-20260917T143754Z.jsonl | spamassassin_easy_ham | 25 | 0.760 |
| jev-20260917T143754Z.jsonl | spamassassin_hard_ham | 25 | 0.040 |
| jev-20260917T143754Z.jsonl | spamassassin_spam | 22 | 0.773 |
| jev-20260917T143754Z.jsonl | synthetic | 114 | 0.737 |
| portal-anthropic_claude-fable-5_1-20260917T153601Z.jsonl | hand_authored | 3 | 1.000 |
| portal-anthropic_claude-fable-5_1-20260917T153601Z.jsonl | spamassassin_easy_ham | 7 | 1.000 |
| portal-anthropic_claude-fable-5_1-20260917T153601Z.jsonl | spamassassin_hard_ham | 9 | 0.000 |
| portal-anthropic_claude-fable-5_1-20260917T153601Z.jsonl | spamassassin_spam | 6 | 0.667 |
| portal-anthropic_claude-fable-5_1-20260917T153601Z.jsonl | synthetic | 34 | 0.882 |
| portal-anthropic_claude-haiku-4_5-20260917T145522Z.jsonl | hand_authored | 10 | 0.800 |
| portal-anthropic_claude-haiku-4_5-20260917T145522Z.jsonl | spamassassin_easy_ham | 25 | 0.840 |
| portal-anthropic_claude-haiku-4_5-20260917T145522Z.jsonl | spamassassin_hard_ham | 25 | 0.120 |
| portal-anthropic_claude-haiku-4_5-20260917T145522Z.jsonl | spamassassin_spam | 22 | 0.864 |
| portal-anthropic_claude-haiku-4_5-20260917T145522Z.jsonl | synthetic | 114 | 0.798 |
| portal-anthropic_claude-opus-5-20260917T151012Z.jsonl | hand_authored | 10 | 0.900 |
| portal-anthropic_claude-opus-5-20260917T151012Z.jsonl | spamassassin_easy_ham | 25 | 1.000 |
| portal-anthropic_claude-opus-5-20260917T151012Z.jsonl | spamassassin_hard_ham | 25 | 0.080 |
| portal-anthropic_claude-opus-5-20260917T151012Z.jsonl | spamassassin_spam | 22 | 0.864 |
| portal-anthropic_claude-opus-5-20260917T151012Z.jsonl | synthetic | 114 | 0.798 |
| portal-anthropic_claude-sonnet-5-20260917T145915Z.jsonl | hand_authored | 10 | 0.900 |
| portal-anthropic_claude-sonnet-5-20260917T145915Z.jsonl | spamassassin_easy_ham | 25 | 0.720 |
| portal-anthropic_claude-sonnet-5-20260917T145915Z.jsonl | spamassassin_hard_ham | 25 | 0.000 |
| portal-anthropic_claude-sonnet-5-20260917T145915Z.jsonl | spamassassin_spam | 22 | 0.864 |
| portal-anthropic_claude-sonnet-5-20260917T145915Z.jsonl | synthetic | 114 | 0.807 |

## Jev calibration (confidence decile vs accuracy)

| bucket | n | accuracy |
|---|---|---|
| 0.0-0.1 | 0 | n/a |
| 0.1-0.2 | 1 | 0.000 |
| 0.2-0.3 | 22 | 0.318 |
| 0.3-0.4 | 15 | 0.333 |
| 0.4-0.5 | 15 | 0.400 |
| 0.5-0.6 | 24 | 0.625 |
| 0.6-0.7 | 18 | 0.667 |
| 0.7-0.8 | 8 | 0.875 |
| 0.8-0.9 | 37 | 0.838 |
| 0.9-1.0 | 56 | 0.804 |

## Cascade sweep — Jev -> deepseek-flash

| threshold | auto % | auto err % | missed attacks | final acc | cascade $/1k | pure LLM $/1k |
|---|---|---|---|---|---|---|
| 0.00 | 69.4 | 36.03 | 2 | 0.663 | 0.0635 | 0.0983 |
| 0.05 | 69.4 | 36.03 | 2 | 0.663 | 0.0635 | 0.0983 |
| 0.10 | 69.4 | 36.03 | 2 | 0.663 | 0.0635 | 0.0983 |
| 0.15 | 69.4 | 36.03 | 2 | 0.663 | 0.0635 | 0.0983 |
| 0.20 | 69.4 | 36.03 | 2 | 0.663 | 0.0635 | 0.0983 |
| 0.25 | 67.9 | 35.34 | 2 | 0.663 | 0.0670 | 0.0983 |
| 0.30 | 64.8 | 33.07 | 0 | 0.679 | 0.0727 | 0.0983 |
| 0.35 | 63.3 | 32.26 | 0 | 0.684 | 0.0736 | 0.0983 |
| 0.40 | 60.2 | 31.36 | 0 | 0.689 | 0.0755 | 0.0983 |
| 0.45 | 58.2 | 29.82 | 0 | 0.694 | 0.0781 | 0.0983 |
| 0.50 | 56.1 | 28.18 | 0 | 0.699 | 0.0800 | 0.0983 |
| 0.55 | 50.0 | 24.49 | 0 | 0.704 | 0.0868 | 0.0983 |
| 0.60 | 48.5 | 23.16 | 0 | 0.704 | 0.0890 | 0.0983 |
| 0.65 | 44.9 | 20.45 | 0 | 0.719 | 0.0935 | 0.0983 |
| 0.70 | 42.9 | 21.43 | 0 | 0.719 | 0.0948 | 0.0983 |
| 0.75 | 41.3 | 20.99 | 0 | 0.719 | 0.0983 | 0.0983 |
| 0.80 | 39.8 | 21.79 | 0 | 0.719 | 0.0993 | 0.0983 |
| 0.85 | 34.2 | 20.90 | 0 | 0.719 | 0.1048 | 0.0983 |
| 0.90 | 27.6 | 20.37 | 0 | 0.724 | 0.1129 | 0.0983 |
| 0.95 | 17.9 | 11.43 | 0 | 0.740 | 0.1243 | 0.0983 |
| 1.00 | 7.7 | 13.33 | 0 | 0.740 | 0.1339 | 0.0983 |

Auto-decided misroute decomposition (counts):

| threshold | attack→safe | safe→attack | spam→attack | spam→safe | gray→attack | gray→safe |
|---|---|---|---|---|---|---|
| 0.00 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.05 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.10 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.15 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.20 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.25 | 2 | 0 | 13 | 1 | 3 | 28 |
| 0.30 | 0 | 0 | 12 | 1 | 2 | 27 |
| 0.35 | 0 | 0 | 12 | 1 | 2 | 25 |
| 0.40 | 0 | 0 | 10 | 1 | 2 | 24 |
| 0.45 | 0 | 0 | 9 | 1 | 2 | 22 |
| 0.50 | 0 | 0 | 9 | 1 | 2 | 19 |
| 0.55 | 0 | 0 | 8 | 1 | 1 | 14 |
| 0.60 | 0 | 0 | 8 | 1 | 1 | 12 |
| 0.65 | 0 | 0 | 7 | 0 | 1 | 10 |
| 0.70 | 0 | 0 | 7 | 0 | 1 | 10 |
| 0.75 | 0 | 0 | 7 | 0 | 1 | 9 |
| 0.80 | 0 | 0 | 7 | 0 | 1 | 9 |
| 0.85 | 0 | 0 | 7 | 0 | 1 | 6 |
| 0.90 | 0 | 0 | 6 | 0 | 1 | 4 |
| 0.95 | 0 | 0 | 3 | 0 | 0 | 1 |
| 1.00 | 0 | 0 | 2 | 0 | 0 | 0 |

**Registered constraint (auto-decided exact-label error ≤ 2%): NOT MET at any threshold** — the exact-label metric counts every misroute equally, including benign ones. Operational decomposition follows.

**Operational view (post-hoc decomposition, not the registered metric):** threshold 0.30 → 64.8% auto-decided with zero attack→safe deliveries and zero safe→attack quarantines; remaining auto misroutes are spam→attack 12, spam→safe 1, gray→attack 2, gray→safe 27.

## Cascade sweep — Jev -> anthropic/claude-haiku-4.5

| threshold | auto % | auto err % | missed attacks | final acc | cascade $/1k | pure LLM $/1k |
|---|---|---|---|---|---|---|
| 0.00 | 69.4 | 36.03 | 2 | 0.648 | 0.2186 | 0.7818 |
| 0.05 | 69.4 | 36.03 | 2 | 0.648 | 0.2186 | 0.7818 |
| 0.10 | 69.4 | 36.03 | 2 | 0.648 | 0.2186 | 0.7818 |
| 0.15 | 69.4 | 36.03 | 2 | 0.648 | 0.2186 | 0.7818 |
| 0.20 | 69.4 | 36.03 | 2 | 0.648 | 0.2186 | 0.7818 |
| 0.25 | 67.9 | 35.34 | 2 | 0.648 | 0.2454 | 0.7818 |
| 0.30 | 64.8 | 33.07 | 0 | 0.653 | 0.2914 | 0.7818 |
| 0.35 | 63.3 | 32.26 | 0 | 0.663 | 0.2983 | 0.7818 |
| 0.40 | 60.2 | 31.36 | 0 | 0.679 | 0.3141 | 0.7818 |
| 0.45 | 58.2 | 29.82 | 0 | 0.689 | 0.3355 | 0.7818 |
| 0.50 | 56.1 | 28.18 | 0 | 0.694 | 0.3514 | 0.7818 |
| 0.55 | 50.0 | 24.49 | 0 | 0.704 | 0.4078 | 0.7818 |
| 0.60 | 48.5 | 23.16 | 0 | 0.704 | 0.4249 | 0.7818 |
| 0.65 | 44.9 | 20.45 | 0 | 0.709 | 0.4599 | 0.7818 |
| 0.70 | 42.9 | 21.43 | 0 | 0.709 | 0.4701 | 0.7818 |
| 0.75 | 41.3 | 20.99 | 0 | 0.709 | 0.4962 | 0.7818 |
| 0.80 | 39.8 | 21.79 | 0 | 0.704 | 0.5041 | 0.7818 |
| 0.85 | 34.2 | 20.90 | 0 | 0.704 | 0.5470 | 0.7818 |
| 0.90 | 27.6 | 20.37 | 0 | 0.714 | 0.6090 | 0.7818 |
| 0.95 | 17.9 | 11.43 | 0 | 0.724 | 0.7028 | 0.7818 |
| 1.00 | 7.7 | 13.33 | 0 | 0.724 | 0.7780 | 0.7818 |

Auto-decided misroute decomposition (counts):

| threshold | attack→safe | safe→attack | spam→attack | spam→safe | gray→attack | gray→safe |
|---|---|---|---|---|---|---|
| 0.00 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.05 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.10 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.15 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.20 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.25 | 2 | 0 | 13 | 1 | 3 | 28 |
| 0.30 | 0 | 0 | 12 | 1 | 2 | 27 |
| 0.35 | 0 | 0 | 12 | 1 | 2 | 25 |
| 0.40 | 0 | 0 | 10 | 1 | 2 | 24 |
| 0.45 | 0 | 0 | 9 | 1 | 2 | 22 |
| 0.50 | 0 | 0 | 9 | 1 | 2 | 19 |
| 0.55 | 0 | 0 | 8 | 1 | 1 | 14 |
| 0.60 | 0 | 0 | 8 | 1 | 1 | 12 |
| 0.65 | 0 | 0 | 7 | 0 | 1 | 10 |
| 0.70 | 0 | 0 | 7 | 0 | 1 | 10 |
| 0.75 | 0 | 0 | 7 | 0 | 1 | 9 |
| 0.80 | 0 | 0 | 7 | 0 | 1 | 9 |
| 0.85 | 0 | 0 | 7 | 0 | 1 | 6 |
| 0.90 | 0 | 0 | 6 | 0 | 1 | 4 |
| 0.95 | 0 | 0 | 3 | 0 | 0 | 1 |
| 1.00 | 0 | 0 | 2 | 0 | 0 | 0 |

**Registered constraint (auto-decided exact-label error ≤ 2%): NOT MET at any threshold** — the exact-label metric counts every misroute equally, including benign ones. Operational decomposition follows.

**Operational view (post-hoc decomposition, not the registered metric):** threshold 0.30 → 64.8% auto-decided with zero attack→safe deliveries and zero safe→attack quarantines; remaining auto misroutes are spam→attack 12, spam→safe 1, gray→attack 2, gray→safe 27.

## Cascade sweep — Jev -> anthropic/claude-opus-5

| threshold | auto % | auto err % | missed attacks | final acc | cascade $/1k | pure LLM $/1k |
|---|---|---|---|---|---|---|
| 0.00 | 69.4 | 36.03 | 2 | 0.689 | 1.4449 | 5.8234 |
| 0.05 | 69.4 | 36.03 | 2 | 0.689 | 1.4449 | 5.8234 |
| 0.10 | 69.4 | 36.03 | 2 | 0.689 | 1.4449 | 5.8234 |
| 0.15 | 69.4 | 36.03 | 2 | 0.689 | 1.4449 | 5.8234 |
| 0.20 | 69.4 | 36.03 | 2 | 0.689 | 1.4449 | 5.8234 |
| 0.25 | 67.9 | 35.34 | 2 | 0.689 | 1.6384 | 5.8234 |
| 0.30 | 64.8 | 33.07 | 0 | 0.704 | 2.0494 | 5.8234 |
| 0.35 | 63.3 | 32.26 | 0 | 0.709 | 2.1088 | 5.8234 |
| 0.40 | 60.2 | 31.36 | 0 | 0.714 | 2.2631 | 5.8234 |
| 0.45 | 58.2 | 29.82 | 0 | 0.719 | 2.4328 | 5.8234 |
| 0.50 | 56.1 | 28.18 | 0 | 0.724 | 2.5519 | 5.8234 |
| 0.55 | 50.0 | 24.49 | 0 | 0.735 | 2.9344 | 5.8234 |
| 0.60 | 48.5 | 23.16 | 0 | 0.735 | 3.0636 | 5.8234 |
| 0.65 | 44.9 | 20.45 | 0 | 0.740 | 3.3457 | 5.8234 |
| 0.70 | 42.9 | 21.43 | 0 | 0.740 | 3.4147 | 5.8234 |
| 0.75 | 41.3 | 20.99 | 0 | 0.740 | 3.5884 | 5.8234 |
| 0.80 | 39.8 | 21.79 | 0 | 0.740 | 3.6391 | 5.8234 |
| 0.85 | 34.2 | 20.90 | 0 | 0.740 | 3.9269 | 5.8234 |
| 0.90 | 27.6 | 20.37 | 0 | 0.740 | 4.3662 | 5.8234 |
| 0.95 | 17.9 | 11.43 | 0 | 0.745 | 5.0644 | 5.8234 |
| 1.00 | 7.7 | 13.33 | 0 | 0.745 | 5.5699 | 5.8234 |

Auto-decided misroute decomposition (counts):

| threshold | attack→safe | safe→attack | spam→attack | spam→safe | gray→attack | gray→safe |
|---|---|---|---|---|---|---|
| 0.00 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.05 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.10 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.15 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.20 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.25 | 2 | 0 | 13 | 1 | 3 | 28 |
| 0.30 | 0 | 0 | 12 | 1 | 2 | 27 |
| 0.35 | 0 | 0 | 12 | 1 | 2 | 25 |
| 0.40 | 0 | 0 | 10 | 1 | 2 | 24 |
| 0.45 | 0 | 0 | 9 | 1 | 2 | 22 |
| 0.50 | 0 | 0 | 9 | 1 | 2 | 19 |
| 0.55 | 0 | 0 | 8 | 1 | 1 | 14 |
| 0.60 | 0 | 0 | 8 | 1 | 1 | 12 |
| 0.65 | 0 | 0 | 7 | 0 | 1 | 10 |
| 0.70 | 0 | 0 | 7 | 0 | 1 | 10 |
| 0.75 | 0 | 0 | 7 | 0 | 1 | 9 |
| 0.80 | 0 | 0 | 7 | 0 | 1 | 9 |
| 0.85 | 0 | 0 | 7 | 0 | 1 | 6 |
| 0.90 | 0 | 0 | 6 | 0 | 1 | 4 |
| 0.95 | 0 | 0 | 3 | 0 | 0 | 1 |
| 1.00 | 0 | 0 | 2 | 0 | 0 | 0 |

**Registered constraint (auto-decided exact-label error ≤ 2%): NOT MET at any threshold** — the exact-label metric counts every misroute equally, including benign ones. Operational decomposition follows.

**Operational view (post-hoc decomposition, not the registered metric):** threshold 0.30 → 64.8% auto-decided with zero attack→safe deliveries and zero safe→attack quarantines; remaining auto misroutes are spam→attack 12, spam→safe 1, gray→attack 2, gray→safe 27.

## Cascade sweep — Jev -> anthropic/claude-sonnet-5

| threshold | auto % | auto err % | missed attacks | final acc | cascade $/1k | pure LLM $/1k |
|---|---|---|---|---|---|---|
| 0.00 | 69.4 | 36.03 | 2 | 0.663 | 0.4978 | 2.0630 |
| 0.05 | 69.4 | 36.03 | 2 | 0.663 | 0.4978 | 2.0630 |
| 0.10 | 69.4 | 36.03 | 2 | 0.663 | 0.4978 | 2.0630 |
| 0.15 | 69.4 | 36.03 | 2 | 0.663 | 0.4978 | 2.0630 |
| 0.20 | 69.4 | 36.03 | 2 | 0.663 | 0.4978 | 2.0630 |
| 0.25 | 67.9 | 35.34 | 2 | 0.658 | 0.5652 | 2.0630 |
| 0.30 | 64.8 | 33.07 | 0 | 0.668 | 0.6981 | 2.0630 |
| 0.35 | 63.3 | 32.26 | 0 | 0.673 | 0.7160 | 2.0630 |
| 0.40 | 60.2 | 31.36 | 0 | 0.679 | 0.7564 | 2.0630 |
| 0.45 | 58.2 | 29.82 | 0 | 0.684 | 0.8122 | 2.0630 |
| 0.50 | 56.1 | 28.18 | 0 | 0.689 | 0.8538 | 2.0630 |
| 0.55 | 50.0 | 24.49 | 0 | 0.694 | 0.9955 | 2.0630 |
| 0.60 | 48.5 | 23.16 | 0 | 0.694 | 1.0400 | 2.0630 |
| 0.65 | 44.9 | 20.45 | 0 | 0.704 | 1.1334 | 2.0630 |
| 0.70 | 42.9 | 21.43 | 0 | 0.704 | 1.1600 | 2.0630 |
| 0.75 | 41.3 | 20.99 | 0 | 0.704 | 1.2286 | 2.0630 |
| 0.80 | 39.8 | 21.79 | 0 | 0.704 | 1.2489 | 2.0630 |
| 0.85 | 34.2 | 20.90 | 0 | 0.699 | 1.3628 | 2.0630 |
| 0.90 | 27.6 | 20.37 | 0 | 0.709 | 1.5458 | 2.0630 |
| 0.95 | 17.9 | 11.43 | 0 | 0.709 | 1.7905 | 2.0630 |
| 1.00 | 7.7 | 13.33 | 0 | 0.704 | 1.9866 | 2.0630 |

Auto-decided misroute decomposition (counts):

| threshold | attack→safe | safe→attack | spam→attack | spam→safe | gray→attack | gray→safe |
|---|---|---|---|---|---|---|
| 0.00 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.05 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.10 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.15 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.20 | 2 | 0 | 13 | 1 | 4 | 29 |
| 0.25 | 2 | 0 | 13 | 1 | 3 | 28 |
| 0.30 | 0 | 0 | 12 | 1 | 2 | 27 |
| 0.35 | 0 | 0 | 12 | 1 | 2 | 25 |
| 0.40 | 0 | 0 | 10 | 1 | 2 | 24 |
| 0.45 | 0 | 0 | 9 | 1 | 2 | 22 |
| 0.50 | 0 | 0 | 9 | 1 | 2 | 19 |
| 0.55 | 0 | 0 | 8 | 1 | 1 | 14 |
| 0.60 | 0 | 0 | 8 | 1 | 1 | 12 |
| 0.65 | 0 | 0 | 7 | 0 | 1 | 10 |
| 0.70 | 0 | 0 | 7 | 0 | 1 | 10 |
| 0.75 | 0 | 0 | 7 | 0 | 1 | 9 |
| 0.80 | 0 | 0 | 7 | 0 | 1 | 9 |
| 0.85 | 0 | 0 | 7 | 0 | 1 | 6 |
| 0.90 | 0 | 0 | 6 | 0 | 1 | 4 |
| 0.95 | 0 | 0 | 3 | 0 | 0 | 1 |
| 1.00 | 0 | 0 | 2 | 0 | 0 | 0 |

**Registered constraint (auto-decided exact-label error ≤ 2%): NOT MET at any threshold** — the exact-label metric counts every misroute equally, including benign ones. Operational decomposition follows.

**Operational view (post-hoc decomposition, not the registered metric):** threshold 0.30 → 64.8% auto-decided with zero attack→safe deliveries and zero safe→attack quarantines; remaining auto misroutes are spam→attack 12, spam→safe 1, gray→attack 2, gray→safe 27.

## Auxiliary signals (mean noul value by true label)

| label | n | deception_present | credentials_or_payment |
|---|---|---|---|
| safe | 50 | 0.077 | 0.040 |
| gray | 50 | 0.210 | 0.108 |
| spam | 46 | 0.518 | 0.271 |
| attack | 50 | 0.669 | 0.574 |
