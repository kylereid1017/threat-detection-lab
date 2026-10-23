# Cascade cost model — measured (Jev in front of Claude tiers via Nous Portal)

Generated: 2026-09-17T15:44:19.092135+00:00 · recomputed from raw records; Portal-routed runs, 2026-09-17.

Basis: 196 scored emails (200 minus 4 audit exclusions, uniform across runs). Claude calls went through a local proxy to Nous Portal; token counts and `usage.cost` are the provider's own billing figures, and spot checks matched Anthropic list prices exactly (e.g. opus probe: 29 prompt tok x $5/M = $0.000145 billed).

## Pure-model economics (measured)

| tier | n | accuracy | attack recall | p50 ms | $/email | $/1k |
|---|---|---|---|---|---|---|
| claude-haiku-4.5 | 196 | 72.4% | 94% | 1074 | $0.000782 | $0.7818 |
| claude-sonnet-5 | 196 | 70.4% | 98% | 2533 | $0.002063 | $2.0630 |
| claude-opus-5 | 196 | 74.5% | 98% | 3176 | $0.005823 | $5.8234 |
| claude-fable-5.1 | 59 | 74.6% | 100% | 5029 | $0.009096 | $9.0964 |

DeepSeek V4.1 Flash (measured, direct API): $0.000141/email, $0.1406/1k, 69.4% accuracy — for the full comparison see RESULTS.md.

## Cascade: Jev → tier (measured LLM answers)

Operational threshold = the highest auto-decide cutoff with zero attack→safe misroutes; Jev cost for all traffic included in every row.

| tier | threshold | auto % | auto err % | missed attacks | final acc | cascade $/1k | pure $/1k | savings | projected savings @0.30 |
|---|---|---|---|---|---|---|---|---|
| claude-haiku-4.5 | 0.30 | 64.8% | 33.07% | 0 | 65.3% | $0.2914 | $0.7818 | 63% | 59% |
| claude-sonnet-5 | 0.30 | 64.8% | 33.07% | 0 | 66.8% | $0.6981 | $2.0630 | 66% | 62% |
| claude-opus-5 | 0.30 | 64.8% | 33.07% | 0 | 70.4% | $2.0494 | $5.8234 | 65% | 64% |
| claude-fable-5.1 | — | cascade not available (subset run) | | | | | | |

## Portal spend this session (tracked)

| run | observations | $ (billed where returned, else list-rate) |
|---|---|---|
| portal-anthropic_claude-fable-5_1-20260917T153601Z.jsonl | 60 | $0.5452 |
| portal-anthropic_claude-haiku-4_5-20260917T145522Z.jsonl | 200 | $0.1555 |
| portal-anthropic_claude-opus-5-20260917T151012Z.jsonl | 200 | $1.1555 |
| portal-anthropic_claude-sonnet-5-20260917T145915Z.jsonl | 200 | $0.4100 |
| retired/ (superseded fable pass) | 80 | $0.6956 |
| **total tracked** | **740** | **$2.9619** |

Balance check: the portal shows $3.36; if the portal UI total agrees with the table above (± a few cents for earlier probes), the accounting is confirmed end to end.

## Latency shape

Auto-decided traffic returns in Jev's ~0.22s p50; escalated traffic pays Jev + tier latency. Blend depends on the auto-decide share above.
