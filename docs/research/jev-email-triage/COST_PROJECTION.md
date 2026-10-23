# Cascade cost projection — Jev in front of Claude tiers

Basis: 196 emails, measured mean 598 input / 14 output tokens (DeepSeek tokenizer, used as the token-count basis for every tier).
Jev cost for all traffic: $0.0414/1k emails (measured).

**Projection method:** Claude cost = measured tokens x vendor list prices (clients.py PRICING, accessed 2026-09-17). No live Claude runs exist in this experiment (API credits unavailable), so Claude accuracy/latency on this corpus is NOT measured. Token-count basis: DeepSeek tokenizer as a proxy; Claude's tokenizer will differ by roughly 10-20% on English text.

| tier | pure $/1k | cascade $/1k @0.30 | savings | cascade $/1k @0.50 | savings | cascade $/1k @0.75 | savings |
|---|---|---|---|---|---|---|---|
| claude-haiku-4-5 | $0.6696 | $0.2771 | 59% | $0.3352 | 50% | $0.4343 | 35% |
| claude-sonnet-5 | $1.3392 | $0.5129 | 62% | $0.6290 | 53% | $0.8272 | 38% |
| claude-opus-5 | $3.3479 | $1.2200 | 64% | $1.5104 | 55% | $2.0058 | 40% |
| claude-fable-5-1 | $6.6958 | $2.3986 | 64% | $2.9794 | 56% | $3.9701 | 41% |

Measured comparison (same corpus, real runs): Jev alone $0.0414/1k at 224ms p50; DeepSeek alone $0.0983/1k at 894ms p50; Jev->DeepSeek cascade at t=0.30 $0.0727/1k with 64.8% auto-decided.

Latency shape (measured for Jev; projected for Claude): auto-decided traffic returns in ~0.22s; escalated traffic pays Jev + Claude. Blend at t=0.30 is ~0.22s for about two thirds of traffic.
