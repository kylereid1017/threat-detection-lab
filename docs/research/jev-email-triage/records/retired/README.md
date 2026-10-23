# Retired run files

`portal-anthropic_claude-fable-5_1-20260917T152200Z.jsonl` — RETIRED 2026-09-17.

Reason: the initial fable pass ran at `max_tokens=64` (3/60 rows errored on
truncated output), and the retry resume was invoked without `--sample`, which
made the runner target the full 200-email corpus; the process was killed after
appending 23 out-of-sample rows. The frozen-60 sample definition was polluted,
so the file was retired and replaced by a clean full-sample run at
`max_tokens=512` (`portal-anthropic_claude-fable-5_1-20260917T*Z.jsonl` in the
parent directory). Nothing was deleted — the retired file is preserved here
verbatim, and its paid rows ($0.2139) count toward the session's Portal spend.

Only files under `records/*.jsonl` feed the scorer; `retired/` is excluded.
