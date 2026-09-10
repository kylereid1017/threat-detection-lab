# Archived run artifacts (contaminated measurements)

These files are the raw artifacts behind the aggregate figures that were **withdrawn on
2026-09-10**: the endurance state, checkpoints, boundary histories, layer exports, noise-floor
and telemetry-replay outputs, and the raw run log of the pre-record-layer pipeline.

Their aggregates mixed benign noise-floor events into the attack denominator, restored resume
state from rounded figures, and divided by unfiltered probe counts. The affected publications
are STRAT-001/002/003; the full analysis is in
[`docs/cables/ERRATA-2026-09-10.md`](../../../cables/ERRATA-2026-09-10.md).

They are retained here so the withdrawal is auditable. **Do not cite figures from these
files.** The superseding run is `endur-20260910T220224Z-be1a82`: its observation ledger is
`../records/run-endur-20260910T220224Z-be1a82.jsonl`, and its published synthesis is
`docs/cables/CABLE-2026-STRAT-004-empirical-swarm-synthesis.md`.

(The raw run log `endurance_run.log` is retained on the local working copy only — it is not
versioned.)
