"""Embed the Jev scale corpus with EmbeddingGemma 2 (text-only) — Battery C.

Frozen by tools/eg2_triage/PLAN.md (C3). Reads only the text fields of each record
(From / Reply-To / Subject / body via Jev's own normalizer); labels are never read here.

Modes
  --smoke   Phase-0: embed the first 200 rows (file order) at 1024 tokens, measure
            throughput, and apply the registered truncation rule (<= 6.0 h projected
            -> 1024, else 512). Writes corpus/email/scale/eg2/smoke.json. No claims.
  (default) Full run at the max_seq_length decided by the smoke file. Resumable:
            chunks already on disk are skipped; embed-log.jsonl is append-only.
  --consolidate  Merge chunk files into embeddings-768.npy + ids.json.

Outputs are local only (corpus/email/scale/eg2/): embeddings derive from
non-redistributed public-corpus content.

Run:
  python tools/eg2_triage/embed_email.py --smoke
  python tools/eg2_triage/embed_email.py
  python tools/eg2_triage/embed_email.py --consolidate
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "jev_triage"))
from run_jev import normalized_state  # noqa: E402  (PLAN C3: Jev's normalizer verbatim)

CORPUS = REPO / "corpus" / "email" / "scale" / "scale-corpus.jsonl"
OUT = REPO / "corpus" / "email" / "scale" / "eg2"
CHUNKS = OUT / "chunks"
SMOKE_FILE = OUT / "smoke.json"
LOG = OUT / "embed-log.jsonl"

MODEL_ID = "google/embeddinggemma-2"
PREFIX = "task: classification | query: "
EXPECTED_ROWS = 18314
SMOKE_ROWS = 200
SMOKE_SEQ = 1024
FALLBACK_SEQ = 512
BUDGET_HOURS = 6.0
CHUNK = 256
BATCH = 16
ALLOWED_DTYPES = {"torch.float32", "torch.bfloat16"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_texts() -> tuple[list[str], list[str]]:
    ids, texts = [], []
    with CORPUS.open(encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            rec = json.loads(line)
            ids.append(rec["email_id"])
            texts.append(PREFIX + normalized_state(rec))
    return ids, texts


def assert_dtype(model) -> str:
    """Model card: fp16 silently NaNs/degrades. Abort unless fp32/bf16."""
    dtypes = {str(p.dtype) for p in model.parameters()}
    bad = dtypes - ALLOWED_DTYPES
    if bad:
        raise SystemExit(f"ABORT: disallowed parameter dtype(s) {sorted(bad)}; PLAN C3 requires fp32/bf16")
    return ",".join(sorted(dtypes))


def load_model(max_seq: int):
    import torch
    from sentence_transformers import SentenceTransformer

    dtype = torch.bfloat16 if (torch.cuda.is_available() and torch.cuda.is_bf16_supported()) else torch.float32
    model = SentenceTransformer(
        MODEL_ID,
        config_kwargs={"vision_config": None, "audio_config": None},
        model_kwargs={"torch_dtype": dtype},
    )
    model.max_seq_length = max_seq
    return model, assert_dtype(model)


def encode(model, texts: list[str]) -> tuple[np.ndarray, list[float]]:
    """Encode in BATCH-sized groups; return vectors and per-email latency (ms) per batch."""
    vecs, per_email_ms = [], []
    for i in range(0, len(texts), BATCH):
        batch = texts[i:i + BATCH]
        t0 = time.perf_counter()
        v = model.encode(batch, batch_size=len(batch), normalize_embeddings=True,
                         convert_to_numpy=True, show_progress_bar=False)
        dt = (time.perf_counter() - t0) * 1000.0
        per_email_ms.extend([dt / len(batch)] * len(batch))
        vecs.append(v.astype(np.float32))
    return np.vstack(vecs), per_email_ms


def smoke() -> int:
    ids, texts = load_texts()
    if len(ids) != EXPECTED_ROWS:
        raise SystemExit(f"ABORT: corpus has {len(ids)} rows, PLAN C2 requires {EXPECTED_ROWS}")
    t_load = time.perf_counter()
    model, dtypes = load_model(SMOKE_SEQ)
    load_s = time.perf_counter() - t_load
    vecs, ms = encode(model, texts[:SMOKE_ROWS])
    finite = bool(np.isfinite(vecs).all())
    mean_ms = float(np.mean(ms))
    projected_h = mean_ms * EXPECTED_ROWS / 1000.0 / 3600.0
    decided = SMOKE_SEQ if projected_h <= BUDGET_HOURS else FALLBACK_SEQ
    result = {
        "ts_utc": now(), "model": MODEL_ID, "dtypes": dtypes, "rows": SMOKE_ROWS,
        "smoke_max_seq": SMOKE_SEQ, "batch": BATCH, "model_load_s": round(load_s, 1),
        "per_email_ms_mean": round(mean_ms, 1), "per_email_ms_p50": round(float(np.median(ms)), 1),
        "projected_full_hours_at_1024": round(projected_h, 2), "budget_hours": BUDGET_HOURS,
        "decided_max_seq": decided, "all_finite": finite, "dim": int(vecs.shape[1]),
        "rule": "PLAN C3: <= 6.0 h projected at 1024 -> 1024, else 512 (timing only; no labels read)",
    }
    OUT.mkdir(parents=True, exist_ok=True)
    SMOKE_FILE.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if finite else 2


def full() -> int:
    if not SMOKE_FILE.exists():
        raise SystemExit("ABORT: run --smoke first (PLAN C3 truncation decision)")
    decided = json.loads(SMOKE_FILE.read_text(encoding="utf-8"))["decided_max_seq"]
    ids, texts = load_texts()
    if len(ids) != EXPECTED_ROWS:
        raise SystemExit(f"ABORT: corpus has {len(ids)} rows, PLAN C2 requires {EXPECTED_ROWS}")
    CHUNKS.mkdir(parents=True, exist_ok=True)
    model, dtypes = load_model(decided)
    n_chunks = (len(ids) + CHUNK - 1) // CHUNK
    nonfinite_total = 0
    with LOG.open("a", encoding="utf-8") as log:
        log.write(json.dumps({"kind": "run_meta", "ts_utc": now(), "model": MODEL_ID, "dtypes": dtypes,
                              "max_seq_length": decided, "batch": BATCH, "chunk": CHUNK,
                              "rows": len(ids), "prefix": PREFIX}) + "\n")
        for c in range(n_chunks):
            path = CHUNKS / f"chunk-{c:04d}.npz"
            if path.exists():
                continue
            lo, hi = c * CHUNK, min((c + 1) * CHUNK, len(ids))
            vecs, ms = encode(model, texts[lo:hi])
            bad = ~np.isfinite(vecs).all(axis=1)
            nonfinite_total += int(bad.sum())
            np.savez(path, ids=np.array(ids[lo:hi]), vecs=vecs, ms=np.array(ms, dtype=np.float32))
            log.write(json.dumps({"kind": "chunk", "ts_utc": now(), "chunk": c, "lo": lo, "hi": hi,
                                  "per_email_ms_mean": round(float(np.mean(ms)), 1),
                                  "nonfinite_rows": int(bad.sum())}) + "\n")
            log.flush()
            print(f"[{now()}] chunk {c + 1}/{n_chunks} rows {lo}-{hi} "
                  f"{np.mean(ms):.0f} ms/email nonfinite={int(bad.sum())}", flush=True)
            if nonfinite_total > 0.001 * EXPECTED_ROWS:
                raise SystemExit(f"HALT: {nonfinite_total} non-finite rows exceeds 0.1% (PLAN C3)")
    return 0


def consolidate() -> int:
    files = sorted(CHUNKS.glob("chunk-*.npz"))
    ids, vecs, ms = [], [], []
    for f in files:
        z = np.load(f)
        ids.extend(z["ids"].tolist())
        vecs.append(z["vecs"])
        ms.append(z["ms"])
    if len(ids) != EXPECTED_ROWS or len(set(ids)) != EXPECTED_ROWS:
        raise SystemExit(f"ABORT: consolidated {len(ids)} rows ({len(set(ids))} unique); expected {EXPECTED_ROWS}")
    mat = np.vstack(vecs)
    np.save(OUT / "embeddings-768.npy", mat)
    np.save(OUT / "latency-ms.npy", np.concatenate(ms))
    (OUT / "ids.json").write_text(json.dumps(ids), encoding="utf-8")
    digest = hashlib.sha256(mat.tobytes()).hexdigest()
    print(json.dumps({"rows": len(ids), "dim": int(mat.shape[1]), "sha256": digest}))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--smoke", action="store_true")
    g.add_argument("--consolidate", action="store_true")
    args = ap.parse_args()
    if args.smoke:
        return smoke()
    if args.consolidate:
        return consolidate()
    return full()


if __name__ == "__main__":
    sys.exit(main())
