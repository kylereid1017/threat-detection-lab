"""Uncontended CPU timing for EG2 inputs (not pre-registered; a latency measurement only).

Batteries A and E ran concurrently, so their per-item latencies are contended. This times
48 items of each input type alone on the machine, after the batteries finish.
Writes docs/research/eg2-url-benchmark/timing-solo.json.
"""

from __future__ import annotations

import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "eg2_triage"))
from battery_a_urls import DATA_DIR, PREFIX, load_sample  # noqa: E402

N, BATCH = 48, 16


def time_items(model, items):
    model.encode(items[:BATCH], batch_size=BATCH, normalize_embeddings=True, show_progress_bar=False)  # warm-up
    ms = []
    for i in range(0, N, BATCH):
        t = time.perf_counter()
        model.encode(items[i:i + BATCH], batch_size=BATCH, normalize_embeddings=True, show_progress_bar=False)
        ms.append((time.perf_counter() - t) * 1000 / BATCH)
    return float(np.median(ms))


def main() -> int:
    import torch
    from sentence_transformers import SentenceTransformer

    model = SentenceTransformer("google/embeddinggemma-2", config_kwargs={"audio_config": None},
                                model_kwargs={"torch_dtype": torch.float32})
    df = load_sample().iloc[: N + BATCH]
    urls = [PREFIX + str(u).strip() for u in df["url"]]
    imgs = [str((DATA_DIR / f).resolve()) for f in df["file_name"]]
    out = {
        "ts_utc": datetime.now(timezone.utc).isoformat(),
        "cpu": platform.processor(), "torch_threads": torch.get_num_threads(), "dtype": "float32",
        "batch": BATCH, "n": N,
        "ms_per_item": {
            "url_text": time_items(model, urls),
            "screenshot": time_items(model, [{"text": "<|image|>", "image": [p]} for p in imgs]),
            "url_plus_screenshot": time_items(model, [{"text": f"{u} <|image|>", "image": [p]} for u, p in zip(urls, imgs)]),
        },
    }
    m = out["ms_per_item"]
    out["summary"] = (f"URL text {m['url_text']:.0f} ms, screenshot {m['screenshot'] / 1000:.1f} s, "
                      f"URL + screenshot {m['url_plus_screenshot'] / 1000:.1f} s per item")
    (REPO / "docs" / "research" / "eg2-url-benchmark" / "timing-solo.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
