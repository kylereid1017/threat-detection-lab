"""Resume the scale Jev battery once TypeSafe recovers; abort passes that pile up
consecutive errors (A9 stopping rule), back off, and continue automatically.

Run:   python tools/jev_triage/resume_watchdog_scale.py
Wraps: run_jev_scale.py --resume in repeated passes while the service is intermittently
       down. Exits 0 when every corpus email has a clean observation; 2 if the service
       stays unhealthy past the cap.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
VENV_PY = REPO / ".venv" / "Scripts" / "python.exe"
RUNNER = REPO / "tools" / "jev_triage" / "run_jev_scale.py"
RECORDS = REPO / "docs" / "research" / "jev-email-triage" / "records" / "scale"
MANIFEST = REPO / "corpus" / "email" / "scale" / "scale-manifest.json"

PROBE_INTERVAL = 90          # seconds between recovery probes while unhealthy
CONSECUTIVE_LIMIT = 25       # consecutive row errors that abort a pass
BACKOFF_AFTER_ABORT = 300    # seconds to wait after an aborted pass
MAX_UNHEALTHY_SECONDS = 8 * 3600

sys.path.insert(0, str(REPO / "tools" / "jev_triage"))
import clients  # noqa: E402


def healthy() -> bool:
    try:
        clients.jev_system_one("Recovery probe. Ignore this content.",
                               {"r": {"type": "noul", "instructions": "Is this a reachability test?"}})
        return True
    except Exception:
        return False


def stats() -> tuple[int, int, int]:
    files = sorted(RECORDS.glob("jev-scale-*.jsonl"))
    if not files:
        return 0, 0, 0
    observations = []
    for line in files[-1].read_text(encoding="utf-8").split("\n"):
        if line.strip():
            row = json.loads(line)
            if row.get("kind") == "observation":
                observations.append(row)
    clean = {r["email_id"] for r in observations if not r.get("error")}
    errors = sum(1 for r in observations if r.get("error"))
    return len(observations), len(clean), errors


def wait_healthy() -> bool:
    waited = 0
    while not healthy():
        print(f"[watchdog] service unhealthy; waited {waited}s so far", flush=True)
        if waited >= MAX_UNHEALTHY_SECONDS:
            return False
        time.sleep(PROBE_INTERVAL)
        waited += PROBE_INTERVAL
    print(f"[watchdog] service healthy after {waited}s of waiting", flush=True)
    return True


def run_pass() -> str:
    print("[watchdog] launching resume pass", flush=True)
    proc = subprocess.Popen(
        [str(VENV_PY), str(RUNNER), "--resume"], cwd=str(REPO),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace")
    consecutive = 0
    for line in proc.stdout:
        print(line, end="", flush=True)
        if "ERROR:" in line:
            consecutive += 1
            if consecutive >= CONSECUTIVE_LIMIT:
                print(f"[watchdog] {CONSECUTIVE_LIMIT} consecutive errors — aborting pass", flush=True)
                proc.kill()
                proc.wait()
                return "errors"
        elif "pred=" in line:
            consecutive = 0
    proc.wait()
    return "done"


def main() -> int:
    total = json.loads(MANIFEST.read_text(encoding="utf-8"))["total"]
    passes = 0
    while True:
        passes += 1
        print(f"[watchdog] pass {passes}; target {total} emails", flush=True)
        if not wait_healthy():
            print("[watchdog] giving up: service unhealthy past the cap", flush=True)
            return 2
        outcome = run_pass()
        _, clean, errors = stats()
        print(f"[watchdog] pass {passes} outcome={outcome} clean={clean}/{total} errored_rows={errors}",
              flush=True)
        if clean >= total:
            print("[watchdog] battery complete: every email has a clean observation", flush=True)
            return 0
        if outcome == "errors":
            time.sleep(BACKOFF_AFTER_ABORT)
        elif errors == 0:
            print("[watchdog] no errors remain but coverage is incomplete; retrying once more", flush=True)
            time.sleep(30)


if __name__ == "__main__":
    raise SystemExit(main())
