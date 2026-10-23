"""Preflight checks for the Jev email-triage experiment.

Verifies, in one pass and with minimal spend:
  1. All three API keys resolve and authenticate (Jev, DeepSeek, Anthropic).
  2. The exact model IDs for the baselines (listed from the vendors).
  3. Public corpus sources are reachable (HEAD only; no download yet).

Run:  python tools/jev_triage/preflight.py
Exit code 0 = all green.
"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clients  # noqa: E402

CORPUS_SOURCES = [
    "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
    "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
]

failures = []


def check(name, fn):
    try:
        detail = fn()
        print(f"[OK]   {name}: {detail}")
        return True
    except Exception as exc:  # noqa: BLE001 - report and continue
        print(f"[FAIL] {name}: {exc}")
        failures.append(name)
        return False


def check_jev():
    data, elapsed = clients.jev_system_one(
        "Preflight check. Ignore this content.",
        {"reachable": {"type": "noul", "instructions": "Is this a reachability test?"}},
    )
    answer = data["answers"]["reachable"]
    return f"model={data.get('model')} noul={answer.get('noul')} {elapsed * 1000:.0f}ms"


def check_deepseek():
    data = clients.get_json(
        clients.DEEPSEEK_MODELS_URL,
        {"Authorization": f"Bearer {clients.load_key('DEEPSEEK_API_KEY')}"},
    )
    names = [m.get("id") for m in data.get("data", [])]
    reply, elapsed = clients.deepseek_chat(
        "deepseek-flash",
        [{"role": "user", "content": "Reply with JSON: {\"ok\": true}"}],
        max_tokens=16,
    )
    content = reply["choices"][0]["message"]["content"]
    return f"models={names} tiny_call={content!r} {elapsed * 1000:.0f}ms"


def check_anthropic():
    key = clients.load_key("ANTHROPIC_API_KEY")
    data = clients.get_json(
        clients.ANTHROPIC_MODELS_URL,
        {"x-api-key": key, "anthropic-version": clients.ANTHROPIC_VERSION},
    )
    names = [m.get("id") for m in data.get("data", [])]
    haiku = next((n for n in names if "haiku" in n), None)
    if not haiku:
        raise RuntimeError(f"no haiku model in account list: {names[:10]}")
    reply, elapsed = clients.anthropic_messages(
        haiku, "Reply with JSON only.",
        [{"role": "user", "content": "Reply: {\"ok\": true}"}], max_tokens=16,
    )
    text = reply["content"][0]["text"]
    return f"models={names} haiku={haiku} tiny_call={text!r} {elapsed * 1000:.0f}ms"


def check_corpus_sources():
    results = []
    for url in CORPUS_SOURCES:
        request = urllib.request.Request(url, method="HEAD")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                size = response.headers.get("Content-Length")
                results.append(f"{url.rsplit('/', 1)[-1]}={response.status}/{(int(size) // 1024) if size else '?'}KB")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"{url} -> HTTP {exc.code}") from exc
    return " ".join(results)


if __name__ == "__main__":
    print("== Jev email-triage preflight ==")
    check("TYPESAFE key + API", check_jev)
    check("DEEPSEEK key + API", check_deepseek)
    check("ANTHROPIC key + API", check_anthropic)
    check("corpus sources reachable", check_corpus_sources)
    print()
    if failures:
        print(f"FAILED: {', '.join(failures)}")
        sys.exit(1)
    print("ALL PREFLIGHT CHECKS PASSED")
