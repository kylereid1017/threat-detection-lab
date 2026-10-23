"""Standard-library clients for the Jev email-triage evaluation harness.

No third-party dependencies: urllib + json only, so the harness runs under any
Python 3.9+ interpreter, including the repository venv.

Keys are resolved from the environment first, then from local secrets files
(Hermes profile .env). Nothing here ever prints key material.
"""

from __future__ import annotations

import json
import os
import random
import time
import urllib.error
import urllib.request
from pathlib import Path

TYPESAFE_URL = "https://api.typesafe.ai/v1/systemone"
DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
DEEPSEEK_MODELS_URL = "https://api.deepseek.com/models"
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODELS_URL = "https://api.anthropic.com/v1/models"
ANTHROPIC_VERSION = "2023-06-01"
PORTAL_CHAT_URL = "http://127.0.0.1:8645/v1/chat/completions"

RETRYABLE_STATUS = {429, 500, 502, 503, 504, 529}

# Vendor list prices, USD per million tokens. Accessed 2026-09-17 from the
# sources below. Used only by scoring/costing code; never billed by this harness.
PRICING = {
    "jev-latest": {
        "input": 0.042, "output": 0.0, "output_note": "output tokens free",
        "source": "https://typesafe.ai (pricing section)",
    },
    "deepseek-flash": {
        "input": 0.15, "output": 0.60,
        "input_peak": 0.30, "output_peak": 1.20,
        "source": "https://api-docs.deepseek.com/quick_start/pricing/",
    },
    "claude-haiku-4-5": {
        "input": 1.00, "output": 5.00,
        "source": "https://platform.claude.com/docs/en/about-claude/pricing",
    },
    "claude-sonnet-5": {
        "input": 2.00, "output": 10.00,
        "source": "https://platform.claude.com/docs/en/about-claude/pricing",
    },
    "claude-opus-5": {
        "input": 5.00, "output": 25.00,
        "source": "https://platform.claude.com/docs/en/about-claude/pricing",
    },
    "claude-fable-5-1": {
        "input": 10.00, "output": 50.00,
        "source": "https://platform.claude.com/docs/en/about-claude/pricing",
    },
    # Nous Portal-proxied Claude models (prices shown are Anthropic list prices;
    # Portal billing may differ - cross-check https://portal.nousresearch.com).
    "anthropic/claude-haiku-4.5": {
        "input": 1.00, "output": 5.00,
        "source": "anthropic list via Nous Portal proxy",
    },
    "anthropic/claude-sonnet-5": {
        "input": 2.00, "output": 10.00,
        "source": "anthropic list via Nous Portal proxy",
    },
    "anthropic/claude-opus-5": {
        "input": 5.00, "output": 25.00,
        "source": "anthropic list via Nous Portal proxy",
    },
    "anthropic/claude-fable-5.1": {
        "input": 10.00, "output": 50.00,
        "source": "anthropic list via Nous Portal proxy",
    },
}
PRICING_ACCESSED = "2026-09-17"


def _env_file_candidates():
    out = []
    hermes_home = os.environ.get("HERMES_HOME")
    if hermes_home:
        out.append(Path(hermes_home) / ".env")
    out.append(Path.home() / ".hermes" / ".env")
    local = os.environ.get("LOCALAPPDATA")
    if local:
        out.append(Path(local) / "hermes" / ".env")
    repo_env = Path(__file__).resolve().parents[2] / ".env"
    out.append(repo_env)
    return out


def _usable(value):
    value = (value or "").strip().strip('"').strip("'")
    if not value or value.startswith("${"):
        return None
    return value


def load_key(name):
    """Resolve a secret by env var name: environment first, then local .env files.

    Raises RuntimeError naming the variable when nothing is found (never prints a value).
    """
    key = _usable(os.environ.get(name))
    if key:
        return key
    for candidate in _env_file_candidates():
        try:
            text = candidate.read_text(encoding="utf-8-sig")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            var, _, value = line.partition("=")
            if var.strip() == name:
                key = _usable(value)
                if key:
                    return key
    raise RuntimeError(f"{name} not found in environment or local .env files")


def post_json(url, payload, headers, *, timeout=120.0, retries=4):
    """POST JSON with retry/backoff on 429/5xx; returns (parsed_body, elapsed_seconds)."""
    body = json.dumps(payload).encode("utf-8")
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
                return data, time.perf_counter() - started
        except urllib.error.HTTPError as exc:
            text = ""
            try:
                text = exc.read().decode("utf-8", "replace")
            except Exception:
                pass
            if exc.code in RETRYABLE_STATUS and attempt < retries:
                retry_after = exc.headers.get("retry-after") if exc.headers else None
                try:
                    delay = float(retry_after) if retry_after else None
                except ValueError:
                    delay = None
                time.sleep(delay if delay is not None else min(2 ** attempt + random.random(), 30.0))
                continue
            raise RuntimeError(f"HTTP {exc.code} from {url}: {text[:600]}") from exc
        except urllib.error.URLError as exc:
            if attempt < retries:
                time.sleep(min(2 ** attempt + random.random(), 30.0))
                continue
            raise RuntimeError(f"Connection error to {url}: {exc.reason}") from exc
    raise RuntimeError(f"POST {url} failed after {retries + 1} attempts")


def get_json(url, headers, *, timeout=60.0, retries=3):
    """GET JSON with the same retry policy; returns parsed body."""
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            text = ""
            try:
                text = exc.read().decode("utf-8", "replace")
            except Exception:
                pass
            if exc.code in RETRYABLE_STATUS and attempt < retries:
                time.sleep(min(2 ** attempt + random.random(), 30.0))
                continue
            raise RuntimeError(f"HTTP {exc.code} from {url}: {text[:400]}") from exc
        except urllib.error.URLError as exc:
            if attempt < retries:
                time.sleep(min(2 ** attempt + random.random(), 15.0))
                continue
            raise RuntimeError(f"Connection error to {url}: {exc.reason}") from exc
    raise RuntimeError(f"GET {url} failed after {retries + 1} attempts")


def jev_system_one(state, questions, *, model="jev-latest", timeout=120.0):
    """One TypeSafe System One call. Returns (response_dict, elapsed_seconds)."""
    key = load_key("TYPESAFE_API_KEY")
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "tdl-jev-triage/0.1",
    }
    payload = {"state": state, "model": model, "questions": questions}
    return post_json(TYPESAFE_URL, payload, headers, timeout=timeout)


def deepseek_chat(model, messages, *, max_tokens=64, temperature=0.0, timeout=180.0,
                  thinking=False):
    """One DeepSeek chat completion. Returns (response_dict, elapsed_seconds)."""
    key = load_key("DEEPSEEK_API_KEY")
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "User-Agent": "tdl-jev-triage/0.1",
    }
    payload = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "response_format": {"type": "json_object"},
        "thinking": {"type": "enabled" if thinking else "disabled"},
    }
    return post_json(DEEPSEEK_URL, payload, headers, timeout=timeout)


def anthropic_messages(model, system, messages, *, max_tokens=64, temperature=0.0,
                       timeout=180.0):
    """One Anthropic messages call. Returns (response_dict, elapsed_seconds)."""
    key = load_key("ANTHROPIC_API_KEY")
    headers = {
        "x-api-key": key,
        "anthropic-version": ANTHROPIC_VERSION,
        "Content-Type": "application/json",
        "User-Agent": "tdl-jev-triage/0.1",
    }
    payload = {
        "model": model,
        "system": system,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    return post_json(ANTHROPIC_URL, payload, headers, timeout=timeout)


def portal_chat(model, system, user, *, max_tokens=64, temperature=0.0, timeout=180.0):
    """OpenAI-format chat through a local proxy (Nous Portal upstream).

    No response_format: the proxy/upstream may not honor JSON mode for every model;
    the frozen prompt already demands strict JSON and the parser is lenient.
    """
    headers = {
        "Authorization": "Bearer local-proxy",
        "Content-Type": "application/json",
        "User-Agent": "tdl-jev-triage/0.1",
    }
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "max_tokens": max_tokens,
        "temperature": temperature,
    }
    return post_json(PORTAL_CHAT_URL, payload, headers, timeout=timeout)
