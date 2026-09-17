"""Generate the inert synthetic email corpus for the Jev triage experiment.

One DeepSeek call per batch (JSON mode), validated for schema AND inertness
before a record is kept. Inertness rules (mirrors PLAN.md §3):

  - hosts must end in .example/.invalid/.test; IPs only 192.0.2.0/24
  - no live URLs of any kind; hxxp:// prefixes allowed
  - attachments are filename mentions only

Everything is written incrementally and resumable: batches already present in
the output file are skipped on re-run. A generation lock records the model,
prompt hash, batch plan, per-label counts, rejects, and output hash.

Run:
  python tools/jev_triage/generate_synthetic.py --smoke   # 2 batches, quality look
  python tools/jev_triage/generate_synthetic.py           # full run (~17 batches)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clients  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
CORPUS_DIR = REPO / "corpus" / "email"
OUT = CORPUS_DIR / "synthetic.jsonl"
GEN_LOCK = CORPUS_DIR / "synthetic-generation-lock.json"

GENERATOR_MODEL = "deepseek-flash"
SEED = 20260917

SYSTEM_PROMPT = """You generate realistic email for a security evaluation corpus. Output JSON only.

Hard rules (violating these makes the output unusable):
- Every domain in sender addresses, links, and body text must end in .example, .invalid, or .test
  (e.g. "billing@acme-invoices.example", "https://portal.secure-login.invalid"). No exceptions.
- URLs may use hxxp:// prefixes where a suspicious link is intended.
- IP addresses, if any, must be from 192.0.2.0/24 only.
- Phone numbers must be in the 555-01xx range (e.g. 555-0142).
- Never use a real company's live domain, real campaign URLs, or real people's names.
  Impersonated brands use lookalike patterns on reserved TLDs (e.g. "micros0ft-support.example").
- Attachments are referenced by filename in the body only (e.g. "Invoice_4471.pdf"). No payloads.
- Plain text bodies. No HTML markup. No headers other than what the schema asks for.
- Settings are modern (2026): acknowledgements of mobile clients, Teams/Zoom/video calls,
  shared-document workflows, e-signature requests, MFA prompts are all fair game — with inert domains.

Quality rules:
- Vary length (400-1100 characters typical), tone, industry, and sender persona across a batch.
- Attack emails must be plausible, not cartoonish: correct-ish grammar, believable pretexts,
  context that sounds like real business. Difficulty 3 = sophisticated (subtle tells only).
- Gray emails must be genuinely ambiguous: a careful analyst could argue either way.
- Spam is clearly junk with no deception attempts and no malicious content.
- Safe emails are ordinary wanted mail (personal, work, transactional, subscribed)."""

BATCH_TEMPLATE = """Produce exactly {count} emails for the spec below. Output JSON:

{{"emails": [{{"subtype": "...", "difficulty": 1, "from_name": "...", "from_addr": "...", "reply_to": "... or null", "subject": "...", "body": "..."}}]}}

Spec:
{spec}

Rules for this batch:
- subtype must be one of: {subtypes}
- difficulty: {difficulty_mix}
- Aim for variety across the batch; no two emails should share a sender or subject pattern.
- bodies: plain text, 400-1100 characters, include a plausible signature block or sign-off where natural.
- reply_to: only set when it differs from from_addr and that difference is intentional."""

BATCHES = [
    # label, count, subtypes, difficulty mix, batch id
    ("attack", 8, ["credential_phishing"], "2,3,3,3,2,3,3,3", "attack-phish-1"),
    ("attack", 7, ["invoice_fraud"], "3,3,2,3,3,3,3", "attack-invoice-1"),
    ("attack", 7, ["malware_lure"], "2,3,3,2,3,3,3", "attack-malware-1"),
    ("attack", 5, ["extortion"], "2,2,3,3,3", "attack-extortion-1"),
    ("attack", 6, ["qr_phishing"], "2,3,3,2,3,3", "attack-qr-1"),
    ("attack", 7, ["tech_support_scam"], "2,2,3,3,2,3,3", "attack-techsupport-1"),
    ("safe", 7, ["personal", "notification"], "1,1,2,2,1,2,2", "safe-personal-1"),
    ("safe", 6, ["transactional"], "1,2,2,1,2,2", "safe-transaction-1"),
    ("safe", 6, ["internal_work"], "1,2,2,1,2,2", "safe-internal-1"),
    ("safe", 6, ["newsletter_subscribed"], "1,1,2,2,1,2", "safe-newsletter-1"),
    ("gray", 7, ["cold_outreach", "vendor_oddity"], "2,2,3,3,2,3,3", "gray-outreach-1"),
    ("gray", 6, ["unknown_list_bulk"], "2,2,3,2,3,3", "gray-unknownbulk-1"),
    ("gray", 6, ["ambiguous_marketing"], "2,3,2,3,2,3", "gray-ambiguous-1"),
    ("gray", 6, ["internal_oddity"], "3,3,2,3,3,2", "gray-internalodd-1"),
    ("spam", 7, ["promo_bulk", "retail"], "1,1,2,1,2,1,2", "spam-promo-1"),
    ("spam", 6, ["get_rich", "work_from_home"], "1,2,1,2,1,2", "spam-getrich-1"),
    ("spam", 6, ["retail", "promo_bulk"], "1,1,2,2,1,2", "spam-retail-1"),
    ("spam", 6, ["pharma_ish", "get_rich"], "1,2,2,1,2,2", "spam-misc-1"),
]

REQUIRED_MECHANICS = {
    "credential_phishing": "must ask the recipient to enter credentials/identity data via a link, form, or reply; must impersonate a trusted service, brand, or internal team; include a pressure element (deadline, account loss, suspension).",
    "invoice_fraud": "must contain an actual payment-manipulation or impersonation mechanic: changed/updated banking details, a new account or escrow for an urgent payment, a payroll/direct-deposit change, a gift-card/crypto request, or authority impersonation requesting an out-of-process wire. Subtle means the fraud is embedded in otherwise-normal business context — the fraud must still be present.",
    "malware_lure": "must ask the recipient to open or run something that would execute content: an attachment (HTML, ISO, password-protected ZIP, macro document), an instruction to enable macros or open a file from downloads, or a link promising a document.",
    "extortion": "must contain a threat (exposure, harm, shame, disruption) plus a specific demand (amount, wallet/address, deadline).",
    "qr_phishing": "must instruct scanning a QR code with a phone framed as MFA/document/re-enrollment, funneling toward credential entry or payment.",
    "tech_support_scam": "must claim a billing charge, renewal, or security event and push the recipient to call a number or visit a link for a fix/refund/cancellation under urgency.",
    "cold_outreach": "must be unsolicited first contact that is plausible enough to consider: unclear how they got the address, or a request that is unusual but not fraudulent. No deception mechanic (that would make it attack).",
    "vendor_oddity": "plausible vendor mail with one concrete anomaly (sender/brand dissonance, odd request, unexpected attachment) that a careful analyst would pause on — but no clear fraud mechanic.",
    "unknown_list_bulk": "bulk-looking mail whose list provenance is unclear: subscribed-or-not is genuinely hard to tell.",
    "ambiguous_marketing": "commercial mail that sits on the boundary between requested and unsolicited; framing makes intent genuinely unclear.",
    "internal_oddity": "internal-looking mail with a real anomaly (unusual request, wrong-looking address, unexpected urgency) that could be legitimate or not.",
    "promo_bulk": "clearly bulk promotional junk with no deception about who they are beyond ordinary marketing puffery.",
    "retail": "retail marketing junk; no credential or payment manipulation.",
    "get_rich": "obvious money-making scheme junk; no direct fraud mechanic aimed at the recipient's accounts.",
    "work_from_home": "obvious work-from-home junk recruiting pitch; no credential capture.",
    "pharma_ish": "obvious product-spam junk; no deception mechanic.",
    "personal": "ordinary personal correspondence; nothing unusual requested.",
    "transactional": "ordinary receipt/order/booking confirmation; links go to inert lookalikes of the service.",
    "internal_work": "ordinary internal work mail: meetings, updates, coordination. Nothing anomalous.",
    "newsletter_subscribed": "content the recipient plausibly subscribed to; clean unsubscribe line.",
    "notification": "service notification (shipping, calendar, storage) with normal framing.",
}


def mechanics_for(subtypes: list[str]) -> str:
    return " ".join(f"[{s}] {REQUIRED_MECHANICS.get(s, 'plausible and consistent with the category.')}"
                    for s in subtypes)



EMAIL_RE = re.compile(r"([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+)")
URL_RE = re.compile(r"\b(?:hxxp|https?)://([^/\s\"'<>]+)", re.IGNORECASE)
IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
TOKEN_RE = re.compile(r"\b[\w-]+(?:\.[\w-]+)+\b")
PHONE_RE = re.compile(r"\+?1?[-.\s]?\(?(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b")

ALLOWED_TLDS = (".example", ".invalid", ".test")
REAL_TLDS = {
    "com", "net", "org", "io", "co", "us", "uk", "ru", "cn", "de", "fr", "info",
    "biz", "xyz", "online", "site", "app", "dev", "ai", "cloud", "me", "gg", "cc",
    "live", "link", "click", "top", "work", "shop", "store", "email", "tech",
}
FILE_EXTS = {
    "pdf", "docx", "doc", "xlsx", "xls", "zip", "rar", "iso", "lnk", "html",
    "htm", "txt", "csv", "eml", "msg", "rtf", "pptx", "jpg", "png", "mp3", "wav",
}


def host_ok(host: str) -> bool:
    host = host.strip().lower().rstrip(".")
    if host.startswith("["):
        return False
    if IP_RE.fullmatch(host):
        return host.startswith("192.0.2.")
    return host.endswith(ALLOWED_TLDS)


def inertness_findings(text: str) -> list[str]:
    findings = []
    scrubbed = text
    for match in EMAIL_RE.finditer(text):
        domain = match.group(2)
        if not host_ok(domain):
            findings.append(f"email-domain:{domain}")
        scrubbed = scrubbed.replace(match.group(0), " ")
    for match in URL_RE.finditer(text):
        host = match.group(1).split(":")[0].split("@")[-1]
        if not host_ok(host):
            findings.append(f"url-host:{host}")
        scrubbed = scrubbed.replace(match.group(0), " ")
    for match in TOKEN_RE.finditer(scrubbed):
        token = match.group(0).lower()
        suffix = token.rsplit(".", 1)[-1]
        if suffix in FILE_EXTS or suffix in ("", "0"):
            continue
        if suffix in REAL_TLDS:
            findings.append(f"bare-domain:{token}")
        elif not any(token.endswith(tld) for tld in ALLOWED_TLDS):
            if len(suffix) in (2, 3) and suffix.isalpha():
                findings.append(f"suspicious-domain:{token}")
    for match in IP_RE.finditer(scrubbed):
        if not match.group(1).startswith("192.0.2."):
            findings.append(f"ip:{match.group(1)}")
    return findings


def phone_findings(text: str) -> list[str]:
    out = []
    for match in PHONE_RE.finditer(text):
        if match.group(1) != "555" or not match.group(2).startswith("01"):
            out.append(match.group(0))
    return out


def validate_email(item: dict) -> tuple[dict | None, str]:
    required = ("subtype", "from_name", "from_addr", "subject", "body")
    for field in required:
        if not item.get(field) or not str(item.get(field)).strip():
            return None, f"missing-{field}"
    body = str(item["body"])
    if not (250 <= len(body) <= 2500):
        return None, f"body-length:{len(body)}"
    haystack = " ".join([
        str(item.get("from_name", "")), str(item.get("from_addr", "")),
        str(item.get("reply_to") or ""), str(item.get("subject", "")), body,
    ])
    findings = inertness_findings(haystack)
    if findings:
        return None, "inertness:" + ";".join(findings[:4])
    phones = phone_findings(haystack)
    if phones:
        item["_warnings"] = {"phone": phones[:3]}
    return item, ""


def load_done_batches() -> set[str]:
    done = set()
    if OUT.exists():
        for line in OUT.read_text(encoding="utf-8").splitlines():
            if line.strip():
                done.add(json.loads(line).get("batch_id", ""))
    return done


def append_records(records: list[dict]):
    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    with OUT.open("a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true", help="run the first two batches only")
    args = parser.parse_args()

    rng = random.Random(SEED)
    done = load_done_batches()
    if done:
        print(f"resuming; batches already present: {len(done)}")

    prompt_hash = hashlib.sha256((SYSTEM_PROMPT + BATCH_TEMPLATE).encode("utf-8")).hexdigest()
    batches = BATCHES[:2] if args.smoke else BATCHES
    reject_log = []
    counts: dict[str, int] = {}
    warnings = 0

    for label, count, subtypes, difficulty_mix, batch_id in batches:
        if batch_id in done:
            continue
        spec = (
            f"category: {label}\n"
            f"subtype pool: {', '.join(subtypes)}\n"
            f"required mechanics: {mechanics_for(subtypes)}\n"
            f"setting hints (choose varied ones): "
            + ", ".join(rng.sample([
                "B2B SaaS", "healthcare billing", "university", "construction", "retail",
                "legal firm", "logistics", "real estate", "nonprofit", "fintech", "HR",
                "manufacturing", "media", "consulting", "city government",
            ], 5))
        )
        user_prompt = BATCH_TEMPLATE.format(
            count=count, spec=spec, subtypes=", ".join(subtypes), difficulty_mix=difficulty_mix,
        )
        kept: list[dict] = []
        attempts = 0
        while len(kept) < count and attempts < 3:
            attempts += 1
            try:
                response, elapsed = clients.deepseek_chat(
                    GENERATOR_MODEL,
                    [{"role": "system", "content": SYSTEM_PROMPT},
                     {"role": "user", "content": user_prompt}],
                    max_tokens=6000, temperature=0.9, thinking=False, timeout=300,
                )
                content = response["choices"][0]["message"]["content"]
                payload = json.loads(content)
                items = payload.get("emails", [])
            except Exception as exc:  # noqa: BLE001
                reject_log.append({"batch_id": batch_id, "attempt": attempts,
                                   "reason": f"call-or-parse: {exc}"})
                time.sleep(2)
                continue
            for item in items:
                if len(kept) >= count:
                    break
                record, reason = validate_email(item)
                if record is None:
                    reject_log.append({"batch_id": batch_id, "attempt": attempts, "reason": reason})
                    continue
                if record.get("_warnings"):
                    warnings += 1
                record.update({"label": label, "batch_id": batch_id, "generator": GENERATOR_MODEL})
                kept.append(record)
            print(f"   {batch_id}: attempt {attempts} -> kept {len(kept)}/{count} ({elapsed:.1f}s)")
        if len(kept) < count:
            print(f"   !! {batch_id}: only {len(kept)}/{count} after {attempts} attempts")
        for index, record in enumerate(kept, start=1):
            record["email_id"] = f"syn-{batch_id}-{index:02d}"
        append_records(kept)
        counts[label] = counts.get(label, 0) + len(kept)

    # lock (rewritten each run to reflect the full file on disk)
    all_lines = OUT.read_text(encoding="utf-8").splitlines() if OUT.exists() else []
    file_hash = hashlib.sha256(OUT.read_bytes()).hexdigest() if OUT.exists() else ""
    lock = {
        "generator": GENERATOR_MODEL,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "prompt_sha256": prompt_hash,
        "batch_plan": [{"batch_id": b[4], "label": b[0], "count": b[1],
                        "subtypes": b[2], "difficulty_mix": b[3]} for b in BATCHES],
        "records_in_file": len(all_lines),
        "counts_this_run": counts,
        "rejects": reject_log,
        "warnings": warnings,
        "output_sha256": file_hash,
        "note": ("Synthetic, inert email generated by an LLM for mechanics evaluation. "
                 "Not evidence of real-world efficacy. All hosts on reserved TLDs; "
                 "regenerate with: python tools/jev_triage/generate_synthetic.py"),
    }
    GEN_LOCK.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(f"\nrecords in file: {len(all_lines)}")
    print(f"rejects: {len(reject_log)}; warnings: {warnings}")
    print(f"lock -> {GEN_LOCK}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
