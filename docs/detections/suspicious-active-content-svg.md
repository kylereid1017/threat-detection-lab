# Suspicious active-content SVG attachment

## Goal

Identify an SVG attachment that combines active browser behavior with an external redirect. This is narrower than detecting SVG attachments generally and is intended for attachment triage or static file inspection.

## Detection hypothesis

An SVG is more suspicious when it contains all of the following:

1. an SVG root near the beginning of the file (an XML declaration or leading whitespace is allowed; the root must appear within the first 1 KB);
2. executable content such as a script block, JavaScript URI, or event handler;
3. browser-navigation behavior; and
4. an HTTP(S) destination.

The rule requires the combination. A static logo does not match. A normal linked image does not match. A local script that only changes document content does not match. A URL that appears only inside a comment or metadata does not match.

## Public basis

Public reporting has documented phishing campaigns using SVG attachments because SVG can contain script and links while appearing to be an image:

- BleepingComputer, "Phishing attacks use SVG attachments to evade detection" (November 2024): https://www.bleepingcomputer.com/news/security/phishing-attacks-use-svg-attachments-to-evade-detection/
- Hoxhunt, "SVG Phishing Email Attachments" (October 2025): https://hoxhunt.com/blog/svg-phishing-email-attachments-mini-report
- YARA official documentation: https://yara.readthedocs.io/

## ATT&CK mapping

- T1566.001 — Phishing: Spearphishing Attachment
- T1204.002 — User Execution: Malicious File

The mapping describes likely delivery and execution context. The rule itself examines a file and does not prove delivery, user execution, credential theft, or actor attribution.

## Fixtures

All fixtures are inert and synthetic. External-looking URLs use reserved `.invalid` names. Positive fixtures cover six variants: script-block redirect, event-handler redirect, XML-declaration-prefixed redirect, mixed-case markup, `window.open` navigation, and `javascript:` URI navigation. Negative fixtures cover static artwork, a conventional link, a local script without external navigation, a URL present only inside a comment, and benign interactive behavior (animation toggling) without navigation.

## Measured results (2026-09-03)

Machine-readable results: `evaluation-benign-corpus.json` in this directory. Summary:

- Synthetic positives: 6/6 matched, 0 missed.
- Synthetic negatives: 0/5 fired.
- Benign public corpus: 2,079 Bootstrap Icons v1.13.1 files (MIT license, archive SHA-256 pinned in `corpus/acquisition-lock.json`), 0 false positives.

These are two separate measurements. The corpus result says the rule does not fire on benign icon artwork. It says nothing about how many real malicious SVGs the rule catches, and it is not an accuracy or recall claim — no representative, legally redistributable malicious corpus exists in this repository. Production deployment requires validation on representative benign and malicious corpora from the deployment environment.

## Known limitations

- Encoded, heavily obfuscated, or dynamically constructed URLs (e.g. `String.fromCharCode`, hex-encoded hosts, redirect chains through intermediate pages) may evade the rule.
- The rule is a byte-pattern scan, not an XML parser. Deeply nested or nonstandard structure that pushes the SVG root past the first 1 KB will not match; a structural parser would be more robust and is a possible future improvement.
- The rule does not decode nested content, follow redirects, or examine linked resources.
- Legitimate interactive SVG applications that navigate externally (rare in email attachments) may be false positives.
- Production deployment would require threshold review, telemetry mapping, and operational ownership.

## Reproducing the evaluation

    curl -sSL <source_url from corpus/acquisition-lock.json> -o bootstrap-icons.zip
    python tools/_extract_corpus.py   # verifies the pinned SHA-256 before extracting
    python tools/evaluate_rule.py