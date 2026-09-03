# Suspicious active-content SVG attachment

## Goal

Identify an SVG attachment that combines active browser behavior with an external redirect. This is narrower than detecting SVG attachments generally and is intended for attachment triage or static file inspection.

## Detection hypothesis

An SVG is more suspicious when it contains all of the following:

1. an SVG root at the beginning of the file;
2. executable content such as a script block, JavaScript URI, or event handler;
3. browser-navigation behavior; and
4. an HTTP(S) destination.

The rule requires the combination. A static logo does not match. A normal linked image does not match. A local script that only changes document content does not match.

## Public basis

Public reporting has documented phishing campaigns using SVG attachments because SVG can contain script and links while appearing to be an image:

- BleepingComputer, “Phishing attacks use SVG attachments to evade detection” (November 2024): https://www.bleepingcomputer.com/news/security/phishing-attacks-use-svg-attachments-to-evade-detection/
- Hoxhunt, “SVG Phishing Email Attachments” (October 2025): https://hoxhunt.com/blog/svg-phishing-email-attachments-mini-report
- YARA official documentation: https://yara.readthedocs.io/

## ATT&CK mapping

- T1566.001 — Phishing: Spearphishing Attachment
- T1204.002 — User Execution: Malicious File

The mapping describes likely delivery and execution context. The rule itself examines a file and does not prove delivery, user execution, credential theft, or actor attribution.

## Fixtures

All fixtures are inert and synthetic. External-looking URLs use reserved `.invalid` names. Positive fixtures exercise two implementations of navigation. Negative fixtures cover static artwork, a conventional link, and a local script without external navigation.

## Known limitations

- Encoded, heavily obfuscated, or dynamically constructed URLs may evade the rule.
- The rule does not decode nested content or follow redirects.
- Legitimate interactive SVG applications that redirect externally may be false positives.
- Requiring the SVG root at byte zero excludes files with an XML declaration or leading whitespace; this is an intentional precision-first v1 constraint.
- Production deployment would require validation on representative benign and malicious corpora, threshold review, telemetry mapping, and operational ownership.

## Next evaluation step

Build a provenance-tracked public corpus, record SHA-256 hashes and licenses, and report a confusion matrix rather than presenting synthetic fixture accuracy as real-world efficacy.
