# Active Content in SVG Phishing Attachments: Detection Opportunities and Evasion Tradeoffs

Kyle Reid — 2026-09-03 — threat-detection-lab v0.1.0

## Executive summary

SVG files are an effective phishing delivery vector because they are simultaneously images and documents that can execute script, carry links, and navigate the browser. Public reporting shows rising use in credential-phishing campaigns. This note explains the mechanism, describes a tested static detection for the active-content pattern, honestly measures what that detection does and does not prove, and outlines the evasion paths a static rule alone cannot cover. Static rules are a useful triage layer — not a defense on their own.

## Scope and research question

How can a defender statically identify SVG attachments whose active content is designed to navigate a user to an external destination, and where do such detections fail? The detection work and measurements referenced here come from this repository ([v0.1.0](https://github.com/kylereid1017/threat-detection-lab/releases/tag/v0.1.0)). All research uses public sources only.

## Observed facts

- Public campaign reporting documents phishing emails carrying SVG attachments that redirect users to credential-harvesting sites when opened, precisely because the attachment looks like an image to both users and some filters. BleepingComputer reported on this pattern in November 2024, noting SVG's ability to smuggle script past content inspection [1]. Hoxhunt's H1 2025 mini-report describes SVG phishing attachments as a rising threat category while QR-code lures declined [2].
- The W3C SVG specification allows `<script>` elements, `javascript:` URIs, and interactivity/event attributes; SVG rendered in a browser context executes these [3].
- Whether an SVG executes script depends entirely on the rendering context: browsers execute it; many email clients block it, render SVG statically, or refuse it. Client behavior is heterogeneous and often undocumented [4].

## How active SVG content works

An SVG attachment is text markup. A lure typically arrives as a plausible image ("view your invoice") whose markup contains either a `<script>` block or an event handler such as `onload` that assigns an external URL to `location`. When opened in a browser context, the navigation fires and the user lands on the credential page. The image is the disguise; the navigation is the payload.

## Detection hypothesis

The detection in this repository fires only when several independent signals co-occur: an SVG root near the start of the file, executable content (script block, event handler, or `javascript:` URI), browser-navigation behavior, and an external HTTP(S) destination. The combination matters: a static logo fails, a normal linked image fails, and a local script with no navigation fails. Requiring multiple signals trades some recall for precision — the right default for an alerting layer where analyst fatigue is the dominant failure mode.

## Experimental method and results

The rule was evaluated two ways (machine-readable results: `docs/detections/evaluation-benign-corpus.json`):

- Synthetic fixtures: six inert positives (script-block, event-handler, XML-declaration-prefixed, mixed-case, `window.open`, and `javascript:` URI redirects) and five benign negatives, including interactive-but-non-navigating content. Result: 6/6 matched, 0/5 fired.
- Benign public corpus: 2,079 Bootstrap Icons v1.13.1 SVGs (MIT), hash-pinned with a provenance lock. Result: 0 false positives.

These results are deliberately modest. The positives are synthetic, so they demonstrate intended behavior, not real-world catch rate. The benign corpus is static icon artwork, so the 0-FP result shows the rule stays quiet on one class of benign SVGs, not all benign email SVGs. No accuracy or recall claim is made; establishing those requires representative corpora from a real deployment.

## Evasion tradeoffs

A static byte-pattern rule has realistic blind spots. An adversary who understands the detection can: construct URLs dynamically (string concatenation, `fromCharCode`) so no literal `http://` appears; encode strings (HTML entities, hex escapes) to break byte matching; chain through an intermediate page or fetch a destination from a remote resource; use SVG links (`<a href>`) without script — statically indistinguishable from legitimate linked images; push the SVG root past the first 1 KB with padding; rely on unenumerated event handlers or navigation idioms; or rename the file and mismatch extension/content-type.

Two deeper caveats: a byte scan is not an XML parser, so adversarial structure can outflank it, and client rendering differences mean the same file is weaponized in one context and inert in another. Evasion against combination rules is not free — each obfuscation layer is itself a weak signal a richer pipeline could detect — but no static rule ends this arms race.

## Analytical judgments

- The mechanism, not a specific actor toolkit, is the durable detection target: attachments combining script-capable formats with external navigation outlive any one campaign.
- Precision-first, multi-signal rules are the correct starting layer for attachment triage; recall improvements belong in a pipeline with more context (URL reputation, sender history), not in ever-looser regexes.

## Hypotheses requiring further testing

- Interactive benign SVGs sent in real mail (marketing graphics, e-signature previews) will produce measurable false positives absent from the icon corpus.
- A substantial share of real-world malicious SVGs avoid all enumerated signals (e.g., script-free link-only lures); quantifying that needs a representative malicious corpus.
- Obfuscation such as entity encoding is rare enough in benign mail to be a useful secondary signal.

## Known unknowns

- Real-world prevalence of SVG attachment phishing (no public dataset with published methodology).
- A complete per-client execution matrix across mail clients and preview contexts.
- Actual benign SVG attachment volume in enterprise mail flows.

## Defensive recommendations

Layered, in roughly increasing order of attacker cost:

1. Policy: block or quarantine SVG (and other script-capable) attachments at the gateway where business need does not require them.
2. Content validation: check declared MIME/content-type against actual content, not just extension.
3. Static active-content inspection: rules like the one here, evaluated against environment-specific corpora before deployment.
4. URL extraction and reputation: pull destinations from surviving attachments and score them.
5. Safe rendering: render attachments in isolation or non-executing contexts rather than the browser.
6. Telemetry and feedback: route every disposition into analyst review and re-tune on measured errors.

## ATT&CK mapping

- [T1566.001 Phishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) — delivery of the SVG lure.
- [T1204.002 User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002/) — the user opening the attachment in an executing context.

The mapping describes delivery and execution context; the detection itself examines a file and proves neither.

## References

1. BleepingComputer, "Phishing attacks use SVG attachments to evade detection," November 2024. https://www.bleepingcomputer.com/news/security/phishing-attacks-use-svg-attachments-to-evade-detection/ (accessed 2026-09-03.)
2. Hoxhunt, "SVG Phishing Email Attachments (Mini-Report 2026)," October 2025. https://hoxhunt.com/blog/svg-phishing-email-attachments-mini-report (accessed 2026-09-03.)
3. W3C, "SVG 2 Specification." https://www.w3.org/TR/SVG2/ (accessed 2026-09-03.)
4. The measured detection, evaluation tooling, and pinned-corpus provenance: this repository, release v0.1.0 (2026-09-03).