# Adversarial Swarm Campaign Report — Suspicious_Active_Content_SVG_Attachment

**Target Type:** `yara` | **Cycles Completed:** `2`  
**Total Variants Generated:** `7` | **Critic Approved:** `7`  
**Detected:** `5` | **Evaded (Gaps Found):** `2`  
**Rule Resilience Score:** `71.4%`

---

## Findings & Boundary Attributions

| Axis | Mutation | Status | Root Cause | Recommendation |
|---|---|---|---|---|
| structural | `svg_baseline_script_redirect` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| syntax | `svg_onload_event_handler` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| structural | `svg_cdata_encapsulation` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| obfuscation | `svg_mixed_case_markup` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| structural | `svg_comment_padding_exceeding_1kb` | 🚨 Evasion Gap | YARA rule enforces `$svg at 0 or $svg in (0..1024)`. Prepending comments >1 KB pushes the root element outside the scan window. | REC-YARA-001: Expand root search window to 4,096 bytes or complement with structural XML parser. |
| obfuscation | `svg_string_concatenation_location` | 🚨 Evasion Gap | Literal string matching for 'location' and 'href' was bypassed via JavaScript property bracket access and string concatenation (`window['loc'+'ation']`). | REC-YARA-002: Pair static file matching with dynamic sandbox inspection or AST JavaScript tokenization. |
| syntax | `svg_onerror_event_redirect` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
