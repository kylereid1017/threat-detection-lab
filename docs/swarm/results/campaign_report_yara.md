# Adversarial Swarm Campaign Report — Suspicious_Active_Content_SVG_Attachment

**Target Type:** `yara` | **Cycles Completed:** `2`  
**Total Variants Generated:** `7` | **Critic Approved:** `7`  
**Detected:** `7` | **Evaded (Gaps Found):** `0`  
**Rule Resilience Score:** `100.0%`

---

## Findings & Boundary Attributions

| Axis | Mutation | Status | Root Cause | Recommendation |
|---|---|---|---|---|
| structural | `svg_baseline_script_redirect` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| syntax | `svg_onload_event_handler` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| structural | `svg_cdata_encapsulation` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| obfuscation | `svg_mixed_case_markup` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| structural | `svg_comment_padding_exceeding_1kb` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| obfuscation | `svg_string_concatenation_location` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| syntax | `svg_onerror_event_redirect` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
