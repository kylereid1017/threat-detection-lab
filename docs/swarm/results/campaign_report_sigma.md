# Adversarial Swarm Campaign Report — Suspicious Process Spawning From Explorer Run Prompt (ClickFix Pattern)

**Target Type:** `sigma` | **Cycles Completed:** `3`  
**Total Variants Generated:** `11` | **Critic Approved:** `11`  
**Detected:** `11` | **Evaded (Gaps Found):** `0`  
**Rule Resilience Score:** `100.0%`

---

## Findings & Boundary Attributions

| Axis | Mutation | Status | Root Cause | Recommendation |
|---|---|---|---|---|
| syntax | `proc_powershell_standard_clickfix` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| obfuscation | `proc_powershell_windowstyle_numeric` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| syntax | `proc_powershell_windowstyle_short_h` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| lolbin | `proc_mshta_remote_url` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| lolbin | `proc_curl_outbound_download` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| syntax | `proc_cmd_start_b_staging` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| obfuscation | `proc_powershell_base64_encoded` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| lolbin | `proc_pwsh_core_clickfix` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| obfuscation | `proc_powershell_split_invoke_restmethod` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| lolbin | `proc_rundll32_url_protocol_handler` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
| lolbin | `proc_wscript_remote_script_fetch` | ✅ Detected | Rule logic successfully triggered on variant features. | Current rule signature is resilient against this variation. |
