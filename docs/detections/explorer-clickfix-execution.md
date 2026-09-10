# Explorer Run-prompt execution (ClickFix pattern)

## Sample handling note

Every command-line example in this document is **defanged**. Interpreter names are split
(`power` + `shell`), URLs use `hxxp://` with bracketed dots, and no example is a complete,
pasteable command. An earlier revision of this file contained intact cradle strings and was
repeatedly quarantined by endpoint antivirus, which is itself a useful data point: the
signature surface of the documentation matched the signature surface of the attack.
Defanged examples are the standing convention for this repository.

## Goal

Identify an interpreter or downloader utility launched **directly by `explorer.exe`** with
arguments that indicate remote content retrieval, hidden-window execution, or encoded
command execution. This is narrower than alerting on interpreter execution generally, and
narrower than alerting on any `explorer.exe` child.

The behavior models ClickFix and ClearFake social engineering, where a web page instructs
the user to press Win+R, paste clipboard contents, and press Enter. The pasted content runs
as a child of the shell rather than as a child of a browser or an office application.

## Detection hypothesis

An event is suspicious when all three hold:

1. the parent image is `explorer.exe`;
2. the child image is a scripting interpreter, a signed proxy binary, or a downloader
   (`power`+`shell`, `pwsh`, `cmd`, `ms`+`hta`, `curl`, `certutil`, `rundll32`, `wscript`,
   `cscript`); **and**
3. the command line carries a retrieval or evasion behavior appropriate to that binary.

Requirement three is per-binary rather than global. A remote URL is meaningful for `ms`+`hta`
and `curl`; it is not the discriminator for `cmd`, where the discriminator is a chained
interpreter invocation combined with a hidden-window or encoded-command switch.

The rule fires on the combination only. An interactive shell opened from the Run box does
not match. A local script path does not match. A help invocation does not match.

## Public basis

- Sekoia, "ClickFix social engineering technique": https://www.sekoia.io/en/clickfix-social-engineering-technique/
- Palo Alto Unit 42, "Threat Brief: ClickFix social engineering": https://unit42.paloaltonetworks.com/threat-brief-clickfix-social-engineering/
- Hoxhunt, "SVG phishing email attachments": https://hoxhunt.com/blog/svg-phishing-email-attachments-mini-report

## ATT&CK mapping

| Technique | Name | Role in this rule |
|---|---|---|
| T1204.002 | User Execution: Malicious File | The user is the execution primitive. |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Primary interpreter branch. |
| T1059.003 | Windows Command Shell | `cmd` staging branch. |
| T1059.005 | Visual Basic | `wscript` / `cscript` branch. |
| T1218.005 | System Binary Proxy Execution: Mshta | Signed proxy branch. |
| T1218.011 | System Binary Proxy Execution: Rundll32 | Signed proxy branch. |
| T1027 | Obfuscated Files or Information | Encoded-command and hidden-window switches. |
| T1105 | Ingress Tool Transfer | Download cradles and `curl` / `certutil` retrieval. |

The mapping describes the execution context the rule observes. The rule sees one process
creation event. It does not prove user deception, successful download, payload execution,
or actor attribution.

## Telemetry prerequisites

Declared inline in the rule under `telemetry_prerequisites`, and expanded in
`docs/telemetry/PREREQUISITES.md`. In summary:

- Sysmon Event ID 1, or Security Event ID 4688 with command-line capture enabled.
- Command-line capture requires the "Include command line in process creation events"
  policy. Without it, `CommandLine` is empty and every action clause fails, taking recall
  to zero while the rule continues to validate and deploy cleanly. This is the most
  important silent failure mode for this rule.
- Sysmon configurations that exclude `explorer.exe` parentage or interpreter binaries
  remove the rule's entire input.

## Fixtures

All fixtures are inert synthetic process-creation events. Remote hosts use RFC 2606
reserved names.

Six positive fixtures cover the branches independently: `cmd` staging into an interpreter,
`curl` retrieval to a temporary path, `ms`+`hta` remote invocation, encoded-command
execution, rest-method retrieval piped to expression evaluation, and web-client retrieval
under a hidden window.

Negative fixtures cover the near-miss cases that separate this rule from a naive
parent-child rule: an interactive shell from the Run box, an interactive `cmd`, a `curl`
help invocation, a local script path, `notepad`, and a retrieval issued from a terminal
application rather than from `explorer.exe`.

## Measured results

Regression tests compile the rule against an in-memory SQLite event store and assert
exact fixture outcomes (`tests/test_sigma_rules.py`).

| Measurement | Result |
|---|---|
| Synthetic positives matched | 6 of 6 |
| Synthetic negatives fired | 0 of 6 |
| Benign enterprise noise-floor profiles fired | 0 |
| SIEM dialects compiled | Splunk SPL, Elasticsearch Lucene, CrowdStrike LogScale |

These are fixture measurements, not accuracy claims. The positives are events this
repository authored. They demonstrate that the logic behaves as specified and that
refactoring does not silently break a branch. They say nothing about recall against real
campaign traffic, and no representative real-world corpus of ClickFix process events is
redistributable here.

## Known limitations

Discovered by the boundary harness and retained deliberately as documented gaps:

- **Argument-form coverage is enumerated, not parsed.** The rule matches switch spellings
  as literal substrings. It was expanded once already to cover truncated forms of the
  window-style switch after the swarm found them. Any spelling not enumerated evades. A
  command-line tokenizer that normalizes abbreviations before matching would be durable;
  substring enumeration is a treadmill.
- **Parent lineage is a single hop.** An intermediate process between `explorer.exe` and
  the interpreter breaks the parent clause entirely.
- **Retrieval aliases outside the enumerated set evade.** Alternate download primitives,
  COM-based retrieval, and native .NET method calls are not covered.
- **Encoding and concatenation defeat the action clauses.** Environment-variable
  reassembly and character-code construction were both used by the swarm to bypass the
  literal matches.
- **`falsepositives` is under-specified.** Administrative use of the Run box for remote
  scripting will alert. Environments with heavy administrative shell use from the desktop
  need a tuning pass before this deploys at `high`.

## Reproducing

    python -m unittest tests.test_sigma_rules -v
    python -m tools.swarm.cli --target sigma --max-cycles 3
