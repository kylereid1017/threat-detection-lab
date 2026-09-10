# macOS developer runtime credential access

## Goal

Identify a developer runtime (`node`, `python`, `osascript`, `sh`, `bash`) executing a child
process whose command line references developer credential material: AWS CLI credentials,
SSH private keys, browser cookie vaults, or user LaunchAgent paths.

The rule models the workstation stage of DPRK Contagious Interview activity, where a
weaponized take-home project executes a package lifecycle hook that stages a credential
harvester. It is the endpoint counterpart to the ingress YARA rule that inspects
`package.json` and `setup.py` manifests before they reach the developer.

## Detection hypothesis

Credential paths are read constantly by legitimate tooling. The discriminator is not the
path; it is **which process lineage** touches the path. The AWS CLI reading
`~/.aws/credentials` is the intended behavior of that file. A Node.js or Python process
spawning a child that reads it, seconds after a dependency install, is not.

The rule therefore requires both a runtime parent and a credential target in the same
event. Either alone is normal.

## Public basis

- CISA advisory AA24-059A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-059a
- Google Cloud threat intelligence on DPRK malware in developer job-hunting lures:
  https://cloud.google.com/blog/topics/threat-intelligence/dprk-malware-developer-job-hunting

## ATT&CK mapping

| Technique | Name |
|---|---|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools |
| T1552.001 | Unsecured Credentials: Credentials In Files |
| T1539 | Steal Web Session Cookie |
| T1059.006 | Command and Scripting Interpreter: Python |
| T1059.007 | Command and Scripting Interpreter: JavaScript |

## Telemetry prerequisites

- macOS Endpoint Security Framework `ES_EVENT_TYPE_NOTIFY_EXEC`, or Auditd / Sysmon for
  Linux Event ID 1 on Linux developer hosts.
- Full command-line argument capture. Without arguments, the credential target is invisible
  and the rule degrades to matching every interpreter child process, which is unusable.
- The rule observes **process execution**, not file access. A harvester that reads the
  credential file through a language-native file API, without ever placing the path on a
  command line, produces no matching event. This is the rule's central blind spot and the
  reason the correlation rule exists.

## Known limitations

- **In-process reads evade completely.** `fs.readFileSync` in Node or `open()` in Python
  never touches a command line. Closing this requires ESF file-open events
  (`ES_EVENT_TYPE_NOTIFY_OPEN`) filtered on the credential paths, correlated back to the
  runtime process. That telemetry is a prerequisite the rule does not currently demand,
  and the gap should be read as scoped rather than solved.
- **Path enumeration is literal.** Alternate key filenames, a non-default AWS profile
  directory, or a Chromium-family browser whose cookie vault sits at a different path all
  evade.
- **Parent matching is a single hop.** A harvester launched through an intermediate shell
  wrapper is not attributed to the runtime.
- **Benign parents exist.** Deployment scripts and infrastructure tooling invoked from
  shell wrappers legitimately reference AWS config paths. The `sh` and `bash` parents carry
  most of that false-positive risk; environments with heavy shell-driven deployment should
  evaluate splitting them into a lower-severity variant.

## Fixtures

Positive fixtures cover a Node runtime staging AWS credentials and a Python runtime staging
SSH keys. Negative coverage comes from the enterprise noise-floor profiles in
`tools/swarm/noise_floor.py`.

Coverage is thinner than the ClickFix rule. Fixtures for the cookie-vault and LaunchAgent
branches are not yet written, and those branches are therefore untested.

## Reproducing

    python -m unittest tests.test_new_detection_rules -v
    python -m unittest tests.test_supply_chain_craftsman -v
