# Malicious package lifecycle hooks

## Goal

Inspect an inbound `package.json` or `setup.py` manifest for the combination of a package
lifecycle hook and an execution or remote-retrieval primitive. The intended deployment is
ingress inspection: mail attachments, archive scanning, or repository intake, before a
developer runs an install.

## Detection hypothesis

Lifecycle hooks are the execution primitive of a dependency-based supply chain lure. The
victim never runs the attacker's code deliberately. They run `npm install`, and the
`postinstall` hook runs it for them.

A hook alone is unremarkable. The rule requires a hook plus either an evaluation or
decoding primitive, or a downloader paired with a URL scheme.

## Public basis

- CISA advisory AA24-059A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-059a

## ATT&CK mapping

| Technique | Name |
|---|---|
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools |
| T1059.007 | Command and Scripting Interpreter: JavaScript |
| T1027 | Obfuscated Files or Information |
| T1105 | Ingress Tool Transfer |

## Measured results

The rule was evaluated against a corpus of real, benign dependency manifests that this
repository did not author. Results are machine-readable in
`evaluation-package-manifests.json`.

| Revision | Manifests scanned | False positives | Rate | 95% Wilson CI |
|---|---|---|---|---|
| v1 (byte-scoped) | 1,755 | 9 | 0.51% | 0.27% to 0.97% |
| v2 (value-scoped) | 1,755 | 0 | 0.00% | 0.00% to 0.22% |

The v1 measurement is retained because it is the reason v2 exists. Every one of the nine
false positives came from the same defect: the rule matched its primitives anywhere in the
file rather than inside the hook's own value. The packages that fired were `undici`, `got`,
`node-fetch`, `keyv`, and `ts-api-utils`. These are among the most widely installed packages
on npm. They matched because a `prepare` hook was present and the words `curl`, `wget`, or
`Buffer` appeared elsewhere in the manifest, typically in the keywords array.

Deployed as a block, v1 would have quarantined a large fraction of ordinary Node projects.

v2 scopes hook matching to the hook's JSON string value, walking escaped quotes so that the
common `node -e "..."` form is still covered. All four synthetic attack variants produced by
the supply chain craftsman continue to match: base64 evaluation, a download cradle piped to
a shell, a setuptools command override with a network fetch, and a concatenated global
lookup of the evaluation function.

Recall is not measured. No representative, legally redistributable corpus of malicious
manifests exists here, so no precision or accuracy figure is claimed.

## Known limitations

- **Still a byte scanner, not a parser.** v2 scopes matches to a hook value using a regular
  expression over the raw file. A manifest that splits a hook value across JSON escape
  sequences in unusual ways, or that stores the payload in a separate file the hook calls,
  is not covered.
- **Value length is bounded.** The value scan window stops after 600 characters. A hook that
  pads its value beyond that before reaching the primitive evades.
- **Indirection through a script file evades entirely.** A hook reading `node scripts/x.js`
  is indistinguishable from a benign build step at manifest level. Detecting that requires
  scanning the archive contents, not the manifest.
- **The setup.py branch is unchanged and thinly measured.** Only eleven Python manifests
  appeared in the corpus. Its false-positive behavior is effectively unmeasured, and the
  upper confidence bound from this corpus should not be applied to it.
- **Obfuscation beyond the enumerated forms evades.** Character-code construction and
  arbitrary string splitting are not covered.

The rule is a triage signal for a human queue. It is now precise enough on benign traffic to
justify that use, and it remains unproven against real malicious traffic.

## Reproducing

    python -m unittest tests.test_yara_rules -v
    python tools/evaluate_manifest_corpus.py
