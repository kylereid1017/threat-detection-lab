# Cloud IMDS abuse and model checkpoint exfiltration

## Goal

Identify three linked behaviors on a GPU training node: a privileged container breakout, an
Instance Metadata Service token request that yields the node's IAM role credentials, and a
bulk transfer of model checkpoint files to object storage.

The chain models the frontier-AI-lab threat scenario where an adversary who lands inside a
training workload escalates to the host, borrows the node role, and exfiltrates weights.

## Detection hypothesis

Each stage is individually explainable. Metadata service requests are routine on EC2.
Object-storage transfers of checkpoints are what a training pipeline does. `nsenter` has
legitimate operator uses. The signal is the sequence, and the rule as written does not
capture the sequence; it fires on any single stage.

## Scope limitation, stated plainly

This rule matches **process creation command lines only**. That is a deliberate first layer,
and it is the weakest of the three layers this scenario requires.

An adversary who uses a cloud SDK rather than a command-line client defeats it entirely. A
call to the metadata service through an HTTP client library, or a multipart upload issued
through `boto3`, produces no command line containing a metadata address or a bucket path.
Since SDK use is the *normal* way to interact with object storage from inside a training
job, the evasion is not an exotic bypass. It is the default path.

The authoritative telemetry for this scenario is:

| Layer | Source | Status |
|---|---|---|
| Host and container execution | Auditd, eBPF (Falco, Tetragon) | Implemented here |
| Cloud control plane | AWS CloudTrail | See `rules/sigma/cloud/` |
| Orchestration | Kubernetes audit log | See `rules/sigma/cloud/` |

Read this rule as the execution-layer tripwire, not as the detection for model weight theft.

## ATT&CK mapping

| Technique | Name |
|---|---|
| T1611 | Escape to Host |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API |
| T1530 | Data from Cloud Storage |
| T1567.002 | Exfiltration to Cloud Storage |

## Telemetry prerequisites

- Execve auditing that survives container namespace boundaries. Host-only auditing does not
  observe in-container metadata requests.
- IMDSv2 enforcement changes the observable: the token request itself becomes the artifact.
  On instances still permitting IMDSv1, a single unauthenticated request retrieves
  credentials and the token-header pattern never appears.

## Known limitations

- **SDK and library calls are invisible.** Described above. This is the dominant gap.
- **The condition is a disjunction.** Any one stage alerts. On a training cluster, the
  checkpoint-transfer branch will fire on legitimate pipeline activity, and the tensor
  filename patterns are common enough that this branch should be considered unvalidated
  until measured against real cluster telemetry.
- **Enumerated breakout primitives only.** Three escape techniques are matched literally.
  Others evade.
- **No false-positive measurement exists for a real GPU cluster.** The noise floor in this
  repository models enterprise endpoints, not ML training infrastructure. Any false-positive
  claim for this rule would be unfounded, so none is made.

## Reproducing

    python -m unittest tests.test_new_detection_rules -v
    python -m unittest tests.test_cloud_cluster_craftsman -v
