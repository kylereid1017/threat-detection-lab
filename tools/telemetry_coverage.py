"""Telemetry-layer coverage mapping for a detection corpus.

The question this answers: for each ATT&CK technique a corpus claims to cover,
which telemetry layer is that coverage actually sitting on, and does the corpus
depend on a single layer for techniques that are observable at several.

This matters because a technique count is not a coverage measure. Twelve rules
for a technique, all reading process creation, cover exactly one execution path.
An adversary who performs the same technique through a cloud SDK, a language
runtime, or an API call produces nothing any of the twelve can see. The corpus
still reports the technique as covered.

The specific case that motivated this: cloud credential and storage techniques
are frequently covered only by process-creation rules matching command-line
strings, even though the authoritative record of the activity is a control-plane
audit log. Command-line matching for cloud API activity is not a partial
detection. It is a detection for the subset of adversaries who use the CLI.

Usage:
    python -m tools.telemetry_coverage --git-corpus https://github.com/SigmaHQ/sigma \
        --path-prefix rules/
    python -m tools.telemetry_coverage --rules rules/sigma --label local
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import date
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.brittleness.git_corpus import CorpusError, read_rule_corpus  # noqa: E402

DEFAULT_OUT = ROOT / "docs" / "brittleness"

TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

#: Telemetry layers, ordered from the layer an adversary has most control over to
#: the layer they have least. The ordering is the point: an adversary chooses
#: their own command line, and does not choose what the cloud control plane
#: records about an API call they made.
LAYERS = (
    "endpoint_process",
    "endpoint_other",
    "network",
    "application",
    "identity",
    "cloud_control_plane",
)


def classify_layer(logsource: Dict[str, Any]) -> str:
    """Map a Sigma logsource to a telemetry layer."""
    product = str(logsource.get("product", "")).lower()
    category = str(logsource.get("category", "")).lower()
    service = str(logsource.get("service", "")).lower()

    if category in {"process_creation", "process_access", "ps_script", "ps_module", "ps_classic_start"}:
        return "endpoint_process"
    if product in {"aws", "gcp", "azure", "m365", "kubernetes", "onelogin"}:
        return "cloud_control_plane"
    if service in {"cloudtrail", "audit", "activitylogs", "auditlogs", "signinlogs"}:
        return "cloud_control_plane"
    if product in {"okta", "auth0"} or "signin" in service or "authentication" in service:
        return "identity"
    if category in {"network_connection", "dns_query", "dns", "firewall", "proxy", "webserver"}:
        return "network"
    if category in {"file_event", "file_access", "file_change", "registry_set", "registry_add", "registry_event", "image_load", "driver_load", "create_remote_thread", "pipe_created", "wmi_event"}:
        return "endpoint_other"
    if product in {"windows", "linux", "macos"}:
        return "endpoint_other"
    return "application"


#: Techniques whose real record lives in a control plane or identity provider.
#: Coverage for these that sits only on endpoint process creation is coverage for
#: the subset of adversaries who happen to use a command-line client.
CONTROL_PLANE_TECHNIQUES = {
    "t1078.004": "Valid Accounts: Cloud Accounts",
    "t1530": "Data from Cloud Storage",
    "t1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "t1567.002": "Exfiltration to Cloud Storage",
    "t1580": "Cloud Infrastructure Discovery",
    "t1526": "Cloud Service Discovery",
    "t1538": "Cloud Service Dashboard",
    "t1619": "Cloud Storage Object Discovery",
    "t1651": "Cloud Administration Command",
    "t1611": "Escape to Host",
    "t1609": "Container Administration Command",
    "t1610": "Deploy Container",
}


def parse_rule(text: str, name: str) -> Optional[Dict[str, Any]]:
    try:
        documents = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except yaml.YAMLError:
        return None
    if not documents:
        return None
    doc = documents[0]
    if not isinstance(doc.get("detection"), dict):
        return None
    tags = doc.get("tags") or []
    techniques = []
    for tag in tags:
        match = TECHNIQUE_RE.match(str(tag).strip())
        if match:
            techniques.append(match.group(1).lower())
    return {
        "name": name,
        "title": str(doc.get("title", name)),
        "layer": classify_layer(doc.get("logsource") or {}),
        "techniques": techniques,
    }


def build_map(rules: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    by_technique: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    layer_totals: Dict[str, int] = defaultdict(int)
    rules_with_technique = 0
    total = 0

    for rule in rules:
        total += 1
        layer_totals[rule["layer"]] += 1
        if rule["techniques"]:
            rules_with_technique += 1
        for technique in rule["techniques"]:
            by_technique[technique][rule["layer"]] += 1

    single_layer = []
    for technique, layers in by_technique.items():
        if len(layers) == 1:
            layer, count = next(iter(layers.items()))
            single_layer.append(
                {"technique": technique, "layer": layer, "rule_count": count}
            )
    single_layer.sort(key=lambda e: -e["rule_count"])

    blind_spots = []
    for technique, label in CONTROL_PLANE_TECHNIQUES.items():
        layers = by_technique.get(technique)
        if not layers:
            blind_spots.append(
                {
                    "technique": technique,
                    "name": label,
                    "rule_count": 0,
                    "status": "no rules in corpus",
                    "layers": {},
                }
            )
            continue
        control = layers.get("cloud_control_plane", 0) + layers.get("identity", 0)
        endpoint = layers.get("endpoint_process", 0)
        total_rules = sum(layers.values())
        if control == 0 and set(layers) == {"endpoint_process"}:
            status = "covered only at the endpoint process layer"
        elif control == 0:
            status = "no control-plane coverage"
        elif endpoint > control:
            status = "endpoint-weighted"
        else:
            status = "control-plane covered"
        blind_spots.append(
            {
                "technique": technique,
                "name": label,
                "rule_count": total_rules,
                "status": status,
                "layers": dict(sorted(layers.items())),
            }
        )
    blind_spots.sort(key=lambda e: (e["status"] != "covered only at the endpoint process layer", -e["rule_count"]))

    return {
        "rules_analyzed": total,
        "rules_with_attack_technique": rules_with_technique,
        "techniques_covered": len(by_technique),
        "layer_totals": dict(sorted(layer_totals.items(), key=lambda kv: -kv[1])),
        "layer_share": {
            layer: round(count / total, 4) for layer, count in sorted(layer_totals.items())
        }
        if total
        else {},
        "single_layer_techniques": single_layer[:60],
        "single_layer_technique_count": len(single_layer),
        "control_plane_assessment": blind_spots,
        "interpretation": (
            "A technique covered by rules on a single layer is covered for one execution "
            "path. For cloud and container techniques the authoritative record is a "
            "control-plane audit log, so process-creation-only coverage detects the subset "
            "of adversaries who use a command-line client rather than an SDK."
        ),
    }


def load_local(rules_dir: Path) -> List[Dict[str, Any]]:
    parsed = []
    for path in sorted(Path(rules_dir).glob("**/*.yml")):
        rule = parse_rule(path.read_text(encoding="utf-8"), path.name)
        if rule:
            parsed.append(rule)
    return parsed


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rules", type=Path, default=ROOT / "rules" / "sigma")
    parser.add_argument("--git-corpus", metavar="URL")
    parser.add_argument("--path-prefix", default="")
    parser.add_argument("--label", default="")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--no-write", action="store_true")
    args = parser.parse_args(argv)

    acquisition = None
    if args.git_corpus:
        try:
            read = read_rule_corpus(args.git_corpus, path_prefix=args.path_prefix)
        except CorpusError as exc:
            print(f"[-] {exc}", file=sys.stderr)
            return 2
        acquisition = read.to_dict()
        rules = [r for r in (parse_rule(t, n) for n, t in read.files) if r]
        label = args.label or args.git_corpus.rstrip("/").split("/")[-1]
    else:
        if not args.rules.is_dir():
            print(f"[-] no rule directory at {args.rules}", file=sys.stderr)
            return 2
        rules = load_local(args.rules)
        label = args.label or args.rules.name

    if not rules:
        print("[-] no parseable rules", file=sys.stderr)
        return 2

    report = build_map(rules)
    report["corpus"] = label
    report["generated"] = date.today().isoformat()
    if acquisition:
        report["acquisition"] = acquisition

    print(f"corpus:                  {label}")
    print(f"rules analyzed:          {report['rules_analyzed']}")
    print(f"techniques covered:      {report['techniques_covered']}")
    print(f"single-layer techniques: {report['single_layer_technique_count']}")
    print("\nrules by telemetry layer:")
    for layer, count in report["layer_totals"].items():
        share = report["layer_share"].get(layer, 0.0)
        print(f"  {count:>6}  {share * 100:5.1f}%  {layer}")

    print("\ncontrol-plane techniques, where their coverage sits:")
    for entry in report["control_plane_assessment"]:
        layers = ", ".join(f"{k}={v}" for k, v in entry["layers"].items()) or "none"
        print(f"  {entry['technique']:<10} {entry['status']:<38} [{layers}]")

    if not args.no_write:
        args.out.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)
        path = args.out / f"telemetry_coverage_{safe}.json"
        path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        disp = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        print(f"\nwrote {disp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
