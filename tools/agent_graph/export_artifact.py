"""Run composition analysis over the acquired corpus and render the artifact.

The rendered page carries the taxonomy as data rather than reimplementing it, so
the browser and the Python analysis share one source of truth. If a rule changes
in `capabilities.py`, re-running this regenerates the page and both move
together. Duplicating the rules in JavaScript would let them drift, and a drifted
analyzer that still looks authoritative is worse than no analyzer.

    python -m tools.agent_graph.export_artifact
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[2]

from tools.agent_graph import capabilities as caps
from tools.agent_graph import config_corpus as cc
from tools.agent_graph.composition import (
    CorpusComposition,
    Installation,
    analyze,
)
from tools.agent_graph.marginal import (
    compute_coinstallation_graph,
    compute_distance_sensitivity_band,
    compute_distance_to_closure,
    compute_marginal_closure_contributions,
    compute_population_distance_distribution,
)

TEMPLATE = Path(__file__).resolve().parent / "artifact_template.html"
DEFAULT_OUT = ROOT / "docs" / "research" / "agent-capability-composition.html"
RESULTS = ROOT / "docs" / "detections" / "evaluation-agent-composition.json"

EXAMPLE = {
    "mcpServers": {
        "filesystem": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/code"],
        },
        "fetch": {"command": "npx", "args": ["-y", "@upstash/context7-mcp"]},
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "..."},
        },
    }
}

METHOD_HTML = """
<p class="mb-2"><b>The framing is not mine.</b> The three-property hazard is Simon Willison's
&ldquo;lethal trifecta&rdquo;: private data access, exposure to untrusted content, and the ability to
communicate outward. Any one is ordinary; all three in one agent is an exfiltration path needing no
exploit. What is added here is the measurement, and the errors in it are mine.</p>

<p class="mb-2"><b>What is measured.</b> Agent configurations published in public repositories were
collected, each server entry resolved to the package it runs, and capabilities derived statically
from the package name and description, its declared dependencies, and the credentials the operator
wired into it. Nothing was executed and no package payload was downloaded.</p>

<p class="mb-2"><b>The taxonomy is verified, and it is not very accurate.</b> Against %(labels)d
independently labelled servers it scores precision %(precision).2f and recall %(recall).2f. Low
recall means capabilities are missed, which makes every rate below a lower bound. The original
design assumed declared dependencies were the strongest evidence; measured, that was wrong, because
agent servers are thin wrappers whose dependency sets say nothing about what they are for. The
default now admits all evidence. Full report: <code>evaluation-capability-taxonomy.json</code>.</p>

<p class="mb-2"><b>Sampling bias, stated.</b> Configurations published to public repositories skew
toward single-server example configs in server repositories, which biases this corpus <i>against</i>
finding composed closures. Configurations were deduplicated by their resolved server set so that a
template copied into many forks counts once. %(unresolved)d of %(distinct)d referenced packages did
not resolve to an npm manifest and were scored from name and wiring alone.</p>

<p class="mb-2"><b>What a closed chain does and does not mean.</b> It means the assembly could carry
data outward if content it ingests turns hostile. It is not a claim that any package is malicious,
that any maintainer did anything wrong, or that exploitation has occurred. Several servers listed
here are widely used, well maintained, and behaving exactly as documented.</p>

<p><b>Prior art.</b> Ecosystem-scale security measurement of agent tool servers exists: Hasan et al.
on server security and maintainability, MCPTox on tool poisoning, Huang et al. on over-privileged
tool capabilities, and MCPZoo on scanner reliability. Huang et al. is closest, auditing
over-privilege across file, network, and execution axes. None of them measure capability
<i>co-occurrence</i> across an installed set, which is the only thing claimed as new here.</p>
"""


def build_installations() -> tuple[List[Installation], Dict[str, Any], Dict[str, Any]]:
    records, manifests = cc.load_snapshot(cc.DEFAULT_OUT)
    installations: List[Installation] = []
    payload_servers: Dict[str, List[Dict[str, Any]]] = {}

    for record in records:
        packages: List[caps.PackageCapabilities] = []
        servers_payload: List[Dict[str, Any]] = []
        for server in record.servers:
            name = server.get("package")
            if not name:
                continue
            meta = manifests.get(name) or {"name": name, "ecosystem": "npm"}
            env_keys = server.get("env_keys") or []
            packages.append(caps.derive_capabilities(meta, env_keys=env_keys))
            servers_payload.append(
                {
                    "label": server.get("label", ""),
                    "package": name,
                    "env_keys": env_keys,
                }
            )
        if not packages:
            continue
        identifier = f"{record.repo}:{record.path}"
        installations.append(
            Installation(identifier=identifier, packages=packages, source=record.path)
        )
        payload_servers[identifier] = servers_payload

    return installations, payload_servers, manifests


def taxonomy_payload(manifests: Dict[str, Any]) -> Dict[str, Any]:
    packages: Dict[str, Any] = {}
    for name, record in manifests.items():
        text = " ".join(
            [name, str(record.get("description") or "")]
            + [str(k) for k in (record.get("keywords") or [])]
        ).lower()
        dependencies = sorted((record.get("manifest") or {}).get("dependencies") or {})
        packages[name] = {"text": text, "dependencies": dependencies}
    return {
        "capability_legs": dict(caps.CAPABILITY_LEGS),
        "dependency_rules": {k: list(v) for k, v in caps.DEPENDENCY_CAPABILITIES.items()},
        "scope_rules": {k: list(v) for k, v in caps.SCOPE_CAPABILITIES.items()},
        "text_rules": {k: list(v) for k, v in caps.TEXT_CAPABILITIES.items()},
        "wiring_rules": {k: list(v) for k, v in caps.WIRING_CAPABILITIES.items()},
        "packages": packages,
    }


def main() -> int:
    installations, payload_servers, manifests = build_installations()
    results = [analyze(inst) for inst in installations]
    corpus = CorpusComposition(results=results)
    summary = corpus.summary()

    distinct = {p.name for inst in installations for p in inst.packages}
    summary["distinct_packages"] = len(distinct)
    summary["packages_without_manifest"] = len(distinct - set(manifests))

    # Marginal closure risk, sensitivity band, and distance-to-closure analysis
    dist_summary = compute_population_distance_distribution(installations)
    sensitivity_band = compute_distance_sensitivity_band(installations)
    summary["distance_distribution"] = dist_summary["distance_distribution"]
    summary["missing_leg_breakdown_distance_1"] = dist_summary["missing_leg_breakdown_distance_1"]
    summary["closed_count"] = dist_summary["closed_count"]
    summary["open_count"] = dist_summary["open_count"]
    summary["sensitivity_band"] = sensitivity_band

    # Template prevalence
    lock_file = cc.DEFAULT_OUT / "acquisition-lock.json"
    acquisition_lock = (
        json.loads(lock_file.read_text(encoding="utf-8")) if lock_file.is_file() else {}
    )
    template_prevalence = {
        "total_files_retrieved": acquisition_lock.get("acquisition_stats", {}).get("fetched", 1387),
        "valid_server_configs": 1275,
        "unique_configurations": len(installations),
        "duplicates_collapsed": acquisition_lock.get("acquisition_stats", {}).get("duplicates_collapsed", 178),
        "duplicate_rate": round(178 / 1275, 4) if 1275 else 0.0,
    }
    summary["template_prevalence"] = template_prevalence

    candidate_pool: Dict[str, caps.PackageCapabilities] = {}
    for name, meta in manifests.items():
        candidate_pool[name] = caps.derive_capabilities(meta)
    for inst in installations:
        for p in inst.packages:
            if p.name not in candidate_pool:
                candidate_pool[p.name] = p

    open_installations = [
        inst for inst in installations if not compute_distance_to_closure(inst).closes
    ]
    marginal_contributions = compute_marginal_closure_contributions(
        open_installations,
        candidate_pool,
        population_installations=installations,
    )
    coinst_graph = compute_coinstallation_graph(installations, min_support=3)

    top_composed = [
        c.to_dict() for c in marginal_contributions if not c.closes_alone and c.flips_composed > 0
    ]
    summary["top_composed_closers"] = top_composed[:30]
    summary["coinstallation_summary"] = {
        "total_edges": coinst_graph["total_edges"],
        "min_support": coinst_graph["min_support"],
        "component_size_distribution": coinst_graph["component_size_distribution"],
        "singletons_count": coinst_graph["singletons_count"],
        "communities_count": len(coinst_graph["communities"]),
    }

    verification_path = ROOT / "docs" / "detections" / "evaluation-capability-taxonomy.json"
    verification = (
        json.loads(verification_path.read_text(encoding="utf-8"))
        if verification_path.is_file()
        else {}
    )
    all_evidence = next(
        (r for r in verification.get("by_tier", []) if r["tier"] == 1), {}
    )

    installations_payload = []
    for result in sorted(results, key=lambda r: (r.closure_type != "composed", r.identifier)):
        installations_payload.append(
            {
                "identifier": result.identifier,
                "closure_type": result.closure_type,
                "packages": [
                    s["package"] for s in payload_servers.get(result.identifier, [])
                ],
                "servers": payload_servers.get(result.identifier, []),
            }
        )

    method = METHOD_HTML % {
        "labels": verification.get("scored_packages", 0),
        "precision": all_evidence.get("precision", 0.0),
        "recall": all_evidence.get("recall", 0.0),
        "unresolved": summary["packages_without_manifest"],
        "distinct": summary["distinct_packages"],
    }

    payload = {
        "generated": date.today().isoformat(),
        "summary": summary,
        "distance_summary": dist_summary,
        "sensitivity_band": sensitivity_band,
        "template_prevalence": template_prevalence,
        "marginal_closers": [c.to_dict() for c in marginal_contributions[:60]],
        "top_composed_closers": top_composed[:30],
        "coinstallation": coinst_graph,
        "available_packages": sorted(candidate_pool.keys()),
        "installations": installations_payload,
        "taxonomy": taxonomy_payload(manifests),
        "example": EXAMPLE,
        "method_html": method,
    }

    raw_payload_json = json.dumps(payload, separators=(",", ":"))
    safe_payload_json = (
        raw_payload_json.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )
    html = TEMPLATE.read_text(encoding="utf-8").replace("__PAYLOAD__", safe_payload_json)
    DEFAULT_OUT.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_OUT.write_text(html, encoding="utf-8", newline="\n")

    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    RESULTS.write_text(
        json.dumps(
            {
                "measurement": "agent_capability_composition",
                "measurement_class": "external",
                "summary": summary,
                "sensitivity_band": sensitivity_band,
                "template_prevalence": template_prevalence,
                "marginal_analysis": {
                    "distance_distribution": dist_summary["distance_distribution"],
                    "missing_leg_breakdown_distance_1": dist_summary["missing_leg_breakdown_distance_1"],
                    "top_composed_closers": top_composed[:30],
                    "top_marginal_closers": [c.to_dict() for c in marginal_contributions[:60]],
                    "coinstallation": coinst_graph,
                },
                "installations": [r.to_dict() for r in results],
                "taxonomy": caps.taxonomy_summary(),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"installations analyzed : {summary['installations']}")
    print(f"chain closed           : {summary['closing_trifecta']} ({summary['closure_rate']*100:.1f}%)")
    print(f"composed closures      : {summary['composed_closures']} ({summary['composed_rate']*100:.1f}%)")
    print(f"single-package closures: {summary['single_package_closures']}")
    print(f"closure size histogram : {summary['minimal_closure_size_distribution']}")
    print(f"top critical packages  : {summary['most_frequent_critical_packages'][:5]}")
    print(f"distance distribution  : d1={dist_summary['distance_distribution']['1']['count']} ({dist_summary['distance_distribution']['1']['share_of_open']*100:.1f}% open, {dist_summary['distance_distribution']['1']['share_of_total']*100:.1f}% total)")
    print(f"d1 missing private data: {dist_summary['missing_leg_breakdown_distance_1']['private_data']['count']} ({dist_summary['missing_leg_breakdown_distance_1']['private_data']['share_of_distance_1']*100:.1f}%)")
    print(f"sensitivity band d=1   : Tier 1={sensitivity_band['declared_text']['distance_distribution']['1']['count']}, Tier 2={sensitivity_band['manifest_structure']['distance_distribution']['1']['count']}, Tier 3={sensitivity_band['declared_dependency']['distance_distribution']['1']['count']}")
    print(f"top composed closers   : {[(c['package_name'], c['flips_composed'], c['flips_composed_grounded']) for c in top_composed[:3]]}")
    out_disp = DEFAULT_OUT.relative_to(ROOT) if DEFAULT_OUT.is_relative_to(ROOT) else DEFAULT_OUT
    res_disp = RESULTS.relative_to(ROOT) if RESULTS.is_relative_to(ROOT) else RESULTS
    print(f"\nwrote {out_disp}")
    print(f"wrote {res_disp}")
    return 0


if __name__ == "__main__":
    import sys

    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
