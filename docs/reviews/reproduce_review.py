"""Offline regression specifications from the 2026-09-06 review.

Run with the project's interpreter from any directory. Expected to FAIL against
reviewed code: failures reproduce defects, not repairs. Does not run packages,
access networks, edit production data, or instantiate the endurance runner.
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools.agent_audit import audit_config_data, format_report_text
from tools.agent_graph.capabilities import Evidence, PackageCapabilities, Tier
from tools.agent_graph.composition import Installation, analyze
from tools.agent_graph.config_corpus import extract_package
from tools.agent_watchdog import AgentRegistryWatchdog
from tools.swarm.evaluator import MultiEventEvaluator
from tools.swarm.models import CorrelationRule, CorrelationStage, EventSequence, TelemetryEvent
from tools.swarm.synthesizer import StrategicSynthesizer
from tools.brittleness.metrics import analyze_text
from tools.cti.emit import to_stix_bundle
import uuid


def pkg(name, capabilities):
    return PackageCapabilities(name=name, evidence=[
        Evidence(c, Tier.DECLARED_DEPENDENCY, 'inert-review', 'explicit')
        for c in capabilities
    ])


def event(seconds, host, marker):
    return TelemetryEvent(1, 'Review', f'2026-01-01T00:00:{seconds:02d}Z',
                          {'Computer': host, 'Marker': marker})


def rule(marker):
    return (f'title: Inert review {marker}\nlogsource:\n  category: process_creation\n'
            f'  product: windows\ndetection:\n  selection:\n    Marker: {marker}\n'
            '  condition: selection\n')


class ReviewRegressionSpecifications(unittest.TestCase):
    def test_removal_recommendation_actually_breaks_every_chain(self):
        packages = [pkg('A', ['fs_read', 'web_fetch', 'net_egress']),
                    pkg('B', ['fs_read']), pkg('C', ['web_fetch', 'net_egress'])]
        result = analyze(Installation('review', packages))
        for name in result.critical_packages:
            after = Installation('after', [p for p in packages if p.name != name])
            self.assertFalse(analyze(after).closes, f'Removing {name} leaves a closure')

    def test_npm_range_is_not_exactly_pinned(self):
        findings, _ = audit_config_data({'mcpServers': {'x': {
            'command': 'npx', 'args': ['demo@^1.0.0', '--ignore-scripts']}}}, [], {})
        self.assertIn('supply_chain_unpinned', [f.category for f in findings])

    def test_unsupported_input_is_not_certified_hardened(self):
        findings, summary = audit_config_data({'other_schema': {}}, [], {})
        self.assertNotIn('follows hardening baseline', format_report_text(findings, summary, 'review'))

    def test_pinned_uvx_identity_resolves(self):
        self.assertEqual(extract_package('uvx', ['demo==1.2.3']), 'demo')

    def test_watchdog_accepts_acquisition_manifest_shape(self):
        watchdog = AgentRegistryWatchdog(malicious_lookup={'inert-advisory': 'REVIEW'})
        fields = {'bin': {'x': 'x.js'}, 'scripts': {'postinstall': 'node inert.js'},
                  'dependencies': {'axios': '1'}}
        base = {'name': 'ordinary-widget', 'ecosystem': 'npm'}
        flat = watchdog.evaluate_package({**base, **fields})
        nested = watchdog.evaluate_package({**base, 'manifest': fields})
        self.assertEqual(flat.risk_score, nested.risk_score)

    def test_correlation_respects_group_by(self):
        stages = [CorrelationStage('a', rule_yaml=rule('a')), CorrelationStage('b', rule_yaml=rule('b'))]
        correlation = CorrelationRule('review', stages, timespan_seconds=60, group_by=['Computer'])
        sequence = EventSequence('review', [event(0, 'one', 'a'), event(1, 'two', 'b')])
        self.assertFalse(MultiEventEvaluator().evaluate_correlation(correlation, sequence).matched)

    def test_boolean_alternative_is_not_mandatory_commandline(self):
        source = ('title: Inert review\nlogsource:\n  category: process_creation\n'
                  '  product: windows\ndetection:\n  by_image:\n    Image: harmless.exe\n'
                  '  by_cmd:\n    CommandLine: harmless\n  condition: 1 of by_*\n')
        score = analyze_text(source, 'review.yml')
        self.assertNotEqual(score.dimensions['commandline_dependence'], 1.0)

    def test_stix_bundle_has_uuid_identifier(self):
        value = to_stix_bundle([], '2026-09-06')['id'].split('--', 1)[1]
        try:
            uuid.UUID(value)
        except ValueError:
            self.fail(f'Not a STIX UUID: {value}')

    def test_absent_cluster_evidence_cannot_produce_observed_categories(self):
        synthesizer = StrategicSynthesizer.__new__(StrategicSynthesizer)
        counts = synthesizer._cluster_evasions([], 1000)
        self.assertEqual(sum(counts.values()), 0, 'No source records, yet category counts produced')


if __name__ == '__main__':
    unittest.main(verbosity=2)
