import json
import tempfile
import unittest
from pathlib import Path

from yapp.config import get_default_ad_rules_path
from yapp.core.ad_excel import _collect_paths, _excel_value
from yapp.core.ad_reporting import (
    ADAPIFormatter,
    ADReportingError,
    load_ad_rules,
    map_ad_findings,
)


class ADReportingTests(unittest.TestCase):
    def setUp(self):
        self.report = {
            "findings": [
                {
                    "id": "ad.kerberos.asrep_roastable",
                    "severity": "high",
                    "title": "AS-REP roastable",
                    "entities": [
                        {"id": "U1", "type": "User", "name": "<admin>@corp.local"}
                    ],
                    "evidence": [],
                },
                {
                    "id": "ad.kerberos.asrep_roastable",
                    "severity": "high",
                    "title": "AS-REP roastable",
                    "entities": [
                        {"id": "U2", "type": "User", "name": "=cmd"}
                    ],
                    "evidence": [],
                },
                {
                    "id": "ad.password.user_password_never_expires",
                    "severity": "medium",
                    "title": "Password never expires",
                    "entities": [
                        {"id": "U3", "type": "User", "name": "svc@corp.local"}
                    ],
                    "evidence": [],
                },
            ]
        }

    def _write_rules(self, rules):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "ad-rules.json"
        path.write_text(json.dumps({"ad_rules": rules}), encoding="utf-8")
        return path

    def test_default_catalog_covers_all_current_finding_ids(self):
        rules = load_ad_rules(str(get_default_ad_rules_path()))
        finding_ids = {
            finding_id
            for rule in rules
            for finding_id in rule["finding_ids"]
        }
        self.assertEqual(
            {
                "ad.kerberos.asrep_roastable",
                "ad.kerberos.kerberoastable",
                "ad.kerberos.unconstrained_delegation",
                "ad.password.user_password_never_expires",
                "ad.owned.outbound_control",
                "ad.owned.path_to_high_value",
                "ad.permissions.path_to_high_value",
            },
            finding_ids,
        )
        self.assertTrue(
            all(rule["internal_vulnerability_id"] is None for rule in rules)
        )
        mapped = map_ad_findings(self.report, rules)
        self.assertEqual([], ADAPIFormatter().format(mapped))

    def test_exact_mappings_produce_existing_stock_api_contract(self):
        path = self._write_rules(
            [
                {
                    "rule_name": "asrep",
                    "internal_vulnerability_id": 412,
                    "finding_ids": ["ad.kerberos.asrep_roastable"],
                },
                {
                    "rule_name": "password_policy",
                    "internal_vulnerability_id": 412,
                    "finding_ids": ["ad.password.user_password_never_expires"],
                },
            ]
        )

        mapped = map_ad_findings(self.report, load_ad_rules(str(path)))
        output = ADAPIFormatter().format(mapped)

        self.assertEqual(1, len(output))
        self.assertEqual({"type", "finding_id", "affected_entities"}, set(output[0]))
        self.assertEqual(412, output[0]["finding_id"])
        self.assertIn("&lt;admin&gt;@corp.local", output[0]["affected_entities"])
        self.assertIn("svc@corp.local", output[0]["affected_entities"])

    def test_duplicate_finding_mapping_is_rejected(self):
        path = self._write_rules(
            [
                {
                    "rule_name": "first",
                    "internal_vulnerability_id": 1,
                    "finding_ids": ["ad.test"],
                },
                {
                    "rule_name": "second",
                    "internal_vulnerability_id": 2,
                    "finding_ids": ["ad.test"],
                },
            ]
        )
        with self.assertRaises(ADReportingError):
            load_ad_rules(str(path))

    def test_non_boolean_rule_flags_are_rejected(self):
        path = self._write_rules(
            [
                {
                    "rule_name": "bad",
                    "internal_vulnerability_id": 1,
                    "finding_ids": ["ad.test"],
                    "api_output": "false",
                }
            ]
        )
        with self.assertRaises(ADReportingError):
            load_ad_rules(str(path))

    def test_entity_limit_matches_current_external_document_contract(self):
        mapped = [
            {
                "internal_vulnerability_id": 1,
                "api_output": True,
                "affected_entities": [
                    {"id": "U1", "type": "User", "name": "one"},
                    {"id": "U2", "type": "User", "name": "two"},
                ],
            }
        ]
        output = ADAPIFormatter(entity_limit=1).format(mapped)
        self.assertEqual(
            "<p>Please refer to external document named 'replaceMe'.csv</p>",
            output[0]["affected_entities"],
        )

    def test_excel_values_neutralize_formula_injection(self):
        self.assertEqual("'=cmd", _excel_value("=cmd"))
        self.assertEqual("'+SUM(A1:A2)", _excel_value("+SUM(A1:A2)"))
        self.assertEqual("normal", _excel_value("normal"))
        self.assertEqual("bad", _excel_value("bad" + chr(0)))
        self.assertLessEqual(len(_excel_value("a" * 40000)), 32767)

    def test_paths_are_deduplicated_between_report_sections(self):
        path = {
            "source": {"id": "U1", "name": "alice"},
            "target": {"id": "G1", "name": "admins"},
            "nodes": [],
            "edges": ["GenericAll"],
        }
        report = {
            "owned_analysis": {"paths": [path]},
            "findings": [
                {"id": "ad.owned.path_to_high_value", "evidence": [path]}
            ],
        }
        self.assertEqual(1, len(_collect_paths(report)))


if __name__ == "__main__":
    unittest.main()
