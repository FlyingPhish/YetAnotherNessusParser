import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from yapp.core.ad_analyzer import ADGraph
from yapp.core.ad_config import normalize_sensitive_groups
from yapp.core.ad_operator import analyze_operator_data
from yapp.core.ad_posture import ADAnalysisPolicy, build_privilege_context


class ADOperatorTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 7, 15, tzinfo=timezone.utc)
        self.graph = ADGraph()
        self.graph.add_node("DA", "Group", {"name": "Domain Admins@CORP.LOCAL"})
        self.graph.add_node("DCG", "Group", {"name": "Domain Controllers@CORP.LOCAL"})
        self.graph.add_node("SOC", "Group", {"name": "SOC Operators@CORP.LOCAL"})
        self.graph.add_node("UDA", "User", {"name": "admin@corp.local", "enabled": True})
        self.graph.add_node(
            "U1",
            "User",
            {
                "name": "alice@corp.local",
                "enabled": True,
                "passwordnotrequired": True,
                "userpassword": "must-never-appear",
                "lastlogontimestamp": self._days_ago(120),
            },
        )
        for computer_id in ("C1", "C2"):
            self.graph.add_node(
                computer_id,
                "Computer",
                {
                    "name": f"{computer_id.lower()}.corp.local",
                    "enabled": True,
                    "haslaps": False,
                    "lastlogontimestamp": self._days_ago(1),
                },
            )
        self.graph.add_node(
            "DC1",
            "Computer",
            {"name": "dc1.corp.local", "enabled": True, "isdc": True},
        )
        self.graph.add_node("CA1", "EnterpriseCA", {"name": "CORP-CA@CORP.LOCAL"})

        self.graph.add_edge("UDA", "DA", "MemberOf")
        self.graph.add_edge("DC1", "DCG", "MemberOf")
        self.graph.add_edge("U1", "SOC", "MemberOf")
        self.graph.add_edge("UDA", "C1", "AdminTo")
        self.graph.add_edge("SOC", "C1", "AdminTo")
        self.graph.add_edge("SOC", "C2", "AdminTo")
        self.graph.add_edge("C2", "C1", "AdminTo")
        self.graph.add_edge("SOC", "DC1", "AllowedToAct")
        self.graph.add_edge("C1", "UDA", "HasSession")
        self.graph.add_edge("SOC", "CA1", "GenericAll")

        registry = normalize_sensitive_groups()
        registry.append({
            "key": "soc_operators",
            "names": ["soc operators"],
            "sid_suffixes": [],
            "classification": "sensitive",
            "expected_admin": False,
        })
        self.context = build_privilege_context(self.graph, registry)

    def _days_ago(self, days):
        return int((self.now - timedelta(days=days)).timestamp())

    def test_filters_expected_admins_but_keeps_custom_sensitive_access(self):
        result = analyze_operator_data(
            self.graph,
            self.context,
            ADAnalysisPolicy(max_local_admin_hosts=1),
            now=self.now,
        )
        grants = {item["granted_to"]["id"] for item in result["fleet_access"]}

        self.assertNotIn("UDA", grants)
        self.assertIn("SOC", grants)
        self.assertIn("C2", grants)
        finding_ids = {item["id"] for item in result["findings"]}
        self.assertIn("ad.permissions.excessive_local_admin_fanout", finding_ids)
        self.assertIn("ad.permissions.computer_local_admin", finding_ids)

    def test_hygiene_delegation_session_and_adcs_are_risk_scored(self):
        result = analyze_operator_data(
            self.graph,
            self.context,
            ADAnalysisPolicy(user_dormancy_days=90),
            now=self.now,
        )
        finding_ids = {item["id"] for item in result["findings"]}

        self.assertTrue({
            "ad.password.user_password_not_required",
            "ad.password.cleartext_material_present",
            "ad.accounts.user_dormant",
            "ad.password.computer_without_laps",
            "ad.kerberos.rbcd_to_sensitive",
            "ad.sessions.privileged_user_on_non_dc",
            "ad.permissions.nonprivileged_admin_to_adcs",
        }.issubset(finding_ids))
        self.assertTrue(result["adcs"]["present"])
        self.assertEqual(1, len(result["sessions"]))
        self.assertTrue(result["sessions"][0]["privileged_user"])
        self.assertFalse(result["sessions"][0]["domain_controller"])
        self.assertNotIn("must-never-appear", json.dumps(result))

    def test_group_expansion_is_reused_across_fleet_grants(self):
        with patch(
            "yapp.core.ad_operator._descendant_paths",
            wraps=__import__(
                "yapp.core.ad_operator", fromlist=["_descendant_paths"]
            )._descendant_paths,
        ) as descendant_paths:
            result = analyze_operator_data(
                self.graph, self.context, ADAnalysisPolicy(), now=self.now
            )

        self.assertEqual(2, len([
            row for row in result["fleet_access"]
            if row["granted_to"]["id"] == "SOC"
        ]))
        soc_calls = [
            call for call in descendant_paths.call_args_list
            if call.args[2] == "SOC"
        ]
        self.assertEqual(1, len(soc_calls))

    def test_operator_bounds_full_edge_passes(self):
        class CountingEdges(list):
            iterations = 0

            def __iter__(self):
                self.iterations += 1
                return super().__iter__()

        self.graph.edges = CountingEdges(self.graph.edges)
        result = analyze_operator_data(
            self.graph, self.context, ADAnalysisPolicy(), now=self.now
        )

        self.assertLessEqual(self.graph.edges.iterations, 3)
        sessions = next(
            item for item in result["coverage"] if item["feature"] == "sessions"
        )
        self.assertEqual(1, sessions["observed"])

    def test_coverage_distinguishes_absent_optional_data(self):
        result = analyze_operator_data(
            self.graph,
            self.context,
            ADAnalysisPolicy(),
            now=self.now,
        )
        coverage = {item["feature"]: item for item in result["coverage"]}

        self.assertEqual("partial", coverage["user_last_logon"]["status"])
        self.assertEqual("collected", coverage["sessions"]["status"])
        self.assertEqual("partial", coverage["laps_status"]["status"])


if __name__ == "__main__":
    unittest.main()
