import unittest
from datetime import datetime, timedelta, timezone

from yapp.core.ad_analyzer import ADGraph
from yapp.core.ad_posture import (
    ADAnalysisPolicy,
    _dcsync_findings,
    analyze_ad_posture,
)


class ADPostureTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 7, 14, tzinfo=timezone.utc)
        self.graph = ADGraph()
        self.graph.add_node(
            "S-1-5-21-1-512",
            "Group",
            {"name": "DOMAIN ADMINS@CORP.LOCAL", "highvalue": True},
        )
        self.graph.add_node(
            "S-1-5-21-1-525",
            "Group",
            {"name": "PROTECTED USERS@CORP.LOCAL"},
        )
        self.graph.add_node("NESTED", "Group", {"name": "TIER ZERO ADMINS"})
        self.graph.add_node("HELPDESK", "Group", {"name": "HELPDESK"})
        self.graph.add_node("SYNC", "Group", {"name": "SYNC OPERATORS"})
        self.graph.add_node("D1", "Domain", {"name": "CORP.LOCAL", "highvalue": True})

        self.graph.add_node(
            "U1",
            "User",
            {"name": "ALICE@CORP.LOCAL", "samaccountname": "alice", "enabled": True},
        )
        self.graph.add_node(
            "U2",
            "User",
            {
                "name": "BOB@CORP.LOCAL",
                "samaccountname": "bob",
                "enabled": True,
                "pwdlastset": self._days_ago(400),
            },
        )
        self.graph.add_node(
            "U3",
            "User",
            {"name": "CAROL@CORP.LOCAL", "samaccountname": "carol", "enabled": True},
        )
        self.graph.add_node(
            "S-1-5-21-1-502",
            "User",
            {
                "name": "KRBTGT@CORP.LOCAL",
                "samaccountname": "krbtgt",
                "enabled": False,
                "pwdlastset": self._days_ago(200),
            },
        )
        self.graph.add_node(
            "C1",
            "Computer",
            {
                "name": "LEGACYWORKSTATION.CORP.LOCAL",
                "samaccountname": "LEGACYWORKSTATION$",
                "enabled": True,
                "whencreated": self._days_ago(100),
                "pwdlastset": self._days_ago(100) + 3600,
            },
        )

        self.graph.add_edge("U1", "S-1-5-21-1-512", "MemberOf")
        self.graph.add_edge("U1", "S-1-5-21-1-525", "MemberOf")
        self.graph.add_edge("U2", "NESTED", "MemberOf")
        self.graph.add_edge("NESTED", "S-1-5-21-1-512", "MemberOf")
        self.graph.add_edge("C1", "S-1-5-21-1-512", "MemberOf")
        self.graph.add_edge("U3", "HELPDESK", "MemberOf")
        self.graph.add_edge("HELPDESK", "S-1-5-21-1-512", "GenericAll")
        self.graph.add_edge("U2", "SYNC", "MemberOf")
        self.graph.add_edge("SYNC", "D1", "GetChanges")
        self.graph.add_edge("SYNC", "D1", "GetChangesAll")

    def _days_ago(self, days):
        return int((self.now - timedelta(days=days)).timestamp())

    def test_reports_requested_posture_findings(self):
        result = analyze_ad_posture(
            self.graph,
            ADAnalysisPolicy(max_domain_admins=1),
            now=self.now,
        )
        finding_ids = {finding["id"] for finding in result["findings"]}

        self.assertTrue(
            {
                "ad.groups.excessive_domain_admins",
                "ad.privilege.user_not_protected_users",
                "ad.password.user_password_old",
                "ad.password.krbtgt_password_old",
                "ad.privilege.computer_in_administrative_group",
                "ad.kerberos.timeroast_candidate",
                "ad.permissions.control_over_high_privilege",
                "ad.permissions.dcsync",
            }.issubset(finding_ids)
        )

    def test_administrative_inventory_preserves_transitive_membership(self):
        result = analyze_ad_posture(self.graph, now=self.now)
        bob = next(
            item
            for item in result["memberships"]
            if item["principal"]["id"] == "U2"
            and item["group"]["id"] == "S-1-5-21-1-512"
        )

        self.assertEqual("transitive", bob["membership"])
        self.assertEqual(["NESTED"], [node["id"] for node in bob["via"]])

    def test_acl_inventory_expands_effective_group_members(self):
        result = analyze_ad_posture(self.graph, now=self.now)
        permission = next(
            item
            for item in result["permissions"]
            if item["principal"]["id"] == "HELPDESK"
        )

        self.assertEqual("GenericAll", permission["relationship"])
        self.assertEqual(
            ["U3"],
            [entity["id"] for entity in permission["effective_principals"]],
        )
        self.assertEqual("direct", permission["effective_paths"][0]["membership"])
        self.assertEqual([], permission["effective_paths"][0]["via"])

    def test_computer_membership_finding_preserves_membership_path(self):
        result = analyze_ad_posture(self.graph, now=self.now)
        finding = next(
            item for item in result["findings"]
            if item["id"] == "ad.privilege.computer_in_administrative_group"
        )

        membership = finding["evidence"][0]["memberships"][0]
        self.assertEqual("direct", membership["membership"])
        self.assertEqual("S-1-5-21-1-512", membership["group"]["id"])
        self.assertEqual([], membership["via"])

    def test_dcsync_path_includes_membership_and_composite_edge(self):
        result = analyze_ad_posture(self.graph, now=self.now)
        path = next(
            path
            for path in result["dcsync_paths"]
            if path["source"]["id"] == "U2"
        )

        self.assertEqual(["MemberOf", "DCSync"], path["edges"])
        self.assertEqual(["U2", "SYNC", "D1"], [node["id"] for node in path["nodes"]])

    def test_dcsync_combines_rights_inherited_from_multiple_groups(self):
        graph = ADGraph()
        graph.add_node("U1", "User", {"name": "alice"})
        graph.add_node("G1", "Group", {"name": "replication readers"})
        graph.add_node("G2", "Group", {"name": "replication all"})
        graph.add_node("D1", "Domain", {"name": "corp.local"})
        graph.add_edge("U1", "G1", "MemberOf")
        graph.add_edge("U1", "G2", "MemberOf")
        graph.add_edge("G1", "D1", "GetChanges")
        graph.add_edge("G2", "D1", "GetChangesAll")

        result = analyze_ad_posture(graph, now=self.now)
        finding = next(
            item
            for item in result["findings"]
            if item["id"] == "ad.permissions.dcsync"
        )

        self.assertEqual("U1", finding["entities"][0]["id"])
        self.assertEqual(2, len(finding["evidence"][0]["grants"]))

    def test_dcsync_does_not_walk_unrelated_principals(self):
        class UnusedMemberships(dict):
            def get(self, *_args, **_kwargs):
                raise AssertionError("unrelated membership traversal")

        graph = ADGraph()
        for index in range(100):
            graph.add_node(f"U{index}", "User", {"name": f"user{index}"})

        findings, paths = _dcsync_findings(
            graph, UnusedMemberships(), {}, set()
        )

        self.assertEqual([], findings)
        self.assertEqual([], paths)

    def test_timeroast_evidence_uses_legacy_machine_password_shape(self):
        result = analyze_ad_posture(self.graph, now=self.now)
        finding = next(
            item
            for item in result["findings"]
            if item["id"] == "ad.kerberos.timeroast_candidate"
        )

        self.assertEqual(
            "legacyworkstat",
            finding["evidence"][0]["legacy_password_candidate"],
        )


if __name__ == "__main__":
    unittest.main()
