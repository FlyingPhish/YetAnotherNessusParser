import unittest

from yapp.core.ad_analyzer import ADGraph
from yapp.core.ad_owned import analyze_owned_principals


class EffectiveControlTests(unittest.TestCase):
    def setUp(self):
        self.graph = ADGraph()
        self.graph.add_node("U1", "User", {"name": "alice@corp.local"})
        self.graph.add_node("G1", "Group", {"name": "helpdesk@corp.local"})
        self.graph.add_node("G2", "Group", {"name": "ops@corp.local"})
        self.graph.add_node("C1", "Computer", {"name": "server01.corp.local"})
        self.graph.add_node("D1", "Domain", {"name": "corp.local"})

    def test_nested_group_right_is_effective_outbound_control(self):
        self.graph.add_edge("U1", "G1", "MemberOf")
        self.graph.add_edge("G1", "G2", "MemberOf")
        self.graph.add_edge("G2", "C1", "GenericAll")

        result = analyze_owned_principals(self.graph, ["alice@corp.local"])
        control = result["principals"][0]["direct_controls"][0]

        self.assertEqual("GenericAll", control["relationship"])
        self.assertEqual("G2", control["granted_to"][0]["id"])
        self.assertEqual(["G1", "G2"], [node["id"] for node in control["via"]])

    def test_group_cycle_is_bounded(self):
        self.graph.add_edge("U1", "G1", "MemberOf")
        self.graph.add_edge("G1", "G2", "MemberOf")
        self.graph.add_edge("G2", "G1", "MemberOf")
        self.graph.add_edge("G2", "C1", "AdminTo")

        result = analyze_owned_principals(self.graph, ["alice@corp.local"])
        self.assertEqual(1, result["principals"][0]["direct_control_count"])

    def test_dcsync_combines_effective_replication_rights(self):
        self.graph.add_edge("U1", "G1", "MemberOf")
        self.graph.add_edge("U1", "D1", "GetChanges")
        self.graph.add_edge("G1", "D1", "GetChangesAll")

        result = analyze_owned_principals(self.graph, ["alice@corp.local"])
        controls = result["principals"][0]["direct_controls"]
        dcsync = next(control for control in controls if control["relationship"] == "DCSync")

        self.assertEqual("critical", dcsync["severity"])
        self.assertEqual(
            ["getchanges", "getchangesall"],
            dcsync["properties"]["composite_rights"],
        )


if __name__ == "__main__":
    unittest.main()
