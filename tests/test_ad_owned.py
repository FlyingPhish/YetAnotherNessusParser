import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from yapp.core.ad_analyzer import ADGraph, load_bloodhound_zip
from yapp.core.ad_owned import analyze_owned_principals, resolve_owned_principals


class OwnedPrincipalTests(unittest.TestCase):
    def setUp(self):
        self.graph = ADGraph()
        self.graph.add_node(
            "S-1-5-21-1000",
            "User",
            {
                "name": "ALICE@CORP.LOCAL",
                "samaccountname": "alice",
                "userprincipalname": "alice@corp.local",
                "domain": "CORP.LOCAL",
            },
        )
        self.graph.add_node("C1", "Computer", {"name": "WKSTN01.CORP.LOCAL"})
        self.graph.add_node("G1", "Group", {"name": "DOMAIN ADMINS@CORP.LOCAL"})
        self.graph.add_edge("S-1-5-21-1000", "C1", "AdminTo")
        self.graph.add_edge("S-1-5-21-1000", "G1", "UnknownFutureEdge")

    def test_resolves_sid_upn_and_domain_sam_without_duplicates(self):
        result = resolve_owned_principals(
            self.graph,
            ["S-1-5-21-1000", "alice@corp.local", "corp.local\\alice"],
        )
        self.assertEqual(1, len(result["resolved"]))
        self.assertEqual([], result["unresolved"])

    def test_reports_ambiguous_short_name(self):
        self.graph.add_node(
            "S-1-5-21-2000",
            "User",
            {"name": "ALICE@CHILD.LOCAL", "samaccountname": "alice"},
        )
        result = resolve_owned_principals(self.graph, ["alice"])
        self.assertEqual([], result["resolved"])
        self.assertEqual(1, len(result["ambiguous"]))
        self.assertEqual(2, len(result["ambiguous"][0]["candidates"]))

    def test_maps_only_allow_listed_direct_control(self):
        result = analyze_owned_principals(self.graph, ["alice@corp.local"])
        principal = result["principals"][0]
        self.assertEqual(1, principal["direct_control_count"])
        self.assertEqual("AdminTo", principal["direct_controls"][0]["relationship"])
        self.assertEqual("ad.owned.outbound_control", result["findings"][0]["id"])


class RelationshipDirectionTests(unittest.TestCase):
    def test_session_direction_is_computer_to_user(self):
        collection = {
            "meta": {"type": "computers"},
            "data": [
                {
                    "ObjectIdentifier": "C1",
                    "Properties": {"name": "WKSTN01.CORP.LOCAL"},
                    "Sessions": [{"ComputerSID": "C1", "UserSID": "U1"}],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "collection.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("computers.json", json.dumps(collection))
            graph = load_bloodhound_zip(archive_path)

        session = next(edge for edge in graph.edges if edge.kind == "HasSession")
        self.assertEqual("C1", session.source)
        self.assertEqual("U1", session.target)


if __name__ == "__main__":
    unittest.main()
