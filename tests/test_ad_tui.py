import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from yapp.core.ad_analyzer import ADGraph
from yapp.tui.ad_app import ADBloodHoundApp
from yapp.tui.ad_indexer import _path_rows, _pivots
from yapp.tui.indexer import build_scan_index
from yapp.tui.screens.ad import ADMissionScreen
from yapp.tui.state import ADIndex


class ADTUIAdapterTests(unittest.TestCase):
    def test_auto_dispatches_zip_to_separate_ad_index(self):
        payload = {
            "meta": {"type": "users"},
            "data": [{
                "ObjectIdentifier": "U1",
                "Properties": {"name": "alice@corp.local", "enabled": True},
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            collection = Path(directory) / "bloodhound.zip"
            with zipfile.ZipFile(collection, "w") as archive:
                archive.writestr("users.json", json.dumps(payload))
            index = build_scan_index(str(collection), include_paths=False)

        self.assertIsInstance(index, ADIndex)
        self.assertEqual("ad", index.parse_options["file_type"])
        self.assertIn("U1", index.nodes)
        self.assertNotIn("findings_rows", vars(index))

    def test_unknown_edges_remain_evidence_only_and_rank_below_allow_list(self):
        base = {
            "source": {"id": "U1", "name": "alice", "type": "User"},
            "target": {"id": "G1", "name": "Domain Admins", "type": "Group"},
            "nodes": [
                {"id": "U1", "name": "alice", "type": "User"},
                {"id": "G1", "name": "Domain Admins", "type": "Group"},
            ],
            "length": 1,
        }
        report = {
            "findings": [{
                "id": "ad.owned.path_to_domain_admin",
                "evidence": [
                    {**base, "edges": ["GenericAll"]},
                    {**base, "edges": ["FutureUnknownEdge"]},
                ],
            }],
            "path_analysis": {"choke_points": []},
        }

        rows = _path_rows(report, {"U1"})

        self.assertEqual(2, len(rows))
        self.assertEqual("GenericAll", rows[0].steps[0].relationship)
        self.assertTrue(rows[0].steps[0].traversable)
        self.assertFalse(rows[1].steps[0].traversable)
        self.assertEqual("evidence", rows[1].steps[0].category)
        self.assertGreater(rows[0].score, rows[1].score)

    def test_ranking_is_deterministic_and_rewards_choke_reuse(self):
        path = {
            "source": {"id": "U1", "name": "alice", "type": "User"},
            "target": {"id": "G1", "name": "Domain Admins", "type": "Group"},
            "nodes": [
                {"id": "U1", "name": "alice", "type": "User"},
                {"id": "G1", "name": "Domain Admins", "type": "Group"},
            ],
            "edges": ["GenericAll"],
        }
        report = {
            "findings": [{
                "id": "ad.owned.path_to_domain_admin",
                "evidence": [path],
            }],
            "path_analysis": {
                "choke_points": [{
                    "source": path["source"],
                    "relationship": "GenericAll",
                    "target": path["target"],
                    "path_count": 4,
                }],
            },
        }

        first = _path_rows(report, {"U1"})
        second = _path_rows(report, {"U1"})

        self.assertEqual(first[0].path_id, second[0].path_id)
        self.assertEqual(4, first[0].choke_count)
        self.assertTrue(first[0].owned)

    def test_owned_pivot_retains_inherited_control_path(self):
        graph = ADGraph()
        graph.add_node("U1", "User", {"name": "alice"})
        graph.add_node("G1", "Group", {"name": "helpdesk"})
        graph.add_node("C1", "Computer", {"name": "server01"})
        report = {
            "owned_analysis": {
                "principals": [{
                    "principal": {"id": "U1", "name": "alice", "type": "User"},
                    "direct_controls": [{
                        "relationship": "AdminTo",
                        "category": "local_admin",
                        "severity": "high",
                        "target": {"id": "C1", "name": "server01", "type": "Computer"},
                        "via": [{"id": "G1", "name": "helpdesk", "type": "Group"}],
                    }],
                }],
            },
        }

        pivot = _pivots(graph, [], report)["U1"]
        control = next(item for item in pivot.outbound if item.relationship == "AdminTo")

        self.assertFalse(control.direct)
        self.assertEqual("G1", control.via[0]["id"])
        self.assertTrue(control.traversable)


class ADTUIScreenTests(unittest.IsolatedAsyncioTestCase):
    async def test_mission_screen_mounts_with_empty_path_queue(self):
        index = ADIndex(
            input_file="collection.zip",
            parse_options={"file_type": "ad", "include_paths": False},
            report={
                "summary": {"critical": 0, "high": 0},
                "privilege_analysis": {"memberships": []},
                "operator_analysis": {"coverage": []},
                "path_analysis": {"choke_points": []},
            },
            paths=[],
            nodes={},
            pivots={},
            assumed_owned=[],
            metadata={
                "source_name": "collection.zip",
                "node_count": 0,
                "edge_count": 0,
                "critical": 0,
                "high": 0,
                "coverage_warnings": 0,
            },
        )
        app = ADBloodHoundApp(index, ".")
        async with app.run_test() as pilot:
            await pilot.pause()
            self.assertIsInstance(app.screen, ADMissionScreen)


if __name__ == "__main__":
    unittest.main()
