import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from yapp.core.ad_analyzer import ADGraph, run_direct_rules
from yapp.tui.ad_app import ADBloodHoundApp
from yapp.tui.ad_exposures import build_exposure_rows
from yapp.tui.ad_indexer import _path_rows, _pivots
from yapp.tui.indexer import build_scan_index
from yapp.tui.screens.ad import (
    ADExposureDetailScreen,
    ADExposureQueueScreen,
    ADMissionScreen,
)
from yapp.tui.state import ADExposureRow, ADIndex


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

    def test_exposures_group_broad_membership_privileged_control_and_local_admin(self):
        graph = ADGraph()
        graph.add_node("C1", "Computer", {"name": "ws1"})
        graph.add_node("C2", "Computer", {"name": "ws2"})
        domain_computers = {"id": "GDC", "name": "DOMAIN COMPUTERS@CORP", "type": "Group"}
        administrators = {"id": "GA", "name": "ADMINISTRATORS@CORP", "type": "Group"}
        controller = {"id": "G1", "name": "HELPDESK@CORP", "type": "Group"}
        privileged = {"id": "U2", "name": "ADMIN@CORP", "type": "User"}
        actor = {"id": "U1", "name": "ALICE@CORP", "type": "User"}
        report = {
            "privilege_analysis": {
                "memberships": [
                    {
                        "principal": domain_computers,
                        "group": administrators,
                        "membership": "direct",
                        "via": [],
                    },
                    {
                        "principal": privileged,
                        "group": administrators,
                        "membership": "direct",
                        "via": [],
                    },
                ],
                "permissions": [{
                    "principal": controller,
                    "relationship": "GenericAll",
                    "category": "acl_control",
                    "severity": "high",
                    "target": privileged,
                    "effective_principals": [actor],
                    "effective_paths": [{
                        "principal": actor,
                        "membership": "direct",
                        "via": [],
                    }],
                }],
            },
            "operator_analysis": {
                "fleet_access": [
                    {
                        "relationship": "AdminTo",
                        "granted_to": controller,
                        "principal": actor,
                        "target": {"id": target, "name": target, "type": "Computer"},
                        "via": [],
                    }
                    for target in ("C1", "C2")
                ],
            },
            "findings": [{
                "id": "ad.kerberos.kerberoastable",
                "severity": "high",
                "entities": [actor],
            }, {
                "id": "ad.permissions.shadow_credentials_to_sensitive",
                "severity": "critical",
                "title": "Shadow credentials to sensitive target",
                "description": "A principal can alter key credentials on a sensitive target.",
                "remediation": "Remove the unnecessary right.",
                "entities": [controller, privileged],
            }],
        }

        rows = build_exposure_rows(report, graph, ["U1"])
        by_category = {row.category: row for row in rows}

        self.assertEqual(2, by_category["broad_admin_membership"].effective_count)
        self.assertEqual(1, by_category["privileged_control"].target_count)
        self.assertEqual(1, by_category["privileged_control"].effective_count)
        self.assertTrue(by_category["privileged_control"].owned)
        self.assertEqual(2, by_category["local_admin_access"].target_count)
        self.assertTrue(by_category["local_admin_access"].owned)
        self.assertEqual("Kerberoast", by_category["kerberoastable"].relationship)
        self.assertTrue(by_category["kerberoastable"].owned)
        self.assertEqual(
            "Shadow credentials to sensitive target",
            by_category["security_posture"].summary,
        )

    def test_direct_rules_accept_bloodhound_has_spn_flag(self):
        graph = ADGraph()
        graph.add_node("U1", "User", {"name": "svc_sql", "HasSPN": True})

        finding_ids = {finding["id"] for finding in run_direct_rules(graph)}

        self.assertIn("ad.kerberos.kerberoastable", finding_ids)


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
            self.assertIn(
                "No bounded high-value routes found",
                str(app.screen.query_one("#queue-help").render()),
            )

    async def test_explore_search_endpoints_path_tree_and_graph_mount(self):
        graph = ADGraph()
        graph.add_node("U1", "User", {"name": "alice@corp.local"})
        graph.add_node("G1", "Group", {"name": "helpdesk@corp.local"})
        graph.add_edge("U1", "G1", "MemberOf")
        report = {
            "summary": {"critical": 0, "high": 0},
            "privilege_analysis": {"memberships": []},
            "operator_analysis": {"coverage": []},
            "path_analysis": {"choke_points": []},
        }
        nodes = {
            "U1": {"id": "U1", "name": "alice@corp.local", "type": "User"},
            "G1": {"id": "G1", "name": "helpdesk@corp.local", "type": "Group"},
        }
        index = ADIndex(
            input_file="collection.zip",
            parse_options={"file_type": "ad", "include_paths": False},
            report=report,
            paths=[],
            nodes=nodes,
            pivots=_pivots(graph, [], report),
            assumed_owned=[],
            metadata={"source_name": "collection.zip"},
        )
        app = ADBloodHoundApp(index, ".")
        async with app.run_test(size=(100, 35)) as pilot:
            await pilot.pause()
            screen = app.screen
            screen.action_show_explore()
            screen.query_one("#explore-search").value = "alice"
            await pilot.pause()
            self.assertEqual(1, screen.query_one("#search-results").row_count)

            screen._focus_node("U1")
            screen.action_set_source()
            screen._focus_node("G1")
            screen.action_set_target()
            screen.action_find_explore_path()
            await pilot.pause()

            self.assertEqual("U1", screen.source_id)
            self.assertEqual("G1", screen.target_id)
            self.assertEqual(1, screen.explore_path.length)
            path_tree = screen.query_one("#path-tree")
            self.assertIn(
                "MemberOf",
                str(path_tree.root.children[0].children[0].label),
            )
            self.assertIn(
                "fallback",
                str(screen.query_one("#graph-status").render()).casefold(),
            )

    async def test_pivot_explains_direction_and_returns_to_explore(self):
        graph = ADGraph()
        graph.add_node("U1", "User", {"name": "alice@corp.local"})
        graph.add_node("G1", "Group", {"name": "helpdesk@corp.local"})
        graph.add_edge("U1", "G1", "MemberOf")
        report = {
            "summary": {"critical": 0, "high": 0},
            "privilege_analysis": {"memberships": []},
            "operator_analysis": {"coverage": []},
            "path_analysis": {"choke_points": []},
        }
        index = ADIndex(
            input_file="collection.zip",
            parse_options={"file_type": "ad", "include_paths": False},
            report=report,
            paths=[],
            nodes={
                "U1": {"id": "U1", "name": "alice@corp.local", "type": "User"},
                "G1": {"id": "G1", "name": "helpdesk@corp.local", "type": "Group"},
            },
            pivots=_pivots(graph, [], report),
            assumed_owned=[],
            metadata={"source_name": "collection.zip"},
        )
        app = ADBloodHoundApp(index, ".")
        async with app.run_test(size=(100, 35)) as pilot:
            await pilot.pause()
            app.action_open_ad_node("U1")
            await pilot.pause()
            self.assertIn("ways into", str(app.screen.query_one("#node-direction-help").render()))
            self.assertIsNotNone(app.screen.query_one("#node-graph"))
            app.screen.action_set_source()
            await pilot.pause()
            self.assertIsInstance(app.screen, ADMissionScreen)
            self.assertEqual("U1", app.screen.source_id)

    async def test_exposure_queue_and_detail_mount(self):
        exposure = ADExposureRow(
            exposure_id="E1",
            category="local_admin_access",
            priority="HIGH",
            score=80,
            principal={"id": "U1", "name": "alice", "type": "User"},
            relationship="AdminTo",
            targets=({
                "entity": {"id": "C1", "name": "server01", "type": "Computer"},
                "target_class": "computer",
            },),
            target_count=1,
            effective_count=1,
        )
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
            metadata={"source_name": "collection.zip"},
            exposures=[exposure],
        )
        app = ADBloodHoundApp(index, ".")
        async with app.run_test() as pilot:
            await pilot.pause()
            app.action_open_ad_exposures()
            await pilot.pause()
            self.assertIsInstance(app.screen, ADExposureQueueScreen)
            self.assertIn(
                "effective actors inherit the grant",
                str(app.screen.query_one("#exposure-help").render()),
            )
            app.action_open_ad_exposure("E1")
            await pilot.pause()
            self.assertIsInstance(app.screen, ADExposureDetailScreen)
            self.assertIn(
                "Local admin access",
                str(app.screen.query_one("#exposure-heading").render()),
            )



if __name__ == "__main__":
    unittest.main()
