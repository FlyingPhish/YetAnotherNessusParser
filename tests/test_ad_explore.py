import subprocess
import unittest

from yapp.tui.ad_explore import find_path, focused_relationships, search_nodes
from yapp.tui.ad_graphviz import _build_dot, render_focused_graph
from yapp.tui.state import ADIndex, ADNodePivot, ADRelationship


def _edge(source, relationship, target, traversable=True):
    return ADRelationship(
        source=source,
        relationship=relationship,
        target=target,
        category="membership",
        severity="high",
        traversable=traversable,
    )


class ADExploreTests(unittest.TestCase):
    def setUp(self):
        self.alice = {"id": "U1", "name": "ALICE@CORP.LOCAL", "type": "User"}
        self.helpdesk = {"id": "G1", "name": "HELPDESK@CORP.LOCAL", "type": "Group"}
        self.admins = {"id": "G2", "name": "DOMAIN ADMINS@CORP.LOCAL", "type": "Group"}
        member_of = _edge(self.alice, "MemberOf", self.helpdesk)
        generic_all = _edge(self.helpdesk, "GenericAll", self.admins)
        evidence = _edge(self.alice, "UnknownEdge", self.admins, traversable=False)
        self.index = ADIndex(
            input_file="collection.zip",
            parse_options={},
            report={
                "owned_analysis": {
                    "principals": [{"principal": self.alice}],
                },
            },
            paths=[],
            nodes={node["id"]: node for node in (self.alice, self.helpdesk, self.admins)},
            pivots={
                "U1": ADNodePivot(
                    self.alice,
                    outbound=(member_of, evidence),
                ),
                "G1": ADNodePivot(
                    self.helpdesk,
                    outbound=(generic_all,),
                    inbound=(member_of,),
                ),
                "G2": ADNodePivot(
                    self.admins,
                    inbound=(generic_all, evidence),
                ),
            },
            assumed_owned=["alice@corp.local"],
            metadata={},
        )

    def test_search_supports_type_prefix_and_exact_ranking(self):
        self.assertEqual("U1", search_nodes(self.index, "alice")[0]["id"])
        self.assertEqual("G2", search_nodes(self.index, "group:domain")[0]["id"])
        self.assertEqual([], search_nodes(self.index, "computer:domain"))

    def test_pathfinding_uses_only_allowed_and_selected_relationships(self):
        path = find_path(self.index, "U1", "G2")
        self.assertEqual(("MemberOf", "GenericAll"), tuple(
            step.relationship for step in path.steps
        ))
        self.assertTrue(path.owned)
        self.assertIsNone(find_path(
            self.index,
            "U1",
            "G2",
            excluded_relationships=["GenericAll"],
        ))
        neighborhood = focused_relationships(self.index, "U1")
        self.assertEqual(("MemberOf", "UnknownEdge"), tuple(
            edge.relationship for edge in neighborhood
        ))

    def test_graphviz_uses_fixed_argv_and_renders_positions(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(
                argv,
                0,
                stdout=(
                    "graph 1 4 2\n"
                    "node n0 0.5 1 1 0.5 ALICE solid box black white\n"
                    "node n1 3.5 1 1 0.5 HELPDESK solid box black white\n"
                    "edge n0 n1 2 1 1 3 1 MemberOf 2 1 solid black\n"
                    "stop\n"
                ),
                stderr="",
            )

        edge = self.index.pivots["U1"].outbound[0]
        result = render_focused_graph(
            [self.alice, self.helpdesk],
            [edge],
            executable="dot-test",
            runner=runner,
            width=70,
            height=12,
        )

        self.assertEqual("graphviz", result.backend)
        self.assertTrue(calls[0][0][0].endswith("dot-test"))
        self.assertIn("─", result.text)
        self.assertIn("●", result.text)
        self.assertEqual("-Tplain", calls[0][0][1])
        self.assertNotIn("shell", calls[0][1])
        self.assertIn("●ALICE@CORP.LOC", result.text)
        self.assertIn("◆HELPDESK@CORP.", result.text)
        self.assertIn("MemberOf", result.text)

    def test_missing_graphviz_has_bounded_outline_fallback(self):
        edge = self.index.pivots["U1"].outbound[0]
        result = render_focused_graph(
            [self.alice, self.helpdesk],
            [edge],
            executable="",
        )
        if result.backend == "fallback":
            self.assertIn("MemberOf", result.text)
        self.assertIn("Graphviz", result.warning)

    def test_operator_can_force_terminal_outline(self):
        edge = self.index.pivots["U1"].outbound[0]

        result = render_focused_graph(
            [self.index.nodes["U1"], self.index.nodes["G1"]],
            [edge],
            force_fallback=True,
        )

        self.assertEqual("fallback", result.backend)
        self.assertIn("Terminal outline", result.warning)

    def test_dot_labels_cannot_break_out_of_their_attribute(self):
        malicious = {
            "id": "U9",
            "name": 'alice"]; rankdir="TB"; injected [label="yes',
            "type": "User",
        }

        dot = _build_dot([malicious], [])

        self.assertNotIn('label="alice"]', dot)
        self.assertIn('alice\\"]', dot)
        self.assertIn('rankdir=\\"TB\\"', dot)
        self.assertEqual(6, len(dot.splitlines()))


if __name__ == "__main__":
    unittest.main()
