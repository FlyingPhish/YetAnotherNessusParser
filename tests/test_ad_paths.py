import sys
import types
import unittest

from yapp.core.ad_analyzer import ADGraph
from yapp.core.ad_paths import add_path_findings


class _Result:
    def __init__(self, rows=None):
        self.rows = list(rows or [])

    def has_next(self):
        return bool(self.rows)

    def get_next(self):
        return self.rows.pop(0)


class _Connection:
    instances = []

    def __init__(self, database):
        self.queries = []
        self.__class__.instances.append(self)

    def execute(self, query, parameters=None):
        self.queries.append((query, parameters or {}))
        if query.startswith("MATCH p="):
            return _Result([["U1", "G1", ["U1", "C1", "G1"], ["AdminTo", "GenericAll"], 2]])
        return _Result()


class PathQueryTests(unittest.TestCase):
    def test_uses_valid_relationship_and_shortest_path_syntax(self):
        fake_kuzu = types.ModuleType("kuzu")
        fake_kuzu.Database = lambda location: object()
        fake_kuzu.Connection = _Connection
        original = sys.modules.get("kuzu")
        sys.modules["kuzu"] = fake_kuzu
        self.addCleanup(self._restore_module, original)

        graph = ADGraph()
        graph.add_node("U1", "User", {"name": "alice@corp.local"})
        graph.add_node("C1", "Computer", {"name": "server01.corp.local"})
        graph.add_node("G1", "Group", {"name": "domain admins", "highvalue": True})
        graph.add_edge("U1", "C1", "AdminTo")
        graph.add_edge("C1", "G1", "GenericAll")
        graph.add_edge("U1", "G1", "UnknownFutureEdge")

        findings = []
        paths = add_path_findings(graph, findings, source_ids=["U1"])
        queries = [query for query, _ in _Connection.instances[-1].queries]

        relationship_queries = [query for query in queries if "CREATE (source)-" in query]
        self.assertEqual(2, len(relationship_queries))
        self.assertTrue(all("CREATE (source)-[:Edge" in query for query in relationship_queries))
        path_query = next(query for query in queries if query.startswith("MATCH p="))
        self.assertIn("[path:Edge* SHORTEST 1..6]", path_query)
        self.assertIn("length(path) AS path_length", path_query)
        self.assertEqual(1, len(paths))
        self.assertEqual("ad.owned.path_to_high_value", findings[0]["id"])

    @staticmethod
    def _restore_module(original):
        if original is None:
            sys.modules.pop("kuzu", None)
        else:
            sys.modules["kuzu"] = original


if __name__ == "__main__":
    unittest.main()
