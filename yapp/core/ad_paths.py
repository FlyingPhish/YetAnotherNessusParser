"""Optional Kuzu-backed BloodHound path rules."""

from __future__ import annotations

import csv
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional, Sequence

from .ad_analyzer import ADGraph, _entity, _finding, _prop, _truthy
from .ad_owned import traversable_edge_kinds


def _cypher_string(value: str) -> str:
    """Quote a generated local path as a Cypher string literal."""
    slash = chr(92)
    quote = chr(39)
    return (
        quote
        + value.replace(slash, slash + slash).replace(quote, slash + quote)
        + quote
    )


def _load_graph(connection: Any, graph: ADGraph, allowed_edges: set[str]) -> None:
    """Load the graph with Kuzu bulk COPY instead of per-row Cypher DML."""
    connection.execute(
        "CREATE NODE TABLE Node (id STRING PRIMARY KEY, kind STRING, name STRING)"
    )
    connection.execute("CREATE REL TABLE Edge (FROM Node TO Node, kind STRING)")

    with TemporaryDirectory(prefix="yapp-ad-") as temporary_directory:
        directory = Path(temporary_directory)
        nodes_path = directory / "nodes.csv"
        edges_path = directory / "edges.csv"

        with nodes_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerows(
                (node.id, node.kind, node.name) for node in graph.nodes.values()
            )
        edge_count = 0
        with edges_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            for edge in graph.edges:
                if edge.kind.casefold() not in allowed_edges:
                    continue
                writer.writerow((edge.source, edge.target, edge.kind))
                edge_count += 1

        connection.execute(f"COPY Node FROM {_cypher_string(str(nodes_path))}")
        if edge_count:
            connection.execute(f"COPY Edge FROM {_cypher_string(str(edges_path))}")


def add_path_findings(
    graph: ADGraph,
    findings: List[Dict[str, Any]],
    max_depth: int = 6,
    source_ids: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Append bounded, allow-listed paths to high-value nodes."""
    import kuzu  # type: ignore

    targets = [
        node
        for node in graph.nodes.values()
        if _truthy(_prop(node, "highvalue", "high_value", "istierzero"))
    ]
    if not targets or source_ids is not None and not source_ids:
        return []

    allowed_edges = set(traversable_edge_kinds())
    db = kuzu.Database(":memory:")
    connection = kuzu.Connection(db)
    _load_graph(connection, graph, allowed_edges)

    depth = max(1, min(int(max_depth), 12))
    source_filter = (
        "source.id IN $sources" if source_ids is not None else "source.kind = 'User'"
    )
    parameters = {"targets": [node.id for node in targets]}
    if source_ids is not None:
        parameters["sources"] = list(source_ids)
    result = connection.execute(
        f"MATCH p=(source:Node)-[path:Edge* SHORTEST 1..{depth}]->(target:Node) "
        f"WHERE {source_filter} AND target.id IN $targets "
        "RETURN source.id, target.id, "
        "properties(nodes(p), \"id\"), properties(rels(p), \"kind\"), "
        "length(path) AS path_length "
        "ORDER BY path_length ASC LIMIT 10000",
        parameters=parameters,
    )

    nodes_by_id = graph.nodes
    seen = set()
    paths: List[Dict[str, Any]] = []
    owned_mode = source_ids is not None
    while result.has_next():
        source_id, target_id, path_ids, path_edges, path_length = result.get_next()
        key = (source_id, target_id)
        if key in seen:
            continue
        seen.add(key)
        source = nodes_by_id.get(source_id)
        target = nodes_by_id.get(target_id)
        if not source or not target:
            continue
        path = {
            "source": _entity(source),
            "target": _entity(target),
            "nodes": [
                _entity(nodes_by_id[node_id])
                for node_id in path_ids
                if node_id in nodes_by_id
            ],
            "edges": list(path_edges),
            "length": path_length,
            "max_depth": depth,
        }
        paths.append(path)
        findings.append(
            _finding(
                "ad.owned.path_to_high_value"
                if owned_mode
                else "ad.permissions.path_to_high_value",
                "critical" if owned_mode else "high",
                "Owned principal has a path to a high-value asset"
                if owned_mode
                else "User has a path to a high-value asset",
                "The collection contains a bounded, allow-listed attack path to a high-value asset.",
                [_entity(source), _entity(target)],
                [path],
                "Remove unnecessary privilege and review every relationship in the path.",
            )
        )
    return paths
