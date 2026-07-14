"""Optional Kuzu-backed BloodHound path rules."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from .ad_analyzer import ADGraph, _entity, _finding, _prop, _truthy
from .ad_owned import traversable_edge_kinds


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
    connection.execute(
        "CREATE NODE TABLE Node (id STRING PRIMARY KEY, kind STRING, name STRING)"
    )
    connection.execute(
        "CREATE REL TABLE Edge (FROM Node TO Node, kind STRING, properties STRING)"
    )

    for node in graph.nodes.values():
        connection.execute(
            "CREATE (n:Node {id: $id, kind: $kind, name: $name})",
            parameters={"id": node.id, "kind": node.kind, "name": node.name},
        )
    for edge in graph.edges:
        if edge.kind.casefold() not in allowed_edges:
            continue
        connection.execute(
            "MATCH (source:Node {id: $source}), (target:Node {id: $target}) "
            "CREATE (source)-(:Edge {kind: $kind, properties: $properties})->(target)",
            parameters={
                "source": edge.source,
                "target": edge.target,
                "kind": edge.kind,
                "properties": str(edge.properties),
            },
        )

    depth = max(1, min(int(max_depth), 12))
    source_filter = (
        "source.id IN $sources" if source_ids is not None else "source.kind = 'User'"
    )
    parameters = {"targets": [node.id for node in targets]}
    if source_ids is not None:
        parameters["sources"] = list(source_ids)
    result = connection.execute(
        f"MATCH p=(source:Node)-[:Edge*1..{depth}]->(target:Node) "
        f"WHERE {source_filter} AND target.id IN $targets "
        "RETURN source.id, target.id, "
        "[n IN nodes(p) | n.id], [r IN rels(p) | r.kind], length(p) "
        "ORDER BY length(p) ASC LIMIT 10000",
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
