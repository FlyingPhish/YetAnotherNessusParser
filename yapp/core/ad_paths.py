"""Optional Kuzu-backed BloodHound path rules."""

from __future__ import annotations

from typing import Any, Dict, List

from .ad_analyzer import ADGraph, _entity, _finding, _prop, _truthy


def add_path_findings(graph: ADGraph, findings: List[Dict[str, Any]], max_depth: int = 6) -> None:
    """Append bounded paths from users to high-value nodes.

    Kuzu is imported here (rather than at package import time) so normal YAPP
    users do not need the native graph dependency installed.
    """
    import kuzu  # type: ignore

    targets = [
        node
        for node in graph.nodes.values()
        if _truthy(_prop(node, "highvalue", "high_value", "istierzero"))
    ]
    if not targets:
        return

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
            {"id": node.id, "kind": node.kind, "name": node.name},
        )
    for edge in graph.edges:
        connection.execute(
            "MATCH (source:Node {id: $source}), (target:Node {id: $target}) "
            "CREATE (source)-(:Edge {kind: $kind, properties: $properties})->(target)",
            {
                "source": edge.source,
                "target": edge.target,
                "kind": edge.kind,
                "properties": str(edge.properties),
            },
        )

    depth = max(1, min(int(max_depth), 12))
    result = connection.execute(
        f"MATCH p=(source:Node)-[:Edge*1..{depth}]->(target:Node) "
        "WHERE source.kind = 'User' AND target.id IN $targets "
        "RETURN source.id, target.id, "
        "[n IN nodes(p) | n.id], [r IN rels(p) | r.kind] LIMIT 10000",
        {"targets": [node.id for node in targets]},
    )

    nodes_by_id = graph.nodes
    seen = set()
    while result.has_next():
        source_id, target_id, path_ids, path_edges = result.get_next()
        key = (source_id, target_id)
        if key in seen:
            continue
        seen.add(key)
        source = nodes_by_id.get(source_id)
        target = nodes_by_id.get(target_id)
        if not source or not target:
            continue
        findings.append(
            _finding(
                "ad.permissions.path_to_high_value",
                "high",
                "User has a path to a high-value asset",
                "The collection contains a bounded attack path from a user to a high-value asset.",
                [_entity(source), _entity(target)],
                [
                    {
                        "path": [
                            {"id": node_id, "name": nodes_by_id[node_id].name}
                            for node_id in path_ids
                            if node_id in nodes_by_id
                        ],
                        "edges": list(path_edges),
                        "max_depth": depth,
                    }
                ],
                "Remove unnecessary privilege and review every relationship in the path.",
            )
        )

