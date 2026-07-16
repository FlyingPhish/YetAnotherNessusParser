"""Optional Kuzu-backed BloodHound path rules."""

from __future__ import annotations

import csv
from collections import defaultdict, deque
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional, Sequence

from .ad_analyzer import ADGraph, _entity, _finding, _prop, _truthy
from .ad_owned import traversable_edge_kinds
from .ad_posture import _is_domain_admins


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


def _high_value_targets(graph: ADGraph) -> List[Any]:
    return [
        node
        for node in graph.nodes.values()
        if _truthy(_prop(node, "highvalue", "high_value", "istierzero"))
        or _is_domain_admins(node)
    ]


def _append_path_finding(
    findings: List[Dict[str, Any]],
    path: Dict[str, Any],
    *,
    owned_mode: bool,
) -> None:
    source = path["source"]
    target = path["target"]
    target_node = target["_node"]
    if _is_domain_admins(target_node):
        finding_id = (
            "ad.owned.path_to_domain_admin"
            if owned_mode
            else "ad.permissions.path_to_domain_admin"
        )
        title = (
            "Owned principal has a path to Domain Admins"
            if owned_mode
            else "User has a path to Domain Admins"
        )
    else:
        finding_id = (
            "ad.owned.path_to_high_value"
            if owned_mode
            else "ad.permissions.path_to_high_value"
        )
        title = (
            "Owned principal has a path to a high-value asset"
            if owned_mode
            else "User has a path to a high-value asset"
        )
    clean_path = {**path, "source": source["entity"], "target": target["entity"]}
    findings.append(
        _finding(
            finding_id,
            "critical" if owned_mode else "high",
            title,
            "The collection contains a bounded, allow-listed attack path to a high-value asset.",
            [source["entity"], target["entity"]],
            [clean_path],
            "Remove unnecessary privilege and review every relationship in the path.",
        )
    )


def add_path_findings(
    graph: ADGraph,
    findings: List[Dict[str, Any]],
    max_depth: int = 6,
    source_ids: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Append bounded, allow-listed paths to high-value nodes."""
    import kuzu  # type: ignore

    targets = _high_value_targets(graph)
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
            "source": {"entity": _entity(source)},
            "target": {"entity": _entity(target), "_node": target},
            "nodes": [
                _entity(nodes_by_id[node_id])
                for node_id in path_ids
                if node_id in nodes_by_id
            ],
            "edges": list(path_edges),
            "length": path_length,
            "max_depth": depth,
        }
        _append_path_finding(findings, path, owned_mode=owned_mode)
        paths.append({
            **path,
            "source": path["source"]["entity"],
            "target": path["target"]["entity"],
        })
    return paths


def add_priority_path_findings(
    graph: ADGraph,
    findings: List[Dict[str, Any]],
    max_depth: int = 6,
    source_ids: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Append one nearest high-value route per source in O(V+E).

    The TUI needs a prioritized queue, not every source-target combination.
    A deterministic reverse multi-source BFS avoids dense-graph path explosion
    while retaining the authoritative traversal allow-list.
    """
    targets = _high_value_targets(graph)
    if not targets or source_ids is not None and not source_ids:
        return []

    depth = max(1, min(int(max_depth), 12))
    allowed_edges = set(traversable_edge_kinds())
    incoming: Dict[str, List[Any]] = defaultdict(list)
    for edge in graph.edges:
        if edge.kind.casefold() in allowed_edges:
            incoming[edge.target].append(edge)
    for edges in incoming.values():
        edges.sort(key=lambda edge: (edge.kind.casefold(), edge.source))

    target_ids = {node.id for node in targets}
    distance = {node.id: 0 for node in sorted(targets, key=lambda item: item.id)}
    next_step: Dict[str, Any] = {}
    queue = deque(sorted(target_ids))
    while queue:
        current = queue.popleft()
        if distance[current] >= depth:
            continue
        for edge in incoming.get(current, []):
            if edge.source in distance:
                continue
            distance[edge.source] = distance[current] + 1
            next_step[edge.source] = edge
            queue.append(edge.source)

    if source_ids is None:
        sources = sorted(
            (node.id for node in graph.nodes_of_kind("User")),
            key=str.casefold,
        )
    else:
        sources = sorted(set(source_ids), key=str.casefold)

    paths: List[Dict[str, Any]] = []
    for source_id in sources:
        if source_id not in next_step:
            continue
        node_ids = [source_id]
        edges = []
        current = source_id
        while current not in target_ids and len(edges) < depth:
            edge = next_step.get(current)
            if edge is None:
                break
            edges.append(edge.kind)
            current = edge.target
            node_ids.append(current)
        if current not in target_ids:
            continue
        source = graph.nodes.get(source_id)
        target = graph.nodes.get(current)
        if not source or not target:
            continue
        path = {
            "source": {"entity": _entity(source)},
            "target": {"entity": _entity(target), "_node": target},
            "nodes": [_entity(graph.nodes[node_id]) for node_id in node_ids],
            "edges": edges,
            "length": len(edges),
            "max_depth": depth,
        }
        _append_path_finding(
            findings,
            path,
            owned_mode=source_ids is not None,
        )
        paths.append({
            **path,
            "source": path["source"]["entity"],
            "target": path["target"]["entity"],
        })
    return paths
