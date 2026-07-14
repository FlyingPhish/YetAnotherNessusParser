"""Effective outbound control calculation, including nested group rights."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from .ad_analyzer import ADGraph, _entity


_REPLICATION_RIGHTS = {
    "getchanges",
    "getchangesall",
    "getchangesinfilteredset",
}


def _effective_sources(
    memberships: Mapping[str, Sequence[str]], principal_id: str
) -> Dict[str, List[str]]:
    paths = {principal_id: []}
    queue = deque([principal_id])
    while queue:
        current = queue.popleft()
        for group_id in memberships.get(current, []):
            if group_id in paths:
                continue
            paths[group_id] = [*paths[current], group_id]
            queue.append(group_id)
    return paths


def map_effective_controls(
    graph: ADGraph,
    owned_ids: Iterable[str],
    policies: Mapping[str, Any],
) -> Dict[str, List[Dict[str, Any]]]:
    """Map direct and group-inherited outbound rights for each owned user."""
    outgoing: Dict[str, List[Any]] = defaultdict(list)
    memberships: Dict[str, List[str]] = defaultdict(list)
    for edge in graph.edges:
        outgoing[edge.source].append(edge)
        if edge.kind.casefold() == "memberof":
            memberships[edge.source].append(edge.target)

    controls_by_owned: Dict[str, List[Dict[str, Any]]] = {}
    for owned_id in owned_ids:
        effective_sources = _effective_sources(memberships, owned_id)
        controls: Dict[Tuple[str, str], Dict[str, Any]] = {}
        replication: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"rights": set(), "sources": set(), "via": []}
        )

        for source_id, via_ids in effective_sources.items():
            via = [
                _entity(graph.nodes[node_id])
                for node_id in via_ids
                if node_id in graph.nodes
            ]
            for edge in outgoing.get(source_id, []):
                edge_kind = edge.kind.casefold()
                if edge_kind in _REPLICATION_RIGHTS:
                    detail = replication[edge.target]
                    detail["rights"].add(edge_kind)
                    detail["sources"].add(source_id)
                    if not detail["via"] or len(via) < len(detail["via"]):
                        detail["via"] = via

                policy = policies.get(edge_kind)
                target = graph.nodes.get(edge.target)
                if not policy or not policy.direct_control or not target:
                    continue
                control = {
                    "relationship": edge.kind,
                    "category": policy.category,
                    "severity": policy.severity,
                    "target": _entity(target),
                    "granted_to": [_entity(graph.nodes[source_id])],
                    "via": via,
                    "properties": edge.properties,
                }
                key = (edge_kind, edge.target)
                existing = controls.get(key)
                if existing is None or len(via) < len(existing["via"]):
                    controls[key] = control

        for target_id, detail in replication.items():
            if not {"getchanges", "getchangesall"}.issubset(detail["rights"]):
                continue
            target = graph.nodes.get(target_id)
            if not target:
                continue
            controls[("dcsync", target_id)] = {
                "relationship": "DCSync",
                "category": "directory_replication",
                "severity": "critical",
                "target": _entity(target),
                "granted_to": [
                    _entity(graph.nodes[source_id])
                    for source_id in sorted(detail["sources"])
                    if source_id in graph.nodes
                ],
                "via": detail["via"],
                "properties": {"composite_rights": sorted(detail["rights"])},
            }
        controls_by_owned[owned_id] = list(controls.values())
    return controls_by_owned
