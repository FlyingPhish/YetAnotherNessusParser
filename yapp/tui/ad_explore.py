"""Bounded object search and interactive pathfinding for the AD workspace."""

from __future__ import annotations

import hashlib
from collections import deque
from typing import Iterable, Sequence

from .state import ADIndex, ADPathRow, ADRelationship

_TYPE_ALIASES = {
    "user": "user",
    "group": "group",
    "computer": "computer",
    "domain": "domain",
    "gpo": "gpo",
    "ou": "ou",
    "ca": "certificateauthority",
    "template": "certtemplate",
}
_MAX_QUERY_CHARS = 512
_MAX_VISITED = 100_000


def search_nodes(
    index: ADIndex,
    query: str,
    *,
    limit: int = 200,
) -> list[dict]:
    """Return deterministic name/ID matches, with optional ``type:term`` syntax."""
    query = query.strip()[:_MAX_QUERY_CHARS]
    limit = min(limit, 1000)
    if not query or limit < 1:
        return []
    requested_type = ""
    term = query
    if ":" in query:
        prefix, candidate = query.split(":", 1)
        requested_type = _TYPE_ALIASES.get(prefix.strip().casefold(), "")
        if requested_type:
            term = candidate.strip()
    needle = term.casefold()
    if not needle:
        return []

    ranked = []
    for node in index.nodes.values():
        kind = str(node.get("type") or "").casefold()
        if requested_type and kind != requested_type:
            continue
        name = str(node.get("name") or "")
        node_id = str(node.get("id") or "")
        name_key = name.casefold()
        id_key = node_id.casefold()
        if needle not in name_key and needle not in id_key:
            continue
        if name_key == needle or id_key == needle:
            rank = 0
        elif name_key.startswith(needle):
            rank = 1
        elif needle in name_key:
            rank = 2
        else:
            rank = 3
        ranked.append((rank, name_key, kind, node_id, node))
    ranked.sort(key=lambda item: item[:4])
    return [dict(item[-1]) for item in ranked[:limit]]


def relationship_types(index: ADIndex) -> tuple[str, ...]:
    """Return traversable relationship names available to Explore."""
    relationships = {
        item.relationship
        for pivot in index.pivots.values()
        for item in pivot.outbound
        if item.traversable
    }
    return tuple(sorted(relationships, key=str.casefold))


def _owned_ids(index: ADIndex) -> set[str]:
    return {
        str((item.get("principal") or {}).get("id") or "")
        for item in (index.report.get("owned_analysis") or {}).get("principals") or []
    }


def find_path(
    index: ADIndex,
    source_id: str,
    target_id: str,
    *,
    excluded_relationships: Iterable[str] = (),
    max_depth: int = 8,
) -> ADPathRow | None:
    """Find one shortest allow-listed path between two exact object IDs."""
    max_depth = max(1, min(max_depth, 16))
    if source_id not in index.nodes or target_id not in index.nodes:
        return None
    excluded = {value.casefold() for value in excluded_relationships}
    if source_id == target_id:
        return ADPathRow(
            path_id=_path_id(source_id, target_id, ()),
            source=dict(index.nodes[source_id]),
            target=dict(index.nodes[target_id]),
            nodes=(dict(index.nodes[source_id]),),
            steps=(),
            target_class="selected target",
            score=0,
            owned=source_id in _owned_ids(index),
        )

    queue = deque([(source_id, 0)])
    parents: dict[str, tuple[str, ADRelationship]] = {}
    visited = {source_id}
    while queue and len(visited) <= _MAX_VISITED:
        node_id, depth = queue.popleft()
        if depth >= max_depth:
            continue
        pivot = index.pivots.get(node_id)
        if not pivot:
            continue
        for step in pivot.outbound:
            if len(visited) >= _MAX_VISITED:
                return None
            next_id = str(step.target.get("id") or "")
            if (
                not step.traversable
                or step.relationship.casefold() in excluded
                or not next_id
                or next_id in visited
            ):
                continue
            parents[next_id] = (node_id, step)
            if next_id == target_id:
                return _build_path(index, source_id, target_id, parents)
            visited.add(next_id)
            queue.append((next_id, depth + 1))
    return None


def _build_path(
    index: ADIndex,
    source_id: str,
    target_id: str,
    parents: dict[str, tuple[str, ADRelationship]],
) -> ADPathRow:
    steps = []
    cursor = target_id
    while cursor != source_id:
        previous, step = parents[cursor]
        steps.append(step)
        cursor = previous
    steps.reverse()
    nodes = [dict(index.nodes[source_id])]
    nodes.extend(dict(step.target) for step in steps)
    return ADPathRow(
        path_id=_path_id(source_id, target_id, steps),
        source=dict(index.nodes[source_id]),
        target=dict(index.nodes[target_id]),
        nodes=tuple(nodes),
        steps=tuple(steps),
        target_class="selected target",
        score=max(0, 100 - len(steps) * 5),
        owned=source_id in _owned_ids(index),
    )


def _path_id(
    source_id: str,
    target_id: str,
    steps: Sequence[ADRelationship],
) -> str:
    material = "\0".join([
        source_id,
        target_id,
        *(f"{step.relationship}:{step.target.get('id', '')}" for step in steps),
    ])
    return "explore-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def focused_relationships(
    index: ADIndex,
    node_id: str,
    *,
    excluded_relationships: Iterable[str] = (),
    limit: int = 40,
) -> tuple[ADRelationship, ...]:
    """Return a bounded, useful neighborhood for the focused graph."""
    pivot = index.pivots.get(node_id)
    limit = min(limit, 200)
    if not pivot or limit < 1:
        return ()
    excluded = {value.casefold() for value in excluded_relationships}
    candidates = [
        *pivot.outbound,
        *pivot.inbound,
    ]
    output = []
    seen = set()
    for item in sorted(
        candidates,
        key=lambda row: (
            not row.traversable,
            row.relationship.casefold(),
            str(row.source.get("name") or "").casefold(),
            str(row.target.get("name") or "").casefold(),
        ),
    ):
        key = (
            str(item.source.get("id") or ""),
            item.relationship.casefold(),
            str(item.target.get("id") or ""),
        )
        if item.relationship.casefold() in excluded or key in seen:
            continue
        seen.add(key)
        output.append(item)
        if len(output) >= limit:
            break
    return tuple(output)


def compress_fanout(
    focus_id: str,
    relationships: Sequence[ADRelationship],
    *,
    threshold: int = 5,
) -> tuple[tuple[dict, ...], tuple[ADRelationship, ...]]:
    """Collapse repeated focused-node fan-out into safe synthetic summary nodes."""
    threshold = max(2, min(threshold, 100))
    grouped: dict[tuple[str, str, str], list[ADRelationship]] = {}
    passthrough = []
    for item in relationships:
        if str(item.source.get("id") or "") == focus_id:
            key = ("out", item.relationship, str(item.target.get("type") or "object"))
        elif str(item.target.get("id") or "") == focus_id:
            key = ("in", item.relationship, str(item.source.get("type") or "object"))
        else:
            passthrough.append(item)
            continue
        grouped.setdefault(key, []).append(item)
    nodes = {}
    output = list(passthrough)
    for key, items in grouped.items():
        if len(items) < threshold:
            output.extend(items)
            continue
        direction, relationship, kind = key
        summary_id = f"summary:{focus_id}:{direction}:{relationship}:{kind}"
        summary = {"id": summary_id, "name": f"+{len(items)} {kind}s", "type": "summary"}
        nodes[summary_id] = summary
        exemplar = items[0]
        output.append(ADRelationship(
            source=dict(exemplar.source) if direction == "out" else summary,
            relationship=relationship,
            target=summary if direction == "out" else dict(exemplar.target),
            category=exemplar.category,
            severity=exemplar.severity,
            traversable=exemplar.traversable,
            why="Collapsed fan-out; expand the selected node for individual objects.",
        ))
    for item in output:
        nodes[str(item.source.get("id") or "")] = dict(item.source)
        nodes[str(item.target.get("id") or "")] = dict(item.target)
    return tuple(nodes.values()), tuple(output)
