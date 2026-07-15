"""Small, deterministic attack-path choke-point summaries."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping


def _domain(entity: Mapping[str, Any]) -> str:
    name = str(entity.get("name") or "")
    if "@" in name:
        return name.rsplit("@", 1)[-1].upper()
    if str(entity.get("type") or "").casefold() == "domain":
        return name.upper()
    if "." in name:
        return name.split(".", 1)[-1].upper()
    return "UNKNOWN"


def _target_class(path: Mapping[str, Any]) -> str:
    target = path.get("target", {})
    name = str(target.get("name") or "").split("@", 1)[0].casefold()
    edges = {str(edge).casefold() for edge in path.get("edges", [])}
    if "dcsync" in edges:
        return "dcsync"
    if name == "domain admins":
        return "domain_admin"
    target_type = str(target.get("type") or "high_value").casefold()
    return f"high_value_{target_type}"


def summarize_choke_points(
    paths: Iterable[Mapping[str, Any]],
    *,
    minimum_paths: int = 2,
) -> List[Dict[str, Any]]:
    """Count reused path steps per domain and target class."""
    counts: Dict[tuple, Dict[str, Any]] = {}
    for path in paths:
        nodes = path.get("nodes", [])
        edges = path.get("edges", [])
        source = path.get("source", {})
        target = path.get("target", {})
        domain = _domain(target) or _domain(source)
        target_class = _target_class(path)
        for index, relationship in enumerate(edges):
            if index + 1 >= len(nodes):
                continue
            from_node = nodes[index]
            to_node = nodes[index + 1]
            key = (
                domain,
                target_class,
                str(from_node.get("id") or from_node.get("name") or ""),
                str(relationship),
                str(to_node.get("id") or to_node.get("name") or ""),
            )
            item = counts.setdefault(key, {
                "domain": domain,
                "target_class": target_class,
                "source": dict(from_node),
                "relationship": str(relationship),
                "target": dict(to_node),
                "path_count": 0,
                "path_sources": set(),
                "path_targets": set(),
            })
            item["path_count"] += 1
            item["path_sources"].add(str(source.get("id") or source.get("name") or ""))
            item["path_targets"].add(str(target.get("id") or target.get("name") or ""))

    rows = []
    for item in counts.values():
        if item["path_count"] < minimum_paths:
            continue
        rows.append({
            "domain": item["domain"],
            "target_class": item["target_class"],
            "source": item["source"],
            "relationship": item["relationship"],
            "target": item["target"],
            "path_count": item["path_count"],
            "distinct_source_count": len(item["path_sources"]),
            "distinct_target_count": len(item["path_targets"]),
        })
    return sorted(
        rows,
        key=lambda item: (
            item["domain"],
            item["target_class"],
            -item["path_count"],
            item["relationship"].casefold(),
            item["source"].get("name", "").casefold(),
        ),
    )
