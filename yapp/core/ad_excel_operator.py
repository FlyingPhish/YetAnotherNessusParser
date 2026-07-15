"""Compatibility helpers for AD operator workbook rows."""

from __future__ import annotations

from typing import Any, Iterable, Iterator, Mapping, Sequence


def _fleet_access_rows(
    items: Iterable[Mapping[str, Any]],
) -> Iterator[Sequence[Any]]:
    """Yield the original compact fleet shape for library callers."""
    for item in items:
        grant = item.get("granted_to", {})
        principal = item.get("principal", {})
        target = item.get("target", {})
        yield (
            item.get("domain", ""),
            item.get("relationship", ""),
            grant.get("type", ""),
            grant.get("name", ""),
            grant.get("id", ""),
            principal.get("type", ""),
            principal.get("name", ""),
            principal.get("id", ""),
            target.get("name", ""),
            target.get("id", ""),
            " -> ".join(node.get("name", "") for node in item.get("via", [])),
        )
