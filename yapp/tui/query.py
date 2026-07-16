"""Filtering, sorting, and pagination helpers for TUI queue."""

from __future__ import annotations

from .state import FindingRow, QueryOptions


def _sort_key(sort_by: str):
    if sort_by == "severity":
        return lambda row: (row.severity, row.risk_score, row.affected_hosts_count, row.plugin_id)
    if sort_by == "hosts":
        return lambda row: (row.affected_hosts_count, row.risk_score, row.severity, row.plugin_id)
    if sort_by == "plugin":
        return lambda row: row.plugin_id
    if sort_by == "name":
        return lambda row: row.name.lower()

    # default: risk
    return lambda row: (row.risk_score, row.severity, row.affected_hosts_count, row.plugin_id)


def filter_and_sort(rows: list[FindingRow], query: QueryOptions) -> list[FindingRow]:
    """Return full filtered/sorted findings list."""
    search_text = query.search_text.strip().lower()

    filtered = rows

    if query.severities:
        filtered = [row for row in filtered if row.severity in query.severities]

    if search_text:
        filtered = [row for row in filtered if search_text in row.search_blob]

    reverse = query.sort_by not in {"plugin", "name"}
    filtered = sorted(filtered, key=_sort_key(query.sort_by), reverse=reverse)

    return filtered


def apply_query(rows: list[FindingRow], query: QueryOptions) -> tuple[list[FindingRow], int]:
    """Return current page of filtered findings and total count."""
    filtered = filter_and_sort(rows, query)
    total = len(filtered)

    page = max(0, query.page)
    page_size = max(1, query.page_size)

    start = page * page_size
    end = start + page_size

    if start >= total and total > 0:
        page = max(0, (total - 1) // page_size)
        start = page * page_size
        end = start + page_size

    return filtered[start:end], total
