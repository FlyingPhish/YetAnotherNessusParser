"""Operator-focused workbook sheets kept separate from core finding rendering."""

from __future__ import annotations

from typing import Any, Callable, Mapping


def add_operator_sheets(
    add_sheet: Callable[..., Any],
    workbook: Any,
    report: Mapping[str, Any],
) -> None:
    operator = report.get("operator_analysis", {})

    access_rows = []
    for item in operator.get("fleet_access", []):
        grant = item.get("granted_to", {})
        principal = item.get("principal", {})
        target = item.get("target", {})
        access_rows.append((
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
        ))
    add_sheet(
        workbook,
        "Fleet Access",
        [
            "Domain", "Relationship", "Granted Type", "Granted To", "Granted ID",
            "Effective Type", "Effective Principal", "Effective ID", "Computer",
            "Computer ID", "Via",
        ],
        access_rows,
    )

    add_sheet(
        workbook,
        "Collection Coverage",
        ["Feature", "Status", "Observed", "Applicable"],
        (
            (
                item.get("feature", ""),
                item.get("status", ""),
                item.get("observed", ""),
                item.get("applicable", ""),
            )
            for item in operator.get("coverage", [])
        ),
    )

    for sheet_name, key, extra_name, extra_key in (
        ("Delegation", "delegation", "Delegation Type", "type"),
        ("Credential Access", "credential_access", "Credential", "credential"),
    ):
        add_sheet(
            workbook,
            sheet_name,
            [
                "Domain", extra_name, "Principal Type", "Principal", "Principal ID",
                "Relationship", "Target Type", "Target", "Target ID",
            ],
            (
                (
                    item.get("domain", ""),
                    item.get(extra_key, ""),
                    item.get("principal", {}).get("type", ""),
                    item.get("principal", {}).get("name", ""),
                    item.get("principal", {}).get("id", ""),
                    item.get("relationship", ""),
                    item.get("target", {}).get("type", ""),
                    item.get("target", {}).get("name", ""),
                    item.get("target", {}).get("id", ""),
                )
                for item in operator.get(key, [])
            ),
        )

    adcs = operator.get("adcs", {})
    access_by_target = {}
    for item in adcs.get("administrative_access", []):
        access_by_target.setdefault(item.get("target", {}).get("id", ""), []).append(
            item.get("principal", {}).get("name", "")
        )
    add_sheet(
        workbook,
        "AD CS",
        ["Present", "Object Type", "Object", "Object ID", "Non-standard Admins"],
        (
            (
                adcs.get("present", False),
                item.get("type", ""),
                item.get("name", ""),
                item.get("id", ""),
                ", ".join(access_by_target.get(item.get("id", ""), [])),
            )
            for item in adcs.get("objects", [])
        ),
    )

    account = operator.get("account_inventory", {})
    account_rows = []
    for key, entity_key in (
        ("dormant_users", "account"),
        ("dormant_computers", "computer"),
        ("sid_history", "principal"),
        ("pre_windows_2000_members", "member"),
    ):
        for item in account.get(key, []):
            entity = item.get(entity_key, {})
            detail = {name: value for name, value in item.items() if name != entity_key}
            account_rows.append((
                key,
                entity.get("type", ""),
                entity.get("name", ""),
                entity.get("id", ""),
                detail,
            ))
    add_sheet(
        workbook,
        "Account Inventory",
        ["Category", "Entity Type", "Entity", "Entity ID", "Detail JSON"],
        account_rows,
    )


def add_choke_point_sheet(
    add_sheet: Callable[..., Any],
    workbook: Any,
    report: Mapping[str, Any],
) -> None:
    add_sheet(
        workbook,
        "Choke Points",
        [
            "Domain", "Target Class", "Path Count", "Distinct Sources",
            "Distinct Targets", "Source Type", "Source", "Relationship",
            "Target Type", "Target",
        ],
        (
            (
                item.get("domain", ""),
                item.get("target_class", ""),
                item.get("path_count", 0),
                item.get("distinct_source_count", 0),
                item.get("distinct_target_count", 0),
                item.get("source", {}).get("type", ""),
                item.get("source", {}).get("name", ""),
                item.get("relationship", ""),
                item.get("target", {}).get("type", ""),
                item.get("target", {}).get("name", ""),
            )
            for item in report.get("path_analysis", {}).get("choke_points", [])
        ),
    )
