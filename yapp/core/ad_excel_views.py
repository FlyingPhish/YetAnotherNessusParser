"""Concise operator views for AD workbooks."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable, Dict, Iterable, List, Mapping, Sequence, Tuple

from .ad_reporting import _SEVERITY_ORDER


_FINDING_IDS = {
    "computer_membership": "ad.privilege.computer_in_administrative_group",
    "privileged_control": "ad.permissions.control_over_high_privilege",
    "user_dormant": "ad.accounts.user_dormant",
    "computer_dormant": "ad.computers.computer_dormant",
    "sensitive_sid_history": "ad.privilege.sensitive_sid_history",
    "legacy_group": "ad.groups.pre_windows_2000_dangerous_member",
}


def _domain(entity: Mapping[str, Any]) -> str:
    name = str(entity.get("name") or "")
    if "@" in name:
        return name.rsplit("@", 1)[-1].upper()
    if str(entity.get("type") or "").casefold() == "domain":
        return name.upper()
    if "." in name:
        return name.split(".", 1)[-1].upper()
    return ""


def _entity(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _entity_names(values: Any) -> str:
    if isinstance(values, Mapping):
        values = [values]
    if not isinstance(values, (list, tuple)):
        return ""
    return ", ".join(
        str(value.get("name") or value.get("id") or "")
        for value in values
        if isinstance(value, Mapping)
    )


def _path_names(values: Any) -> str:
    if not isinstance(values, (list, tuple)):
        return ""
    return " -> ".join(
        str(value.get("name") or value.get("id") or "")
        for value in values
        if isinstance(value, Mapping)
    )


def _risk_context(evidence: Mapping[str, Any]) -> str:
    labels = {
        "count": "Count",
        "maximum": "Policy maximum",
        "target_count": "Targets",
        "password_age_days": "Password age (days)",
        "last_logon_age_days": "Last logon age (days)",
        "maximum_days": "Policy maximum (days)",
        "creation_delta_hours": "Creation delta (hours)",
        "effective_principal_count": "Effective principals",
        "never_logged_on": "Never logged on",
        "has_laps": "Has LAPS",
        "values_redacted": "Values redacted",
        "legacy_password_candidate": "Legacy password candidate",
    }
    parts = [
        f"{label}: {evidence[key]}"
        for key, label in labels.items()
        if key in evidence and evidence[key] is not None
    ]
    for key, label in (
        ("composite_rights", "Rights"),
        ("present_fields", "Present fields"),
        ("sid_history", "SID history"),
    ):
        values = evidence.get(key)
        if isinstance(values, (list, tuple)) and values:
            parts.append(f"{label}: {', '.join(str(value) for value in values)}")
    groups = _entity_names(evidence.get("administrative_groups"))
    if groups:
        parts.append(f"Administrative groups: {groups}")
    memberships = evidence.get("memberships")
    if isinstance(memberships, list):
        for membership in memberships:
            if not isinstance(membership, Mapping):
                continue
            group = _entity(membership.get("group"))
            via = _path_names(membership.get("via"))
            detail = f"{membership.get('membership', 'membership')} -> {group.get('name', '')}"
            if via:
                detail += f" via {via}"
            parts.append(detail)
    effective = _entity_names(evidence.get("effective_principals"))
    if effective:
        parts.append(f"Effective principals: {effective}")
    return "; ".join(parts)


def _finding_roles(
    finding: Mapping[str, Any],
) -> Tuple[Mapping[str, Any], str, Mapping[str, Any], str, str]:
    evidence_items = finding.get("evidence", [])
    evidence = (
        evidence_items[0]
        if isinstance(evidence_items, list)
        and evidence_items
        and isinstance(evidence_items[0], Mapping)
        else {}
    )
    principal = {}
    for key in ("principal", "source", "account", "computer", "member"):
        principal = _entity(evidence.get(key))
        if principal:
            break
    target = _entity(evidence.get("target")) or _entity(evidence.get("group"))
    entities = [
        value for value in finding.get("entities", []) if isinstance(value, Mapping)
    ]
    if not principal and entities:
        principal = entities[0]
    if not target and len(entities) > 1:
        target = entities[1]

    relationship = str(evidence.get("relationship") or "")
    edges = evidence.get("edges")
    if not relationship and isinstance(edges, list):
        relationship = " -> ".join(str(edge) for edge in edges)
    finding_id = str(finding.get("id") or "")
    if not relationship and finding_id == _FINDING_IDS["computer_membership"]:
        relationship = "MemberOf"

    via = _path_names(evidence.get("via"))
    if not via and isinstance(evidence.get("nodes"), list):
        via = _path_names(evidence["nodes"])
    context = _risk_context(evidence)
    return principal, relationship, target, via, context


def _risk_rows(
    report: Mapping[str, Any], mapping: Mapping[str, Any]
) -> List[Sequence[Any]]:
    rows = []
    findings = [
        finding for finding in report.get("findings", []) if isinstance(finding, Mapping)
    ]
    findings.sort(
        key=lambda item: (
            -_SEVERITY_ORDER.get(str(item.get("severity", "info")).casefold(), 0),
            str(item.get("id") or ""),
            str(item.get("title") or ""),
        )
    )
    for number, finding in enumerate(findings, start=1):
        principal, relationship, target, via, context = _finding_roles(finding)
        entities = [
            entity
            for entity in finding.get("entities", [])
            if isinstance(entity, Mapping)
        ]
        used_ids = {principal.get("id"), target.get("id")}
        related = ", ".join(
            str(entity.get("name") or entity.get("id") or "")
            for entity in entities
            if entity.get("id") not in used_ids
        )
        finding_id = str(finding.get("id") or "")
        rows.append((
            f"R{number:05d}",
            mapping.get(finding_id, ""),
            finding.get("severity", ""),
            finding_id,
            finding.get("title", ""),
            _domain(target) or _domain(principal),
            principal.get("type", ""),
            principal.get("name", ""),
            principal.get("id", ""),
            relationship,
            target.get("type", ""),
            target.get("name", ""),
            target.get("id", ""),
            via,
            related,
            context,
            finding.get("remediation", ""),
        ))
    return rows


def _registry_entry(
    group: Mapping[str, Any], registry: Sequence[Mapping[str, Any]]
) -> Mapping[str, Any]:
    group_id = str(group.get("id") or "").upper()
    name = str(group.get("name") or "").split("@", 1)[0].strip().casefold()
    for entry in registry:
        if name in entry.get("names", ()) or any(
            group_id.endswith(str(suffix).upper())
            for suffix in entry.get("sid_suffixes", ())
        ):
            return entry
    return {}


def _membership_rows(privilege: Mapping[str, Any]) -> List[Sequence[Any]]:
    registry = privilege.get("sensitive_group_registry", [])
    rows = []
    for item in privilege.get("memberships", []):
        principal = _entity(item.get("principal"))
        group = _entity(item.get("group"))
        config = _registry_entry(group, registry)
        principal_type = str(principal.get("type") or "")
        if principal_type.casefold() == "computer":
            status, severity, finding_id = (
                "Finding",
                "critical",
                _FINDING_IDS["computer_membership"],
            )
        elif principal_type.casefold() == "group":
            status, severity, finding_id = "Review", "high", ""
        else:
            status, severity, finding_id = "Inventory", "info", ""
        rows.append((
            _domain(group) or _domain(principal),
            status,
            severity,
            finding_id,
            principal_type,
            principal.get("name", ""),
            principal.get("id", ""),
            item.get("membership", ""),
            _path_names(item.get("via")),
            group.get("name", ""),
            group.get("id", ""),
            config.get("classification", "bloodhound_high_value"),
            config.get("expected_admin", ""),
        ))
    return sorted(
        rows,
        key=lambda row: (-_SEVERITY_ORDER.get(str(row[2]).casefold(), 0), row[0], row[5]),
    )


def _permission_rows(privilege: Mapping[str, Any]) -> List[Sequence[Any]]:
    rows = []
    for item in privilege.get("permissions", []):
        granted = _entity(item.get("principal"))
        target = _entity(item.get("target"))
        effective_paths = item.get("effective_paths", [])
        if not effective_paths:
            effective = item.get("effective_principals", [])
            effective_paths = (
                [{"principal": principal, "via": []} for principal in effective]
                if effective
                else [{"principal": granted, "via": []}]
            )
        for path in effective_paths:
            principal = _entity(path.get("principal"))
            chain = [principal, *path.get("via", []), granted]
            rows.append((
                _domain(target) or _domain(principal),
                "Finding",
                item.get("severity", ""),
                _FINDING_IDS["privileged_control"],
                principal.get("type", ""),
                principal.get("name", ""),
                principal.get("id", ""),
                _path_names(chain) if principal.get("id") != granted.get("id") else "Direct",
                granted.get("name", ""),
                item.get("relationship", ""),
                item.get("category", ""),
                target.get("type", ""),
                target.get("name", ""),
                target.get("id", ""),
            ))
    return rows


def _edge_risks(report: Mapping[str, Any]) -> Tuple[Dict[tuple, tuple], Dict[str, tuple]]:
    exact: Dict[tuple, tuple] = {}
    by_source: Dict[str, tuple] = {}
    for finding in report.get("findings", []):
        if not isinstance(finding, Mapping):
            continue
        principal, relationship, target, _, _ = _finding_roles(finding)
        risk = (
            finding.get("severity", ""),
            finding.get("id", ""),
            finding.get("title", ""),
        )
        if principal.get("id") and finding.get("id") in {
            "ad.permissions.computer_local_admin",
            "ad.permissions.excessive_local_admin_fanout",
        }:
            by_source[str(principal["id"])] = risk
        if principal.get("id") and relationship and target.get("id"):
            exact[(str(principal["id"]), relationship.casefold(), str(target["id"]))] = risk
    return exact, by_source


def _row_risk(
    item: Mapping[str, Any],
    exact: Mapping[tuple, tuple],
    by_source: Mapping[str, tuple],
    source_key: str = "principal",
    allow_source: bool = False,
) -> Tuple[str, str, str, str]:
    source = _entity(item.get(source_key))
    target = _entity(item.get("target"))
    relationship = str(item.get("relationship") or "")
    risk = exact.get((str(source.get("id") or ""), relationship.casefold(), str(target.get("id") or "")))
    if risk is None and allow_source:
        risk = by_source.get(str(source.get("id") or ""))
    if not risk:
        return "Inventory", "info", "", ""
    return "Finding", str(risk[0]), str(risk[1]), str(risk[2])


def _fleet_rows(
    items: Iterable[Mapping[str, Any]],
    exact: Mapping[tuple, tuple],
    by_source: Mapping[str, tuple],
) -> List[Sequence[Any]]:
    rows = []
    for item in items:
        grant = _entity(item.get("granted_to"))
        principal = _entity(item.get("principal"))
        target = _entity(item.get("target"))
        status, severity, finding_id, reason = _row_risk(
            {**item, "principal": grant}, exact, by_source,
            allow_source=True,
        )
        rows.append((
            item.get("domain", ""),
            status,
            severity,
            finding_id,
            item.get("relationship", ""),
            principal.get("type", ""),
            principal.get("name", ""),
            principal.get("id", ""),
            grant.get("name", ""),
            _path_names(item.get("via")),
            target.get("name", ""),
            target.get("id", ""),
            reason,
        ))
    return rows


def _relationship_rows(
    items: Iterable[Mapping[str, Any]],
    exact: Mapping[tuple, tuple],
    by_source: Mapping[str, tuple],
    category_key: str,
) -> List[Sequence[Any]]:
    rows = []
    for item in items:
        principal = _entity(item.get("principal"))
        target = _entity(item.get("target"))
        status, severity, finding_id, reason = _row_risk(item, exact, by_source)
        rows.append((
            item.get("domain", ""),
            status,
            severity,
            finding_id,
            item.get(category_key, ""),
            principal.get("type", ""),
            principal.get("name", ""),
            principal.get("id", ""),
            item.get("relationship", ""),
            target.get("type", ""),
            target.get("name", ""),
            target.get("id", ""),
            reason,
        ))
    return rows


def _session_rows(
    items: Iterable[Mapping[str, Any]],
    exact: Mapping[tuple, tuple],
    by_source: Mapping[str, tuple],
) -> List[Sequence[Any]]:
    rows = []
    for item in items:
        computer = _entity(item.get("principal"))
        user = _entity(item.get("target"))
        status, severity, finding_id, reason = _row_risk(
            item, exact, by_source
        )
        rows.append((
            item.get("domain", ""), status, severity, finding_id,
            computer.get("name", ""), computer.get("id", ""),
            user.get("name", ""), user.get("id", ""),
            item.get("privileged_user", False),
            item.get("domain_controller", False), reason,
        ))
    return rows


def _account_rows(
    account: Mapping[str, Any], report: Mapping[str, Any]
) -> List[Sequence[Any]]:
    risky_entities: Dict[Tuple[str, str], str] = {}
    for finding in report.get("findings", []):
        if not isinstance(finding, Mapping):
            continue
        for entity in finding.get("entities", []):
            if isinstance(entity, Mapping):
                risky_entities[(str(finding.get("id") or ""), str(entity.get("id") or ""))] = str(
                    finding.get("severity") or ""
                )
    rows = []
    categories = (
        ("dormant_users", "Dormant user", "account", _FINDING_IDS["user_dormant"]),
        ("dormant_computers", "Dormant computer", "computer", _FINDING_IDS["computer_dormant"]),
        ("sid_history", "SID history", "principal", _FINDING_IDS["sensitive_sid_history"]),
        ("pre_windows_2000_members", "Legacy group member", "member", _FINDING_IDS["legacy_group"]),
    )
    for key, label, entity_key, finding_id in categories:
        for item in account.get(key, []):
            entity = _entity(item.get(entity_key))
            severity = risky_entities.get((finding_id, str(entity.get("id") or "")), "info")
            status = "Finding" if severity != "info" else "Review"
            detail = ""
            if key == "sid_history":
                detail = ", ".join(str(value) for value in item.get("sid_history", []))
            elif key == "pre_windows_2000_members":
                detail = f"{item.get('membership', '')} member of {_entity(item.get('group')).get('name', '')}"
            rows.append((
                _domain(entity),
                status,
                severity,
                finding_id if status == "Finding" else "",
                label,
                entity.get("type", ""),
                entity.get("name", ""),
                entity.get("id", ""),
                item.get("last_logon_age_days", ""),
                item.get("maximum_days", ""),
                detail,
            ))
    return rows


def _attack_path_rows(
    paths: Sequence[Mapping[str, Any]], report: Mapping[str, Any]
) -> List[Sequence[Any]]:
    owned_ids = {
        str(entity.get("id") or "")
        for entity in report.get("owned_analysis", {}).get("resolved", [])
        if isinstance(entity, Mapping)
    }
    rows = []
    for number, path in enumerate(paths, start=1):
        source = _entity(path.get("source"))
        target = _entity(path.get("target"))
        edges = [str(edge) for edge in path.get("edges", [])]
        target_name = str(target.get("name") or "").split("@", 1)[0].casefold()
        if any(edge.casefold() == "dcsync" for edge in edges):
            path_class = "DCSync"
            finding_id = "ad.permissions.dcsync"
            severity = "critical"
        elif target_name == "domain admins":
            path_class = "Domain Admin"
            finding_id = (
                "ad.owned.path_to_domain_admin"
                if str(source.get("id") or "") in owned_ids
                else "ad.permissions.path_to_domain_admin"
            )
            severity = "critical" if str(source.get("id") or "") in owned_ids else "high"
        else:
            path_class = f"High-value {target.get('type', 'object')}"
            finding_id = (
                "ad.owned.path_to_high_value"
                if str(source.get("id") or "") in owned_ids
                else "ad.permissions.path_to_high_value"
            )
            severity = "critical" if str(source.get("id") or "") in owned_ids else "high"
        nodes = [node for node in path.get("nodes", []) if isinstance(node, Mapping)]
        chain = []
        for index, node in enumerate(nodes):
            chain.append(str(node.get("name") or node.get("id") or ""))
            if index < len(edges):
                chain.append(f"--{edges[index]}-->")
        rows.append((
            f"P{number:05d}",
            _domain(target) or _domain(source),
            severity,
            finding_id,
            path_class,
            source.get("name", ""),
            source.get("id", ""),
            target.get("name", ""),
            target.get("id", ""),
            path.get("length", len(edges)),
            " ".join(chain),
        ))
    return rows


def _add_if_rows(
    add_sheet: Callable[..., Any],
    workbook: Any,
    name: str,
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
) -> None:
    if rows:
        add_sheet(workbook, name, headers, rows)


def add_operator_views(
    add_sheet: Callable[..., Any],
    workbook: Any,
    report: Mapping[str, Any],
    mapping: Mapping[str, Any],
    paths: Sequence[Mapping[str, Any]],
) -> None:
    """Add only decision-supporting views; omit empty and dump-style sheets."""
    privilege = report.get("privilege_analysis", {})
    operator = report.get("operator_analysis", {})
    exact_risks, source_risks = _edge_risks(report)

    add_sheet(
        workbook,
        "Risk Register",
        [
            "Risk ID", "Internal Vulnerability ID", "Severity", "Finding ID",
            "Title", "Domain", "Principal Type", "Principal", "Principal ID",
            "Relationship", "Target Type", "Target", "Target ID", "Via / Path",
            "Related Entities", "Risk Context", "Remediation",
        ],
        _risk_rows(report, mapping),
    )

    _add_if_rows(
        add_sheet, workbook, "Privileged Memberships",
        [
            "Domain", "Operator Status", "Severity", "Finding ID",
            "Principal Type", "Principal", "Principal ID", "Membership", "Via",
            "Sensitive Group", "Group ID", "Classification", "Expected Admin",
        ],
        _membership_rows(privilege),
    )
    _add_if_rows(
        add_sheet, workbook, "Privileged Controls",
        [
            "Domain", "Operator Status", "Severity", "Finding ID",
            "Effective Type", "Effective Principal", "Effective ID",
            "Membership Path", "Granted To", "Relationship", "Category",
            "Target Type", "Target", "Target ID",
        ],
        _permission_rows(privilege),
    )
    _add_if_rows(
        add_sheet, workbook, "Fleet Access",
        [
            "Domain", "Operator Status", "Severity", "Finding ID", "Relationship",
            "Principal Type", "Effective Principal", "Principal ID", "Granted To",
            "Via", "Computer", "Computer ID", "Risk Reason",
        ],
        _fleet_rows(operator.get("fleet_access", []), exact_risks, source_risks),
    )
    for sheet_name, key, label, category_key in (
        ("Delegation", "delegation", "Delegation Type", "type"),
        ("Credential Access", "credential_access", "Credential", "credential"),
    ):
        _add_if_rows(
            add_sheet, workbook, sheet_name,
            [
                "Domain", "Operator Status", "Severity", "Finding ID", label,
                "Principal Type", "Principal", "Principal ID", "Relationship",
                "Target Type", "Target", "Target ID", "Risk Reason",
            ],
            _relationship_rows(
                operator.get(key, []), exact_risks, source_risks, category_key
            ),
        )

    _add_if_rows(
        add_sheet, workbook, "Sessions",
        [
            "Domain", "Operator Status", "Severity", "Finding ID", "Computer",
            "Computer ID", "User", "User ID", "Privileged User",
            "Domain Controller", "Risk Reason",
        ],
        _session_rows(
            operator.get("sessions", []), exact_risks, source_risks
        ),
    )

    adcs = operator.get("adcs", {})
    adcs_access = defaultdict(list)
    for item in adcs.get("administrative_access", []):
        adcs_access[str(_entity(item.get("target")).get("id") or "")].append(item)
    adcs_rows = []
    for authority in adcs.get("objects", []):
        access_items = adcs_access.get(str(authority.get("id") or ""), []) or [{}]
        for item in access_items:
            principal = _entity(item.get("principal"))
            status, severity, finding_id, reason = (
                _row_risk(item, exact_risks, source_risks)
                if item
                else ("Inventory", "info", "", "")
            )
            adcs_rows.append((
                _domain(authority), status, severity, finding_id,
                authority.get("type", ""), authority.get("name", ""),
                authority.get("id", ""), principal.get("type", ""),
                principal.get("name", ""), principal.get("id", ""),
                item.get("relationship", "") if item else "", reason,
            ))
    _add_if_rows(
        add_sheet, workbook, "AD CS",
        [
            "Domain", "Operator Status", "Severity", "Finding ID", "Object Type",
            "AD CS Object", "Object ID", "Principal Type", "Principal",
            "Principal ID", "Administrative Right", "Risk Reason",
        ],
        adcs_rows,
    )

    _add_if_rows(
        add_sheet, workbook, "Stale & Legacy Accounts",
        [
            "Domain", "Operator Status", "Severity", "Finding ID", "Category",
            "Entity Type", "Entity", "Entity ID", "Age (days)",
            "Policy Maximum (days)", "Detail",
        ],
        _account_rows(operator.get("account_inventory", {}), report),
    )

    owned = report.get("owned_analysis", {})
    owned_rows = []
    for item in owned.get("principals", []):
        principal = _entity(item.get("principal"))
        controls = item.get("direct_controls", []) or [{}]
        for control in controls:
            target = _entity(control.get("target"))
            owned_rows.append((
                "Resolved", control.get("severity", "info"), principal.get("name", ""),
                principal.get("id", ""), control.get("relationship", ""),
                control.get("category", ""), target.get("type", ""),
                target.get("name", ""), target.get("id", ""),
                _path_names(control.get("via")), _entity_names(control.get("granted_to")),
            ))
    owned_rows.extend(
        ("Unresolved", "info", identity, "", "", "", "", "", "", "", "")
        for identity in owned.get("unresolved", [])
    )
    _add_if_rows(
        add_sheet, workbook, "Owned Access",
        [
            "Status", "Severity", "Owned Principal", "Principal ID", "Relationship",
            "Category", "Target Type", "Target", "Target ID", "Via", "Granted To",
        ],
        owned_rows,
    )

    _add_if_rows(
        add_sheet, workbook, "Attack Paths",
        [
            "Path ID", "Domain", "Severity", "Finding ID", "Path Class",
            "Source", "Source ID", "Target", "Target ID", "Length", "Attack Chain",
        ],
        _attack_path_rows(paths, report),
    )

    choke_rows = [
        (
            item.get("domain", ""), item.get("target_class", ""),
            item.get("path_count", 0), item.get("distinct_source_count", 0),
            item.get("distinct_target_count", 0),
            _entity(item.get("source")).get("type", ""),
            _entity(item.get("source")).get("name", ""),
            _entity(item.get("source")).get("id", ""),
            item.get("relationship", ""),
            _entity(item.get("target")).get("type", ""),
            _entity(item.get("target")).get("name", ""),
            _entity(item.get("target")).get("id", ""),
        )
        for item in report.get("path_analysis", {}).get("choke_points", [])
    ]
    _add_if_rows(
        add_sheet, workbook, "Choke Points",
        [
            "Domain", "Target Class", "Path Count", "Distinct Sources",
            "Distinct Targets", "Source Type", "Source", "Source ID",
            "Relationship", "Target Type", "Target", "Target ID",
        ],
        choke_rows,
    )

    add_sheet(
        workbook, "Collection Coverage",
        ["Feature", "Status", "Observed", "Applicable"],
        [
            (
                item.get("feature", ""), item.get("status", ""),
                item.get("observed", ""), item.get("applicable", ""),
            )
            for item in operator.get("coverage", [])
        ],
    )
