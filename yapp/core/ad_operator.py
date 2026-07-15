"""Risk-filtered operator inventories and hygiene checks for BloodHound data."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .ad_analyzer import ADGraph, ADNode, _entity, _finding, _prop, _truthy
from .ad_posture import (
    ADAnalysisPolicy,
    _age_days,
    _descendant_paths,
    _is_enabled,
    _rid,
)


_FLEET_RELATIONSHIPS = {"adminto", "canrdp"}
_ADCS_KINDS = {
    "certificateauthority",
    "enterpriseca",
    "rootca",
    "aiaca",
    "ntauthstore",
    "certtemplate",
    "issuancepolicy",
}


def _domain(node: ADNode) -> str:
    explicit = _prop(node, "domain", "domainname")
    if explicit:
        return str(explicit).upper()
    name = node.name
    if "@" in name:
        return name.rsplit("@", 1)[-1].upper()
    if node.kind.casefold() == "computer" and "." in name:
        return name.split(".", 1)[-1].upper()
    return ""


def _is_domain_controller(
    node: ADNode,
    administrative_paths: Mapping[str, Mapping[str, Sequence[str]]],
    matched_groups: Mapping[str, Mapping[str, Any]],
) -> bool:
    if node.kind.casefold() != "computer":
        return False
    if _truthy(_prop(node, "isdc", "is_dc", "domaincontroller")):
        return True
    return any(
        matched_groups.get(group_id, {}).get("key") == "domain_controllers"
        and node.id in paths
        for group_id, paths in administrative_paths.items()
    )


def _coverage(
    feature: str,
    nodes: Sequence[ADNode],
    *properties: str,
) -> Dict[str, Any]:
    observed = sum(1 for node in nodes if _prop(node, *properties) is not None)
    applicable = len(nodes)
    if not applicable or not observed:
        status = "not_collected"
    elif observed == applicable:
        status = "complete"
    else:
        status = "partial"
    return {
        "feature": feature,
        "status": status,
        "observed": observed,
        "applicable": applicable,
    }


def _effective_principals(
    graph: ADGraph,
    members: Mapping[str, Sequence[str]],
    source: ADNode,
) -> List[Tuple[ADNode, List[str]]]:
    if source.kind.casefold() != "group":
        return [(source, [source.id])]
    return [
        (graph.nodes[principal_id], path)
        for principal_id, path in _descendant_paths(graph, members, source.id).items()
        if graph.nodes[principal_id].kind.casefold() in {"user", "computer"}
    ]


def _fleet_access(
    graph: ADGraph,
    context: Mapping[str, Any],
    policy: ADAnalysisPolicy,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    members = context["members"]
    expected_admin_ids = context["expected_admin_ids"]
    rows: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    seen = set()
    admin_targets: Dict[str, set[str]] = defaultdict(set)
    grants: Dict[str, ADNode] = {}

    for edge in graph.edges:
        relationship = edge.kind.casefold()
        if relationship not in _FLEET_RELATIONSHIPS:
            continue
        source = graph.nodes.get(edge.source)
        target = graph.nodes.get(edge.target)
        if not source or not target or target.kind.casefold() != "computer":
            continue
        if source.id in expected_admin_ids:
            continue
        grants[source.id] = source
        if relationship == "adminto":
            admin_targets[source.id].add(target.id)

        for principal, path in _effective_principals(graph, members, source):
            if principal.id in expected_admin_ids or not _is_enabled(principal):
                continue
            key = (relationship, source.id, principal.id, target.id)
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "domain": _domain(target) or _domain(principal),
                "relationship": edge.kind,
                "granted_to": _entity(source),
                "principal": _entity(principal),
                "target": _entity(target),
                "via": [
                    _entity(graph.nodes[node_id])
                    for node_id in path[1:-1]
                    if node_id in graph.nodes
                ],
            })

    for source_id, target_ids in sorted(admin_targets.items()):
        source = grants[source_id]
        targets = [graph.nodes[target_id] for target_id in sorted(target_ids)]
        if source.kind.casefold() == "computer":
            findings.append(_finding(
                "ad.permissions.computer_local_admin",
                "high",
                "Computer account has local administrative access",
                "A computer account can administer one or more other computers.",
                [_entity(source), *[_entity(target) for target in targets]],
                [{"target_count": len(targets)}],
                "Remove machine-account local administration unless the trust is explicitly required and monitored.",
            ))
        if len(targets) > policy.max_local_admin_hosts:
            findings.append(_finding(
                "ad.permissions.excessive_local_admin_fanout",
                "high",
                "Local administrator access exceeds policy",
                f"The principal can administer {len(targets)} computers; policy permits {policy.max_local_admin_hosts}.",
                [_entity(source), *[_entity(target) for target in targets]],
                [{
                    "target_count": len(targets),
                    "maximum": policy.max_local_admin_hosts,
                }],
                "Reduce local administrator scope and use tiered, just-in-time administration.",
            ))
    return rows, findings


def _account_hygiene(
    graph: ADGraph,
    context: Mapping[str, Any],
    policy: ADAnalysisPolicy,
    now: datetime,
) -> Tuple[Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]:
    privileged_ids = context["privileged_ids"]
    registry = context["registry"]
    inventory: Dict[str, List[Dict[str, Any]]] = {
        "dormant_users": [],
        "dormant_computers": [],
        "sid_history": [],
        "pre_windows_2000_members": [],
    }
    findings: List[Dict[str, Any]] = []

    for user in graph.nodes_of_kind("User"):
        if not _is_enabled(user):
            continue
        if _truthy(_prop(user, "passwordnotreqd", "passwordnotrequired", "pwdnotrequired")):
            findings.append(_finding(
                "ad.password.user_password_not_required",
                "high",
                "User account does not require a password",
                "The account has the password-not-required flag set.",
                [_entity(user)],
                [{"password_not_required": True}],
                "Require a password and review how the account is authenticated and managed.",
            ))
        cleartext_fields = [
            field
            for field in ("userpassword", "unixuserpassword", "unicodepwd")
            if _prop(user, field) is not None
        ]
        if cleartext_fields:
            findings.append(_finding(
                "ad.password.cleartext_material_present",
                "critical",
                "Directory attribute may contain password material",
                "A password-bearing directory attribute is populated; the value has been intentionally redacted.",
                [_entity(user)],
                [{"present_fields": cleartext_fields, "values_redacted": True}],
                "Remove the attribute value, rotate the credential, and investigate read access and exposure.",
            ))
        if _rid(user) == "501":
            findings.append(_finding(
                "ad.accounts.guest_enabled",
                "high",
                "Built-in Guest account is enabled",
                "The domain or local built-in Guest identity is enabled.",
                [_entity(user)],
                [{"rid": 501}],
                "Disable Guest unless a documented exception requires it.",
            ))

        last_logon = _prop(user, "lastlogontimestamp", "lastlogon")
        age = _age_days(last_logon, now)
        created_age = _age_days(_prop(user, "whencreated", "created"), now)
        never_logged_on = last_logon in (0, "0", -1, "-1")
        if (
            _rid(user) not in {"501", "502"}
            and (
                age is not None and age > policy.user_dormancy_days
                or never_logged_on
                and created_age is not None
                and created_age > policy.user_dormancy_days
            )
        ):
            evidence = {
                "last_logon_age_days": age,
                "never_logged_on": never_logged_on,
                "maximum_days": policy.user_dormancy_days,
            }
            inventory["dormant_users"].append({"account": _entity(user), **evidence})
            findings.append(_finding(
                "ad.accounts.user_dormant",
                "medium",
                "Enabled user account is dormant",
                "An enabled user has not logged on within the configured policy window.",
                [_entity(user)],
                [evidence],
                "Confirm ownership and business need, then disable or remove the account if unused.",
            ))

    for computer in graph.nodes_of_kind("Computer"):
        if not _is_enabled(computer):
            continue
        age = _age_days(_prop(computer, "lastlogontimestamp", "lastlogon"), now)
        if age is not None and age > policy.computer_dormancy_days:
            evidence = {
                "last_logon_age_days": age,
                "maximum_days": policy.computer_dormancy_days,
            }
            inventory["dormant_computers"].append({
                "computer": _entity(computer),
                **evidence,
            })
            findings.append(_finding(
                "ad.computers.computer_dormant",
                "medium",
                "Enabled computer account is dormant",
                "An enabled computer has not logged on within the configured policy window.",
                [_entity(computer)],
                [evidence],
                "Validate the asset, then disable and remove stale computer accounts through the normal lifecycle process.",
            ))
        has_laps = _prop(computer, "haslaps", "has_laps")
        if has_laps is not None and not _truthy(has_laps) and (
            age is None or age <= policy.computer_dormancy_days
        ):
            findings.append(_finding(
                "ad.password.computer_without_laps",
                "medium",
                "Active computer does not have LAPS coverage",
                "The collection explicitly reports that the computer is not managed by LAPS.",
                [_entity(computer)],
                [{"has_laps": False}],
                "Deploy Windows LAPS or an equivalent unique, managed local administrator credential control.",
            ))

    suffixes = {
        suffix.upper()
        for entry in registry
        for suffix in entry.get("sid_suffixes", ())
    }
    for node in graph.nodes_of_kind("User", "Computer", "Group"):
        admin_count = _prop(node, "admincount", "admin_count")
        if node.id in privileged_ids and admin_count is not None and not _truthy(admin_count):
            findings.append(_finding(
                "ad.privilege.privileged_missing_admincount",
                "medium",
                "Privileged principal is not marked for protected ACL handling",
                "A sensitive principal has an explicit false AdminCount value.",
                [_entity(node)],
                [{"admin_count": admin_count}],
                "Validate AdminSDHolder protection and correct unintended ACL inheritance state.",
            ))
        elif node.id not in privileged_ids and _truthy(admin_count):
            findings.append(_finding(
                "ad.privilege.stale_admincount",
                "low",
                "Non-privileged principal retains AdminCount",
                "The principal is no longer sensitive but remains marked by historical protected-group membership.",
                [_entity(node)],
                [{"admin_count": admin_count}],
                "Confirm the principal is no longer privileged, then restore intended ACL inheritance and clear stale metadata.",
            ))

        sid_history = _prop(node, "sidhistory", "sid_history")
        if sid_history in (None, "", []):
            continue
        values = sid_history if isinstance(sid_history, list) else [sid_history]
        serialized = [str(value) for value in values]
        entry = {"principal": _entity(node), "sid_history": serialized}
        inventory["sid_history"].append(entry)
        if any(
            sid.upper().endswith(suffix)
            for sid in serialized
            for suffix in suffixes
        ):
            findings.append(_finding(
                "ad.privilege.sensitive_sid_history",
                "critical",
                "SIDHistory grants sensitive-group identity",
                "The principal has SIDHistory matching a configured sensitive group SID.",
                [_entity(node)],
                [entry],
                "Investigate the migration history and remove unauthorized SIDHistory after validating dependencies.",
            ))

    members = context["members"]
    for group in graph.nodes_of_kind("Group"):
        if group.name.split("@", 1)[0].strip().casefold() != "pre-windows 2000 compatible access":
            continue
        for member_id, path in _descendant_paths(graph, members, group.id).items():
            member = graph.nodes[member_id]
            row = {
                "member": _entity(member),
                "group": _entity(group),
                "membership": "direct" if len(path) == 2 else "transitive",
            }
            inventory["pre_windows_2000_members"].append(row)
            sid = str(_prop(member, "objectid", "sid") or member.id).upper()
            if sid in {"S-1-1-0", "S-1-5-7"}:
                findings.append(_finding(
                    "ad.groups.pre_windows_2000_dangerous_member",
                    "high",
                    "Pre-Windows 2000 Compatible Access contains a broad identity",
                    "Everyone or Anonymous Logon is effectively a member of the legacy compatibility group.",
                    [_entity(member), _entity(group)],
                    [row],
                    "Remove broad identities unless a verified legacy requirement exists.",
                ))
    return inventory, findings


def _relationship_inventory(
    graph: ADGraph,
    context: Mapping[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    privileged_ids = context["privileged_ids"]
    expected_admin_ids = context["expected_admin_ids"]
    administrative_paths = context["administrative_paths"]
    matched_groups = context["matched_groups"]
    delegation: List[Dict[str, Any]] = []
    credential_access: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    for edge in graph.edges:
        kind = edge.kind.casefold()
        source = graph.nodes.get(edge.source)
        target = graph.nodes.get(edge.target)
        if not source or not target:
            continue
        sensitive_target = target.id in privileged_ids or _is_domain_controller(
            target, administrative_paths, matched_groups
        )
        row = {
            "domain": _domain(target) or _domain(source),
            "principal": _entity(source),
            "relationship": edge.kind,
            "target": _entity(target),
        }

        if kind in {"allowedtoact", "addallowedtoact", "writeaccountrestrictions"}:
            delegation.append({**row, "type": "rbcd"})
            if sensitive_target and source.id not in expected_admin_ids:
                findings.append(_finding(
                    "ad.kerberos.rbcd_to_sensitive",
                    "critical",
                    "RBCD relationship reaches a sensitive computer",
                    "A non-standard principal can use or configure resource-based constrained delegation against a sensitive target.",
                    [_entity(source), _entity(target)],
                    [row],
                    "Remove unnecessary RBCD permissions and investigate the delegating identity and target.",
                ))
        elif kind == "allowedtodelegate":
            delegation.append({**row, "type": "constrained"})
            if sensitive_target and source.id not in expected_admin_ids:
                findings.append(_finding(
                    "ad.kerberos.constrained_delegation_to_sensitive",
                    "high",
                    "Constrained delegation reaches a sensitive computer",
                    "A non-standard principal is configured to delegate authentication to a sensitive target.",
                    [_entity(source), _entity(target)],
                    [row],
                    "Restrict delegation targets and prefer resource-based constrained delegation with tightly controlled principals.",
                ))
        elif kind in {"readlapspassword", "synclapspassword"}:
            credential_access.append({**row, "credential": "laps"})
            if source.id not in expected_admin_ids:
                findings.append(_finding(
                    "ad.permissions.laps_reader",
                    "high",
                    "Non-standard principal can read a LAPS password",
                    "A principal outside the configured expected-administrator set can read or synchronize a managed local password.",
                    [_entity(source), _entity(target)],
                    [row],
                    "Restrict LAPS readers to the smallest approved administrative group.",
                ))
        elif kind == "readgmsapassword":
            credential_access.append({**row, "credential": "gmsa"})
            if sensitive_target and source.id not in expected_admin_ids:
                findings.append(_finding(
                    "ad.permissions.gmsa_reader_to_privileged",
                    "critical",
                    "Principal can read a privileged gMSA password",
                    "A non-standard principal can retrieve a managed password for a sensitive identity.",
                    [_entity(source), _entity(target)],
                    [row],
                    "Remove unnecessary gMSA readers and rotate the managed account after remediation.",
                ))
        elif kind == "addkeycredentiallink":
            credential_access.append({**row, "credential": "key_credential"})
            if sensitive_target and source.id not in expected_admin_ids:
                findings.append(_finding(
                    "ad.permissions.shadow_credentials_to_sensitive",
                    "critical",
                    "Principal can add a key credential to a sensitive identity",
                    "The relationship can enable a Shadow Credentials attack against a sensitive principal.",
                    [_entity(source), _entity(target)],
                    [row],
                    "Remove the write path, review key credentials, and rotate affected credentials where compromise is possible.",
                ))
        elif kind == "hassession" and target.id in privileged_ids:
            if not _is_domain_controller(source, administrative_paths, matched_groups):
                findings.append(_finding(
                    "ad.sessions.privileged_user_on_non_dc",
                    "high",
                    "Privileged user has a session on a non-domain controller",
                    "A sensitive user session is exposed on a lower-tier computer.",
                    [_entity(target), _entity(source)],
                    [row],
                    "End the session, investigate credential exposure, and enforce administrative tiering.",
                ))
    return delegation, credential_access, findings


def _adcs_inventory(
    graph: ADGraph,
    context: Mapping[str, Any],
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    objects = [
        node
        for node in graph.nodes.values()
        if node.kind.casefold() in _ADCS_KINDS
        or _truthy(_prop(node, "iscertificationauthority", "isca"))
    ]
    object_ids = {node.id for node in objects}
    access = []
    findings = []
    expected_admin_ids = context["expected_admin_ids"]
    administrative_rights = {
        "adminto", "genericall", "manageca", "managecertificates",
        "owns", "writedacl", "writeowner",
    }
    for edge in graph.edges:
        if edge.kind.casefold() not in administrative_rights or edge.target not in object_ids:
            continue
        source = graph.nodes.get(edge.source)
        target = graph.nodes.get(edge.target)
        if not source or not target or source.id in expected_admin_ids:
            continue
        row = {
            "principal": _entity(source),
            "relationship": edge.kind,
            "target": _entity(target),
        }
        access.append(row)
        findings.append(_finding(
            "ad.permissions.nonprivileged_admin_to_adcs",
            "critical",
            "Non-standard principal administers an AD CS object",
            "A principal outside the expected-administrator set has administrative access to a collected AD CS object.",
            [_entity(source), _entity(target)],
            [row],
            "Remove unnecessary administration and use a dedicated AD CS assessment to validate the service configuration.",
        ))
    return {
        "present": bool(objects),
        "objects": [_entity(node) for node in objects],
        "administrative_access": access,
    }, findings


def analyze_operator_data(
    graph: ADGraph,
    context: Mapping[str, Any],
    policy: ADAnalysisPolicy,
    *,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Return compact JSON/Excel inventories and their risk-filtered findings."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    users = list(graph.nodes_of_kind("User"))
    computers = list(graph.nodes_of_kind("Computer"))
    fleet_access, fleet_findings = _fleet_access(graph, context, policy)
    account_inventory, account_findings = _account_hygiene(
        graph, context, policy, now
    )
    delegation, credential_access, relationship_findings = _relationship_inventory(
        graph, context
    )
    adcs, adcs_findings = _adcs_inventory(graph, context)
    session_count = sum(
        1 for edge in graph.edges if edge.kind.casefold() == "hassession"
    )
    coverage = [
        _coverage("user_last_logon", users, "lastlogontimestamp", "lastlogon"),
        _coverage("computer_last_logon", computers, "lastlogontimestamp", "lastlogon"),
        _coverage("laps_status", computers, "haslaps", "has_laps"),
        {
            "feature": "sessions",
            "status": "collected" if session_count or "sessions" in graph.collected_features else "not_collected",
            "observed": session_count,
            "applicable": len(computers),
        },
        {
            "feature": "adcs_objects",
            "status": "collected" if adcs["present"] or "adcs_objects" in graph.collected_features else "not_collected",
            "observed": len(adcs["objects"]),
            "applicable": None,
        },
    ]
    return {
        "coverage": coverage,
        "fleet_access": fleet_access,
        "account_inventory": account_inventory,
        "delegation": delegation,
        "credential_access": credential_access,
        "adcs": adcs,
        "findings": [
            *fleet_findings,
            *account_findings,
            *relationship_findings,
            *adcs_findings,
        ],
    }
