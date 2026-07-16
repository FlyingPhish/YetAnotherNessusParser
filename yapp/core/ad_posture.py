"""Administrative posture checks derived from a BloodHound collection."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .ad_analyzer import ADGraph, ADNode, _entity, _finding, _prop, _truthy
from .ad_config import match_sensitive_group, normalize_sensitive_groups
from .ad_owned import EDGE_POLICIES
from .ad_effective import _effective_sources


@dataclass(frozen=True)
class ADAnalysisPolicy:
    """Thresholds that are policy choices rather than collection semantics."""

    max_domain_admins: int = 5
    max_password_age_days: int = 365
    max_krbtgt_password_age_days: int = 180
    timeroast_password_age_days: int = 30
    timeroast_creation_window_days: int = 1
    user_dormancy_days: int = 90
    computer_dormancy_days: int = 90
    max_local_admin_hosts: int = 10

    def __post_init__(self) -> None:
        for name, value in vars(self).items():
            if not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


_DOMAIN_ADMINS_RID = "512"
_PROTECTED_USERS_RID = "525"
_ACL_CONTROL_KINDS = {
    kind
    for kind, policy in EDGE_POLICIES.items()
    if policy.direct_control and policy.category not in {"remote_access", "local_admin"}
}
_DEDICATED_CONTROL_KINDS = {
    "addallowedtoact",
    "addkeycredentiallink",
    "allowedtoact",
    "allowedtodelegate",
    "readgmsapassword",
    "readlapspassword",
    "synclapspassword",
    "writeaccountrestrictions",
}


def _rid(node: ADNode) -> str:
    sid = str(_prop(node, "objectid", "objectidentifier", "sid") or node.id)
    return sid.rsplit("-", 1)[-1] if sid.upper().startswith("S-1-") else ""


def _name_key(node: ADNode) -> str:
    return node.name.split("@", 1)[0].strip().casefold()


def _is_domain_admins(node: ADNode) -> bool:
    return node.kind.casefold() == "group" and (
        _rid(node) == _DOMAIN_ADMINS_RID or _name_key(node) == "domain admins"
    )


def _is_protected_users(node: ADNode) -> bool:
    return node.kind.casefold() == "group" and (
        _rid(node) == _PROTECTED_USERS_RID or _name_key(node) == "protected users"
    )


def _sensitive_group_config(
    node: ADNode, registry: Sequence[Mapping[str, Any]]
) -> Optional[Mapping[str, Any]]:
    if node.kind.casefold() != "group":
        return None
    sid = str(_prop(node, "objectid", "objectidentifier", "sid") or node.id)
    matched = match_sensitive_group(sid, node.name, registry)
    if matched:
        return matched
    if _truthy(_prop(node, "highvalue", "high_value", "istierzero")):
        return {
            "key": "bloodhound_high_value",
            "classification": "tier_zero",
            "expected_admin": True,
        }
    return None


def _is_administrative_group(
    node: ADNode, registry: Optional[Sequence[Mapping[str, Any]]] = None
) -> bool:
    return _sensitive_group_config(
        node, registry or normalize_sensitive_groups()
    ) is not None


def _is_enabled(node: ADNode) -> bool:
    value = _prop(node, "enabled")
    return True if value is None else _truthy(value)


def _timestamp(value: Any) -> Optional[datetime]:
    """Parse BloodHound epoch values and common legacy collection formats."""
    if value in (None, "", 0, "0", -1, "-1"):
        return None
    if isinstance(value, str):
        stripped = value.strip()
        try:
            number = float(stripped)
        except ValueError:
            try:
                parsed = datetime.fromisoformat(stripped.replace("Z", "+00:00"))
                return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)
            except ValueError:
                return None
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
    else:
        return None

    # AD FILETIME is 100 ns since 1601; BloodHound normally stores Unix seconds.
    if number > 10**16:
        number = number / 10_000_000 - 11_644_473_600
    elif number > 10**12:
        number /= 1000
    try:
        return datetime.fromtimestamp(number, timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def _age_days(value: Any, now: datetime) -> Optional[int]:
    timestamp = _timestamp(value)
    if timestamp is None:
        return None
    return max(0, (now - timestamp).days)


def _membership_indexes(
    graph: ADGraph,
) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    memberships: Dict[str, List[str]] = defaultdict(list)
    members: Dict[str, List[str]] = defaultdict(list)
    for edge in graph.edges:
        if edge.kind.casefold() != "memberof":
            continue
        memberships[edge.source].append(edge.target)
        members[edge.target].append(edge.source)
    return memberships, members


def _descendant_paths(
    graph: ADGraph,
    members: Mapping[str, Sequence[str]],
    group_id: str,
    cache: Optional[Dict[str, Dict[str, List[str]]]] = None,
) -> Dict[str, List[str]]:
    """Return shortest principal-to-group membership paths."""
    if cache is not None and group_id in cache:
        return cache[group_id]
    paths = {group_id: [group_id]}
    queue = deque([group_id])
    while queue:
        current = queue.popleft()
        for member_id in members.get(current, []):
            if member_id in paths:
                continue
            paths[member_id] = [member_id, *paths[current]]
            queue.append(member_id)
    result = {
        principal_id: path
        for principal_id, path in paths.items()
        if principal_id != group_id and principal_id in graph.nodes
    }
    if cache is not None:
        cache[group_id] = result
    return result


def _path_evidence(
    graph: ADGraph,
    path_ids: Sequence[str],
    relationship: str,
    target: ADNode,
) -> Dict[str, Any]:
    source = graph.nodes[path_ids[0]]
    nodes = [_entity(graph.nodes[node_id]) for node_id in path_ids if node_id in graph.nodes]
    nodes.append(_entity(target))
    return {
        "source": _entity(source),
        "target": _entity(target),
        "nodes": nodes,
        "edges": ["MemberOf"] * max(0, len(path_ids) - 1) + [relationship],
        "length": len(path_ids),
    }


def _administrative_memberships(
    graph: ADGraph,
    members: Mapping[str, Sequence[str]],
    registry: Sequence[Mapping[str, Any]],
    descendant_paths: Optional[Dict[str, Dict[str, List[str]]]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, List[str]]]]:
    rows: List[Dict[str, Any]] = []
    paths_by_group: Dict[str, Dict[str, List[str]]] = {}
    for group in sorted(
        (node for node in graph.nodes.values() if _is_administrative_group(node, registry)),
        key=lambda node: (node.name.casefold(), node.id),
    ):
        paths = _descendant_paths(graph, members, group.id, descendant_paths)
        paths_by_group[group.id] = paths
        for principal_id, path_ids in paths.items():
            principal = graph.nodes[principal_id]
            if principal.kind.casefold() not in {"user", "computer", "group"}:
                continue
            rows.append({
                "principal": _entity(principal),
                "group": _entity(group),
                "membership": "direct" if len(path_ids) == 2 else "transitive",
                "via": [
                    _entity(graph.nodes[node_id])
                    for node_id in path_ids[1:-1]
                    if node_id in graph.nodes
                ],
            })
    return rows, paths_by_group


def _high_privilege_ids(
    graph: ADGraph,
    administrative_paths: Mapping[str, Mapping[str, Sequence[str]]],
    registry: Sequence[Mapping[str, Any]],
) -> set[str]:
    privileged = {
        node.id
        for node in graph.nodes.values()
        if _truthy(_prop(node, "highvalue", "high_value", "istierzero"))
        or _is_administrative_group(node, registry)
    }
    for paths in administrative_paths.values():
        privileged.update(paths)
    return privileged


def build_privilege_context(
    graph: ADGraph,
    sensitive_groups: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build the shared membership and sensitivity context once per collection."""
    registry = normalize_sensitive_groups(sensitive_groups)
    memberships_index, members = _membership_indexes(graph)
    descendant_paths: Dict[str, Dict[str, List[str]]] = {}
    memberships, administrative_paths = _administrative_memberships(
        graph, members, registry, descendant_paths
    )
    privileged_ids = _high_privilege_ids(graph, administrative_paths, registry)
    expected_admin_ids: set[str] = set()
    matched_groups: Dict[str, Mapping[str, Any]] = {}
    for node in graph.nodes.values():
        config = _sensitive_group_config(node, registry)
        if not config:
            continue
        matched_groups[node.id] = config
        if config.get("expected_admin"):
            expected_admin_ids.add(node.id)
            expected_admin_ids.update(administrative_paths.get(node.id, {}))
    return {
        "registry": registry,
        "memberships_index": memberships_index,
        "members": members,
        "memberships": memberships,
        "administrative_paths": administrative_paths,
        "descendant_paths": descendant_paths,
        "privileged_ids": privileged_ids,
        "expected_admin_ids": expected_admin_ids,
        "matched_groups": matched_groups,
    }


def _permission_findings(
    graph: ADGraph,
    members: Mapping[str, Sequence[str]],
    privileged_ids: set[str],
    descendant_paths: Optional[Dict[str, Dict[str, List[str]]]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    findings: List[Dict[str, Any]] = []
    permissions: List[Dict[str, Any]] = []
    for edge in graph.edges:
        kind = edge.kind.casefold()
        if (
            kind not in _ACL_CONTROL_KINDS
            or kind in _DEDICATED_CONTROL_KINDS
            or edge.target not in privileged_ids
        ):
            continue
        source = graph.nodes.get(edge.source)
        target = graph.nodes.get(edge.target)
        policy = EDGE_POLICIES.get(kind)
        if (
            not source
            or not target
            or not policy
            or source.id == target.id
            or source.id in privileged_ids
        ):
            continue
        effective = []
        effective_paths = []
        if source.kind.casefold() == "group":
            descendants = _descendant_paths(
                graph, members, source.id, descendant_paths
            )
            effective_paths = [
                {
                    "principal": _entity(graph.nodes[principal_id]),
                    "membership": "direct" if len(path_ids) == 2 else "transitive",
                    "via": [
                        _entity(graph.nodes[node_id])
                        for node_id in path_ids[1:-1]
                        if node_id in graph.nodes
                    ],
                }
                for principal_id, path_ids in descendants.items()
                if graph.nodes[principal_id].kind.casefold() in {"user", "computer"}
            ]
            effective = [item["principal"] for item in effective_paths]
        permission = {
            "principal": _entity(source),
            "relationship": edge.kind,
            "category": policy.category,
            "severity": policy.severity,
            "target": _entity(target),
            "effective_principals": effective,
            "effective_paths": effective_paths,
            "properties": edge.properties,
        }
        permissions.append(permission)
        findings.append(_finding(
            "ad.permissions.control_over_high_privilege",
            policy.severity,
            "Principal controls a high-privilege object",
            "A user or group has an allow-listed control right over a privileged user or group.",
            [_entity(source), _entity(target)],
            [permission],
            "Remove unnecessary ACEs and delegate only the minimum required permission.",
        ))
    return findings, permissions


def _dcsync_findings(
    graph: ADGraph,
    memberships: Mapping[str, Sequence[str]],
    members: Mapping[str, Sequence[str]],
    privileged_ids: set[str],
    descendant_paths: Optional[Dict[str, Dict[str, List[str]]]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    rights: Dict[Tuple[str, str], set[str]] = defaultdict(set)
    properties: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for edge in graph.edges:
        kind = edge.kind.casefold()
        target = graph.nodes.get(edge.target)
        if not target or target.kind.casefold() != "domain":
            continue
        if kind in {"getchanges", "getchangesall", "getchangesinfilteredset"}:
            rights[(edge.source, edge.target)].add(kind)
        elif kind in {"genericall", "allextendedrights"}:
            rights[(edge.source, edge.target)].update({"getchanges", "getchangesall"})
        else:
            continue
        properties[(edge.source, edge.target)].append(edge.properties)

    findings: List[Dict[str, Any]] = []
    paths: List[Dict[str, Any]] = []
    complete_sources = set()
    rights_by_source: Dict[str, List[Tuple[str, set[str]]]] = defaultdict(list)
    for (source_id, target_id), granted_rights in rights.items():
        rights_by_source[source_id].append((target_id, granted_rights))
    for (source_id, target_id), granted_rights in sorted(rights.items()):
        if not {"getchanges", "getchangesall"}.issubset(granted_rights):
            continue
        source = graph.nodes.get(source_id)
        target = graph.nodes.get(target_id)
        if not source or not target or source_id in privileged_ids:
            continue
        complete_sources.add((source_id, target_id))
        source_paths = {source_id: [source_id]}
        if source.kind.casefold() == "group":
            source_paths.update(_descendant_paths(graph, members, source_id, descendant_paths))
        attack_paths = [
            _path_evidence(graph, path_ids, "DCSync", target)
            for principal_id, path_ids in source_paths.items()
            if graph.nodes[principal_id].kind.casefold() in {"user", "computer", "group"}
        ]
        paths.extend(attack_paths)
        evidence = {
            "principal": _entity(source),
            "target": _entity(target),
            "composite_rights": sorted(granted_rights),
            "effective_principal_count": len(attack_paths),
            "properties": properties[(source_id, target_id)],
        }
        findings.append(_finding(
            "ad.permissions.dcsync",
            "critical",
            "Principal can replicate domain secrets",
            "The principal has the effective rights required to perform DCSync.",
            [_entity(source), _entity(target)],
            [evidence],
            "Restrict replication rights to approved domain controller identities and investigate delegated grants.",
        ))
    # Identify affected principals from the small set of right-bearing sources.
    # Membership ordering and evidence paths are resolved only for that subset.
    affected_principals: set[str] = set()
    covered_targets: Dict[str, set[str]] = defaultdict(set)
    for source_id, target_grants in rights_by_source.items():
        source = graph.nodes.get(source_id)
        if not source:
            continue
        source_paths = {source_id: [source_id]}
        if source.kind.casefold() == "group":
            source_paths.update(
                _descendant_paths(graph, members, source_id, descendant_paths)
            )
        for principal_id in source_paths:
            principal = graph.nodes.get(principal_id)
            if not principal or principal.kind.casefold() not in {"user", "computer"}:
                continue
            for target_id, _granted_rights in target_grants:
                if (source_id, target_id) in complete_sources:
                    covered_targets[principal_id].add(target_id)
                else:
                    affected_principals.add(principal_id)

    if not affected_principals:
        return findings, paths

    for principal in graph.nodes_of_kind("User", "Computer"):
        if principal.id in privileged_ids or principal.id not in affected_principals:
            continue
        effective_sources = _effective_sources(memberships, principal.id)
        target_rights: Dict[str, set[str]] = defaultdict(set)
        target_grants: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for source_id, membership_path in effective_sources.items():
            for target_id, granted_rights in rights_by_source.get(source_id, []):
                target_rights[target_id].update(granted_rights)
                target_grants[target_id].append({
                    "granted_to": _entity(graph.nodes[source_id]),
                    "rights": sorted(granted_rights),
                    "via": [
                        _entity(graph.nodes[node_id])
                        for node_id in membership_path
                        if node_id in graph.nodes
                    ],
                })
        for target_id, granted_rights in target_rights.items():
            if (
                not {"getchanges", "getchangesall"}.issubset(granted_rights)
                or target_id in covered_targets.get(principal.id, ())
            ):
                continue
            target = graph.nodes.get(target_id)
            if not target:
                continue
            path = _path_evidence(graph, [principal.id], "DCSync", target)
            paths.append(path)
            findings.append(_finding(
                "ad.permissions.dcsync",
                "critical",
                "Principal can replicate domain secrets",
                "The principal inherits the combined rights required to perform DCSync from multiple grants.",
                [_entity(principal), _entity(target)],
                [{
                    "principal": _entity(principal),
                    "target": _entity(target),
                    "composite_rights": sorted(granted_rights),
                    "grants": target_grants[target_id],
                }],
                "Restrict replication rights to approved domain controller identities and investigate delegated grants.",
            ))
    return findings, paths


def analyze_ad_posture(
    graph: ADGraph,
    policy: Optional[ADAnalysisPolicy] = None,
    *,
    now: Optional[datetime] = None,
    sensitive_groups: Optional[Sequence[Mapping[str, Any]]] = None,
    privilege_context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Return posture findings plus operator-focused privilege inventory."""
    policy = policy or ADAnalysisPolicy()
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    context = dict(privilege_context or build_privilege_context(graph, sensitive_groups))
    registry = context["registry"]
    memberships_index = context["memberships_index"]
    members = context["members"]
    memberships = context["memberships"]
    administrative_paths = context["administrative_paths"]
    descendant_paths = context.get("descendant_paths")
    privileged_ids = context["privileged_ids"]
    findings: List[Dict[str, Any]] = []

    domain_admin_groups = [node for node in graph.nodes.values() if _is_domain_admins(node)]
    for group in domain_admin_groups:
        paths = administrative_paths.get(group.id) or _descendant_paths(
            graph, members, group.id, descendant_paths
        )
        admins = [
            graph.nodes[principal_id]
            for principal_id in paths
            if graph.nodes[principal_id].kind.casefold() == "user"
            and _is_enabled(graph.nodes[principal_id])
        ]
        if len(admins) > policy.max_domain_admins:
            findings.append(_finding(
                "ad.groups.excessive_domain_admins",
                "high",
                "Domain Admins membership exceeds policy",
                f"The group has {len(admins)} enabled user members; policy permits at most {policy.max_domain_admins}.",
                [_entity(group), *[_entity(node) for node in admins]],
                [{"count": len(admins), "maximum": policy.max_domain_admins}],
                "Remove standing membership that is not strictly required and use time-bound elevation.",
            ))

    protected_groups = [node for node in graph.nodes.values() if _is_protected_users(node)]
    protected_ids = set()
    for group in protected_groups:
        protected_ids.update(_descendant_paths(graph, members, group.id, descendant_paths))
    privileged_users = {
        principal_id
        for paths in administrative_paths.values()
        for principal_id in paths
        if graph.nodes[principal_id].kind.casefold() == "user"
        and _is_enabled(graph.nodes[principal_id])
    }
    for user_id in (
        sorted(privileged_users - protected_ids) if protected_groups else []
    ):
        user = graph.nodes[user_id]
        findings.append(_finding(
            "ad.privilege.user_not_protected_users",
            "medium",
            "Privileged user is not in Protected Users",
            "An enabled administrative user is not an effective member of Protected Users.",
            [_entity(user)],
            [{"administrative_groups": [
                _entity(graph.nodes[group_id])
                for group_id, paths in administrative_paths.items()
                if user_id in paths
            ]}],
            "Assess compatibility, then add eligible privileged user accounts to Protected Users or an equivalent authentication policy silo.",
        ))

    for user in graph.nodes_of_kind("User"):
        password_age = _age_days(_prop(user, "pwdlastset", "passwordlastset"), now)
        sam = str(_prop(user, "samaccountname") or "").rstrip("$").casefold()
        is_krbtgt = _rid(user) == "502" or sam == "krbtgt" or _name_key(user) == "krbtgt"
        if is_krbtgt:
            if password_age is not None and password_age > policy.max_krbtgt_password_age_days:
                findings.append(_finding(
                    "ad.password.krbtgt_password_old",
                    "high",
                    "KRBTGT password exceeds the age policy",
                    f"The KRBTGT password is {password_age} days old; policy permits {policy.max_krbtgt_password_age_days} days.",
                    [_entity(user)],
                    [{"password_age_days": password_age, "maximum_days": policy.max_krbtgt_password_age_days}],
                    "Use Microsoft's supported procedure to rotate KRBTGT twice with the required replication and ticket-lifetime delay.",
                ))
        elif _is_enabled(user) and password_age is not None and password_age > policy.max_password_age_days:
            findings.append(_finding(
                "ad.password.user_password_old",
                "medium",
                "User password exceeds the age policy",
                f"The password is {password_age} days old; policy permits {policy.max_password_age_days} days.",
                [_entity(user)],
                [{"password_age_days": password_age, "maximum_days": policy.max_password_age_days}],
                "Review account use and rotate the credential using an appropriate managed-account strategy.",
            ))

    for computer in graph.nodes_of_kind("Computer"):
        groups = [
            graph.nodes[group_id]
            for group_id, paths in administrative_paths.items()
            if computer.id in paths
        ]
        if groups:
            findings.append(_finding(
                "ad.privilege.computer_in_administrative_group",
                "critical",
                "Computer account has administrative group membership",
                "A computer account is an effective member of an administrative group.",
                [_entity(computer), *[_entity(group) for group in groups]],
                [{
                    "administrative_groups": [_entity(group) for group in groups],
                    "memberships": [
                        {
                            "group": _entity(group),
                            "membership": (
                                "direct"
                                if len(administrative_paths[group.id][computer.id]) == 2
                                else "transitive"
                            ),
                            "via": [
                                _entity(graph.nodes[node_id])
                                for node_id in administrative_paths[group.id][computer.id][1:-1]
                                if node_id in graph.nodes
                            ],
                        }
                        for group in groups
                    ],
                }],
                "Remove computer accounts from administrative groups unless the design is explicitly required and reviewed.",
            ))

        password_time = _timestamp(_prop(computer, "pwdlastset", "passwordlastset"))
        created_time = _timestamp(_prop(computer, "whencreated", "created"))
        password_age = _age_days(_prop(computer, "pwdlastset", "passwordlastset"), now)
        if (
            _is_enabled(computer)
            and password_time is not None
            and created_time is not None
            and password_age is not None
            and password_age > policy.timeroast_password_age_days
            and abs((password_time - created_time).total_seconds())
            <= policy.timeroast_creation_window_days * 86400
        ):
            sam = str(_prop(computer, "samaccountname") or computer.name.split(".", 1)[0])
            candidate_password = sam.rstrip("$")[:14].lower()
            findings.append(_finding(
                "ad.kerberos.timeroast_candidate",
                "high",
                "Computer is a likely legacy-password TimeRoast target",
                "The computer password is stale and was last set near account creation, consistent with a pre-created account whose weak legacy password may never have rotated.",
                [_entity(computer)],
                [{
                    "password_age_days": password_age,
                    "creation_delta_hours": round(abs((password_time - created_time).total_seconds()) / 3600, 2),
                    "legacy_password_candidate": candidate_password,
                }],
                "Confirm whether the account was ever joined, rotate or remove it, and investigate disabled machine-password rotation.",
            ))

    permission_findings, permissions = _permission_findings(
        graph, members, privileged_ids, descendant_paths
    )
    dcsync_findings, dcsync_paths = _dcsync_findings(
        graph, memberships_index, members, privileged_ids, descendant_paths
    )
    findings.extend(permission_findings)
    findings.extend(dcsync_findings)
    return {
        "policy": vars(policy),
        "sensitive_group_registry": registry,
        "administrative_groups": [
            _entity(node)
            for node in graph.nodes.values()
            if _is_administrative_group(node, registry)
        ],
        "memberships": memberships,
        "permissions": permissions,
        "dcsync_paths": dcsync_paths,
        "findings": findings,
    }
