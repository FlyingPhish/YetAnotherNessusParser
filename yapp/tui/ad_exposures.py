"""Build bounded, aggregated privilege-exposure rows for the AD TUI."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any, Mapping, Sequence

from ..core.ad_analyzer import ADGraph, _prop, _truthy
from ..core.ad_owned import EDGE_POLICIES
from .state import ADExposureRow

_BROAD_GROUPS = {
    "authenticated users",
    "domain computers",
    "domain users",
    "everyone",
}
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _base_name(entity: Mapping[str, Any]) -> str:
    return str(entity.get("name") or "").split("@", 1)[0].casefold()


def _stable_id(*parts: Any) -> str:
    return hashlib.sha256(repr(parts).encode("utf-8")).hexdigest()[:16]


def _entity_id(entity: Mapping[str, Any]) -> str:
    return str(entity.get("id") or entity.get("name") or "")


def _target_classes(graph: ADGraph) -> dict[str, str]:
    classes = {}
    for node in graph.nodes.values():
        kind = node.kind.casefold()
        if kind == "computer" and _truthy(
            _prop(node, "isdc", "is_dc", "domaincontroller")
        ):
            classes[node.id] = "domain_controller"
        elif _truthy(_prop(node, "istierzero", "highvalue", "high_value")):
            classes[node.id] = "tier_zero"
    return classes


def _membership_rows(
    report: Mapping[str, Any],
    graph: ADGraph,
    owned_ids: set[str],
) -> list[ADExposureRow]:
    rows = []
    computer_count = sum(1 for _ in graph.nodes_of_kind("Computer"))
    memberships = (report.get("privilege_analysis") or {}).get("memberships") or []
    for membership in memberships:
        principal = dict(membership.get("principal") or {})
        principal_type = str(principal.get("type") or "").casefold()
        broad = principal_type == "group" and _base_name(principal) in _BROAD_GROUPS
        computer = principal_type == "computer"
        if not broad and not computer:
            continue
        group = dict(membership.get("group") or {})
        via = tuple(dict(item) for item in membership.get("via") or [])
        severity = "critical" if broad else "high"
        affected = computer_count if broad and _base_name(principal) == "domain computers" else 1
        category = "broad_admin_membership" if broad else "computer_admin_membership"
        summary = (
            f"Broad group reaches {group.get('name', 'an administrative group')}; "
            f"up to {affected:,} collected computer accounts may inherit access"
            if broad and _base_name(principal) == "domain computers"
            else f"{principal.get('name', 'Computer')} is an effective member of "
            f"{group.get('name', 'an administrative group')}"
        )
        rows.append(
            ADExposureRow(
                exposure_id=_stable_id(category, _entity_id(principal), _entity_id(group)),
                category=category,
                priority="CRITICAL" if broad else "HIGH",
                score=100 if broad else 82,
                principal=principal,
                relationship="MemberOf",
                targets=({
                    "entity": group,
                    "membership": membership.get("membership") or "unknown",
                    "via": via,
                    "privileged_memberships": (),
                },),
                target_count=1,
                effective_count=affected,
                owned=_entity_id(principal) in owned_ids,
                summary=summary,
                why=(
                    "A broad computer population inherits administrative-group privileges."
                    if broad
                    else (
                        "A computer identity holds administrative-group privilege and "
                        "may extend host compromise into AD."
                    )
                ),
                caveat=(
                    "Primary-group membership is often implicit in BloodHound data; "
                    "the group edge is collected, while individual computer edges may not be."
                    if broad
                    else (
                        "Validate whether the computer membership is intentional and "
                        "whether the account is currently active."
                    )
                ),
            )
        )
    return rows


def _privileged_control_rows(
    report: Mapping[str, Any],
    owned_ids: set[str],
) -> list[ADExposureRow]:
    privilege = report.get("privilege_analysis") or {}
    memberships_by_principal: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for membership in privilege.get("memberships") or []:
        principal_id = _entity_id(membership.get("principal") or {})
        if principal_id:
            memberships_by_principal[principal_id].append(dict(membership))

    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for permission in privilege.get("permissions") or []:
        principal = dict(permission.get("principal") or {})
        relationship = str(permission.get("relationship") or "Unknown")
        key = (_entity_id(principal), relationship.casefold())
        item = grouped.setdefault(key, {
            "principal": principal,
            "relationship": relationship,
            "category": permission.get("category") or "acl_control",
            "severity": permission.get("severity") or "high",
            "targets": {},
            "effective": {},
        })
        severity = str(permission.get("severity") or "high")
        if _SEVERITY_ORDER.get(severity, 0) > _SEVERITY_ORDER.get(item["severity"], 0):
            item["severity"] = severity

        target = dict(permission.get("target") or {})
        target_id = _entity_id(target)
        if target_id:
            item["targets"][target_id] = {
                "entity": target,
                "privileged_memberships": tuple(
                    memberships_by_principal.get(target_id, [])
                ),
                "via": (),
            }

        effective_paths = {
            _entity_id(path.get("principal") or {}): path
            for path in permission.get("effective_paths") or []
        }
        for actor in permission.get("effective_principals") or []:
            actor = dict(actor)
            actor_id = _entity_id(actor)
            path = effective_paths.get(actor_id) or {}
            if actor_id:
                item["effective"][actor_id] = {
                    "entity": actor,
                    "membership": path.get("membership") or "effective",
                    "via": tuple(dict(value) for value in path.get("via") or []),
                }

    rows = []
    for key, item in grouped.items():
        principal = item["principal"]
        targets = tuple(
            sorted(
                item["targets"].values(),
                key=lambda row: str(row["entity"].get("name") or "").casefold(),
            )
        )
        effective = tuple(
            sorted(
                item["effective"].values(),
                key=lambda row: str(row["entity"].get("name") or "").casefold(),
            )
        )
        severity = str(item["severity"])
        policy = EDGE_POLICIES.get(str(item["relationship"]).casefold())
        owned = _entity_id(principal) in owned_ids or any(
            _entity_id(row["entity"]) in owned_ids for row in effective
        )
        score = (
            {"critical": 90, "high": 75, "medium": 58, "low": 35, "info": 15}.get(severity, 50)
            + min(len(targets), 10) * 2
            + (15 if owned else 0)
        )
        target_types = {str(row["entity"].get("type") or "").casefold() for row in targets}
        target_label = (
            "privileged users"
            if target_types == {"user"}
            else "privileged objects"
        )
        rows.append(
            ADExposureRow(
                exposure_id=_stable_id("privileged_control", *key),
                category="privileged_control",
                priority="ACT NOW" if owned else severity.upper(),
                score=score,
                principal=principal,
                relationship=str(item["relationship"]),
                targets=targets[:1000],
                target_count=len(targets),
                effective_count=len(effective),
                effective_principals=effective[:1000],
                owned=owned,
                summary=(
                    f"{len(targets):,} {target_label} controlled; "
                    f"{len(effective):,} effective actors"
                ),
                why=(
                    "This allow-listed directory right can control identities or groups "
                    "that are effective members of administrative groups."
                ),
                caveat=(
                    "Validate object protections, deny ACEs, inheritance, and operational prerequisites."
                    if policy
                    else "The relationship is retained as evidence and is not assumed exploitable."
                ),
            )
        )
    return rows


def _local_admin_rows(
    report: Mapping[str, Any],
    graph: ADGraph,
    owned_ids: set[str],
) -> list[ADExposureRow]:
    target_classes = _target_classes(graph)
    grouped: dict[str, dict[str, Any]] = {}
    fleet = (report.get("operator_analysis") or {}).get("fleet_access") or []
    for access in fleet:
        if str(access.get("relationship") or "").casefold() != "adminto":
            continue
        granted_to = dict(access.get("granted_to") or access.get("principal") or {})
        key = _entity_id(granted_to)
        item = grouped.setdefault(key, {
            "principal": granted_to,
            "targets": {},
            "effective": {},
        })
        target = dict(access.get("target") or {})
        target_id = _entity_id(target)
        if target_id:
            item["targets"][target_id] = {
                "entity": target,
                "target_class": target_classes.get(target_id, "computer"),
                "via": (),
                "privileged_memberships": (),
            }
        actor = dict(access.get("principal") or {})
        actor_id = _entity_id(actor)
        if actor_id:
            item["effective"][actor_id] = {
                "entity": actor,
                "membership": "direct" if not access.get("via") else "inherited",
                "via": tuple(dict(value) for value in access.get("via") or []),
            }

    rows = []
    for key, item in grouped.items():
        principal = item["principal"]
        targets = tuple(
            sorted(
                item["targets"].values(),
                key=lambda row: str(row["entity"].get("name") or "").casefold(),
            )
        )
        effective = tuple(
            sorted(
                item["effective"].values(),
                key=lambda row: str(row["entity"].get("name") or "").casefold(),
            )
        )
        owned = _entity_id(principal) in owned_ids or any(
            _entity_id(row["entity"]) in owned_ids for row in effective
        )
        sensitive = sum(
            1 for row in targets
            if row.get("target_class") in {"domain_controller", "tier_zero"}
        )
        broad = _base_name(principal) in _BROAD_GROUPS
        score = 72 + min(len(targets), 10) * 2 + min(sensitive, 3) * 8
        if broad:
            score += 12
        if owned:
            score += 20
        rows.append(
            ADExposureRow(
                exposure_id=_stable_id("local_admin", key),
                category="local_admin_access",
                priority="ACT NOW" if owned else ("CRITICAL" if sensitive or broad else "HIGH"),
                score=score,
                principal=principal,
                relationship="AdminTo",
                targets=targets[:1000],
                target_count=len(targets),
                effective_count=len(effective),
                effective_principals=effective[:1000],
                owned=owned,
                summary=(
                    f"Local administrator on {len(targets):,} computers; "
                    f"{len(effective):,} effective actors"
                    + (f"; {sensitive:,} Tier Zero/DC targets" if sensitive else "")
                ),
                why=(
                    "Local administration can enable code execution, credential access, "
                    "session theft, and onward host pivots."
                ),
                caveat=(
                    "Validate network reachability, remote-management paths, endpoint controls, "
                    "and whether the grant remains effective."
                ),
            )
        )
    return rows


def build_exposure_rows(
    report: Mapping[str, Any],
    graph: ADGraph,
    owned_ids: Sequence[str],
) -> list[ADExposureRow]:
    """Return deterministic, aggregated exposure rows for operator triage."""
    owned = set(owned_ids)
    rows = [
        *_membership_rows(report, graph, owned),
        *_privileged_control_rows(report, owned),
        *_local_admin_rows(report, graph, owned),
    ]
    return sorted(
        rows,
        key=lambda row: (
            -row.score,
            row.category,
            str(row.principal.get("name") or "").casefold(),
            row.relationship.casefold(),
            row.exposure_id,
        ),
    )
