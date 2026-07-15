"""AD-specific adapter for the operator TUI.

All graph and ranking work happens here; Textual widgets only render bounded views.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from ..config import get_default_ad_rules_path
from ..core.ad_analyzer import (
    ADGraph,
    ADNode,
    _prop,
    _truthy,
    load_bloodhound_zip,
)
from ..core.ad_owned import EDGE_POLICIES
from ..core.ad_pipeline import analyze_bloodhound
from ..core.ad_posture import _is_domain_admins
from ..core.ad_reporting import load_ad_configuration
from .ad_exposures import build_exposure_rows
from .state import ADIndex, ADNodePivot, ADPathRow, ADRelationship

_SEVERITY_WEIGHT = {"info": 0, "low": 5, "medium": 12, "high": 22, "critical": 32}
_TARGET_WEIGHT = {
    "domain_admin": 60,
    "dcsync": 60,
    "tier_zero": 50,
    "domain_controller": 45,
    "adcs": 40,
    "high_value": 35,
}
_CATEGORY_COPY = {
    "membership": (
        "Membership carries the principal into the next security context.",
        "Use the effective group identity to evaluate its outbound rights.",
        "Nested membership may be constrained by scope, deny ACEs, or operational controls.",
    ),
    "local_admin": (
        "Local administration normally enables control of the target host.",
        "Validate a remote-management route and inspect sessions or reusable credentials.",
        "Host reachability, endpoint controls, and local policy still apply.",
    ),
    "remote_access": (
        "The relationship permits a remote logon or management channel.",
        "Use the host as a bounded pivot and inspect exposed privileged sessions.",
        "Authentication, firewall, and endpoint policy prerequisites must be validated.",
    ),
    "acl_control": (
        "The right can change or take control of the target directory object.",
        "Inspect the exact right and target for a safe privilege-escalation primitive.",
        "Protected objects, inheritance, and deny ACEs can affect practical use.",
    ),
    "group_control": (
        "The right can alter effective group membership.",
        "Evaluate the privileges gained by adding a controlled principal.",
        "Confirm write scope and any approval or monitoring controls.",
    ),
    "credential_access": (
        "The relationship exposes or controls managed credential material.",
        "Assess whether the credential unlocks the target or additional hosts.",
        "Collection proves the right, not that credential retrieval will succeed.",
    ),
    "credential_control": (
        "The relationship can alter authentication material for the target.",
        "Evaluate account takeover and the target's downstream access.",
        "Validate object protections and authentication prerequisites.",
    ),
    "directory_replication": (
        "Combined replication rights can expose domain credential material.",
        "Treat the domain as a Tier Zero objective and validate the complete right set.",
        "DCSync requires the required composite replication rights.",
    ),
    "delegation_control": (
        "Delegation control can create an impersonation route to the target.",
        "Validate SPNs and delegation prerequisites before treating it as actionable.",
        "Protocol, SPN, and account configuration determine practical exploitability.",
    ),
    "kerberos_control": (
        "The right can influence Kerberos authentication for the target.",
        "Evaluate an authentication-material or service-ticket pivot.",
        "Domain policy and target configuration may constrain the primitive.",
    ),
    "evidence": (
        "The collection records this relationship as evidence.",
        "Investigate it manually before using it in an attack plan.",
        "Unknown relationships are never assumed exploitable by YAPP.",
    ),
}


def _entity(node: ADNode) -> dict[str, Any]:
    return {"id": node.id, "name": node.name, "type": node.kind}


def _relationship(
    source: Mapping[str, Any],
    relationship: str,
    target: Mapping[str, Any],
    *,
    direct: bool = True,
    via: Sequence[Mapping[str, Any]] = (),
    category_override: str | None = None,
    severity_override: str | None = None,
) -> ADRelationship:
    policy = EDGE_POLICIES.get(relationship.casefold())
    category = category_override or (policy.category if policy else "evidence")
    why, opportunity, caveat = _CATEGORY_COPY.get(category, _CATEGORY_COPY["evidence"])
    return ADRelationship(
        source=dict(source),
        relationship=relationship,
        target=dict(target),
        category=category,
        severity=severity_override or (policy.severity if policy else "info"),
        traversable=bool(policy and policy.traversable),
        direct=direct,
        via=tuple(dict(item) for item in via),
        why=why,
        opportunity=opportunity,
        caveat=caveat,
    )


def _iter_report_paths(report: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    privilege = report.get("privilege_analysis") or {}
    yield from privilege.get("dcsync_paths") or []
    owned = report.get("owned_analysis") or {}
    yield from owned.get("paths") or []
    for finding in report.get("findings") or []:
        if ".path_to_" not in str(finding.get("id") or ""):
            continue
        for evidence in finding.get("evidence") or []:
            if isinstance(evidence, Mapping) and evidence.get("nodes") and evidence.get("edges"):
                yield evidence


def _target_class(
    path: Mapping[str, Any],
    target_classes: Mapping[str, str] | None = None,
) -> str:
    target = path.get("target") or {}
    name = str(target.get("name") or "").split("@", 1)[0].casefold()
    edges = {str(edge).casefold() for edge in path.get("edges") or []}
    target_type = str(target.get("type") or "").casefold()
    if "dcsync" in edges:
        return "dcsync"
    if name == "domain admins":
        return "domain_admin"
    target_id = str(target.get("id") or "")
    if target_classes and target_id in target_classes:
        return target_classes[target_id]
    if target_type in {"certificateauthority", "enterpriseca", "rootca", "aiaca", "ntauthstore"}:
        return "adcs"
    return "high_value"


def _graph_target_classes(graph: ADGraph) -> dict[str, str]:
    classes: dict[str, str] = {}
    adcs_kinds = {
        "certificateauthority", "enterpriseca", "rootca", "aiaca",
        "ntauthstore", "certtemplate", "issuancepolicy",
    }
    for node in graph.nodes.values():
        kind = node.kind.casefold()
        if _is_domain_admins(node):
            classes[node.id] = "domain_admin"
        elif kind in adcs_kinds:
            classes[node.id] = "adcs"
        elif kind == "computer" and _truthy(
            _prop(node, "isdc", "is_dc", "domaincontroller")
        ):
            classes[node.id] = "domain_controller"
        elif _truthy(_prop(node, "istierzero", "highvalue", "high_value")):
            classes[node.id] = "tier_zero"
    return classes


def _choke_lookup(report: Mapping[str, Any]) -> dict[tuple[str, str, str], int]:
    output: dict[tuple[str, str, str], int] = {}
    for row in (report.get("path_analysis") or {}).get("choke_points") or []:
        source = row.get("source") or {}
        target = row.get("target") or {}
        key = (
            str(source.get("id") or ""),
            str(row.get("relationship") or "").casefold(),
            str(target.get("id") or ""),
        )
        output[key] = max(output.get(key, 0), int(row.get("path_count") or 0))
    return output


def _path_rows(
    report: Mapping[str, Any],
    owned_ids: set[str],
    target_classes: Mapping[str, str] | None = None,
) -> list[ADPathRow]:
    choke = _choke_lookup(report)
    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    rows: list[ADPathRow] = []
    for path in _iter_report_paths(report):
        nodes = tuple(dict(node) for node in path.get("nodes") or [])
        edges = tuple(str(edge) for edge in path.get("edges") or [])
        if len(nodes) < 2 or len(edges) != len(nodes) - 1:
            continue
        identity = (
            tuple(str(node.get("id") or node.get("name") or "") for node in nodes),
            tuple(edge.casefold() for edge in edges),
        )
        if identity in seen:
            continue
        seen.add(identity)
        steps = tuple(
            _relationship(nodes[index], edge, nodes[index + 1])
            for index, edge in enumerate(edges)
        )
        choke_count = max(
            (
                choke.get(
                    (
                        str(step.source.get("id") or ""),
                        step.relationship.casefold(),
                        str(step.target.get("id") or ""),
                    ),
                    0,
                )
                for step in steps
            ),
            default=0,
        )
        target_class = _target_class(path, target_classes)
        source_id = str(nodes[0].get("id") or "")
        owned = source_id in owned_ids
        traversable = all(step.traversable for step in steps)
        severity = max((_SEVERITY_WEIGHT.get(step.severity, 0) for step in steps), default=0)
        score = (
            _TARGET_WEIGHT.get(target_class, 30)
            + (40 if owned else 0)
            + severity
            + min(choke_count, 10) * 2
            + max(0, 12 - len(steps) * 2)
            - (0 if traversable else 80)
        )
        digest = hashlib.sha256(repr(identity).encode("utf-8")).hexdigest()[:16]
        rows.append(
            ADPathRow(
                path_id=digest,
                source=nodes[0],
                target=nodes[-1],
                nodes=nodes,
                steps=steps,
                target_class=target_class,
                score=score,
                choke_count=choke_count,
                owned=owned,
            )
        )
    return sorted(
        rows,
        key=lambda row: (
            -row.score,
            row.length,
            str(row.source.get("name") or "").casefold(),
            str(row.target.get("name") or "").casefold(),
            row.path_id,
        ),
    )


def _owned_ids(report: Mapping[str, Any]) -> set[str]:
    return {
        str((row.get("principal") or {}).get("id") or "")
        for row in (report.get("owned_analysis") or {}).get("principals") or []
    }


def _pivots(
    graph: ADGraph,
    paths: Sequence[ADPathRow],
    report: Mapping[str, Any],
) -> dict[str, ADNodePivot]:
    outgoing: dict[str, list[ADRelationship]] = defaultdict(list)
    incoming: dict[str, list[ADRelationship]] = defaultdict(list)
    relationship_keys: dict[str, set[tuple[str, str, str]]] = defaultdict(set)
    path_ids: dict[str, list[str]] = defaultdict(list)
    entities = {node_id: _entity(node) for node_id, node in graph.nodes.items()}
    for edge in graph.edges:
        source = entities.get(edge.source)
        target = entities.get(edge.target)
        if not source or not target:
            continue
        item = _relationship(source, edge.kind, target)
        outgoing[edge.source].append(item)
        incoming[edge.target].append(item)
        relationship_keys[edge.source].add(
            ("out", edge.kind.casefold(), edge.target)
        )
        relationship_keys[edge.target].add(
            ("in", edge.kind.casefold(), edge.source)
        )
    for principal in (report.get("owned_analysis") or {}).get("principals") or []:
        source = principal.get("principal") or {}
        source_id = str(source.get("id") or "")
        if not source_id:
            continue
        for control in principal.get("direct_controls") or []:
            target = control.get("target") or {}
            target_id = str(target.get("id") or "")
            if not target_id:
                continue
            via = control.get("via") or []
            item = _relationship(
                source,
                str(control.get("relationship") or "Unknown"),
                target,
                direct=not bool(via),
                via=via,
                category_override=str(control.get("category") or "evidence"),
                severity_override=str(control.get("severity") or "info"),
            )
            outbound_key = ("out", item.relationship.casefold(), target_id)
            inbound_key = ("in", item.relationship.casefold(), source_id)
            if outbound_key not in relationship_keys[source_id]:
                outgoing[source_id].append(item)
                relationship_keys[source_id].add(outbound_key)
            if inbound_key not in relationship_keys[target_id]:
                incoming[target_id].append(item)
                relationship_keys[target_id].add(inbound_key)
    for path in paths:
        for node in path.nodes:
            path_ids[str(node.get("id") or "")].append(path.path_id)
    return {
        node_id: ADNodePivot(
            entity=entity,
            outbound=tuple(sorted(outgoing[node_id], key=lambda item: (not item.traversable, item.relationship.casefold(), str(item.target.get("name") or "").casefold()))),
            inbound=tuple(sorted(incoming[node_id], key=lambda item: (not item.traversable, item.relationship.casefold(), str(item.source.get("name") or "").casefold()))),
            paths=tuple(path_ids[node_id]),
        )
        for node_id, entity in entities.items()
    }


def build_ad_index(
    input_file: str,
    *,
    owned_principals: Sequence[str] = (),
    include_paths: bool = True,
    rules_file: str | None = None,
    progress: Callable[[str], None] | None = None,
) -> ADIndex:
    """Analyze one BloodHound ZIP and build a bounded operator index."""
    source = Path(input_file)
    if progress:
        progress("Loading BloodHound collection")
    graph = load_bloodhound_zip(source)
    configuration = load_ad_configuration(
        str(rules_file or get_default_ad_rules_path())
    )
    report = analyze_bloodhound(
        source,
        include_paths=include_paths,
        owned_principals=owned_principals,
        sensitive_groups=configuration["sensitive_groups"],
        graph=graph,
        operator_paths=True,
        progress=progress,
    )
    paths = _path_rows(
        report,
        _owned_ids(report),
        _graph_target_classes(graph),
    )
    coverage = (report.get("operator_analysis") or {}).get("coverage") or []
    if progress:
        progress("Building privilege exposure queue")
    owned_ids = _owned_ids(report)
    exposures = build_exposure_rows(report, graph, owned_ids)
    if progress:
        progress("Indexing bounded node pivots")
    pivots = _pivots(graph, paths, report)
    if progress:
        progress("Ready to launch TUI")
    return ADIndex(
        input_file=str(source),
        parse_options={
            "file_type": "ad",
            "include_paths": include_paths,
            "rules_file": rules_file,
        },
        report=report,
        paths=paths,
        nodes={node_id: _entity(node) for node_id, node in graph.nodes.items()},
        pivots=pivots,
        assumed_owned=list(owned_principals),
        metadata={
            "source_name": source.name,
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "critical": int((report.get("summary") or {}).get("critical") or 0),
            "high": int((report.get("summary") or {}).get("high") or 0),
            "coverage_warnings": sum(
                1 for item in coverage if item.get("status") not in {"complete", "collected"}
            ),
        },
        exposures=exposures,
    )
