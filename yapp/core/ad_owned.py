"""Owned-principal control analysis for offline BloodHound graphs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .ad_analyzer import ADGraph, ADNode, _entity, _finding, _prop
from .ad_effective import map_effective_controls


@dataclass(frozen=True)
class EdgePolicy:
    category: str
    severity: str = "high"
    direct_control: bool = True
    traversable: bool = True


# Unknown relationships are preserved as evidence but never assumed to be
# exploitable. New BloodHound relationships must be explicitly opted in.
EDGE_POLICIES: Dict[str, EdgePolicy] = {
    "memberof": EdgePolicy("membership", "info", False),
    "adminto": EdgePolicy("local_admin"),
    "canrdp": EdgePolicy("remote_access", "medium"),
    "canpsremote": EdgePolicy("remote_access"),
    "executedcom": EdgePolicy("remote_access"),
    "sqladmin": EdgePolicy("service_control"),
    "hassession": EdgePolicy("session", "high", False),
    "genericall": EdgePolicy("acl_control"),
    "genericwrite": EdgePolicy("acl_control"),
    "writedacl": EdgePolicy("acl_control"),
    "writeowner": EdgePolicy("acl_control"),
    "owns": EdgePolicy("acl_control"),
    "allextendedrights": EdgePolicy("acl_control"),
    "forcechangepassword": EdgePolicy("credential_control"),
    "addmember": EdgePolicy("group_control"),
    "addself": EdgePolicy("group_control"),
    "writespn": EdgePolicy("kerberos_control"),
    "writeaccountrestrictions": EdgePolicy("delegation_control"),
    "addallowedtoact": EdgePolicy("delegation_control"),
    "allowedtoact": EdgePolicy("delegation_control"),
    "allowedtodelegate": EdgePolicy("delegation_control"),
    "readlapspassword": EdgePolicy("credential_access", "critical"),
    "readgmsapassword": EdgePolicy("credential_access", "critical"),
    "getchanges": EdgePolicy("directory_replication", "critical", False, False),
    "getchangesall": EdgePolicy("directory_replication", "critical", False, False),
    "getchangesinfilteredset": EdgePolicy("directory_replication", "critical", False, False),
    "gpplink": EdgePolicy("gpo", "info", False, False),
}

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _normalise_identity(value: str) -> str:
    return value.strip().casefold()


def _aliases(node: ADNode) -> Iterable[str]:
    values = {
        node.id,
        node.name,
        str(_prop(node, "samaccountname") or ""),
        str(_prop(node, "userprincipalname", "upn") or ""),
        str(_prop(node, "distinguishedname") or ""),
    }
    sam = str(_prop(node, "samaccountname") or "")
    domain = str(_prop(node, "domain") or "")
    if sam and domain:
        values.add(f"{domain}\\{sam}")
        values.add(f"{domain.split('.', 1)[0]}\\{sam}")
    return (_normalise_identity(value) for value in values if value)


def resolve_owned_principals(graph: ADGraph, identities: Sequence[str]) -> Dict[str, Any]:
    """Resolve owned identities without guessing ambiguous short names."""
    alias_index: Dict[str, List[ADNode]] = {}
    for node in graph.nodes_of_kind("User"):
        for alias in _aliases(node):
            alias_index.setdefault(alias, []).append(node)

    resolved: List[ADNode] = []
    unresolved: List[str] = []
    ambiguous: List[Dict[str, Any]] = []
    seen_ids = set()
    seen_queries = set()
    for raw_identity in identities:
        identity = raw_identity.strip()
        query = _normalise_identity(identity)
        if not query or query in seen_queries:
            continue
        seen_queries.add(query)
        candidates = {node.id: node for node in alias_index.get(query, [])}
        if len(candidates) == 1:
            node = next(iter(candidates.values()))
            if node.id not in seen_ids:
                resolved.append(node)
                seen_ids.add(node.id)
        elif not candidates:
            unresolved.append(identity)
        else:
            ambiguous.append({
                "query": identity,
                "candidates": [_entity(node) for node in candidates.values()],
            })
    return {
        "resolved_nodes": resolved,
        "resolved": [_entity(node) for node in resolved],
        "unresolved": unresolved,
        "ambiguous": ambiguous,
    }


def read_owned_principals(
    inline: Optional[Sequence[str]] = None,
    files: Optional[Sequence[str]] = None,
) -> List[str]:
    """Read one identity per line, allowing blank lines and # comments."""
    identities = list(inline or [])
    for filename in files or []:
        path = Path(filename)
        if not path.is_file():
            raise FileNotFoundError(f"Owned-user list not found: {path}")
        if path.stat().st_size > 10 * 1024 * 1024:
            raise ValueError(f"Owned-user list exceeds 10 MiB: {path}")
        with open(path, "r", encoding="utf-8", errors="replace") as source:
            identities.extend(
                line.strip()
                for line in source
                if line.strip() and not line.lstrip().startswith("#")
            )
    return identities


def traversable_edge_kinds() -> List[str]:
    return [name for name, policy in EDGE_POLICIES.items() if policy.traversable]


def analyze_owned_principals(graph: ADGraph, identities: Sequence[str]) -> Dict[str, Any]:
    resolution = resolve_owned_principals(graph, identities)
    owned_ids = {node.id for node in resolution.pop("resolved_nodes")}
    controls_by_source = map_effective_controls(graph, owned_ids, EDGE_POLICIES)

    findings: List[Dict[str, Any]] = []
    principals: List[Dict[str, Any]] = []
    for entity in resolution["resolved"]:
        controls = controls_by_source.get(entity["id"], [])
        principals.append({
            "principal": entity,
            "direct_control_count": len(controls),
            "direct_controls": controls,
        })
        if not controls:
            continue
        severity = max(
            (control["severity"] for control in controls),
            key=_SEVERITY_ORDER.__getitem__,
        )
        findings.append(_finding(
            "ad.owned.outbound_control",
            severity,
            "Owned principal has outbound control",
            "An assumed-compromised user directly controls or can access other directory assets.",
            [entity],
            controls,
            "Remove unnecessary rights and investigate each controlled target as a possible pivot.",
        ))

    return {
        **resolution,
        "principals": principals,
        "paths": [],
        "findings": findings,
        "resolved_ids": list(owned_ids),
    }
