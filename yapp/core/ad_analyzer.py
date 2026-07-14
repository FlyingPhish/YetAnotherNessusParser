"""Offline BloodHound collection analysis.

The importer intentionally understands the collection format, not the
BloodHound/Neo4j server.  Rules consume a small, stable graph model so the
collection format and the optional query backend can evolve independently.
"""

from __future__ import annotations

import json
import logging
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Union

logger = logging.getLogger(__name__)


class ADAnalyzerError(ValueError):
    """Raised when a BloodHound collection is invalid or unsafe to process."""


@dataclass
class ADNode:
    id: str
    kind: str
    properties: Dict[str, Any] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return str(
            self.properties.get("name")
            or self.properties.get("samaccountname")
            or self.properties.get("distinguishedname")
            or self.id
        )


@dataclass
class ADEdge:
    source: str
    target: str
    kind: str
    properties: Dict[str, Any] = field(default_factory=dict)


class ADGraph:
    """Small in-memory representation shared by direct and path rules."""

    def __init__(self) -> None:
        self.nodes: Dict[str, ADNode] = {}
        self.edges: List[ADEdge] = []
        self._edge_keys = set()

    def add_node(self, node_id: str, kind: str, properties: Optional[Dict[str, Any]] = None) -> None:
        if not node_id:
            return
        existing = self.nodes.get(node_id)
        if existing:
            if existing.kind == "Unknown" and kind != "Unknown":
                existing.kind = kind
            if properties:
                existing.properties.update(properties)
            return
        self.nodes[node_id] = ADNode(node_id, kind or "Unknown", properties or {})

    def add_edge(
        self,
        source: str,
        target: str,
        kind: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not source or not target or not kind:
            return
        self.add_node(source, "Unknown")
        self.add_node(target, "Unknown")
        edge = ADEdge(source, target, kind, properties or {})
        key = (source, target, kind, json.dumps(edge.properties, sort_keys=True, default=str))
        if key not in self._edge_keys:
            self._edge_keys.add(key)
            self.edges.append(edge)

    def nodes_of_kind(self, *kinds: str) -> Iterable[ADNode]:
        wanted = {kind.lower() for kind in kinds}
        return (node for node in self.nodes.values() if node.kind.lower() in wanted)


_KIND_NAMES = {
    "users": "User",
    "computers": "Computer",
    "groups": "Group",
    "domains": "Domain",
    "ous": "OU",
    "gpos": "GPO",
    "containers": "Container",
    "certificationauthorities": "CertificateAuthority",
    "ous": "OU",
}

_MAX_MEMBER_BYTES = 512 * 1024 * 1024
_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
_MAX_RECORDS = 5_000_000


def _normalise_key(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum())


def _first(mapping: Dict[str, Any], *keys: str) -> Any:
    normalised = {_normalise_key(str(key)): value for key, value in mapping.items()}
    for key in keys:
        if _normalise_key(key) in normalised:
            return normalised[_normalise_key(key)]
    return None


def _record_id(record: Dict[str, Any], properties: Dict[str, Any]) -> Optional[str]:
    value = _first(record, "ObjectIdentifier", "objectid", "id", "ObjectId")
    if value is None:
        value = _first(properties, "ObjectIdentifier", "objectid", "id", "ObjectId")
    return str(value) if value not in (None, "") else None


def _record_properties(record: Dict[str, Any]) -> Dict[str, Any]:
    properties: Dict[str, Any] = {}
    nested = _first(record, "Properties", "property")
    if isinstance(nested, dict):
        properties.update(nested)
    for key, value in record.items():
        if key.lower() not in {"properties", "aces", "sessions", "members", "localadmins"}:
            properties.setdefault(key, value)
    # Keep both a predictable lower-case lookup surface and original values.
    normalised = {_normalise_key(str(key)): value for key, value in properties.items()}
    normalised.update(properties)
    return normalised


def _endpoint(value: Any) -> Optional[str]:
    if isinstance(value, str):
        return value or None
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dict):
        candidate = _first(
            value,
            "ObjectIdentifier",
            "ObjectIdentifierValue",
            "MemberId",
            "MemberSID",
            "UserSID",
            "ComputerSID",
            "PrincipalSID",
            "PrincipalObjectIdentifier",
            "PrincipalId",
            "Id",
        )
        return str(candidate) if candidate not in (None, "") else None
    return None


def _add_record_edges(graph: ADGraph, record: Dict[str, Any], node_id: str) -> None:
    # Group membership is represented as a list on group records in most
    # SharpHound exports.  Direction follows BloodHound: member -> group.
    members = _first(record, "Members", "member")
    if isinstance(members, list):
        for member in members:
            member_id = _endpoint(member)
            if member_id:
                graph.add_edge(member_id, node_id, "MemberOf")

    aces = _first(record, "Aces", "ACLs", "acls")
    if isinstance(aces, list):
        for ace in aces:
            if not isinstance(ace, dict):
                continue
            principal = _endpoint(ace)
            right = _first(ace, "RightName", "Right", "Rights", "permission")
            if isinstance(right, list):
                rights = right
            else:
                rights = [right or "ACL"]
            for permission in rights:
                graph.add_edge(principal or "", node_id, str(permission), {"ace": ace})

    sessions = _first(record, "Sessions", "PrivilegedSessions", "HasSession")
    if isinstance(sessions, list):
        for session in sessions:
            if not isinstance(session, dict):
                continue
            user_id = _first(session, "UserSID", "UserId", "UserIdentifier")
            computer_id = _first(session, "ComputerSID", "ComputerId", "ComputerIdentifier")
            if user_id and computer_id:
                graph.add_edge(str(user_id), str(computer_id), "HasSession")

    local_admins = _first(record, "LocalAdmins", "Administrators")
    if isinstance(local_admins, list):
        for administrator in local_admins:
            administrator_id = _endpoint(administrator)
            if administrator_id:
                graph.add_edge(administrator_id, node_id, "AdminTo")


def load_bloodhound_zip(
    input_file: Union[str, Path],
    *,
    max_member_bytes: int = _MAX_MEMBER_BYTES,
    max_total_bytes: int = _MAX_TOTAL_BYTES,
    max_records: int = _MAX_RECORDS,
) -> ADGraph:
    """Read a BloodHound ZIP without extracting it to disk.

    Limits protect callers from zip bombs and accidentally huge collections.
    Unknown JSON members are ignored; malformed JSON members fail loudly.
    """
    path = Path(input_file)
    if not path.is_file():
        raise FileNotFoundError(f"BloodHound collection not found: {path}")

    graph = ADGraph()
    records_seen = 0
    json_members = 0
    total_uncompressed = 0
    pending: List[Tuple[str, str, Dict[str, Any]]] = []

    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".json"):
                    continue
                if (info.filename.startswith(("/", "\\")) or "\\" in info.filename or ".." in Path(info.filename).parts):
                    raise ADAnalyzerError(f"Unsafe ZIP member path: {info.filename}")
                json_members += 1
                if info.file_size > max_member_bytes:
                    raise ADAnalyzerError(f"ZIP member exceeds size limit: {info.filename}")
                total_uncompressed += info.file_size
                if total_uncompressed > max_total_bytes:
                    raise ADAnalyzerError("BloodHound collection exceeds total size limit")

                try:
                    with archive.open(info) as member:
                        payload = json.load(member)
                except (OSError, json.JSONDecodeError) as exc:
                    raise ADAnalyzerError(f"Invalid BloodHound JSON: {info.filename}: {exc}") from exc

                if not isinstance(payload, dict):
                    continue
                data = payload.get("data", payload.get("Data", []))
                if not isinstance(data, list):
                    continue
                meta = payload.get("meta", payload.get("Meta", {}))
                meta_type = meta.get("type") if isinstance(meta, dict) else None
                kind = _KIND_NAMES.get(str(meta_type).lower(), "") or _KIND_NAMES.get(path.stem.lower(), "")
                if not kind:
                    kind = _KIND_NAMES.get(Path(info.filename).stem.lower(), "Unknown")

                for record in data:
                    if not isinstance(record, dict):
                        continue
                    records_seen += 1
                    if records_seen > max_records:
                        raise ADAnalyzerError("BloodHound collection exceeds record limit")
                    properties = _record_properties(record)
                    node_id = _record_id(record, properties)
                    if not node_id:
                        logger.debug("Skipping record without object identifier in %s", info.filename)
                        continue
                    graph.add_node(node_id, kind, properties)
                    _add_record_edges(graph, record, node_id)
    except zipfile.BadZipFile as exc:
        raise ADAnalyzerError(f"Invalid BloodHound ZIP: {path}") from exc

    if not json_members:
        raise ADAnalyzerError("BloodHound ZIP contains no JSON collection members")
    return graph


def _truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1", "enabled"}
    return bool(value)


def _prop(node: ADNode, *keys: str) -> Any:
    return _first(node.properties, *keys)


def _entity(node: ADNode) -> Dict[str, str]:
    return {"id": node.id, "type": node.kind, "name": node.name}


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    entities: Sequence[Dict[str, str]],
    evidence: Optional[Sequence[Dict[str, Any]]] = None,
    remediation: str = "",
) -> Dict[str, Any]:
    return {
        "id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        "entities": list(entities),
        "evidence": list(evidence or []),
        "remediation": remediation,
    }


def run_direct_rules(graph: ADGraph) -> List[Dict[str, Any]]:
    """Run deterministic controls that do not require graph traversal."""
    findings: List[Dict[str, Any]] = []
    for node in graph.nodes_of_kind("User"):
        if _truthy(_prop(node, "doesnotrequirepreauth", "dontreqpreauth")):
            findings.append(
                _finding(
                    "ad.kerberos.asrep_roastable",
                    "high",
                    "User does not require Kerberos pre-authentication",
                    "This account may be vulnerable to AS-REP roasting.",
                    [_entity(node)],
                    [{"property": "DoesNotRequirePreAuth", "value": True}],
                    "Require Kerberos pre-authentication unless a documented exception exists.",
                )
            )
        spns = _prop(node, "serviceprincipalnames", "spns")
        if isinstance(spns, list) and spns:
            findings.append(
                _finding(
                    "ad.kerberos.kerberoastable",
                    "high",
                    "User has service principal names",
                    "A service account with an SPN may be susceptible to Kerberoasting.",
                    [_entity(node)],
                    [{"property": "ServicePrincipalNames", "value": spns}],
                    "Use a long, managed password or a group managed service account.",
                )
            )
        if _truthy(_prop(node, "passwordneverexpires", "dont_expire_password")):
            findings.append(
                _finding(
                    "ad.password.user_password_never_expires",
                    "medium",
                    "User password does not expire",
                    "A non-expiring password increases the impact of credential exposure.",
                    [_entity(node)],
                    [{"property": "PasswordNeverExpires", "value": True}],
                    "Remove the exception or use a managed service account where appropriate.",
                )
            )

    for node in graph.nodes_of_kind("Computer"):
        if _truthy(_prop(node, "unconstraineddelegation")):
            findings.append(
                _finding(
                    "ad.kerberos.unconstrained_delegation",
                    "high",
                    "Computer permits unconstrained delegation",
                    "Compromise of this computer can expose delegated Kerberos credentials.",
                    [_entity(node)],
                    [{"property": "UnconstrainedDelegation", "value": True}],
                    "Disable unconstrained delegation and use constrained delegation where required.",
                )
            )

    return findings


def analyze_bloodhound(
    input_file: Union[str, Path],
    *,
    include_paths: bool = False,
) -> Dict[str, Any]:
    """Analyse a collection and return the stable JSON-ready result."""
    graph = load_bloodhound_zip(input_file)
    findings = run_direct_rules(graph)
    backend = "direct"
    if include_paths:
        try:
            from .ad_paths import add_path_findings

            add_path_findings(graph, findings)
            backend = "direct+kuzu"
        except ImportError as exc:
            raise ADAnalyzerError(
                "Path analysis requires the optional dependency; install with `pip install yapp[ad]`"
            ) from exc
    severity_counts = {severity: sum(1 for item in findings if item["severity"] == severity) for severity in ("critical", "high", "medium", "low", "info")}
    return {
        "schema_version": 1,
        "source": {"type": "bloodhound_zip", "path": Path(input_file).name},
        "engine": {"path_backend": backend, "node_count": len(graph.nodes), "edge_count": len(graph.edges)},
        "summary": {"total": len(findings), **severity_counts},
        "findings": findings,
    }

