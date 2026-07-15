"""State models for YAPP TUI (no SQL backend)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITY_LABELS = {
    4: "Critical",
    3: "High",
    2: "Medium",
    1: "Low",
    0: "Info",
}

SEVERITY_LOOKUP = {
    "critical": 4,
    "crit": 4,
    "high": 3,
    "medium": 2,
    "med": 2,
    "low": 1,
    "info": 0,
    "none": 0,
    "4": 4,
    "3": 3,
    "2": 2,
    "1": 1,
    "0": 0,
}

TRIAGE_STATES = [
    "new",
    "in_progress",
    "triaged",
    "accepted_risk",
]


@dataclass
class HostRef:
    """Host reference affected by a finding."""

    host_id: str
    ip: str
    fqdn: str
    ports: tuple[str, ...] = ()
    plugin_output_preview: str = ""


@dataclass
class FindingRow:
    """Flattened finding row used in queue table and filtering."""

    plugin_id: str
    name: str
    family: str
    severity: int
    severity_label: str
    risk_factor: str
    risk_score: int
    cvss_base: float
    cvss3_base: float
    affected_hosts_count: int
    cve: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    mitre: tuple[str, ...] = ()
    public_exploit_refs: tuple[str, ...] = ()
    metasploit_modules: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    hidden_references_count: int = 0
    triage_state: str = "new"
    search_blob: str = ""


@dataclass
class FindingDetail:
    """Detailed finding data shown in right-hand pane and host pivot screen."""

    row: FindingRow
    synopsis: str
    description: str
    solution: str
    xref: tuple[str, ...] = ()
    affected_hosts: tuple[HostRef, ...] = ()
    cvss_vector: str = ""
    cvss3_vector: str = ""


@dataclass
class HostSummary:
    """Aggregated host-level view for host pivot workflows."""

    ip: str
    fqdns: set[str] = field(default_factory=set)
    findings: set[str] = field(default_factory=set)
    severity_counts: dict[str, int] = field(
        default_factory=lambda: {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0,
        }
    )
    risk_score: int = 0


@dataclass
class QueryOptions:
    """Current filter and sort state for findings queue."""

    search_text: str = ""
    severities: set[int] = field(default_factory=set)
    sort_by: str = "risk"  # risk|severity|hosts|plugin|name
    page: int = 0
    page_size: int = 100


@dataclass
class ScanIndex:
    """In-memory indexed scan data for no-SQL TUI workflows."""

    input_file: str
    file_type: str
    parse_options: dict[str, Any]
    results: dict[str, Any]
    findings_rows: list[FindingRow]
    finding_details: dict[str, FindingDetail]
    host_summaries: dict[str, HostSummary]
    metadata: dict[str, Any]

    def get_triage_path(self) -> Path:
        """Triage sidecar JSON — sits next to the input file."""
        source = Path(self.input_file).resolve()
        return source.parent / f"{source.stem}.triage.json"


@dataclass(frozen=True)
class ADRelationship:
    """One relationship shown as evidence in a path or node pivot."""

    source: dict[str, Any]
    relationship: str
    target: dict[str, Any]
    category: str
    severity: str
    traversable: bool
    direct: bool = True
    via: tuple[dict[str, Any], ...] = ()
    why: str = ""
    opportunity: str = ""
    caveat: str = ""


@dataclass
class ADPathRow:
    """Ranked, bounded attack path for the operator queue."""

    path_id: str
    source: dict[str, Any]
    target: dict[str, Any]
    nodes: tuple[dict[str, Any], ...]
    steps: tuple[ADRelationship, ...]
    target_class: str
    score: int
    choke_count: int = 0
    owned: bool = False
    triage_state: str = "new"

    @property
    def length(self) -> int:
        return len(self.steps)


@dataclass
class ADNodePivot:
    """Bounded relationship inventory for a selected AD object."""

    entity: dict[str, Any]
    outbound: tuple[ADRelationship, ...] = ()
    inbound: tuple[ADRelationship, ...] = ()
    paths: tuple[str, ...] = ()


@dataclass
class ADIndex:
    """AD-specific, presentation-ready state; deliberately separate from ScanIndex."""

    input_file: str
    parse_options: dict[str, Any]
    report: dict[str, Any]
    paths: list[ADPathRow]
    nodes: dict[str, dict[str, Any]]
    pivots: dict[str, ADNodePivot]
    assumed_owned: list[str]
    metadata: dict[str, Any]
    notes: dict[str, str] = field(default_factory=dict)
    bookmarks: set[str] = field(default_factory=set)

    def get_state_path(self) -> Path:
        """Operator sidecar beside the collection, using only its safe stem."""
        source = Path(self.input_file).resolve()
        return source.parent / f"{source.stem}.ad-tui.json"
