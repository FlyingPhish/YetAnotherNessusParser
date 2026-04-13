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
        """Path for persisting triage state sidecar JSON."""
        source = Path(self.input_file)
        stamp = self.metadata.get("source_fingerprint", "unknown")
        folder = Path(".yapp-tui")
        folder.mkdir(parents=True, exist_ok=True)
        return folder / f"{source.stem}_{stamp}_triage.json"
