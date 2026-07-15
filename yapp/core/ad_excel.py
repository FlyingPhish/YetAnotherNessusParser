"""Excel rendering for normalized offline AD analysis reports."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Mapping, Sequence

from .ad_reporting import _SEVERITY_ORDER, _unique_entities
from .ad_excel_operator import add_choke_point_sheet, add_operator_sheets


def _excel_value(value: Any) -> Any:
    """Return an inert, legal Excel cell value."""
    if value is None:
        return ""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    if isinstance(value, (dict, list, tuple, set)):
        value = json.dumps(value, sort_keys=True, default=str)
    text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F]", "", str(value))
    if len(text) > 32767:
        text = text[:32740] + "... [truncated]"
    return "'" + text if text.startswith(("=", "+", "-", "@")) else text


def _collect_paths(report: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    """Collect unique path evidence from either report location."""
    paths: List[Mapping[str, Any]] = []
    seen = set()
    candidates = list(report.get("owned_analysis", {}).get("paths", []))
    candidates.extend(
        report.get("privilege_analysis", {}).get("dcsync_paths", [])
    )
    for finding in report.get("findings", []):
        if str(finding.get("id", "")).endswith(
            ("path_to_high_value", "path_to_domain_admin")
        ):
            candidates.extend(finding.get("evidence", []))
    for path in candidates:
        if not isinstance(path, dict):
            continue
        key = (
            path.get("source", {}).get("id"),
            path.get("target", {}).get("id"),
            tuple(path.get("edges", [])),
        )
        if key not in seen:
            seen.add(key)
            paths.append(path)
    return paths


class ADExcelFormatter:
    """Build a normalized operator workbook from an AD analysis report."""

    def format(
        self,
        report: Mapping[str, Any],
        mapped_findings: Sequence[Mapping[str, Any]] = (),
    ) -> Any:
        from openpyxl import Workbook

        workbook = Workbook()
        workbook.remove(workbook.active)
        mapping = {
            finding_id: mapped["internal_vulnerability_id"]
            for mapped in mapped_findings
            for finding_id in mapped["finding_ids"]
        }

        self._add_sheet(
            workbook,
            "Summary",
            ["Metric", "Value"],
            self._summary_rows(report, mapped_findings),
        )
        self._add_findings(workbook, report, mapping)
        self._add_entities(workbook, report, mapping)
        self._add_evidence(workbook, report, mapping)
        self._add_privileges(workbook, report)
        add_operator_sheets(self._add_sheet, workbook, report)
        add_choke_point_sheet(self._add_sheet, workbook, report)
        self._add_owned(workbook, report)
        self._add_paths(workbook, report)

        self._style(workbook)
        return workbook

    @staticmethod
    def _add_sheet(
        workbook: Any,
        name: str,
        headers: Sequence[str],
        rows: Iterable[Sequence[Any]],
    ) -> Any:
        sheet = workbook.create_sheet(name)
        sheet.append(list(headers))
        for row in rows:
            sheet.append([_excel_value(value) for value in row])
        return sheet

    @staticmethod
    def _summary_rows(
        report: Mapping[str, Any], mapped: Sequence[Mapping[str, Any]]
    ) -> List[Sequence[Any]]:
        summary = report.get("summary", {})
        engine = report.get("engine", {})
        source = report.get("source", {})
        owned = report.get("owned_analysis", {})
        privilege = report.get("privilege_analysis", {})
        operator = report.get("operator_analysis", {})
        choke_points = report.get("path_analysis", {}).get("choke_points", [])
        return [
            ("Source", source.get("path", "")),
            ("Path backend", engine.get("path_backend", "")),
            ("Nodes", engine.get("node_count", 0)),
            ("Edges", engine.get("edge_count", 0)),
            ("Findings", summary.get("total", 0)),
            ("Critical", summary.get("critical", 0)),
            ("High", summary.get("high", 0)),
            ("Medium", summary.get("medium", 0)),
            ("Low", summary.get("low", 0)),
            ("Info", summary.get("info", 0)),
            ("Mapped internal findings", len(mapped)),
            ("Administrative memberships", len(privilege.get("memberships", []))),
            ("Administrative permissions", len(privilege.get("permissions", []))),
            ("DCSync paths", len(privilege.get("dcsync_paths", []))),
            ("Risk-filtered fleet access", len(operator.get("fleet_access", []))),
            ("AD CS objects", len(operator.get("adcs", {}).get("objects", []))),
            ("Path choke points", len(choke_points)),
            ("Owned principals", len(owned.get("resolved", []))),
            ("Owned paths", len(owned.get("paths", []))),
            ("Unresolved owned identities", len(owned.get("unresolved", []))),
            ("Ambiguous owned identities", len(owned.get("ambiguous", []))),
        ]

    def _add_findings(
        self, workbook: Any, report: Mapping[str, Any], mapping: Mapping[str, Any]
    ) -> None:
        grouped: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
        for finding in report.get("findings", []):
            if isinstance(finding, dict):
                grouped[str(finding.get("id") or "")].append(finding)
        rows = []
        for finding_id, findings in grouped.items():
            first = findings[0]
            severity = max(
                (str(item.get("severity", "info")) for item in findings),
                key=lambda value: _SEVERITY_ORDER.get(value.lower(), -1),
            )
            rows.append(
                (
                    mapping.get(finding_id, ""),
                    finding_id,
                    first.get("title", ""),
                    severity,
                    len(findings),
                    len(_unique_entities(findings)),
                    first.get("description", ""),
                    first.get("remediation", ""),
                )
            )
        self._add_sheet(
            workbook,
            "Findings",
            [
                "Internal Vulnerability ID",
                "Finding ID",
                "Title",
                "Severity",
                "Instances",
                "Affected Entities",
                "Description",
                "Remediation",
            ],
            rows,
        )

    def _add_entities(
        self, workbook: Any, report: Mapping[str, Any], mapping: Mapping[str, Any]
    ) -> None:
        rows = []
        seen = set()
        for finding in report.get("findings", []):
            finding_id = str(finding.get("id") or "")
            for entity in finding.get("entities", []):
                key = (finding_id, entity.get("id"), entity.get("type"), entity.get("name"))
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    (
                        mapping.get(finding_id, ""),
                        finding_id,
                        finding.get("severity", ""),
                        entity.get("type", ""),
                        entity.get("name", ""),
                        entity.get("id", ""),
                    )
                )
        self._add_sheet(
            workbook,
            "Affected Entities",
            [
                "Internal Vulnerability ID",
                "Finding ID",
                "Severity",
                "Entity Type",
                "Entity Name",
                "Object ID",
            ],
            rows,
        )

    def _add_evidence(
        self, workbook: Any, report: Mapping[str, Any], mapping: Mapping[str, Any]
    ) -> None:
        rows = (
            (
                mapping.get(str(finding.get("id") or ""), ""),
                finding.get("id", ""),
                finding.get("title", ""),
                evidence,
            )
            for finding in report.get("findings", [])
            for evidence in finding.get("evidence", [])
        )
        self._add_sheet(
            workbook,
            "Evidence",
            ["Internal Vulnerability ID", "Finding ID", "Title", "Evidence JSON"],
            rows,
        )

    def _add_privileges(self, workbook: Any, report: Mapping[str, Any]) -> None:
        privilege = report.get("privilege_analysis", {})
        membership_rows = []
        for item in privilege.get("memberships", []):
            principal = item.get("principal", {})
            group = item.get("group", {})
            membership_rows.append((
                principal.get("type", ""),
                principal.get("name", ""),
                principal.get("id", ""),
                group.get("name", ""),
                group.get("id", ""),
                item.get("membership", ""),
                " -> ".join(node.get("name", "") for node in item.get("via", [])),
            ))
        permission_rows = []
        for item in privilege.get("permissions", []):
            principal = item.get("principal", {})
            target = item.get("target", {})
            permission_rows.append((
                principal.get("type", ""),
                principal.get("name", ""),
                principal.get("id", ""),
                item.get("severity", ""),
                item.get("category", ""),
                item.get("relationship", ""),
                target.get("type", ""),
                target.get("name", ""),
                target.get("id", ""),
                ", ".join(
                    entity.get("name", "")
                    for entity in item.get("effective_principals", [])
                ),
                item.get("properties", {}),
            ))
        self._add_sheet(
            workbook,
            "Administrative Memberships",
            [
                "Principal Type", "Principal", "Principal ID", "Group",
                "Group ID", "Membership", "Via",
            ],
            membership_rows,
        )
        self._add_sheet(
            workbook,
            "Administrative Permissions",
            [
                "Principal Type", "Principal", "Principal ID", "Severity",
                "Category", "Relationship", "Target Type", "Target",
                "Target ID", "Effective Principals", "Properties JSON",
            ],
            permission_rows,
        )

    def _add_owned(self, workbook: Any, report: Mapping[str, Any]) -> None:
        owned = report.get("owned_analysis", {})
        paths_by_source = defaultdict(int)
        for path in owned.get("paths", []):
            paths_by_source[str(path.get("source", {}).get("id") or "")] += 1

        principal_rows = []
        control_rows = []
        for item in owned.get("principals", []):
            principal = item.get("principal", {})
            principal_rows.append(
                (
                    "resolved",
                    principal.get("name", ""),
                    principal.get("id", ""),
                    item.get("direct_control_count", 0),
                    paths_by_source.get(str(principal.get("id") or ""), 0),
                    "",
                )
            )
            for control in item.get("direct_controls", []):
                target = control.get("target", {})
                control_rows.append(
                    (
                        principal.get("name", ""),
                        principal.get("id", ""),
                        control.get("severity", ""),
                        control.get("category", ""),
                        control.get("relationship", ""),
                        target.get("type", ""),
                        target.get("name", ""),
                        target.get("id", ""),
                        " -> ".join(n.get("name", "") for n in control.get("via", [])),
                        ", ".join(
                            n.get("name", "") for n in control.get("granted_to", [])
                        ),
                        control.get("properties", {}),
                    )
                )
        principal_rows.extend(
            ("unresolved", identity, "", 0, 0, "No match")
            for identity in owned.get("unresolved", [])
        )
        principal_rows.extend(
            (
                "ambiguous",
                item.get("query", ""),
                "",
                0,
                0,
                ", ".join(c.get("name", "") for c in item.get("candidates", [])),
            )
            for item in owned.get("ambiguous", [])
        )
        self._add_sheet(
            workbook,
            "Owned Principals",
            ["Status", "Principal", "Object ID", "Controls", "Paths", "Detail"],
            principal_rows,
        )
        self._add_sheet(
            workbook,
            "Controls",
            [
                "Principal",
                "Principal ID",
                "Severity",
                "Category",
                "Relationship",
                "Target Type",
                "Target",
                "Target ID",
                "Via",
                "Granted To",
                "Properties JSON",
            ],
            control_rows,
        )

    def _add_paths(self, workbook: Any, report: Mapping[str, Any]) -> None:
        path_rows = []
        step_rows = []
        for path_id, path in enumerate(_collect_paths(report), start=1):
            source = path.get("source", {})
            target = path.get("target", {})
            nodes = path.get("nodes", [])
            edges = path.get("edges", [])
            path_rows.append(
                (
                    path_id,
                    source.get("name", ""),
                    source.get("id", ""),
                    target.get("name", ""),
                    target.get("id", ""),
                    path.get("length", len(edges)),
                    " -> ".join(str(edge) for edge in edges),
                    " -> ".join(str(node.get("name", "")) for node in nodes),
                )
            )
            for step, relationship in enumerate(edges, start=1):
                from_node = nodes[step - 1] if step - 1 < len(nodes) else {}
                to_node = nodes[step] if step < len(nodes) else {}
                step_rows.append(
                    (
                        path_id,
                        step,
                        from_node.get("type", ""),
                        from_node.get("name", ""),
                        relationship,
                        to_node.get("type", ""),
                        to_node.get("name", ""),
                    )
                )
        self._add_sheet(
            workbook,
            "Paths",
            [
                "Path ID",
                "Source",
                "Source ID",
                "Target",
                "Target ID",
                "Length",
                "Relationships",
                "Nodes",
            ],
            path_rows,
        )
        self._add_sheet(
            workbook,
            "Path Steps",
            [
                "Path ID",
                "Step",
                "Source Type",
                "Source",
                "Relationship",
                "Target Type",
                "Target",
            ],
            step_rows,
        )

    @staticmethod
    def _style(workbook: Any) -> None:
        from openpyxl.styles import Alignment, Font, PatternFill

        header_fill = PatternFill("solid", fgColor="1F4E78")
        severity_fills = {
            "critical": PatternFill("solid", fgColor="C00000"),
            "high": PatternFill("solid", fgColor="FF0000"),
            "medium": PatternFill("solid", fgColor="FFC000"),
            "low": PatternFill("solid", fgColor="92D050"),
            "info": PatternFill("solid", fgColor="5B9BD5"),
        }
        for sheet in workbook.worksheets:
            sheet.freeze_panes = "A2"
            sheet.auto_filter.ref = sheet.dimensions
            for cell in sheet[1]:
                cell.font = Font(color="FFFFFF", bold=True)
                cell.fill = header_fill
            severity_column = next(
                (cell.column for cell in sheet[1] if cell.value == "Severity"), None
            )
            if severity_column:
                for row in range(2, sheet.max_row + 1):
                    cell = sheet.cell(row, severity_column)
                    fill = severity_fills.get(str(cell.value).lower())
                    if fill:
                        cell.fill = fill
                        cell.font = Font(color="FFFFFF", bold=True)
            for column in sheet.columns:
                width = min(
                    60,
                    max(10, max(len(str(cell.value or "")) for cell in column) + 2),
                )
                sheet.column_dimensions[column[0].column_letter].width = width
            for row in sheet.iter_rows():
                for cell in row:
                    cell.alignment = Alignment(vertical="top", wrap_text=True)
