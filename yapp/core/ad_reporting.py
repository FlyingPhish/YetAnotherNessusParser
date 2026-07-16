"""Rule mapping and API rendering for offline AD analysis reports."""

from __future__ import annotations

import html
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .ad_config import normalize_sensitive_groups


class ADReportingError(ValueError):
    """Raised when AD reporting configuration or input is invalid."""


_MAX_RULES_BYTES = 10 * 1024 * 1024
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def load_ad_configuration(filename: str) -> Dict[str, Any]:
    """Load mappings and the shared sensitive-group registry."""
    path = Path(filename)
    if not path.is_file():
        raise FileNotFoundError(f"AD rules file not found: {path}")
    if path.stat().st_size > _MAX_RULES_BYTES:
        raise ADReportingError(f"AD rules file exceeds 10 MiB: {path}")
    try:
        with path.open("r", encoding="utf-8") as source:
            payload = json.load(source)
    except json.JSONDecodeError as exc:
        raise ADReportingError(f"Invalid AD rules JSON: {exc}") from exc

    raw_rules = payload.get("ad_rules") if isinstance(payload, dict) else None
    if not isinstance(raw_rules, list):
        raise ADReportingError("AD rules file must contain an 'ad_rules' list")

    rules: List[Dict[str, Any]] = []
    rule_names = set()
    finding_owners: Dict[str, str] = {}
    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, dict):
            raise ADReportingError(f"AD rule {index} must be an object")
        for field in ("enabled", "api_output"):
            if field in raw_rule and not isinstance(raw_rule[field], bool):
                raise ADReportingError(
                    f"AD rule {index} field {field} must be a boolean"
                )
        if not raw_rule.get("enabled", True):
            continue

        rule_name = raw_rule.get("rule_name")
        finding_ids = raw_rule.get("finding_ids")
        vulnerability_id = raw_rule.get("internal_vulnerability_id")
        if not isinstance(rule_name, str) or not rule_name.strip():
            raise ADReportingError(f"AD rule {index} has no valid rule_name")
        rule_name = rule_name.strip()
        if rule_name in rule_names:
            raise ADReportingError(f"Duplicate AD rule_name: {rule_name}")
        if (
            not isinstance(finding_ids, list)
            or not finding_ids
            or any(not isinstance(item, str) or not item.strip() for item in finding_ids)
        ):
            raise ADReportingError(f"AD rule '{rule_name}' has no valid finding_ids")
        if vulnerability_id is not None and (
            isinstance(vulnerability_id, bool)
            or not isinstance(vulnerability_id, (str, int))
            or isinstance(vulnerability_id, str) and not vulnerability_id.strip()
        ):
            raise ADReportingError(
                f"AD rule '{rule_name}' has no valid internal_vulnerability_id"
            )

        normalized_ids = list(dict.fromkeys(item.strip() for item in finding_ids))
        for finding_id in normalized_ids:
            owner = finding_owners.get(finding_id)
            if owner:
                raise ADReportingError(
                    f"AD finding '{finding_id}' is mapped by both '{owner}' and "
                    f"'{rule_name}'"
                )
            finding_owners[finding_id] = rule_name

        rule_names.add(rule_name)
        rules.append(
            {
                "rule_name": rule_name,
                "title": str(raw_rule.get("title") or rule_name).strip(),
                "internal_vulnerability_id": vulnerability_id,
                "finding_ids": normalized_ids,
                "api_output": bool(raw_rule.get("api_output", True)),
            }
        )
    try:
        sensitive_groups = normalize_sensitive_groups(
            payload.get("sensitive_groups") if "sensitive_groups" in payload else None
        )
    except ValueError as exc:
        raise ADReportingError(str(exc)) from exc
    return {"rules": rules, "sensitive_groups": sensitive_groups}


def load_ad_rules(filename: str) -> List[Dict[str, Any]]:
    """Load exact AD finding mappings; retained as the stable public helper."""
    return load_ad_configuration(filename)["rules"]


def _deduplicate_entities(
    entities: Iterable[Mapping[str, Any]],
) -> List[Dict[str, str]]:
    output: List[Dict[str, str]] = []
    seen = set()
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        entity_id = str(entity.get("id") or "")
        entity_type = str(entity.get("type") or "Unknown")
        name = str(entity.get("name") or entity_id)
        key = entity_id or f"{entity_type}\0{name}"
        if not name or key in seen:
            continue
        seen.add(key)
        output.append({"id": entity_id, "type": entity_type, "name": name})
    return output


def _unique_entities(findings: Iterable[Mapping[str, Any]]) -> List[Dict[str, str]]:
    return _deduplicate_entities(
        entity
        for finding in findings
        for entity in finding.get("entities", [])
    )


def map_ad_findings(
    report: Mapping[str, Any], rules: Sequence[Mapping[str, Any]]
) -> List[Dict[str, Any]]:
    """Apply exact mappings and return normalized, grouped AD findings."""
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        raise ADReportingError("AD report findings must be a list")

    by_id: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
    for finding in findings:
        if isinstance(finding, dict) and isinstance(finding.get("id"), str):
            by_id[finding["id"]].append(finding)

    mapped: List[Dict[str, Any]] = []
    for rule in rules:
        matches = [
            finding
            for finding_id in rule["finding_ids"]
            for finding in by_id.get(finding_id, [])
        ]
        if not matches:
            continue
        severity = max(
            (str(item.get("severity") or "info").lower() for item in matches),
            key=lambda value: _SEVERITY_ORDER.get(value, -1),
        )
        mapped.append(
            {
                "rule_name": rule["rule_name"],
                "title": rule["title"],
                "internal_vulnerability_id": rule["internal_vulnerability_id"],
                "finding_ids": list(rule["finding_ids"]),
                "api_output": bool(rule.get("api_output", True)),
                "severity": severity,
                "finding_count": len(matches),
                "affected_entities": _unique_entities(matches),
            }
        )
    return mapped


class ADAPIFormatter:
    """Render mapped AD findings using YAPP's existing stock API contract."""

    def __init__(self, entity_limit: Optional[int] = None):
        if entity_limit is not None and entity_limit < 1:
            raise ADReportingError("Entity limit must be a positive integer")
        self.entity_limit = entity_limit

    def format(self, mapped_findings: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        grouped: Dict[Any, List[Mapping[str, Any]]] = defaultdict(list)
        for finding in mapped_findings:
            if (
                finding.get("api_output", True)
                and finding.get("internal_vulnerability_id") is not None
            ):
                grouped[finding["internal_vulnerability_id"]].append(finding)

        output = []
        for vulnerability_id, findings in grouped.items():
            entities = _unique_mapped_entities(findings)
            if not entities:
                continue
            output.append(
                {
                    "type": "stock",
                    "finding_id": vulnerability_id,
                    "affected_entities": self._format_entities(entities),
                }
            )
        return output

    def _format_entities(self, entities: Sequence[Mapping[str, str]]) -> str:
        if self.entity_limit is not None and len(entities) > self.entity_limit:
            return "<p>Please refer to external document named 'replaceMe'.csv</p>"
        names = sorted({str(entity.get("name") or "") for entity in entities} - {""})
        items = "".join(f"<li>{html.escape(name)}</li>" for name in names)
        return f"<p><ul>{items}</ul></p>"


def _unique_mapped_entities(
    findings: Iterable[Mapping[str, Any]],
) -> List[Dict[str, str]]:
    return _deduplicate_entities(
        entity
        for finding in findings
        for entity in finding.get("affected_entities", [])
    )

