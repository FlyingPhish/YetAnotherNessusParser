"""No-SQL scan indexing pipeline for YAPP Textual TUI."""

from __future__ import annotations

import hashlib
import math
import re
from pathlib import Path
from typing import Any, Callable

from ..core.processor import process_file
from ..utils.file_utils import detect_file_type
from .state import (
    FindingDetail,
    FindingRow,
    HostRef,
    HostSummary,
    SEVERITY_LABELS,
    ScanIndex,
)

MITRE_PATTERN = re.compile(r"\b(?:TA\d{4}|T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
NOISY_REFERENCE_PATTERNS = [
    re.compile(r"^https?://(?:www\.)?tenable\.com/plugins/nessus/\d+/?$", re.IGNORECASE)
]
MSF_PATTERN = re.compile(
    r"(?:^|[\s:])(exploit/[a-z0-9_./-]+|auxiliary/[a-z0-9_./-]+|post/[a-z0-9_./-]+)",
    re.IGNORECASE,
)
EXPLOIT_DB_ID_PATTERN = re.compile(r"(?:EDB[-_ ]?ID[:\s-]*|/exploits/)(\d+)", re.IGNORECASE)
PUBLIC_EXPLOIT_URL_PATTERN = re.compile(
    r"^https?://(?:www\.)?(?:exploit-db\.com|packetstormsecurity\.com|rapid7\.com|cxsecurity\.com)/",
    re.IGNORECASE,
)


def _unique_nonempty(values: list[Any]) -> tuple[str, ...]:
    seen = set()
    output = []
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return tuple(output)


def _extract_mitre_refs(*values: str) -> tuple[str, ...]:
    found = []
    seen = set()
    for value in values:
        for match in MITRE_PATTERN.findall(value or ""):
            normalized = match.upper()
            if normalized in seen:
                continue
            seen.add(normalized)
            found.append(normalized)
    return tuple(found)


def _extract_metasploit_modules(*values: str) -> tuple[str, ...]:
    modules = []
    seen = set()

    for value in values:
        text = value or ""
        if "msf" not in text.lower() and "metasploit" not in text.lower():
            continue

        for match in MSF_PATTERN.findall(text):
            module = match.strip().lower()
            if module in seen:
                continue
            seen.add(module)
            modules.append(module)

    return tuple(modules)


def _extract_exploit_db_ids(*values: str) -> tuple[str, ...]:
    ids = []
    seen = set()
    for value in values:
        for match in EXPLOIT_DB_ID_PATTERN.findall(value or ""):
            if match in seen:
                continue
            seen.add(match)
            ids.append(f"EDB-{match}")
    return tuple(ids)


def _extract_public_exploit_refs(
    cve: tuple[str, ...],
    xref: tuple[str, ...],
    see_also: tuple[str, ...],
) -> tuple[str, ...]:
    refs = []
    seen = set()

    # Keep CVEs visible as exploit-research pivot points.
    for item in cve:
        normalized = item.upper()
        if normalized in seen:
            continue
        seen.add(normalized)
        refs.append(normalized)

    # Include explicit exploit-db IDs and known public exploit links.
    for item in _extract_exploit_db_ids(" ".join(xref), " ".join(see_also)):
        if item in seen:
            continue
        seen.add(item)
        refs.append(item)

    for url in see_also:
        if PUBLIC_EXPLOIT_URL_PATTERN.search(url):
            if url in seen:
                continue
            seen.add(url)
            refs.append(url)

    return tuple(refs)


def _is_noisy_reference(reference: str) -> bool:
    return any(pattern.search(reference) for pattern in NOISY_REFERENCE_PATTERNS)


def _clean_references(references: tuple[str, ...]) -> tuple[tuple[str, ...], int]:
    filtered = []
    removed = 0
    for reference in references:
        if _is_noisy_reference(reference):
            removed += 1
            continue
        filtered.append(reference)
    return tuple(filtered), removed


def _calculate_risk_score(severity: int, host_count: int, cvss3: float, cvss: float) -> int:
    severity_base = {
        4: 70,
        3: 55,
        2: 35,
        1: 15,
        0: 2,
    }.get(severity, 2)

    spread_bonus = min(20, int(math.log2(host_count + 1) * 5))
    cvss_bonus = min(10, int(max(cvss3, cvss)))

    return min(100, severity_base + spread_bonus + cvss_bonus)


def _source_fingerprint(path: Path) -> str:
    stat = path.stat()
    material = f"{path.resolve()}|{stat.st_size}|{int(stat.st_mtime)}".encode("utf-8")
    return hashlib.sha1(material).hexdigest()[:10]


def _build_nessus_index(
    input_file: str,
    parse_options: dict[str, Any],
    results: dict[str, Any],
) -> ScanIndex:
    parsed = results.get("parsed")
    if not isinstance(parsed, dict):
        raise ValueError("Parsed Nessus data is missing")

    vulnerabilities = parsed.get("vulnerabilities", {})
    if not isinstance(vulnerabilities, dict):
        raise ValueError("Nessus vulnerabilities section is invalid")

    findings_rows: list[FindingRow] = []
    finding_details: dict[str, FindingDetail] = {}
    host_summaries: dict[str, HostSummary] = {}

    for plugin_id, vuln in vulnerabilities.items():
        severity = int(vuln.get("severity", 0))
        severity_label = SEVERITY_LABELS.get(severity, "None")
        cvss = float(vuln.get("cvss", {}).get("base_score", 0) or 0)
        cvss3 = float(vuln.get("cvss3", {}).get("base_score", 0) or 0)

        cve = _unique_nonempty(vuln.get("cve", []))
        cwe = _unique_nonempty(vuln.get("cwe", []))
        xref = _unique_nonempty(vuln.get("xref", []))
        see_also = _unique_nonempty(vuln.get("see_also", []))
        references, hidden_count = _clean_references(see_also)

        mitre = _extract_mitre_refs(" ".join(xref), " ".join(see_also))
        metasploit_modules = _extract_metasploit_modules(" ".join(xref), " ".join(see_also))
        public_exploit_refs = _extract_public_exploit_refs(cve, xref, see_also)

        affected_hosts_data = vuln.get("affected_hosts", {})
        host_refs: list[HostRef] = []

        for host_id, host_data in affected_hosts_data.items():
            ip = str(host_data.get("ip", ""))
            fqdn = str(host_data.get("fqdn", "")).strip()
            ports = tuple(str(port) for port in host_data.get("ports", []) if str(port))
            plugin_output = str(host_data.get("plugin_output", ""))

            host_refs.append(
                HostRef(
                    host_id=str(host_id),
                    ip=ip,
                    fqdn=fqdn,
                    ports=ports,
                    plugin_output_preview=plugin_output[:1400],
                )
            )

        host_count = len(host_refs)
        risk_score = _calculate_risk_score(severity, host_count, cvss3, cvss)

        search_blob = " ".join(
            [
                str(plugin_id),
                str(vuln.get("name", "")),
                " ".join(cve),
                " ".join(cwe),
                " ".join(mitre),
                " ".join(metasploit_modules),
                " ".join(public_exploit_refs),
                str(vuln.get("family", "")),
            ]
        ).lower()

        row = FindingRow(
            plugin_id=str(plugin_id),
            name=str(vuln.get("name", "")),
            family=str(vuln.get("family", "")),
            severity=severity,
            severity_label=severity_label,
            risk_factor=str(vuln.get("risk_factor", "None")),
            risk_score=risk_score,
            cvss_base=cvss,
            cvss3_base=cvss3,
            affected_hosts_count=host_count,
            cve=cve,
            cwe=cwe,
            mitre=mitre,
            public_exploit_refs=public_exploit_refs,
            metasploit_modules=metasploit_modules,
            references=references,
            hidden_references_count=hidden_count,
            search_blob=search_blob,
        )

        detail = FindingDetail(
            row=row,
            synopsis=str(vuln.get("synopsis", "")),
            description=str(vuln.get("description", "")),
            solution=str(vuln.get("solution", "")),
            xref=xref,
            affected_hosts=tuple(host_refs),
            cvss_vector=str(vuln.get("cvss", {}).get("vector", "")),
            cvss3_vector=str(vuln.get("cvss3", {}).get("vector", "")),
        )

        findings_rows.append(row)
        finding_details[row.plugin_id] = detail

        for host in host_refs:
            if not host.ip:
                continue

            summary = host_summaries.get(host.ip)
            if not summary:
                summary = HostSummary(ip=host.ip)
                host_summaries[host.ip] = summary

            if host.fqdn:
                summary.fqdns.add(host.fqdn)
            summary.findings.add(row.plugin_id)
            summary.severity_counts[severity_label] = summary.severity_counts.get(severity_label, 0) + 1
            summary.risk_score = max(summary.risk_score, row.risk_score)

    findings_rows.sort(
        key=lambda item: (item.risk_score, item.severity, item.affected_hosts_count),
        reverse=True,
    )

    source_path = Path(input_file)
    metadata = {
        "source_name": source_path.name,
        "source_fingerprint": _source_fingerprint(source_path),
        "hosts_total": parsed.get("stats", {}).get("hosts", {}).get("total", 0),
        "vulnerabilities_total": parsed.get("stats", {}).get("vulnerabilities", {}).get("total", 0),
    }

    return ScanIndex(
        input_file=input_file,
        file_type="nessus",
        parse_options=parse_options,
        results=results,
        findings_rows=findings_rows,
        finding_details=finding_details,
        host_summaries=host_summaries,
        metadata=metadata,
    )


def build_scan_index(
    input_file: str,
    file_type: str = "auto",
    consolidate: bool = False,
    api_output: bool = False,
    excel: bool = False,
    rules_file: str | None = None,
    entity_limit: int | None = None,
    log_exclusions: bool = False,
    owned_principals: tuple[str, ...] | list[str] = (),
    include_paths: bool = True,
    progress: Callable[[str], None] | None = None,
) -> ScanIndex | Any:
    """Process input and build in-memory no-SQL indexes for TUI usage."""
    if file_type == "auto" and Path(input_file).suffix.casefold() == ".zip":
        detected = "ad"
    else:
        detected = detect_file_type(input_file) if file_type == "auto" else file_type

    if detected == "ad":
        from .ad_indexer import build_ad_index

        return build_ad_index(
            input_file,
            owned_principals=owned_principals,
            include_paths=include_paths,
            rules_file=rules_file,
            progress=progress,
        )

    if detected != "nessus":
        raise ValueError(
            f"TUI supports Nessus or BloodHound ZIP input; detected '{detected}'."
        )

    parse_options = {
        "file_type": "nessus",
        "consolidate": consolidate,
        "api_output": api_output,
        "excel": excel,
        "rules_file": rules_file,
        "entity_limit": entity_limit,
        "log_exclusions": log_exclusions,
    }

    results = process_file(
        input_file=input_file,
        file_type="nessus",
        consolidate=consolidate,
        api_format=api_output,
        excel_format=excel,
        rules_file=rules_file,
        entity_limit=entity_limit,
        log_exclusions=log_exclusions,
    )

    return _build_nessus_index(input_file=input_file, parse_options=parse_options, results=results)
