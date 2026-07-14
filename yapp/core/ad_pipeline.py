"""Stable orchestration for offline BloodHound analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Union

from .ad_analyzer import ADAnalyzerError, load_bloodhound_zip, run_direct_rules


def analyze_bloodhound(
    input_file: Union[str, Path],
    *,
    include_paths: bool = False,
    owned_principals: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Analyze a collection and return stable JSON-ready output."""
    graph = load_bloodhound_zip(input_file)
    findings = run_direct_rules(graph)
    owned_analysis = None

    if owned_principals:
        from .ad_owned import analyze_owned_principals

        owned_analysis = analyze_owned_principals(graph, owned_principals)
        findings.extend(owned_analysis.pop("findings"))

    backend = "direct"
    if include_paths:
        try:
            from .ad_paths import add_path_findings

            source_ids = owned_analysis.get("resolved_ids") if owned_analysis else None
            paths = add_path_findings(graph, findings, source_ids=source_ids)
            if owned_analysis is not None:
                owned_analysis["paths"] = paths
            backend = "direct+kuzu"
        except ImportError as exc:
            raise ADAnalyzerError(
                "Path analysis requires the optional dependency; "
                "install with `pip install yapp[ad]`"
            ) from exc

    severity_counts = {
        severity: sum(1 for item in findings if item["severity"] == severity)
        for severity in ("critical", "high", "medium", "low", "info")
    }
    result = {
        "schema_version": 1,
        "source": {"type": "bloodhound_zip", "path": Path(input_file).name},
        "engine": {
            "path_backend": backend,
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
        },
        "summary": {"total": len(findings), **severity_counts},
        "findings": findings,
    }
    if owned_analysis is not None:
        owned_analysis.pop("resolved_ids", None)
        result["owned_analysis"] = owned_analysis
    return result
