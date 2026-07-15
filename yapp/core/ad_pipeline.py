"""Stable orchestration for offline BloodHound analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Union

from .ad_analyzer import ADAnalyzerError, load_bloodhound_zip, run_direct_rules
from .ad_posture import ADAnalysisPolicy, analyze_ad_posture, build_privilege_context
from .ad_operator import analyze_operator_data
from .ad_choke_points import summarize_choke_points


def analyze_bloodhound(
    input_file: Union[str, Path],
    *,
    include_paths: bool = False,
    owned_principals: Optional[Sequence[str]] = None,
    policy: Optional[ADAnalysisPolicy] = None,
    sensitive_groups: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """Analyze a collection and return stable JSON-ready output."""
    graph = load_bloodhound_zip(input_file)
    policy = policy or ADAnalysisPolicy()
    privilege_context = build_privilege_context(graph, sensitive_groups)
    findings = run_direct_rules(graph)
    privilege_analysis = analyze_ad_posture(
        graph, policy, privilege_context=privilege_context
    )
    findings.extend(privilege_analysis.pop("findings"))
    operator_analysis = analyze_operator_data(graph, privilege_context, policy)
    findings.extend(operator_analysis.pop("findings"))
    owned_analysis = None

    if owned_principals:
        from .ad_owned import analyze_owned_principals

        owned_analysis = analyze_owned_principals(graph, owned_principals)
        findings.extend(owned_analysis.pop("findings"))

    collected_paths = list(privilege_analysis.get("dcsync_paths", []))
    backend = "direct"
    if include_paths:
        try:
            from .ad_paths import add_path_findings

            source_ids = owned_analysis.get("resolved_ids") if owned_analysis else None
            paths = add_path_findings(graph, findings, source_ids=source_ids)
            collected_paths.extend(paths)
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
        "privilege_analysis": privilege_analysis,
        "operator_analysis": operator_analysis,
        "path_analysis": {
            "choke_points": summarize_choke_points(collected_paths),
        },
    }
    if owned_analysis is not None:
        owned_analysis.pop("resolved_ids", None)
        result["owned_analysis"] = owned_analysis
    return result
