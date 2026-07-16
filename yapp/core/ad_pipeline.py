"""Stable orchestration for offline BloodHound analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Union

from .ad_analyzer import ADAnalyzerError, ADGraph, load_bloodhound_zip, run_direct_rules
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
    graph: Optional[ADGraph] = None,
    operator_paths: bool = False,
    progress: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Analyze a collection and return stable JSON-ready output."""

    def emit(message: str) -> None:
        if progress:
            progress(message)

    if graph is None:
        emit("Loading BloodHound collection")
        graph = load_bloodhound_zip(input_file)
    emit(f"Loaded {len(graph.nodes):,} objects and {len(graph.edges):,} relationships")

    policy = policy or ADAnalysisPolicy()
    emit("Building privilege and membership context")
    privilege_context = build_privilege_context(graph, sensitive_groups)
    findings = run_direct_rules(graph)
    privilege_analysis = analyze_ad_posture(
        graph, policy, privilege_context=privilege_context
    )
    findings.extend(privilege_analysis.pop("findings"))

    emit("Building operator inventories")
    operator_analysis = analyze_operator_data(graph, privilege_context, policy)
    findings.extend(operator_analysis.pop("findings"))
    owned_analysis = None

    if owned_principals:
        from .ad_owned import analyze_owned_principals

        emit(f"Resolving {len(owned_principals):,} assumed-owned identities")
        owned_analysis = analyze_owned_principals(graph, owned_principals)
        findings.extend(owned_analysis.pop("findings"))
        emit(
            "Resolved {:,} owned identities".format(
                len(owned_analysis.get("resolved") or [])
            )
        )

    collected_paths = list(privilege_analysis.get("dcsync_paths", []))
    backend = "direct"
    if include_paths:
        try:
            source_ids = owned_analysis.get("resolved_ids") if owned_analysis else None
            if operator_paths:
                from .ad_paths import add_priority_path_findings

                emit("Calculating prioritized bounded attack paths")
                paths = add_priority_path_findings(
                    graph,
                    findings,
                    source_ids=source_ids,
                )
                backend = "direct+bounded_bfs"
            else:
                from .ad_paths import add_path_findings

                emit("Calculating exhaustive bounded Kuzu attack paths")
                paths = add_path_findings(graph, findings, source_ids=source_ids)
                backend = "direct+kuzu"
            collected_paths.extend(paths)
            if owned_analysis is not None:
                owned_analysis["paths"] = paths
            emit(f"Calculated {len(paths):,} attack paths")
        except ImportError as exc:
            raise ADAnalyzerError(
                "Path analysis backend is unavailable; reinstall YAPP with its "
                "required dependencies"
            ) from exc

    emit("Ranking choke points")
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
    emit("Analysis complete")
    return result
