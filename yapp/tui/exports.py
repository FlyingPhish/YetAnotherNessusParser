"""Export helpers that reuse core YAPP output writers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..utils.file_utils import ensure_output_directory, write_results_to_files
from .state import ScanIndex


def export_scan_results(
    scan: ScanIndex,
    output_folder: str,
    output_name: str | None = None,
    single_file: bool = False,
) -> dict[str, bool]:
    """Write currently loaded scan outputs to disk using existing writer flow."""
    output_dir = ensure_output_directory(output_folder)

    status = write_results_to_files(
        results=scan.results,
        input_file=scan.input_file,
        output_dir=output_dir,
        custom_output_name=output_name,
        single_file=single_file,
    )

    return status


def ensure_api_ready(scan: ScanIndex) -> bool:
    """Generate api_ready on-demand from consolidated data if not already present.

    Mutates scan.results in-place so subsequent calls are a no-op.
    Returns True if api_ready data is now available.
    """
    if scan.results.get("api_ready"):
        return True
    consolidated = scan.results.get("consolidated")
    if not consolidated:
        return False
    from ..core.formatter import APIFormatter
    entity_limit = scan.parse_options.get("entity_limit")
    formatter = APIFormatter(entity_limit=entity_limit)
    api_data = formatter.format_for_api(consolidated)
    scan.results["api_ready"] = api_data
    return bool(api_data)


def export_result_key(
    scan: ScanIndex,
    key: str,
    output_folder: str,
    output_name: str | None = None,
) -> dict[str, bool]:
    """Export a single result type (e.g. 'parsed', 'consolidated', 'api_ready') to disk."""
    data = scan.results.get(key)
    if not data:
        return {}
    output_dir = ensure_output_directory(output_folder)
    return write_results_to_files(
        results={key: data},
        input_file=scan.input_file,
        output_dir=output_dir,
        custom_output_name=output_name,
        single_file=False,
    )


def build_filtered_snapshot(scan: ScanIndex, plugin_ids: list[str]) -> dict[str, Any]:
    """Return a lightweight JSON snapshot for current filtered findings set."""
    parsed = scan.results.get("parsed", {})
    vulnerabilities = parsed.get("vulnerabilities", {}) if isinstance(parsed, dict) else {}

    filtered = {pid: vulnerabilities[pid] for pid in plugin_ids if pid in vulnerabilities}

    return {
        "metadata": {
            "source_file": scan.input_file,
            "file_type": scan.file_type,
            "filtered_count": len(filtered),
            "selection": plugin_ids,
        },
        "vulnerabilities": filtered,
    }


def write_filtered_snapshot(scan: ScanIndex, plugin_ids: list[str], output_path: str) -> Path:
    """Write filtered findings snapshot for analyst handoff or focused review."""
    import json

    snapshot = build_filtered_snapshot(scan, plugin_ids)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    with open(out, "w", encoding="utf-8") as handle:
        json.dump(snapshot, handle, indent=2)

    return out
