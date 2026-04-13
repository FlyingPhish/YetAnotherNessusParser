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
