"""Exports for the AD TUI, delegated to the existing AD reporting stack."""

from __future__ import annotations

from pathlib import Path

from ..config import get_default_ad_rules_path
from ..core.ad_excel import ADExcelFormatter
from ..core.ad_reporting import (
    ADAPIFormatter,
    load_ad_configuration,
    map_ad_findings,
)
from ..utils.file_utils import _build_output_name, _get_base_name, ensure_output_directory
from ..utils.json_utils import write_json_output
from .state import ADIndex


def export_ad_results(
    index: ADIndex,
    output_folder: str,
    output_name: str | None = None,
    *,
    entity_limit: int | None = None,
) -> dict[str, bool]:
    """Write the stable AD JSON, API mapping, and operator workbook."""
    output_dir = ensure_output_directory(output_folder)
    base = _get_base_name(index.input_file, output_name)
    rules_path = index.parse_options.get("rules_file") or get_default_ad_rules_path()
    configuration = load_ad_configuration(str(rules_path))
    mapped = map_ad_findings(index.report, configuration["rules"])
    status: dict[str, bool] = {}

    json_path = output_dir / _build_output_name(base, "_AD_Findings")
    status[str(json_path)] = write_json_output(index.report, json_path)

    api_rows = ADAPIFormatter(entity_limit).format(mapped)
    if api_rows:
        api_path = output_dir / _build_output_name(base, "_AD_API")
        status[str(api_path)] = write_json_output(api_rows, api_path)

    excel_path = output_dir / _build_output_name(base, "_AD_Report", ".xlsx")
    try:
        ADExcelFormatter().format(index.report, mapped).save(excel_path)
        status[str(excel_path)] = True
    except Exception:
        status[str(excel_path)] = False
    return status
