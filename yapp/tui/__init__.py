"""YAPP Textual TUI package."""

from __future__ import annotations

from .app import run_tui_app as _run_nessus_tui_app
from .indexer import build_scan_index
from .state import ADIndex


def run_tui_app(
    scan,
    output_folder: str,
    output_name: str,
    single_file: bool,
    page_size: int,
    entity_limit: int | None = None,
) -> None:
    """Dispatch to the dedicated AD or Nessus Textual application."""
    if isinstance(scan, ADIndex):
        from .ad_app import run_ad_tui_app

        run_ad_tui_app(scan, output_folder, output_name, entity_limit)
        return
    _run_nessus_tui_app(
        scan=scan,
        output_folder=output_folder,
        output_name=output_name,
        single_file=single_file,
        page_size=page_size,
    )


__all__ = ["run_tui_app", "build_scan_index"]
