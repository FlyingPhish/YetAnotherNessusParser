"""Textual application for operator-led offline AD analysis."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from textual.app import App

from .ad_exports import export_ad_results
from .ad_indexer import build_ad_index
from .screens.ad import (
    ADExposureDetailScreen,
    ADExposureQueueScreen,
    ADMissionScreen,
    ADNodeScreen,
    ADPathScreen,
    AssumeOwnedScreen,
)
from .state import ADIndex, TRIAGE_STATES

_STATE_VERSION = 1
_MAX_STATE_BYTES = 1024 * 1024


def _state_path(input_file: str) -> Path:
    source = Path(input_file).resolve()
    return source.parent / f"{source.stem}.ad-tui.json"


def load_ad_operator_state(input_file: str) -> dict[str, Any]:
    """Load a small inert JSON sidecar; malformed or unsafe state is ignored."""
    path = _state_path(input_file)
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_STATE_BYTES:
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(payload, dict) or payload.get("schema_version") != _STATE_VERSION:
        return {}
    owned = payload.get("assumed_owned")
    triage = payload.get("path_triage")
    notes = payload.get("notes")
    bookmarks = payload.get("bookmarks")
    return {
        "assumed_owned": [
            value[:512]
            for value in owned[:1000]
            if isinstance(value, str) and value.strip()
        ] if isinstance(owned, list) else [],
        "path_triage": {
            str(key)[:64]: value
            for key, value in triage.items()
            if isinstance(key, str) and value in TRIAGE_STATES
        } if isinstance(triage, dict) else {},
        "notes": {
            str(key)[:128]: value[:4000]
            for key, value in notes.items()
            if isinstance(key, str) and isinstance(value, str)
        } if isinstance(notes, dict) else {},
        "bookmarks": {
            value[:128] for value in bookmarks
            if isinstance(value, str)
        } if isinstance(bookmarks, list) else set(),
    }


def _merge_state(index: ADIndex, state: dict[str, Any]) -> None:
    triage = state.get("path_triage") or {}
    for path in index.paths:
        if triage.get(path.path_id) in TRIAGE_STATES:
            path.triage_state = triage[path.path_id]
    index.notes = dict(state.get("notes") or {})
    index.bookmarks = set(state.get("bookmarks") or set())


class ADBloodHoundApp(App):
    """Separate AD mode; no Nessus concepts leak into its state or screens."""

    TITLE = "YAPP — Active Directory Mission"
    CSS = """
    Screen { background: $surface; width: 100%; height: 100%; }
    Toast { max-width: 70; }
    """

    def __init__(
        self,
        index: ADIndex,
        output_folder: str,
        output_name: str = "",
        entity_limit: int | None = None,
    ) -> None:
        super().__init__()
        self.ad_index = index
        self.output_folder = output_folder
        self.output_name = output_name
        self.entity_limit = entity_limit
        _merge_state(self.ad_index, load_ad_operator_state(index.input_file))

    def on_mount(self) -> None:
        self.push_screen(ADMissionScreen(self.ad_index))

    def _mission(self) -> ADMissionScreen | None:
        for screen in self.screen_stack:
            if isinstance(screen, ADMissionScreen):
                return screen
        return None

    def _selected_path_id(self) -> str | None:
        if isinstance(self.screen, ADPathScreen):
            return self.screen.path.path_id
        if isinstance(self.screen, ADMissionScreen):
            return self.screen.selected_path_id
        return None

    def _save_state(self) -> None:
        path = self.ad_index.get_state_path()
        payload = {
            "schema_version": _STATE_VERSION,
            "assumed_owned": self.ad_index.assumed_owned,
            "path_triage": {
                row.path_id: row.triage_state
                for row in self.ad_index.paths
                if row.triage_state != "new"
            },
            "notes": self.ad_index.notes,
            "bookmarks": sorted(self.ad_index.bookmarks),
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary_name = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(path.parent),
                prefix=f".{path.stem}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary_name = handle.name
                json.dump(payload, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, path)
        finally:
            if temporary_name and Path(temporary_name).exists():
                Path(temporary_name).unlink()

    def action_open_ad_path(self, path_id: str) -> None:
        path = next((row for row in self.ad_index.paths if row.path_id == path_id), None)
        if path:
            self.push_screen(ADPathScreen(path))

    def action_open_ad_exposures(self) -> None:
        self.push_screen(ADExposureQueueScreen())

    def action_open_ad_exposure(self, exposure_id: str) -> None:
        exposure = next(
            (
                row for row in self.ad_index.exposures
                if row.exposure_id == exposure_id
            ),
            None,
        )
        if exposure:
            self.push_screen(ADExposureDetailScreen(exposure))

    def action_open_ad_node(self, node_id: str) -> None:
        if node_id in self.ad_index.pivots:
            self.push_screen(ADNodeScreen(node_id))

    def action_assume_owned(self) -> None:
        def apply(value: str | None) -> None:
            if value is None:
                return
            identities = []
            seen = set()
            for raw in value.replace("\n", ",").split(","):
                identity = raw.strip()
                key = identity.casefold()
                if not identity or key in seen:
                    continue
                if len(identity) > 512 or len(identities) >= 1000:
                    self.notify("Owned list rejected: identity/count limit exceeded", severity="error")
                    return
                seen.add(key)
                identities.append(identity)
            self._recompute(identities)

        self.push_screen(AssumeOwnedScreen(self.ad_index.assumed_owned), apply)

    def _recompute(self, identities: list[str] | None = None) -> None:
        old = self.ad_index
        identities = list(old.assumed_owned if identities is None else identities)
        self.notify("Recomputing owned controls and bounded paths…")
        try:
            updated = build_ad_index(
                old.input_file,
                owned_principals=identities,
                include_paths=bool(old.parse_options.get("include_paths", True)),
                rules_file=old.parse_options.get("rules_file"),
            )
        except Exception as exc:
            self.notify(f"AD recompute failed: {exc}", severity="error")
            return
        state = {
            "path_triage": {row.path_id: row.triage_state for row in old.paths},
            "notes": old.notes,
            "bookmarks": old.bookmarks,
        }
        _merge_state(updated, state)
        self.ad_index = updated
        self._save_state()
        mission = self._mission()
        if mission:
            mission.refresh_index(updated)
        if not isinstance(self.screen, ADMissionScreen):
            self.pop_screen()
        unresolved = (updated.report.get("owned_analysis") or {}).get("unresolved") or []
        message = f"Owned analysis updated: {len(identities) - len(unresolved)} resolved"
        if unresolved:
            message += f", {len(unresolved)} unresolved"
        self.notify(message, severity="warning" if unresolved else "information")

    def action_refresh_ad(self) -> None:
        self._recompute()

    def action_mark_path(self) -> None:
        path_id = self._selected_path_id()
        row = next((item for item in self.ad_index.paths if item.path_id == path_id), None)
        if not row:
            self.notify("No attack path selected", severity="warning")
            return
        current = TRIAGE_STATES.index(row.triage_state) if row.triage_state in TRIAGE_STATES else 0
        row.triage_state = TRIAGE_STATES[(current + 1) % len(TRIAGE_STATES)]
        self._save_state()
        mission = self._mission()
        if mission:
            mission.refresh_index(self.ad_index)
        self.notify(f"Path → {row.triage_state}")

    def action_bookmark_path(self) -> None:
        path_id = self._selected_path_id()
        if not path_id:
            self.notify("No attack path selected", severity="warning")
            return
        if path_id in self.ad_index.bookmarks:
            self.ad_index.bookmarks.remove(path_id)
            status = "removed"
        else:
            self.ad_index.bookmarks.add(path_id)
            status = "saved"
        self._save_state()
        self.notify(f"Bookmark {status}")

    def action_export_ad(self) -> None:
        try:
            status = export_ad_results(
                self.ad_index,
                self.output_folder,
                self.output_name or None,
                entity_limit=self.entity_limit,
            )
        except Exception as exc:
            self.notify(f"Export failed: {exc}", severity="error")
            return
        failed = [Path(name).name for name, ok in status.items() if not ok]
        if failed:
            self.notify(f"Export failure: {', '.join(failed)}", severity="error")
        else:
            self.notify(f"Exported {len(status)} existing AD outputs → {self.output_folder}")


def run_ad_tui_app(
    index: ADIndex,
    output_folder: str,
    output_name: str = "",
    entity_limit: int | None = None,
) -> None:
    ADBloodHoundApp(index, output_folder, output_name, entity_limit).run()
