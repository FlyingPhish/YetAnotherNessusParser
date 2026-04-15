"""Textual TUI app for high-volume Nessus triage."""

from __future__ import annotations

import json
from pathlib import Path

from textual.app import App
from textual.command import Hit, Hits, Provider

from .exports import export_scan_results, write_filtered_snapshot
from .query import filter_and_sort
from .screens.consolidated_detail import ConsolidatedDetailScreen
from .screens.detail import DetailScreen
from .screens.findings import FindingsScreen
from .screens.host_pivot import HostPivotScreen
from .screens.intel import IntelScreen
from .state import FindingRow, QueryOptions, ScanIndex, SEVERITY_LABELS, TRIAGE_STATES


class YappCommands(Provider):
    """Command palette provider — populated via discover() (empty query) and search() (typed query)."""

    def _all_commands(self) -> list[tuple[str, str, object]]:
        """Return (label, help, callable) for every available command."""
        app: YetAnotherPentestParser = self.app
        cmds: list[tuple[str, str, object]] = []

        for mode in ("severity", "risk", "hosts", "plugin", "name"):
            cmds.append((
                f"Sort by {mode}",
                f"Sort findings by {mode}",
                self._make_sort(mode),
            ))

        sev_combos = [
            ("Filter: Critical only", "Show Critical findings only", {4}),
            ("Filter: High only", "Show High findings only", {3}),
            ("Filter: Critical + High", "Show Critical and High findings", {4, 3}),
            ("Filter: Critical + High + Medium", "Show Critical, High and Medium findings", {4, 3, 2}),
            ("Filter: Show all severities", "Remove severity filter", set()),
        ]
        for label, help_text, sevs in sev_combos:
            cmds.append((label, help_text, self._make_sev_filter(sevs)))

        cmds.extend([
            ("Toggle view (Nessus/Consolidated)", "Switch between Nessus and Consolidated findings view", app.action_toggle_view),
            ("Show Intel overlay", "Show full threat intel for selected finding", app.action_show_intel),
            ("Search findings", "Open search input", app.action_search),
            ("Clear filters", "Clear search and severity filters", app.action_clear_filters),
            ("Export all results", "Export full scan to disk", app.action_export_results),
            ("Export filtered results", "Export current filtered set to disk", app.action_export_filtered),
            ("Next page", "Go to next page of findings", app.action_next_page),
            ("Previous page", "Go to previous page of findings", app.action_prev_page),
        ])
        return cmds

    async def discover(self) -> Hits:
        """Populate palette when no query is typed yet."""
        for label, help_text, command in self._all_commands():
            yield Hit(0.0, label, command, help=help_text)

    async def search(self, query: str) -> Hits:
        """Fuzzy-match against all commands."""
        matcher = self.matcher(query)
        for label, help_text, command in self._all_commands():
            score = matcher.match(label)
            if score > 0:
                yield Hit(score, matcher.highlight(label), command, text=label, help=help_text)

    def _make_sort(self, mode: str):
        def _do():
            app: YetAnotherPentestParser = self.app
            app.query_state.sort_by = mode
            app._refresh_findings()
            app.notify(f"Sort: {mode}")
        return _do

    def _make_sev_filter(self, sevs: set[int]):
        def _do():
            app: YetAnotherPentestParser = self.app
            app.query_state.severities = sevs
            app._refresh_findings(reset_page=True)
            label = "all" if not sevs else ", ".join(
                SEVERITY_LABELS.get(s, "?") for s in sorted(sevs, reverse=True)
            )
            app.notify(f"Filter: {label}")
        return _do


class YetAnotherPentestParser(App):
    """Main TUI app — two-screen master/detail with command palette."""

    TITLE = "YetAnotherPentestParser"
    COMMANDS = {YappCommands}

    CSS = """
    Screen {
        background: $surface;
    }
    """

    def __init__(
        self,
        scan: ScanIndex,
        default_output_folder: str,
        default_output_name: str,
        default_single_file: bool,
        page_size: int,
    ) -> None:
        super().__init__()
        self.scan = scan
        self.query_state = QueryOptions(
            search_text="",
            severities=set(),
            sort_by="severity",
            page=0,
            page_size=max(10, page_size),
        )
        self.default_output_folder = default_output_folder
        self.default_output_name = default_output_name
        self.default_single_file = default_single_file
        self._active_plugin_id: str | None = None
        self.view_mode: str = "nessus"
        self._consolidated_rows: list[FindingRow] | None = None

        self.triage_path = self.scan.get_triage_path()
        self._load_triage_state()

    def on_mount(self) -> None:
        self.push_screen(FindingsScreen(self.scan, self.query_state))

    # ── Triage persistence ──────────────────────────────────────────

    def _load_triage_state(self) -> None:
        if not self.triage_path.exists():
            return
        try:
            payload = json.loads(self.triage_path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(payload, dict):
            return
        for row in self.scan.findings_rows:
            state = payload.get(row.plugin_id)
            if state in TRIAGE_STATES:
                row.triage_state = state

    def _save_triage_state(self) -> None:
        payload = {r.plugin_id: r.triage_state for r in self.scan.findings_rows}
        self.triage_path.write_text(
            json.dumps(payload, indent=2), encoding="utf-8"
        )

    # ── Consolidated view helpers ────────────────────────────────────

    def _get_consolidated_rows(self) -> list[FindingRow]:
        if self._consolidated_rows is not None:
            return self._consolidated_rows
        consolidated = (self.scan.results.get("consolidated") or {})
        vulns = consolidated.get("consolidated_vulnerabilities") or {}
        rows: list[FindingRow] = []
        for rule_name, vuln in vulns.items():
            severity = int(vuln.get("severity", 0))
            sev_label = SEVERITY_LABELS.get(severity, "None")
            cvss = float((vuln.get("cvss") or {}).get("base_score", 0) or 0)
            cvss3 = float((vuln.get("cvss3") or {}).get("base_score", 0) or 0)
            host_count = len(vuln.get("affected_services") or {})
            sev_base = {4: 70, 3: 55, 2: 35, 1: 15, 0: 2}.get(severity, 2)
            risk_score = min(100, sev_base + min(10, host_count) + int(max(cvss3, cvss)))
            title = vuln.get("title", rule_name)
            rows.append(FindingRow(
                plugin_id=rule_name,
                name=title,
                family="Consolidated",
                severity=severity,
                severity_label=sev_label,
                risk_factor=str(vuln.get("risk_factor", "None")),
                risk_score=risk_score,
                cvss_base=cvss,
                cvss3_base=cvss3,
                affected_hosts_count=host_count,
                cve=tuple(vuln.get("cve") or []),
                search_blob=f"{rule_name} {title}".lower(),
            ))
        rows.sort(key=lambda r: (r.risk_score, r.severity, r.affected_hosts_count), reverse=True)
        self._consolidated_rows = rows
        return rows

    # ── Screen helpers ──────────────────────────────────────────────

    def _get_findings_screen(self) -> FindingsScreen | None:
        for screen in self.screen_stack:
            if isinstance(screen, FindingsScreen):
                return screen
        return None

    def _refresh_findings(self, reset_page: bool = False) -> None:
        fs = self._get_findings_screen()
        if fs:
            fs.refresh_table(reset_page=reset_page)

    def _resolve_plugin_id(self) -> str | None:
        """Get active plugin_id from current context."""
        screen = self.screen
        if isinstance(screen, (DetailScreen, ConsolidatedDetailScreen)):
            return screen.plugin_id
        if isinstance(screen, FindingsScreen):
            return screen.selected_plugin_id
        return self._active_plugin_id

    # ── Actions (bound from screens) ───────────────────────────────

    def action_toggle_view(self) -> None:
        consolidated = self.scan.results.get("consolidated")
        if not consolidated or not consolidated.get("consolidated_vulnerabilities"):
            self.notify("No consolidated data — run with --consolidate (-c)", severity="warning")
            return
        self.view_mode = "consolidated" if self.view_mode == "nessus" else "nessus"
        self._refresh_findings(reset_page=True)
        self.notify(f"View: {self.view_mode}")

    def action_push_detail(self, plugin_id: str) -> None:
        self._active_plugin_id = plugin_id
        if self.view_mode == "consolidated":
            self.push_screen(ConsolidatedDetailScreen(self.scan, plugin_id))
        else:
            self.push_screen(DetailScreen(self.scan, plugin_id))

    def action_search(self) -> None:
        def _on_search(value: str | None) -> None:
            if value is None:
                return
            self.query_state.search_text = value.strip()
            self._refresh_findings(reset_page=True)
            self.notify(f"Search: {value.strip() or '(cleared)'}")

        self.app.push_screen(
            _SearchInputScreen(self.query_state.search_text), callback=_on_search
        )

    def action_cycle_sort(self) -> None:
        modes = ["severity", "risk", "hosts", "plugin", "name"]
        try:
            idx = modes.index(self.query_state.sort_by)
        except ValueError:
            idx = 0
        self.query_state.sort_by = modes[(idx + 1) % len(modes)]
        self._refresh_findings(reset_page=True)
        self.notify(f"Sort: {self.query_state.sort_by}")

    def action_filter_severity(self) -> None:
        """Cycle through severity presets: all → C → C+H → C+H+M → all."""
        presets = [set(), {4}, {4, 3}, {4, 3, 2}]
        current = self.query_state.severities
        try:
            idx = next(i for i, p in enumerate(presets) if p == current)
            nxt = presets[(idx + 1) % len(presets)]
        except StopIteration:
            nxt = set()
        self.query_state.severities = nxt
        self._refresh_findings(reset_page=True)
        label = "all" if not nxt else ",".join(
            SEVERITY_LABELS.get(s, "?") for s in sorted(nxt, reverse=True)
        )
        self.notify(f"Severity: {label}")

    def action_clear_filters(self) -> None:
        self.query_state.search_text = ""
        self.query_state.severities = set()
        self._refresh_findings(reset_page=True)
        self.notify("Filters cleared")

    def action_prev_page(self) -> None:
        self.query_state.page = max(0, self.query_state.page - 1)
        self._refresh_findings()

    def action_next_page(self) -> None:
        fs = self._get_findings_screen()
        if fs:
            total_pages = max(
                1,
                (fs.current_total + self.query_state.page_size - 1)
                // self.query_state.page_size,
            )
            self.query_state.page = min(total_pages - 1, self.query_state.page + 1)
        self._refresh_findings()

    def action_mark_triage(self) -> None:
        plugin_id = self._resolve_plugin_id()
        if not plugin_id:
            self.notify("No finding selected", severity="warning")
            return

        detail = self.scan.finding_details.get(plugin_id)
        if not detail:
            self.notify(f"Finding {plugin_id} not found", severity="warning")
            return

        current = detail.row.triage_state
        idx = TRIAGE_STATES.index(current) if current in TRIAGE_STATES else 0
        next_state = TRIAGE_STATES[(idx + 1) % len(TRIAGE_STATES)]
        detail.row.triage_state = next_state
        self._save_triage_state()
        self._refresh_findings()

        # Re-render detail screen if active
        if isinstance(self.screen, DetailScreen):
            self.screen._update_detail()

        self.notify(f"{plugin_id} → {next_state}")

    def action_show_intel(self) -> None:
        plugin_id = self._resolve_plugin_id()
        if not plugin_id:
            self.notify("No finding selected", severity="warning")
            return
        detail = self.scan.finding_details.get(plugin_id)
        if not detail:
            self.notify(f"Finding {plugin_id} not found", severity="warning")
            return
        self.push_screen(IntelScreen(plugin_id=plugin_id, detail=detail))

    def action_host_pivot(self) -> None:
        plugin_id = self._resolve_plugin_id()
        if not plugin_id:
            self.notify("No finding selected", severity="warning")
            return

        detail = self.scan.finding_details.get(plugin_id)
        if not detail:
            self.notify(f"Finding {plugin_id} not found", severity="warning")
            return

        host_risk = {
            ip: s.risk_score for ip, s in self.scan.host_summaries.items()
        }
        self.push_screen(HostPivotScreen(detail=detail, host_risk=host_risk))

    def _output_dir(self) -> Path:
        """Resolve the export directory — user override or next to the input file."""
        if self.default_output_folder:
            return Path(self.default_output_folder)
        return Path(self.scan.input_file).resolve().parent

    def action_export_results(self) -> None:
        out_dir = self._output_dir()
        try:
            status = export_scan_results(
                scan=self.scan,
                output_folder=str(out_dir),
                output_name=self.default_output_name or None,
                single_file=self.default_single_file,
            )
        except Exception as exc:
            self.notify(f"Export failed: {exc}", severity="error")
            return

        failed = [n for n, ok in status.items() if not ok]
        if failed:
            self.notify(f"Partial failure: {', '.join(failed)}", severity="warning")
        else:
            self.notify(f"Exported → {out_dir}")

    def action_export_filtered(self) -> None:
        filtered = filter_and_sort(self.scan.findings_rows, self.query_state)
        filtered_ids = [r.plugin_id for r in filtered]
        if not filtered_ids:
            self.notify("No filtered findings to export", severity="warning")
            return

        stem = Path(self.scan.input_file).stem
        output_path = self._output_dir() / f"{stem}_filtered.json"

        try:
            written = write_filtered_snapshot(self.scan, filtered_ids, str(output_path))
            self.notify(f"Filtered → {written.name}")
        except Exception as exc:
            self.notify(f"Export failed: {exc}", severity="error")


# ── Lightweight search input modal ──────────────────────────────


from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import ModalScreen
from textual.widgets import Input, Static


class _SearchInputScreen(ModalScreen[str | None]):
    """Minimal search input modal."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    CSS = """
    _SearchInputScreen {
        align: center middle;
    }

    #search-modal {
        width: 60;
        height: auto;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }
    """

    def __init__(self, current: str = "") -> None:
        super().__init__()
        self.current = current

    def compose(self) -> ComposeResult:
        from textual.containers import Vertical

        with Vertical(id="search-modal"):
            yield Static("Search findings (plugin/name/CVE/CWE/MITRE):")
            yield Input(value=self.current, id="search-input")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def action_cancel(self) -> None:
        self.dismiss(None)


# ── Entry point ─────────────────────────────────────────────────


def run_tui_app(
    scan: ScanIndex,
    output_folder: str,
    output_name: str,
    single_file: bool,
    page_size: int,
) -> None:
    """Run Textual TUI app with pre-built scan index."""
    app = YetAnotherPentestParser(
        scan=scan,
        default_output_folder=output_folder,
        default_output_name=output_name,
        default_single_file=single_file,
        page_size=page_size,
    )
    app.run()
