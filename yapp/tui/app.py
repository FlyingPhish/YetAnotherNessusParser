"""Textual TUI app for high-volume Nessus triage without SQL."""

from __future__ import annotations

import json
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Checkbox, DataTable, Footer, Header, Input, Static

from .exports import export_scan_results, write_filtered_snapshot
from .query import apply_query, filter_and_sort
from .state import FindingDetail, QueryOptions, ScanIndex, TRIAGE_STATES


def _safe_row_key(row_key) -> str:
    return str(getattr(row_key, "value", row_key))


SEVERITY_NONE_SENTINEL = -1
SEVERITY_FILTER_CHECKBOXES = (
    ("sev-critical", "Critical", 4),
    ("sev-high", "High", 3),
    ("sev-medium", "Medium", 2),
    ("sev-low", "Low", 1),
    ("sev-info", "Info", 0),
)


class HostPivotScreen(ModalScreen[None]):
    """Host-focused pivot for selected finding."""

    BINDINGS = [
        Binding("q", "close", "Close"),
        Binding("escape", "close", "Close"),
        Binding("b", "close", "Back"),
    ]

    CSS = """
    HostPivotScreen {
        align: center middle;
    }

    #host-modal {
        width: 95%;
        height: 90%;
        border: round $accent;
        background: $surface;
        padding: 1;
    }

    #host-title {
        height: auto;
        margin-bottom: 1;
    }

    #host-table {
        height: 1fr;
    }

    #host-detail {
        height: 11;
        border: round $panel;
        padding: 1;
        margin-top: 1;
        overflow-y: auto;
    }
    """

    def __init__(self, detail: FindingDetail, host_risk: dict[str, int]) -> None:
        super().__init__()
        self.detail = detail
        self.host_risk = host_risk

    def compose(self) -> ComposeResult:
        with Vertical(id="host-modal"):
            yield Static(
                f"Host Pivot - {self.detail.row.plugin_id} | {self.detail.row.name}",
                id="host-title",
            )
            yield DataTable(id="host-table")
            yield Static("Select a host row for output preview", id="host-detail")

    def on_mount(self) -> None:
        table = self.query_one("#host-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("IP", "FQDN", "Ports", "Host Risk")

        for host in self.detail.affected_hosts:
            risk = self.host_risk.get(host.ip, 0)
            table.add_row(host.ip, host.fqdn or "-", ", ".join(host.ports) or "-", str(risk), key=host.host_id)

        if self.detail.affected_hosts:
            self._render_host_detail(self.detail.affected_hosts[0].host_id)

    def _render_host_detail(self, host_id: str) -> None:
        panel = self.query_one("#host-detail", Static)

        host = next((item for item in self.detail.affected_hosts if item.host_id == host_id), None)
        if not host:
            panel.update("Host not found")
            return

        preview = host.plugin_output_preview or "(No plugin output for this host)"
        text = [
            f"Host ID: {host.host_id}",
            f"IP: {host.ip}",
            f"FQDN: {host.fqdn or '-'}",
            f"Ports: {', '.join(host.ports) if host.ports else '-'}",
            "",
            "Plugin Output Preview:",
            preview,
        ]

        panel.update("\n".join(text))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._render_host_detail(_safe_row_key(event.row_key))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._render_host_detail(_safe_row_key(event.row_key))

    def action_close(self) -> None:
        self.dismiss(None)


class YetAnotherPentestParser(App):
    """Main TUI application for Nessus queue triage."""

    BINDINGS = [
        Binding("/", "focus_search", "Search"),
        Binding("f", "focus_severity", "Severity"),
        Binding("s", "cycle_sort", "Sort"),
        Binding("[", "prev_page", "Prev Page"),
        Binding("]", "next_page", "Next Page"),
        Binding("m", "mark_triage", "Mark Triage"),
        Binding("h", "host_pivot", "Host Pivot"),
        Binding("e", "export_results", "Export"),
        Binding("ctrl+e", "export_filtered", "Export Filtered"),
        Binding("r", "refresh_filters", "Apply Filters"),
        Binding("q", "quit", "Quit"),
    ]

    CSS = """
    #summary-bar {
        height: auto;
        padding: 0 1;
        border: round $panel;
        margin-bottom: 1;
    }

    #filters-bar {
        height: auto;
        padding: 0 1;
        border: round $panel;
        margin-bottom: 1;
    }

    #controls {
        height: auto;
        margin-bottom: 1;
    }

    #filter-row {
        height: auto;
        margin-bottom: 1;
    }

    #severity-row {
        height: auto;
    }

    #severity-label {
        width: 9;
        content-align: left middle;
    }

    #export-controls {
        height: auto;
        margin-bottom: 1;
    }

    #main-body {
        height: 1fr;
    }

    #findings-table {
        width: 2fr;
        height: 1fr;
    }

    #detail-pane {
        width: 3fr;
        height: 1fr;
        border: round $panel;
        padding: 1;
        overflow-y: auto;
    }

    #status-bar {
        height: auto;
        border: round $accent;
        padding: 0 1;
        margin-top: 1;
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

        self.current_page_rows = []
        self.current_filtered_rows = []
        self.current_total = 0
        self.selected_plugin_id: str | None = None
        self.sort_modes = ["severity", "risk", "hosts", "plugin", "name"]
        self._suspend_filter_auto_refresh = False

        self.triage_path = self.scan.get_triage_path()
        self._load_triage_state()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        yield Static("", id="summary-bar")
        yield Static("", id="filters-bar")

        with Vertical(id="controls"):
            with Horizontal(id="filter-row"):
                yield Input(placeholder="Search plugin/name/CVE/CWE/MITRE", id="search-input")
                yield Button("Apply", id="apply-filters")
                yield Button("Clear", id="clear-filters")
                yield Button("Sort: severity", id="cycle-sort")
                yield Button("Prev", id="prev-page")
                yield Button("Next", id="next-page")

            with Horizontal(id="severity-row"):
                yield Static("Severity:", id="severity-label")
                for checkbox_id, label, _ in SEVERITY_FILTER_CHECKBOXES:
                    yield Checkbox(label, value=True, id=checkbox_id)

        with Horizontal(id="export-controls"):
            yield Input(value=self.default_output_folder, placeholder="Output folder", id="output-folder")
            yield Input(value=self.default_output_name, placeholder="Output base name", id="output-name")
            yield Checkbox("Single file", value=self.default_single_file, id="single-file")
            yield Button("Export", id="export-results")
            yield Button("Export Filtered", id="export-filtered")

        with Horizontal(id="main-body"):
            yield DataTable(id="findings-table")
            yield Static("Select a finding row", id="detail-pane")

        yield Static("Ready", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.cursor_type = "row"
        try:
            table.zebra_stripes = True
        except Exception:
            pass

        # DataTable has internal key handling for `f`; force operator shortcut routing.
        try:
            table.bind("f", "app.focus_severity", show=False)
            table.bind("/", "app.focus_search", show=False)
        except Exception:
            pass

        self._ensure_table_columns()
        self.refresh_view(reset_page=True)

    def _load_triage_state(self) -> None:
        if not self.triage_path.exists():
            return

        try:
            with open(self.triage_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception:
            return

        if not isinstance(payload, dict):
            return

        for row in self.scan.findings_rows:
            state = payload.get(row.plugin_id)
            if state in TRIAGE_STATES:
                row.triage_state = state

    def _save_triage_state(self) -> None:
        payload = {row.plugin_id: row.triage_state for row in self.scan.findings_rows}
        with open(self.triage_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    def _set_status(self, message: str) -> None:
        self.query_one("#status-bar", Static).update(message)

    def _ensure_table_columns(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        try:
            has_columns = table.column_count > 0
        except Exception:
            has_columns = bool(getattr(table, "columns", []))

        if has_columns:
            return

        table.add_columns(
            "Severity",
            "Risk",
            "Hosts",
            "Plugin",
            "Name",
            "Exploit",
            "Triage",
        )

    def _selected_severities_from_controls(self) -> set[int]:
        selected = set()

        for checkbox_id, _, severity in SEVERITY_FILTER_CHECKBOXES:
            if self.query_one(f"#{checkbox_id}", Checkbox).value:
                selected.add(severity)

        if not selected:
            return {SEVERITY_NONE_SENTINEL}

        if len(selected) == len(SEVERITY_FILTER_CHECKBOXES):
            return set()

        return selected

    def _severity_filter_label(self) -> str:
        if self.query_state.severities == {SEVERITY_NONE_SENTINEL}:
            return "none"

        if not self.query_state.severities:
            return "all"

        ordered = [(4, "critical"), (3, "high"), (2, "medium"), (1, "low"), (0, "info")]
        labels = [label for value, label in ordered if value in self.query_state.severities]
        return ",".join(labels) if labels else "all"

    @staticmethod
    def _format_list_preview(values: tuple[str, ...], limit: int = 6) -> str:
        if not values:
            return "-"
        preview = ", ".join(values[:limit])
        if len(values) > limit:
            preview = f"{preview} (+{len(values) - limit} more)"
        return preview

    def _format_exploit_cell_for_row(self, row) -> str:
        parts = []
        if row.metasploit_modules:
            parts.append(f"MSF:{len(row.metasploit_modules)}")
        if row.public_exploit_refs:
            parts.append(f"PUB:{len(row.public_exploit_refs)}")
        return " ".join(parts) if parts else "-"

    def _update_filters_bar(self) -> None:
        filters_bar = self.query_one("#filters-bar", Static)

        search = self.query_state.search_text or "-"
        if len(search) > 64:
            search = f"{search[:61]}..."

        filters_bar.update(
            " | ".join(
                [
                    f"Search: {search}",
                    f"Severity: {self._severity_filter_label()}",
                    f"Sort: {self.query_state.sort_by}",
                    f"Page Size: {self.query_state.page_size}",
                ]
            )
        )

    def _update_summary(self) -> None:
        summary = self.query_one("#summary-bar", Static)

        total_findings = len(self.scan.findings_rows)
        hosts_total = self.scan.metadata.get("hosts_total", 0)
        current_page = self.query_state.page + 1
        total_pages = max(1, (self.current_total + self.query_state.page_size - 1) // self.query_state.page_size)

        selected = self.selected_plugin_id or "-"

        summary.update(
            " | ".join(
                [
                    f"Scan: {self.scan.metadata.get('source_name', Path(self.scan.input_file).name)}",
                    f"Hosts: {hosts_total}",
                    f"Findings: {total_findings}",
                    f"Filtered: {self.current_total}",
                    f"Page: {current_page}/{total_pages}",
                    f"Sort: {self.query_state.sort_by}",
                    f"Selected: {selected}",
                ]
            )
        )

    def _render_current_detail(self) -> None:
        panel = self.query_one("#detail-pane", Static)

        if not self.selected_plugin_id:
            panel.update("Select a finding row")
            return

        detail = self.scan.finding_details.get(self.selected_plugin_id)
        if not detail:
            panel.update("Finding detail not found")
            return

        row = detail.row

        sample_hosts = list(detail.affected_hosts[:5])
        sample_lines = []
        for host in sample_hosts:
            host_entity = host.ip
            if host.ports:
                host_entity = f"{host_entity}:{host.ports[0]}"
            if host.fqdn:
                host_entity = f"{host_entity} ({host.fqdn})"
            sample_lines.append(host_entity)

        detail_lines = [
            f"Plugin ID: {row.plugin_id}",
            f"Title: {row.name}",
            f"Severity: {row.severity_label} ({row.severity}) | Risk Score: {row.risk_score}",
            f"Risk Factor: {row.risk_factor}",
            f"CVSS: {row.cvss_base} | CVSS3: {row.cvss3_base}",
            f"Triage: {row.triage_state}",
            "",
            f"CVE: {self._format_list_preview(row.cve, limit=8)}",
            f"CWE: {self._format_list_preview(row.cwe, limit=8)}",
            f"MITRE: {self._format_list_preview(row.mitre, limit=8)}",
            f"Public exploit refs: {self._format_list_preview(row.public_exploit_refs, limit=8)}",
            f"Metasploit modules: {self._format_list_preview(row.metasploit_modules, limit=6)}",
            f"XREF: {self._format_list_preview(detail.xref, limit=8)}",
            f"References: {self._format_list_preview(row.references, limit=6)}",
            f"Hidden noisy references: {row.hidden_references_count}",
            "",
            f"Affected hosts: {row.affected_hosts_count}",
            "Top entities:",
            *(sample_lines if sample_lines else ["-"]),
            "",
            "Synopsis:",
            detail.synopsis or "-",
            "",
            "Description:",
            detail.description or "-",
            "",
            "Solution:",
            detail.solution or "-",
        ]

        panel.update("\n".join(detail_lines))

    def _selected_row_plugin(self) -> str | None:
        table = self.query_one("#findings-table", DataTable)
        row_index = table.cursor_row
        if row_index is None:
            return None

        if 0 <= row_index < len(self.current_page_rows):
            return self.current_page_rows[row_index].plugin_id

        return None

    def refresh_view(self, reset_page: bool = False) -> None:
        if reset_page:
            self.query_state.page = 0

        self.query_state.search_text = self.query_one("#search-input", Input).value.strip()
        self.query_state.severities = self._selected_severities_from_controls()

        self.current_filtered_rows = filter_and_sort(self.scan.findings_rows, self.query_state)
        self.current_page_rows, self.current_total = apply_query(self.scan.findings_rows, self.query_state)

        sort_button = self.query_one("#cycle-sort", Button)
        sort_button.label = f"Sort: {self.query_state.sort_by}"

        table = self.query_one("#findings-table", DataTable)

        try:
            table.clear(columns=False)
        except TypeError:
            table.clear()
            self._ensure_table_columns()

        for row in self.current_page_rows:
            table.add_row(
                row.severity_label,
                str(row.risk_score),
                str(row.affected_hosts_count),
                row.plugin_id,
                row.name,
                self._format_exploit_cell_for_row(row),
                row.triage_state,
                key=row.plugin_id,
            )

        if self.current_page_rows:
            if self.selected_plugin_id not in {row.plugin_id for row in self.current_page_rows}:
                self.selected_plugin_id = self.current_page_rows[0].plugin_id
        else:
            self.selected_plugin_id = None

        self._update_summary()
        self._update_filters_bar()
        self._render_current_detail()
        self._set_status(
            f"Showing {len(self.current_page_rows)} findings (filtered total {self.current_total})."
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        button_id = event.button.id

        if button_id == "apply-filters":
            self.refresh_view(reset_page=True)
            return

        if button_id == "clear-filters":
            self.query_one("#search-input", Input).value = ""
            self._suspend_filter_auto_refresh = True
            try:
                for checkbox_id, _, _ in SEVERITY_FILTER_CHECKBOXES:
                    self.query_one(f"#{checkbox_id}", Checkbox).value = True
            finally:
                self._suspend_filter_auto_refresh = False
            self.refresh_view(reset_page=True)
            return

        if button_id == "cycle-sort":
            self.action_cycle_sort()
            return

        if button_id == "prev-page":
            self.action_prev_page()
            return

        if button_id == "next-page":
            self.action_next_page()
            return

        if button_id == "export-results":
            self.action_export_results()
            return

        if button_id == "export-filtered":
            self.action_export_filtered()
            return

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "search-input":
            self.refresh_view(reset_page=True)

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        checkbox_id = event.checkbox.id or ""
        if checkbox_id.startswith("sev-") and not self._suspend_filter_auto_refresh:
            self.refresh_view(reset_page=True)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.selected_plugin_id = _safe_row_key(event.row_key)
        self._render_current_detail()
        self._update_summary()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.selected_plugin_id = _safe_row_key(event.row_key)
        self._render_current_detail()
        self._update_summary()

    def action_focus_search(self) -> None:
        self.query_one("#search-input", Input).focus()
        self._set_status("Search filter focused")

    def action_focus_severity(self) -> None:
        self.query_one("#sev-critical", Checkbox).focus()
        self._set_status("Severity filter focused (toggle checkboxes with Space)")

    def action_cycle_sort(self) -> None:
        try:
            current_index = self.sort_modes.index(self.query_state.sort_by)
        except ValueError:
            current_index = 0
        self.query_state.sort_by = self.sort_modes[(current_index + 1) % len(self.sort_modes)]

        sort_button = self.query_one("#cycle-sort", Button)
        sort_button.label = f"Sort: {self.query_state.sort_by}"

        self.refresh_view(reset_page=True)

    def action_prev_page(self) -> None:
        self.query_state.page = max(0, self.query_state.page - 1)
        self.refresh_view()

    def action_next_page(self) -> None:
        total_pages = max(1, (self.current_total + self.query_state.page_size - 1) // self.query_state.page_size)
        self.query_state.page = min(total_pages - 1, self.query_state.page + 1)
        self.refresh_view()

    def action_refresh_filters(self) -> None:
        self.refresh_view(reset_page=True)

    def action_mark_triage(self) -> None:
        plugin_id = self.selected_plugin_id or self._selected_row_plugin()
        if not plugin_id:
            self._set_status("No finding selected")
            return

        detail = self.scan.finding_details.get(plugin_id)
        if not detail:
            self._set_status(f"Finding {plugin_id} not found")
            return

        current = detail.row.triage_state
        idx = TRIAGE_STATES.index(current) if current in TRIAGE_STATES else 0
        next_state = TRIAGE_STATES[(idx + 1) % len(TRIAGE_STATES)]

        detail.row.triage_state = next_state
        self._save_triage_state()
        self.refresh_view()
        self._set_status(f"{plugin_id} triage -> {next_state}")

    def action_host_pivot(self) -> None:
        plugin_id = self.selected_plugin_id or self._selected_row_plugin()
        if not plugin_id:
            self._set_status("No finding selected")
            return

        detail = self.scan.finding_details.get(plugin_id)
        if not detail:
            self._set_status(f"Finding {plugin_id} not found")
            return

        host_risk = {ip: summary.risk_score for ip, summary in self.scan.host_summaries.items()}
        self.push_screen(HostPivotScreen(detail=detail, host_risk=host_risk))

    def action_export_results(self) -> None:
        output_folder = self.query_one("#output-folder", Input).value.strip() or "./output"
        output_name = self.query_one("#output-name", Input).value.strip() or None
        single_file = self.query_one("#single-file", Checkbox).value

        try:
            status = export_scan_results(
                scan=self.scan,
                output_folder=output_folder,
                output_name=output_name,
                single_file=single_file,
            )
        except Exception as exc:
            self._set_status(f"Export failed: {exc}")
            return

        failed = [name for name, ok in status.items() if not ok]
        if failed:
            self._set_status(f"Export partial failure: {', '.join(failed)}")
            return

        self._set_status(f"Export complete -> {output_folder}")

    def action_export_filtered(self) -> None:
        output_folder = self.query_one("#output-folder", Input).value.strip() or "./output"
        output_name = self.query_one("#output-name", Input).value.strip() or Path(self.scan.input_file).stem

        filtered_ids = [row.plugin_id for row in self.current_filtered_rows]
        if not filtered_ids:
            self._set_status("No filtered findings to export")
            return

        output_path = Path(output_folder) / f"{output_name}_FilteredFindings.json"

        try:
            written = write_filtered_snapshot(self.scan, filtered_ids, str(output_path))
        except Exception as exc:
            self._set_status(f"Filtered export failed: {exc}")
            return

        self._set_status(f"Filtered snapshot exported -> {written}")


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
