"""Full-page findings list screen."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import DataTable, Footer, Header, Static

from ..query import apply_query, filter_and_sort
from ..state import ScanIndex, QueryOptions


class FindingsScreen(Screen):
    """Full-page findings table with summary bar."""

    BINDINGS = [
        Binding("enter", "view_detail", "Detail", priority=True),
        Binding("i", "app.show_intel", "Intel"),
        Binding("slash", "app.search", "Search", key_display="/"),
        Binding("s", "app.cycle_sort", "Sort"),
        Binding("f", "app.filter_severity", "Filter"),
        Binding("m", "app.mark_triage", "Mark Triage"),
        Binding("bracketleft", "app.prev_page", "Prev Page", key_display="["),
        Binding("bracketright", "app.next_page", "Next Page", key_display="]"),
        Binding("e", "app.export_combined", "Export"),
        Binding("h", "app.host_pivot", "Host Pivot"),
        Binding("v", "app.toggle_view", "View"),
        Binding("q", "app.quit", "Quit"),
    ]

    CSS = """
    #summary-bar {
        height: auto;
        padding: 0 1;
        background: $primary-background;
        color: $text;
        text-style: bold;
    }

    #findings-table {
        height: 1fr;
    }

    #page-bar {
        height: auto;
        padding: 0 1;
        background: $accent;
        color: $text;
    }
    """

    def __init__(self, scan: ScanIndex, query_state: QueryOptions) -> None:
        super().__init__()
        self.scan = scan
        self.query_state = query_state
        self.current_page_rows: list = []
        self.current_total: int = 0

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("", id="summary-bar")
        yield DataTable(id="findings-table")
        yield Static("", id="page-bar")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("Severity", "Name", "Hosts", "Triage")
        self.refresh_table(reset_page=True)

    def refresh_table(self, reset_page: bool = False) -> None:
        if reset_page:
            self.query_state.page = 0

        row_source = (
            self.app._get_consolidated_rows()
            if self.app.view_mode == "consolidated"
            else self.scan.findings_rows
        )
        self.current_page_rows, self.current_total = apply_query(row_source, self.query_state)

        table = self.query_one("#findings-table", DataTable)
        table.clear()

        for row in self.current_page_rows:
            table.add_row(
                row.severity_label,
                row.name,
                str(row.affected_hosts_count),
                row.triage_state,
                key=row.plugin_id,
            )

        self._update_summary()
        self._update_page_bar()

    def _update_summary(self) -> None:
        bar = self.query_one("#summary-bar", Static)
        meta = self.scan.metadata
        sev_label = self._severity_filter_label()
        view = self.app.view_mode
        bar.update(
            f"  {meta.get('source_name', '?')}  |  "
            f"{meta.get('hosts_total', 0)} hosts  |  "
            f"{len(self.scan.findings_rows)} findings  |  "
            f"Severity: {sev_label}  |  "
            f"Sort: {self.query_state.sort_by}  |  "
            f"View: {view}"
        )

    def _update_page_bar(self) -> None:
        bar = self.query_one("#page-bar", Static)
        page = self.query_state.page + 1
        total_pages = max(
            1,
            (self.current_total + self.query_state.page_size - 1)
            // self.query_state.page_size,
        )
        bar.update(
            f"  Page {page}/{total_pages}  |  "
            f"{len(self.current_page_rows)} shown (filtered {self.current_total})"
        )

    def _severity_filter_label(self) -> str:
        if not self.query_state.severities:
            return "all"
        ordered = [(4, "C"), (3, "H"), (2, "M"), (1, "L"), (0, "I")]
        return ",".join(l for v, l in ordered if v in self.query_state.severities) or "all"

    @property
    def selected_plugin_id(self) -> str | None:
        table = self.query_one("#findings-table", DataTable)
        idx = table.cursor_row
        if idx is not None and 0 <= idx < len(self.current_page_rows):
            return self.current_page_rows[idx].plugin_id
        return None

    def action_view_detail(self) -> None:
        plugin_id = self.selected_plugin_id
        if plugin_id:
            self.app.action_push_detail(plugin_id)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        key = str(getattr(event.row_key, "value", event.row_key))
        self.app.action_push_detail(key)
