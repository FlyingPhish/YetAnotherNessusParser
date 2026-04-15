"""Full-page finding detail screen."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Collapsible,
    DataTable,
    Footer,
    Header,
    Markdown,
    RichLog,
    Static,
)

from ..state import FindingDetail, HostRef, ScanIndex


def _fmt_list(items: tuple[str, ...], none_text: str = "(none)") -> str:
    return ", ".join(items) if items else none_text


def _build_meta_bar(detail: FindingDetail) -> str:
    row = detail.row
    return (
        f"  Plugin {row.plugin_id}  |  "
        f"{row.severity_label}  |  Risk: {row.risk_score}  |  "
        f"CVSS: {row.cvss_base} / CVSS3: {row.cvss3_base}  |  "
        f"Triage: {row.triage_state}  |  "
        f"Hosts: {row.affected_hosts_count}"
    )


def _build_content_md(detail: FindingDetail) -> str:
    """Single Markdown document: title + synopsis + description + solution + references."""
    row = detail.row
    parts: list[str] = [f"# {row.name}", ""]

    if detail.synopsis:
        parts += ["## Synopsis", "", detail.synopsis, ""]

    if detail.description:
        parts += ["## Description", "", detail.description, ""]

    if detail.solution:
        parts += ["## Solution", "", detail.solution, ""]

    if row.references:
        parts += ["## References", ""]
        parts += [f"- {r}" for r in row.references]
        parts.append("")

    return "\n".join(parts)


class DetailScreen(Screen):
    """Full-page finding detail with inline host table and plugin output."""

    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("b", "go_back", "Back"),
        Binding("i", "app.show_intel", "Intel"),
        Binding("m", "app.mark_triage", "Triage"),
        Binding("h", "app.host_pivot", "Host Pivot"),
        Binding("bracketright", "next_finding", "Next", key_display="]"),
        Binding("bracketleft", "prev_finding", "Prev", key_display="["),
        Binding("q", "app.quit", "Quit"),
    ]

    CSS = """
    #detail-meta {
        height: auto;
        padding: 0 1;
        background: $primary-background;
        color: $text;
        text-style: bold;
    }

    #detail-scroll {
        height: 1fr;
        padding: 0 2;
    }

    #hosts-table {
        height: 8;
        margin-bottom: 1;
    }

    #plugin-output {
        height: 12;
        border: round $panel;
    }
    """

    def __init__(self, scan: ScanIndex, plugin_id: str) -> None:
        super().__init__()
        self.scan = scan
        self.plugin_id = plugin_id

    @property
    def detail(self) -> FindingDetail | None:
        return self.scan.finding_details.get(self.plugin_id)

    def compose(self) -> ComposeResult:
        detail = self.detail
        meta_text = _build_meta_bar(detail) if detail else "Finding not found"
        content_text = _build_content_md(detail) if detail else ""
        yield Header(show_clock=True)
        yield Static(meta_text, id="detail-meta")

        with VerticalScroll(id="detail-scroll"):
            yield Markdown(content_text, id="content-md")

            with Collapsible(title="Affected Hosts & Plugin Output", collapsed=False):
                with Vertical():
                    yield DataTable(id="hosts-table")
                    yield RichLog(id="plugin-output", wrap=True, markup=True)

        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#hosts-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("IP", "FQDN", "Ports", "Risk")
        self._update_detail()

    def _update_detail(self) -> None:
        detail = self.detail
        if not detail:
            self.query_one("#detail-meta", Static).update("Finding not found")
            return

        self.query_one("#detail-meta", Static).update(_build_meta_bar(detail))
        self.query_one("#content-md", Markdown).update(_build_content_md(detail))

        table = self.query_one("#hosts-table", DataTable)
        table.clear()
        host_risk = {ip: s.risk_score for ip, s in self.scan.host_summaries.items()}
        for host in detail.affected_hosts:
            table.add_row(
                host.ip,
                host.fqdn or "-",
                ", ".join(host.ports) or "-",
                str(host_risk.get(host.ip, 0)),
                key=host.host_id,
            )

        # Show first host's output by default
        if detail.affected_hosts:
            self._show_plugin_output(detail.affected_hosts[0])
        else:
            log = self.query_one("#plugin-output", RichLog)
            log.clear()
            log.write("(no affected hosts)")

    def _show_plugin_output(self, host: HostRef) -> None:
        log = self.query_one("#plugin-output", RichLog)
        log.clear()
        log.write(f"[bold]{host.ip}[/bold]  {host.fqdn or ''}")
        log.write(f"Ports: {', '.join(host.ports) if host.ports else '-'}")
        log.write("")
        log.write(host.plugin_output_preview or "(no plugin output for this host)")

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id != "hosts-table":
            return
        host_id = str(getattr(event.row_key, "value", event.row_key))
        detail = self.detail
        if not detail:
            return
        host = next((h for h in detail.affected_hosts if h.host_id == host_id), None)
        if host:
            self._show_plugin_output(host)

    def _get_neighbor_plugin_id(self, offset: int) -> str | None:
        for screen in self.app.screen_stack:
            if hasattr(screen, "current_page_rows"):
                rows = screen.current_page_rows
                break
        else:
            return None
        try:
            idx = next(i for i, r in enumerate(rows) if r.plugin_id == self.plugin_id)
        except StopIteration:
            return None
        new_idx = idx + offset
        if 0 <= new_idx < len(rows):
            return rows[new_idx].plugin_id
        return None

    def action_next_finding(self) -> None:
        nxt = self._get_neighbor_plugin_id(1)
        if nxt:
            self.plugin_id = nxt
            self._update_detail()

    def action_prev_finding(self) -> None:
        prev = self._get_neighbor_plugin_id(-1)
        if prev:
            self.plugin_id = prev
            self._update_detail()

    def action_go_back(self) -> None:
        self.app.pop_screen()
