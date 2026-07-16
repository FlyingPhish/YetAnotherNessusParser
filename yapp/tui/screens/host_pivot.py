"""Host pivot modal screen with RichLog for plugin output."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import DataTable, RichLog, Static

from ..state import FindingDetail


class HostPivotScreen(ModalScreen[None]):
    """Modal showing all hosts affected by a finding with plugin output."""

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("b", "close", "Back"),
        Binding("q", "close", "Close"),
    ]

    CSS = """
    HostPivotScreen {
        align: center middle;
    }

    #host-modal {
        width: 95%;
        height: 90%;
        border: tall $accent;
        background: $surface;
        padding: 1;
    }

    #host-title {
        height: auto;
        padding: 0 1;
        text-style: bold;
        border-bottom: solid $panel;
        margin-bottom: 1;
    }

    #host-table {
        height: 1fr;
        width: 100%;
    }

    #host-output {
        height: 12;
        border: tall $panel;
        margin-top: 1;
    }
    """

    def __init__(self, detail: FindingDetail, host_risk: dict[str, int]) -> None:
        super().__init__()
        self.detail = detail
        self.host_risk = host_risk

    def compose(self) -> ComposeResult:
        with Vertical(id="host-modal"):
            yield Static(
                f"  Host View  |  {self.detail.row.plugin_id}  |  {self.detail.row.name}",
                id="host-title",
            )
            yield DataTable(id="host-table")
            yield RichLog(id="host-output", wrap=True, markup=True)

    def on_mount(self) -> None:
        table = self.query_one("#host-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("IP", "FQDN", "Ports", "Host Risk")

        for host in self.detail.affected_hosts:
            risk = self.host_risk.get(host.ip, 0)
            table.add_row(
                host.ip,
                host.fqdn or "-",
                ", ".join(host.ports) or "-",
                str(risk),
                key=host.host_id,
            )

        if self.detail.affected_hosts:
            self._show_output(self.detail.affected_hosts[0].host_id)

    def _show_output(self, host_id: str) -> None:
        log = self.query_one("#host-output", RichLog)
        log.clear()

        host = next(
            (h for h in self.detail.affected_hosts if h.host_id == host_id), None
        )
        if not host:
            log.write("Host not found")
            return

        log.write(f"[bold]{host.ip}[/bold]  {host.fqdn or ''}")
        log.write(f"Ports: {', '.join(host.ports) if host.ports else '-'}")
        log.write("")
        output = host.plugin_output_preview or "(No plugin output)"
        log.write(output)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        key = str(getattr(event.row_key, "value", event.row_key))
        self._show_output(key)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        key = str(getattr(event.row_key, "value", event.row_key))
        self._show_output(key)

    def action_close(self) -> None:
        self.dismiss(None)
