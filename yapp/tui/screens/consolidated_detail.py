"""Full-page consolidated finding detail screen."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Collapsible, DataTable, Footer, Header, Markdown, RichLog, Static

from ..state import ScanIndex, SEVERITY_LABELS


def _get_vuln(scan: ScanIndex, rule_name: str) -> dict | None:
    consolidated = scan.results.get("consolidated") or {}
    return (consolidated.get("consolidated_vulnerabilities") or {}).get(rule_name)


def _build_meta_bar(rule_name: str, vuln: dict) -> str:
    severity = int(vuln.get("severity", 0))
    sev_label = SEVERITY_LABELS.get(severity, "None")
    cvss = float((vuln.get("cvss") or {}).get("base_score", 0) or 0)
    cvss3 = float((vuln.get("cvss3") or {}).get("base_score", 0) or 0)
    services = vuln.get("affected_services") or {}
    return (
        f"  {rule_name}  |  "
        f"{sev_label}  |  "
        f"CVSS: {cvss} / CVSS3: {cvss3}  |  "
        f"Services: {len(services)}"
    )


def _build_content_md(vuln: dict) -> str:
    title = vuln.get("title", "(no title)")
    parts: list[str] = [f"# {title}", ""]

    plugins = vuln.get("consolidated_plugins") or {}
    if plugins:
        parts += ["## Consolidated Plugins", ""]
        parts += [f"- `{pid}`: {name}" for pid, name in plugins.items()]
        parts.append("")

    solutions = vuln.get("solutions") or []
    if solutions:
        parts += ["## Solutions", ""]
        parts += [f"- {s}" for s in solutions]
        parts.append("")

    cve = vuln.get("cve") or []
    if cve:
        parts += ["## CVEs", ""]
        parts += [f"- {c}" for c in cve]
        parts.append("")

    return "\n".join(parts)


class ConsolidatedDetailScreen(Screen):
    """Full-page consolidated finding detail with affected services and plugin output."""

    BINDINGS = [
        Binding("escape", "go_back", "Back"),
        Binding("b", "go_back", "Back"),
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

    #services-table {
        height: 8;
        margin-bottom: 1;
    }

    #plugin-output {
        height: 12;
        border: round $panel;
    }
    """

    def __init__(self, scan: ScanIndex, rule_name: str) -> None:
        super().__init__()
        self.scan = scan
        self.plugin_id = rule_name  # named plugin_id for nav compatibility with DetailScreen

    @property
    def vuln(self) -> dict | None:
        return _get_vuln(self.scan, self.plugin_id)

    def compose(self) -> ComposeResult:
        vuln = self.vuln
        meta = _build_meta_bar(self.plugin_id, vuln) if vuln else f"  {self.plugin_id}  | (not found)"
        content = _build_content_md(vuln) if vuln else ""
        yield Header(show_clock=True)
        yield Static(meta, id="detail-meta")
        with VerticalScroll(id="detail-scroll"):
            yield Markdown(content, id="content-md")
            with Collapsible(title="Affected Services & Plugin Output", collapsed=False):
                with Vertical():
                    yield DataTable(id="services-table")
                    yield RichLog(id="plugin-output", wrap=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#services-table", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_columns("IP", "FQDN", "Port", "Issues")
        self._populate_services()

    def _populate_services(self) -> None:
        vuln = self.vuln
        table = self.query_one("#services-table", DataTable)
        log = self.query_one("#plugin-output", RichLog)
        table.clear()
        log.clear()
        if not vuln:
            return
        services = vuln.get("affected_services") or {}
        svc_keys = list(services.keys())
        for svc_key in svc_keys:
            svc = services[svc_key]
            table.add_row(
                svc.get("ip", "-"),
                svc.get("fqdn", "-") or "-",
                str(svc.get("port", "-")),
                str(len(svc.get("issues_found") or [])),
                key=svc_key,
            )
        if svc_keys:
            self._show_service_output(svc_keys[0], services[svc_keys[0]])

    def _show_service_output(self, svc_key: str, svc: dict) -> None:
        log = self.query_one("#plugin-output", RichLog)
        log.clear()
        log.write(f"[bold]{svc.get('ip', '')}[/bold]  {svc.get('fqdn', '')}")
        log.write(f"Port: {svc.get('port', '-')}")
        log.write("")
        outputs = svc.get("plugin_outputs") or {}
        if outputs:
            for pid, out_data in outputs.items():
                name = out_data.get("name", pid)
                output = str(out_data.get("output", ""))
                log.write(f"[bold cyan]{name}[/bold cyan] ({pid})")
                log.write(output[:1400] or "(no output)")
                log.write("")
        else:
            log.write("(no plugin output)")

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id != "services-table":
            return
        svc_key = str(getattr(event.row_key, "value", event.row_key))
        vuln = self.vuln
        if not vuln:
            return
        svc = (vuln.get("affected_services") or {}).get(svc_key)
        if svc:
            self._show_service_output(svc_key, svc)

    def _update_detail(self) -> None:
        vuln = self.vuln
        meta_text = _build_meta_bar(self.plugin_id, vuln) if vuln else f"  {self.plugin_id}  | (not found)"
        self.query_one("#detail-meta", Static).update(meta_text)
        self.query_one("#content-md", Markdown).update(_build_content_md(vuln) if vuln else "")
        self._populate_services()

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
