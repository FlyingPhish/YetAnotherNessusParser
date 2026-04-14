"""Intel overlay modal — full metadata for a finding."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Markdown, Static


def _fmt_list(items: tuple[str, ...], none_text: str = "(none)") -> str:
    if not items:
        return none_text
    return "\n".join(f"- {item}" for item in items)


def _build_intel_md(plugin_id: str, detail) -> str:
    row = detail.row

    def field(label: str, value: str) -> str:
        return f"**{label}:** {value}"

    def list_field(label: str, items: tuple[str, ...]) -> str:
        if not items:
            return f"**{label}:** (none)"
        if len(items) == 1:
            return f"**{label}:** {items[0]}"
        return f"**{label}:**\n" + "\n".join(f"- {item}" for item in items)

    parts = [
        f"# {row.name}",
        "",
        f"Plugin `{row.plugin_id}`  |  Family: {row.family}  |  Risk Factor: {row.risk_factor}",
        "",
        "---",
        "",
        "## Threat Intelligence",
        "",
        list_field("CVE", row.cve),
        "",
        list_field("CWE", row.cwe),
        "",
        list_field("MITRE ATT&CK", row.mitre),
        "",
        "## Exploit Availability",
        "",
        list_field("Metasploit Modules", row.metasploit_modules),
        "",
        list_field("Public Exploit Refs", row.public_exploit_refs),
        "",
        "## Scoring",
        "",
        field("CVSS Base", str(row.cvss_base) if row.cvss_base else "(none)"),
        "",
        field("CVSS3 Base", str(row.cvss3_base) if row.cvss3_base else "(none)"),
        "",
        field("Risk Score", str(row.risk_score)),
        field("Severity", f"{row.severity_label} ({row.severity})"),
        "",
    ]

    if detail.xref:
        parts += ["## Cross References", ""]
        parts += [f"- {r}" for r in detail.xref]
        parts.append("")

    if row.references:
        parts += ["## References", ""]
        parts += [f"- {r}" for r in row.references]
        parts.append("")

    return "\n".join(parts)


class IntelScreen(ModalScreen[None]):
    """Overlay showing full threat intelligence metadata for a finding."""

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("i", "close", "Close"),
        Binding("q", "close", "Close"),
    ]

    CSS = """
    IntelScreen {
        align: center middle;
    }

    #intel-modal {
        width: 80%;
        height: 85%;
        border: round $accent;
        background: $surface;
    }

    #intel-title {
        height: auto;
        padding: 0 2;
        background: $primary-background;
        text-style: bold;
        text-align: center;
    }

    #intel-scroll {
        height: 1fr;
        padding: 0 2;
    }
    """

    def __init__(self, plugin_id: str, detail) -> None:
        super().__init__()
        self.plugin_id = plugin_id
        self.detail = detail

    def compose(self) -> ComposeResult:
        from textual.containers import Vertical
        with Vertical(id="intel-modal"):
            yield Static(
                f"  Intel  |  Plugin {self.plugin_id}  |  {self.detail.row.name}",
                id="intel-title",
            )
            with VerticalScroll(id="intel-scroll"):
                yield Markdown(_build_intel_md(self.plugin_id, self.detail))

    def action_close(self) -> None:
        self.dismiss(None)
