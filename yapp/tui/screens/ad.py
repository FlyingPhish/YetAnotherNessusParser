"""Operator-led BloodHound screens."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import DataTable, Footer, Header, Input, Static

from ..state import ADIndex, ADPathRow, ADRelationship

_KIND_STYLE = {
    "user": "bright_cyan",
    "group": "bright_yellow",
    "computer": "bright_blue",
    "domain": "bold bright_magenta",
    "certificateauthority": "bright_green",
}


def _name(entity: dict) -> str:
    return str(entity.get("name") or entity.get("id") or "?")


def _entity_text(entity: dict, *, owned: bool = False, target: bool = False) -> Text:
    style = _KIND_STYLE.get(str(entity.get("type") or "").casefold(), "white")
    if owned:
        style = "bold black on bright_cyan"
    elif target:
        style = "bold white on dark_red"
    return Text(_name(entity), style=style, overflow="fold")


def _chain(path: ADPathRow) -> Text:
    output = Text()
    for index, node in enumerate(path.nodes):
        output.append("[")
        output.append_text(
            _entity_text(node, owned=index == 0 and path.owned, target=index == len(path.nodes) - 1)
        )
        output.append("]")
        if index < len(path.steps):
            step = path.steps[index]
            style = "bold green" if step.traversable else "bold red"
            output.append(f" --{step.relationship}--> ", style=style)
    return output


class ADMissionScreen(Screen):
    """Mission overview and prioritized attack-path queue."""

    BINDINGS = [
        Binding("enter", "open_path", "Inspect Path", priority=True),
        Binding("o", "app.assume_owned", "Assume Owned"),
        Binding("m", "app.mark_path", "Triage"),
        Binding("b", "app.bookmark_path", "Bookmark"),
        Binding("e", "app.export_ad", "Export"),
        Binding("r", "app.refresh_ad", "Recompute"),
        Binding("q", "app.quit", "Quit"),
    ]

    CSS = """
    #mission { height: auto; padding: 1 2; border-bottom: solid $primary; }
    #warnings { height: auto; max-height: 7; padding: 0 2; color: $warning; }
    #paths { height: 1fr; }
    #queue-help { height: auto; padding: 0 2; color: $text-muted; }
    """

    def __init__(self, index: ADIndex) -> None:
        super().__init__()
        self.index = index
        self.current_rows: list[ADPathRow] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="mission")
        yield Static(id="warnings")
        yield DataTable(id="paths")
        yield Static("Green edges are allow-listed; evidence-only edges are red and rank below traversable paths.", id="queue-help")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#paths", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_column("Score", width=7)
        table.add_column("Owned", width=7)
        table.add_column("Objective", width=16)
        table.add_column("Steps", width=6)
        table.add_column("Source")
        table.add_column("Target")
        table.add_column("Choke", width=7)
        table.add_column("Triage", width=13)
        self.refresh_index(self.index)

    def refresh_index(self, index: ADIndex) -> None:
        self.index = index
        self.current_rows = index.paths[:1000]
        summary = index.report.get("summary") or {}
        privilege = index.report.get("privilege_analysis") or {}
        owned = index.report.get("owned_analysis") or {}
        mission = Text()
        mission.append(f" {index.metadata.get('source_name', '?')}  ", style="bold")
        mission.append(f"Critical {summary.get('critical', 0)}  ", style="bold bright_magenta")
        mission.append(f"High {summary.get('high', 0)}  ", style="bold red")
        mission.append(f"Owned {len(owned.get('principals') or [])}  ", style="bold bright_cyan")
        mission.append(f"Privileged identities {len(privilege.get('memberships') or [])}  ")
        mission.append(f"Attack paths {len(index.paths)}  ", style="bold")
        mission.append(f"Choke points {len((index.report.get('path_analysis') or {}).get('choke_points') or [])}")
        self.query_one("#mission", Static).update(mission)

        coverage = (index.report.get("operator_analysis") or {}).get("coverage") or []
        warnings = [
            f"{item.get('feature')}: {item.get('status')} ({item.get('observed', 0)}/{item.get('applicable', '?')})"
            for item in coverage
            if item.get("status") not in {"complete", "collected"}
        ]
        self.query_one("#warnings", Static).update(
            "Collection gaps — " + " | ".join(warnings) if warnings else "Collection coverage has no reported gaps."
        )

        table = self.query_one("#paths", DataTable)
        table.clear()
        for row in self.current_rows:
            table.add_row(
                str(row.score),
                "yes" if row.owned else "",
                row.target_class.replace("_", " "),
                str(row.length),
                _entity_text(row.source, owned=row.owned),
                _entity_text(row.target, target=True),
                str(row.choke_count or ""),
                row.triage_state,
                key=row.path_id,
            )

    @property
    def selected_path_id(self) -> str | None:
        table = self.query_one("#paths", DataTable)
        row = table.cursor_row
        if row is None or not 0 <= row < len(self.current_rows):
            return None
        return self.current_rows[row].path_id

    def action_open_path(self) -> None:
        if self.selected_path_id:
            self.app.action_open_ad_path(self.selected_path_id)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.app.action_open_ad_path(str(getattr(event.row_key, "value", event.row_key)))


class ADPathScreen(Screen):
    """Focused chain plus exact step evidence."""

    BINDINGS = [
        Binding("n", "pivot_node", "Pivot Target"),
        Binding("m", "app.mark_path", "Triage"),
        Binding("b", "app.bookmark_path", "Bookmark"),
        Binding("escape", "app.pop_screen", "Back"),
    ]

    CSS = """
    #chain { height: auto; max-height: 8; padding: 1 2; border-bottom: solid $primary; }
    #steps { height: 1fr; min-height: 8; }
    #step-detail { height: 13; padding: 1 2; border-top: solid $panel; overflow-y: auto; }
    """

    def __init__(self, path: ADPathRow) -> None:
        super().__init__()
        self.path = path

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="chain")
        yield DataTable(id="steps")
        with VerticalScroll(id="step-detail"):
            yield Static()
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#chain", Static).update(_chain(self.path))
        table = self.query_one("#steps", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_column("#", width=4)
        table.add_column("From")
        table.add_column("Relationship", width=24)
        table.add_column("To")
        table.add_column("Mode", width=11)
        table.add_column("Policy", width=14)
        for index, step in enumerate(self.path.steps):
            table.add_row(
                str(index + 1),
                _entity_text(step.source, owned=index == 0 and self.path.owned),
                step.relationship,
                _entity_text(step.target, target=index == len(self.path.steps) - 1),
                "direct" if step.direct else "inherited",
                "traversable" if step.traversable else "evidence only",
                key=str(index),
            )
        if self.path.steps:
            self._show_step(0)

    def _selected_step(self) -> int:
        row = self.query_one("#steps", DataTable).cursor_row
        return row if row is not None and 0 <= row < len(self.path.steps) else 0

    def _show_step(self, index: int) -> None:
        step = self.path.steps[index]
        via = " -> ".join(_name(item) for item in step.via) or "none"
        detail = Text()
        detail.append("Source: ", style="bold")
        detail.append(f"{_name(step.source)} [{step.source.get('type', '?')}]\n")
        detail.append(f"ID: {step.source.get('id', '')}\n")
        detail.append("Target: ", style="bold")
        detail.append(f"{_name(step.target)} [{step.target.get('type', '?')}]\n")
        detail.append(f"ID: {step.target.get('id', '')}\n")
        detail.append(f"Relationship: {step.relationship} | Primitive: {step.category} | ")
        detail.append("allow-listed" if step.traversable else "evidence only", style="green" if step.traversable else "red")
        detail.append(f"\nInheritance/via: {via}\n")
        detail.append(f"Why it matters: {step.why}\n")
        detail.append(f"Pivot: {step.opportunity}\n")
        detail.append(f"Caveat: {step.caveat}")
        self.query_one("#step-detail Static", Static).update(detail)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        value = str(getattr(event.row_key, "value", event.row_key))
        if value.isdigit() and int(value) < len(self.path.steps):
            self._show_step(int(value))

    def action_pivot_node(self) -> None:
        if self.path.steps:
            self.app.action_open_ad_node(str(self.path.steps[self._selected_step()].target.get("id") or ""))


class ADNodeScreen(Screen):
    """Bounded inbound/outbound relationship pivot for one AD node."""

    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def __init__(self, node_id: str) -> None:
        super().__init__()
        self.node_id = node_id

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="node-heading")
        yield DataTable(id="node-edges")
        yield Static(id="node-paths")
        yield Footer()

    def on_mount(self) -> None:
        pivot = self.app.ad_index.pivots.get(self.node_id)
        if not pivot:
            self.query_one("#node-heading", Static).update("Node not found")
            return
        heading = Text()
        heading.append(f"{_name(pivot.entity)} [{pivot.entity.get('type', '?')}]\n", style="bold")
        heading.append(f"Exact ID: {pivot.entity.get('id', '')}")
        self.query_one("#node-heading", Static).update(heading)
        table = self.query_one("#node-edges", DataTable)
        table.cursor_type = "row"
        table.add_column("Direction", width=10)
        table.add_column("Relationship", width=24)
        table.add_column("Principal / Target")
        table.add_column("Category", width=20)
        table.add_column("Policy", width=14)
        relationships = [
            *(("outbound", item) for item in pivot.outbound),
            *(("inbound", item) for item in pivot.inbound),
        ]
        for direction, item in relationships[:500]:
            other = item.target if direction == "outbound" else item.source
            table.add_row(
                direction,
                item.relationship,
                _entity_text(other),
                item.category,
                "traversable" if item.traversable else "evidence only",
            )
        omitted = max(0, len(relationships) - 500)
        self.query_one("#node-paths", Static).update(
            f"Paths through node: {len(pivot.paths)} | Relationships shown: {min(500, len(relationships))}"
            + (f" | {omitted} omitted (bounded view)" if omitted else "")
        )


class AssumeOwnedScreen(ModalScreen[str | None]):
    """Small modal for replacing the assumed-owned user set."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    CSS = """
    AssumeOwnedScreen { align: center middle; }
    #owned-box { width: 80; height: auto; border: round $accent; background: $surface; padding: 1 2; }
    """

    def __init__(self, current: list[str]) -> None:
        super().__init__()
        self.current = current

    def compose(self) -> ComposeResult:
        from textual.containers import Vertical
        with Vertical(id="owned-box"):
            yield Static("Assumed-owned users (comma separated; replaces current set):")
            yield Input(value=", ".join(self.current), id="owned-input")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def action_cancel(self) -> None:
        self.dismiss(None)
