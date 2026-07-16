"""Operator-led BloodHound screens."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Static,
    TabbedContent,
    TabPane,
    Tree,
)

from ..ad_explore import (
    find_path,
    compress_fanout,
    focused_relationships,
    relationship_types,
    search_nodes,
)
from ..ad_graphviz import GraphRenderResult, graphviz_available, render_focused_graph
from ..state import ADExposureRow, ADIndex, ADPathRow, ADRelationship

_KIND_STYLE = {
    "user": "bright_cyan",
    "group": "bright_yellow",
    "computer": "bright_blue",
    "domain": "bold bright_magenta",
    "certificateauthority": "bright_green",
}

_EXPOSURE_LABELS = {
    "broad_admin_membership": "Broad admin membership",
    "computer_admin_membership": "Computer admin member",
    "privileged_control": "Privileged object control",
    "local_admin_access": "Local admin access",
    "asrep_roastable": "AS-REP roastable account",
    "kerberoastable": "Kerberoastable service account",
    "unconstrained_delegation": "Unconstrained delegation",
    "non_expiring_password": "Non-expiring password",
    "security_posture": "Security posture",
}

_PRIORITY_STYLES = {
    "ACT NOW": "bold black on bright_cyan",
    "CRITICAL": "bold bright_magenta",
    "HIGH": "bold bright_red",
    "MEDIUM": "bold yellow",
    "REVIEW": "white",
}


def _priority_text(priority: str) -> Text:
    return Text(priority, style=_PRIORITY_STYLES.get(priority, "white"))


def _path_priority(path: ADPathRow) -> str:
    if path.owned:
        return "ACT NOW"
    if path.score >= 80:
        return "HIGH"
    return "REVIEW"


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
    """Decision-first mission view plus an object-led exploration workspace."""

    BINDINGS = [
        Binding("enter", "open_selected", "Open / Inspect", priority=True),
        Binding("/", "focus_search", "Search"),
        Binding("1", "show_mission", "Mission", show=False),
        Binding("2", "show_explore", "Explore", show=False),
        Binding("3", "view_exposures", "Exposures", show=False),
        Binding("4", "show_saved", "Saved", show=False),
        Binding("v", "view_exposures", "Exposures"),
        Binding("x", "show_explore", "Explore"),
        Binding("s", "set_source", "Set Source"),
        Binding("t", "set_target", "Set Target"),
        Binding("p", "find_explore_path", "Find Path"),
        Binding("f", "filter_edges", "Edge Filter"),
        Binding("g", "toggle_graph_renderer", "Graph / Outline"),
        Binding("l", "cycle_graph_layout", "Layout"),
        Binding("z", "toggle_graph_labels", "Labels"),
        Binding("h", "toggle_evidence", "Evidence"),
        Binding("[", "zoom_out", "Zoom Out"),
        Binding("]", "zoom_in", "Zoom In"),
        Binding("o", "app.assume_owned", "Assume Owned"),
        Binding("m", "app.mark_path", "Triage"),
        Binding("b", "app.bookmark_path", "Bookmark"),
        Binding("e", "app.export_ad", "Export"),
        Binding("r", "reverse_or_refresh", "Reverse / Refresh"),
        Binding("q", "app.quit", "Quit"),
        Binding("ctrl+left", "shrink_search_pane", "Search −"),
        Binding("ctrl+right", "grow_search_pane", "Search +"),
        Binding("alt+left", "shrink_inspector_pane", "Inspector −"),
        Binding("alt+right", "grow_inspector_pane", "Inspector +"),
    ]

    CSS = """
    #workspace-tabs { height: 1fr; }
    #mission { height: auto; padding: 1 2; border-bottom: solid $primary; }
    #warnings { height: auto; max-height: 7; padding: 0 2; color: $warning; }
    #paths { height: 1fr; }
    #queue-help { height: auto; padding: 0 2; color: $text-muted; }
    #explore-search { height: 3; margin: 0 1; }
    #endpoint-status { height: auto; padding: 0 2; color: $accent; }
    #explore-body { height: 1fr; }
    #search-results { width: 25%; min-width: 22; border-right: solid $panel; }
    #explore-center { width: 52%; min-width: 36; }
    #graph-status { height: auto; padding: 0 1; color: $text-muted; }
    #graph-view { height: 1fr; padding: 1; overflow: auto; }
    #graph-view.graphviz-active { padding: 0; }
    #path-tree { height: 7; border-top: solid $panel; }
    #entity-pane { width: 23%; min-width: 20; border-left: solid $panel; padding: 1; }
    #explore-help, #workspace-exposure-help, #saved-help, #node-direction-help {
        height: auto; padding: 0 2; color: $text-muted;
    }
    #workspace-exposure-summary, #saved-summary {
        height: auto; padding: 1 2; border-bottom: solid $primary;
    }
    #workspace-exposures, #saved-paths { height: 1fr; }
    """

    def __init__(self, index: ADIndex) -> None:
        super().__init__()
        self.index = index
        self.current_rows: list[ADPathRow] = []
        self.saved_rows: list[ADPathRow] = []
        self.search_rows: list[dict] = []
        self.focused_node_id: str | None = None
        self.source_id: str | None = None
        self.target_id: str | None = None
        self.explore_path: ADPathRow | None = None
        self.excluded_relationships: set[str] = set()
        self.graph_generation = 0
        self.use_graphviz = True
        self.graph_layout = "pivot"
        self.compact_graph_labels = False
        self.hide_evidence = False
        self.graph_zoom = 1.0
        self.search_pane_width = 25
        self.inspector_pane_width = 23

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with TabbedContent(initial="mission-tab", id="workspace-tabs"):
            with TabPane("Mission", id="mission-tab"):
                yield Static(id="mission")
                yield Static(id="warnings")
                yield DataTable(id="paths")
                yield Static(id="queue-help")
            with TabPane("Explore", id="explore-tab"):
                yield Input(
                    placeholder="Search name or SID; try user:alice, group:admin, computer:dc",
                    id="explore-search",
                )
                yield Static(id="endpoint-status")
                with Horizontal(id="explore-body"):
                    yield DataTable(id="search-results")
                    with Vertical(id="explore-center"):
                        yield Static(id="graph-status")
                        yield Static("Search for an object to begin.", id="graph-view")
                        yield Tree("Selected path", id="path-tree")
                    with VerticalScroll(id="entity-pane"):
                        yield Static("Select an object to inspect it.", id="entity-inspector")
                yield Static(
                    "s/t/p path | g renderer | l layout | z labels | h evidence | brackets: zoom",
                    id="explore-help",
                )
            with TabPane("Exposures", id="exposures-tab"):
                yield Static(id="workspace-exposure-summary")
                yield DataTable(id="workspace-exposures")
                yield Static(
                    "Start with ACT NOW, then CRITICAL. Enter opens exact targets and actors.",
                    id="workspace-exposure-help",
                )
            with TabPane("Saved", id="saved-tab"):
                yield Static(id="saved-summary")
                yield DataTable(id="saved-paths")
                yield Static("Bookmarks retain paths worth reporting or revisiting.", id="saved-help")
        yield Footer()

    def on_mount(self) -> None:
        self._setup_path_table(self.query_one("#paths", DataTable))
        self._setup_path_table(self.query_one("#saved-paths", DataTable))
        search = self.query_one("#search-results", DataTable)
        search.cursor_type = "row"
        search.zebra_stripes = True
        search.add_column("Type", width=12)
        search.add_column("Object")
        search.add_column("ID", width=18)
        exposures = self.query_one("#workspace-exposures", DataTable)
        exposures.cursor_type = "row"
        exposures.zebra_stripes = True
        exposures.add_column("Priority", width=11)
        exposures.add_column("Exposure", width=24)
        exposures.add_column("Controlled by")
        exposures.add_column("Relationship", width=20)
        exposures.add_column("Targets", width=8)
        exposures.add_column("Actors", width=8)
        self.refresh_index(self.index)

    @staticmethod
    def _setup_path_table(table: DataTable) -> None:
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_column("Priority", width=11)
        table.add_column("Objective", width=16)
        table.add_column("Steps", width=6)
        table.add_column("Source")
        table.add_column("Target")
        table.add_column("Choke", width=7)
        table.add_column("Triage", width=13)

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
        privileged_principals = {
            str((item.get("principal") or {}).get("id") or "")
            for item in privilege.get("memberships") or []
            if (item.get("principal") or {}).get("id")
        }
        mission.append(f"Privileged principals {len(privileged_principals)}  ")
        mission.append(f"Attack paths {len(index.paths)}  ", style="bold")
        mission.append(f"Exposures {len(index.exposures)}  ", style="bold yellow")
        mission.append(f"Choke points {len((index.report.get('path_analysis') or {}).get('choke_points') or [])}")
        self.query_one("#mission", Static).update(mission)

        coverage = (index.report.get("operator_analysis") or {}).get("coverage") or []
        coverage_warnings = [
            f"{item.get('feature')}: {item.get('status')} ({item.get('observed', 0)}/{item.get('applicable', '?')})"
            for item in coverage
            if item.get("status") not in {"complete", "collected"}
        ]
        warnings = []
        if coverage_warnings:
            warnings.append("Collection gaps — " + " | ".join(coverage_warnings))
        if not graphviz_available():
            warnings.append("Graphviz: dot not found (Explore will use outline fallback)")
        self.query_one("#warnings", Static).update(
            " | ".join(warnings) if warnings else "Collection coverage has no reported gaps; Graphviz is ready."
        )

        table = self.query_one("#paths", DataTable)
        table.clear()
        for row in self.current_rows:
            self._add_path_row(table, row)
        help_text = (
            "Start here: Enter inspects a route • v opens privilege exposures • "
            "o updates assumed-owned users | Green = traversable; red = evidence only"
            if self.current_rows
            else "No bounded high-value routes found. Press v to review privilege "
            "exposures, or check the collection gaps above."
        )
        self.query_one("#queue-help", Static).update(help_text)
        self._refresh_exposures()
        self._refresh_saved()
        self._update_endpoint_status()

    @staticmethod
    def _add_path_row(table: DataTable, row: ADPathRow) -> None:
        table.add_row(
            _priority_text(_path_priority(row)),
            row.target_class.replace("_", " "),
            str(row.length),
            _entity_text(row.source, owned=row.owned),
            _entity_text(row.target, target=True),
            str(row.choke_count or ""),
            row.triage_state,
            key=row.path_id,
        )

    def _refresh_exposures(self) -> None:
        rows = self.index.exposures[:1000]
        counts = {
            "memberships": sum(
                row.category in {"broad_admin_membership", "computer_admin_membership"}
                for row in rows
            ),
            "controls": sum(row.category == "privileged_control" for row in rows),
            "local": sum(row.category == "local_admin_access" for row in rows),
            "posture": sum(
                row.category in {
                    "asrep_roastable", "kerberoastable", "unconstrained_delegation",
                    "non_expiring_password", "security_posture",
                }
                for row in rows
            ),
        }
        self.query_one("#workspace-exposure-summary", Static).update(
            " Privilege Exposures  |  Administrative memberships "
            f"{counts['memberships']}  |  Privileged controls {counts['controls']}  |  "
            f"Local-admin grants {counts['local']}  |  Account posture {counts['posture']}"
        )
        table = self.query_one("#workspace-exposures", DataTable)
        table.clear()
        for row in rows:
            table.add_row(
                _priority_text(row.priority),
                _EXPOSURE_LABELS.get(row.category, row.category.replace("_", " ")),
                _entity_text(row.principal, owned=row.owned),
                row.relationship,
                str(row.target_count),
                str(row.effective_count),
                key=row.exposure_id,
            )

    def _refresh_saved(self) -> None:
        self.saved_rows = [
            row for row in self.index.paths if row.path_id in self.index.bookmarks
        ]
        self.query_one("#saved-summary", Static).update(
            f" Saved Investigation Paths  |  {len(self.saved_rows)} bookmarks"
        )
        table = self.query_one("#saved-paths", DataTable)
        table.clear()
        for row in self.saved_rows:
            self._add_path_row(table, row)

    @property
    def selected_path_id(self) -> str | None:
        if self._active_tab == "saved-tab":
            table = self.query_one("#saved-paths", DataTable)
            rows = self.saved_rows
        else:
            table = self.query_one("#paths", DataTable)
            rows = self.current_rows
        row = table.cursor_row
        if row is None or not 0 <= row < len(rows):
            return None
        return rows[row].path_id

    @property
    def _active_tab(self) -> str:
        return self.query_one("#workspace-tabs", TabbedContent).active

    def action_open_selected(self) -> None:
        if self._active_tab in {"mission-tab", "saved-tab"}:
            if self.selected_path_id:
                self.app.action_open_ad_path(self.selected_path_id)
        elif self._active_tab == "exposures-tab":
            exposure_id = self._selected_exposure_id()
            if exposure_id:
                self.app.action_open_ad_exposure(exposure_id)
        elif self._active_tab == "explore-tab" and self.focused_node_id:
            self._focus_node(self.focused_node_id)

    def action_view_exposures(self) -> None:
        self.query_one("#workspace-tabs", TabbedContent).active = "exposures-tab"

    def action_show_mission(self) -> None:
        self.query_one("#workspace-tabs", TabbedContent).active = "mission-tab"

    def action_show_explore(self) -> None:
        self.query_one("#workspace-tabs", TabbedContent).active = "explore-tab"
        self.query_one("#explore-search", Input).focus()

    def action_show_saved(self) -> None:
        self._refresh_saved()
        self.query_one("#workspace-tabs", TabbedContent).active = "saved-tab"

    def action_focus_search(self) -> None:
        self.action_show_explore()

    def open_explore_node(self, node_id: str, endpoint: str = "") -> None:
        """Bring a pivoted entity into the persistent Explore workspace."""
        if node_id not in self.index.nodes:
            return
        self.query_one("#workspace-tabs", TabbedContent).active = "explore-tab"
        self._focus_node(node_id)
        if endpoint == "source":
            self.source_id = node_id
        elif endpoint == "target":
            self.target_id = node_id
        self._update_endpoint_status()

    def action_reverse_or_refresh(self) -> None:
        if self._active_tab == "explore-tab":
            self.source_id, self.target_id = self.target_id, self.source_id
            self._update_endpoint_status()
            if self.source_id and self.target_id:
                self.action_find_explore_path()
        else:
            self.app.action_refresh_ad()

    def action_set_source(self) -> None:
        if self._active_tab != "explore-tab" or not self.focused_node_id:
            return
        self.source_id = self.focused_node_id
        self._update_endpoint_status()

    def action_set_target(self) -> None:
        if self._active_tab != "explore-tab" or not self.focused_node_id:
            return
        self.target_id = self.focused_node_id
        self._update_endpoint_status()

    def action_find_explore_path(self) -> None:
        if not self.source_id or not self.target_id:
            self.app.notify("Set both a source and target", severity="warning")
            return
        self.explore_path = find_path(
            self.index,
            self.source_id,
            self.target_id,
            excluded_relationships=self.excluded_relationships,
        )
        if not self.explore_path:
            self.query_one("#graph-status", Static).update(
                "No allow-listed path found within 8 steps using the active edge filter."
            )
            self._update_path_tree(None)
            return
        self._update_path_tree(self.explore_path)
        self._request_graph(
            self.explore_path.nodes,
            self.explore_path.steps,
            layout="path",
            selected_id=self.source_id or "",
        )

    def action_filter_edges(self) -> None:
        if self._active_tab != "explore-tab":
            return

        def apply(value: str | None) -> None:
            if value is None:
                return
            self.excluded_relationships = {
                item.strip() for item in value.split(",") if item.strip()
            }
            self._update_endpoint_status()
            if self.source_id and self.target_id:
                self.action_find_explore_path()

        self.app.push_screen(
            RelationshipFilterScreen(
                sorted(self.excluded_relationships),
                list(relationship_types(self.index)),
            ),
            apply,
        )

    def action_toggle_graph_renderer(self) -> None:
        self.use_graphviz = not self.use_graphviz
        renderer = "Graphviz" if self.use_graphviz else "terminal outline"
        self.app.notify(f"Focused graph renderer: {renderer}")
        if self.explore_path:
            self._request_graph(self.explore_path.nodes, self.explore_path.steps)
        elif self.focused_node_id:
            self._focus_node(self.focused_node_id)

    def _rerender_graph(self) -> None:
        if self.explore_path:
            self._request_graph(
                self.explore_path.nodes,
                self.explore_path.steps,
                layout="path",
                selected_id=self.source_id or "",
            )
        elif self.focused_node_id:
            self._focus_node(self.focused_node_id)

    def action_cycle_graph_layout(self) -> None:
        modes = ("pivot", "cluster", "path")
        self.graph_layout = modes[(modes.index(self.graph_layout) + 1) % len(modes)]
        self.app.notify(f"Focused graph layout: {self.graph_layout}")
        self._rerender_graph()

    def action_toggle_graph_labels(self) -> None:
        self.compact_graph_labels = not self.compact_graph_labels
        self.app.notify("Graph labels: compact" if self.compact_graph_labels else "Graph labels: normal")
        self._rerender_graph()

    def action_toggle_evidence(self) -> None:
        self.hide_evidence = not self.hide_evidence
        self.app.notify("Evidence-only edges hidden" if self.hide_evidence else "Evidence-only edges shown")
        self._rerender_graph()

    def action_zoom_in(self) -> None:
        self.graph_zoom = min(2.0, self.graph_zoom + 0.25)
        self._rerender_graph()

    def action_zoom_out(self) -> None:
        self.graph_zoom = max(0.75, self.graph_zoom - 0.25)
        self._rerender_graph()

    def _resize_panes(self, *, search_delta: int = 0, inspector_delta: int = 0) -> None:
        search = max(22, min(38, self.search_pane_width + search_delta))
        inspector = max(20, min(34, self.inspector_pane_width + inspector_delta))
        if 100 - search - inspector < 36:
            self.app.notify("Graph pane kept at its minimum width", severity="warning")
            return
        self.search_pane_width, self.inspector_pane_width = search, inspector
        self.query_one("#search-results", DataTable).styles.width = f"{search}%"
        self.query_one("#explore-center", Vertical).styles.width = f"{100 - search - inspector}%"
        self.query_one("#entity-pane", VerticalScroll).styles.width = f"{inspector}%"

    def action_shrink_search_pane(self) -> None:
        self._resize_panes(search_delta=-3)

    def action_grow_search_pane(self) -> None:
        self._resize_panes(search_delta=3)

    def action_shrink_inspector_pane(self) -> None:
        self._resize_panes(inspector_delta=-3)

    def action_grow_inspector_pane(self) -> None:
        self._resize_panes(inspector_delta=3)

    def _update_endpoint_status(self) -> None:
        source = self.index.nodes.get(self.source_id or "", {})
        target = self.index.nodes.get(self.target_id or "", {})
        excluded = ", ".join(sorted(self.excluded_relationships)) or "none"
        self.query_one("#endpoint-status", Static).update(
            f"Source: {_name(source) if source else 'not set'}  |  "
            f"Target: {_name(target) if target else 'not set'}  |  "
            f"Excluded edges: {excluded}"
        )

    def _selected_exposure_id(self) -> str | None:
        table = self.query_one("#workspace-exposures", DataTable)
        row = table.cursor_row
        exposures = self.index.exposures[:1000]
        if row is None or not 0 <= row < len(exposures):
            return None
        return exposures[row].exposure_id

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id != "explore-search":
            return
        self.search_rows = search_nodes(self.index, event.value)
        table = self.query_one("#search-results", DataTable)
        table.clear()
        for node in self.search_rows:
            table.add_row(
                str(node.get("type") or "?"),
                _entity_text(node),
                str(node.get("id") or "")[-18:],
                key=str(node.get("id") or ""),
            )
        if not self.search_rows:
            self.query_one("#graph-status", Static).update(
                "No matching objects." if event.value.strip() else "Search for an object to begin."
            )

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id != "search-results":
            return
        node_id = str(getattr(event.row_key, "value", event.row_key))
        if node_id in self.index.nodes:
            self._focus_node(node_id, render_graph=False)

    def _focus_node(
        self,
        node_id: str,
        *,
        render_graph: bool = True,
        preserve_path: bool = False,
    ) -> None:
        self.focused_node_id = node_id
        node = self.index.nodes[node_id]
        pivot = self.index.pivots.get(node_id)
        outbound = pivot.outbound if pivot else ()
        inbound = pivot.inbound if pivot else ()
        detail = Text()
        detail.append(f"{_name(node)}\n", style="bold")
        detail.append(f"Type: {node.get('type', '?')}\n")
        detail.append(f"ID: {node.get('id', '')}\n\n")
        properties = node.get("properties") or {}
        if properties:
            detail.append("Object information\n", style="bold")
            for key, value in properties.items():
                detail.append(f"  {key}: {value}\n")
            detail.append("\n")
        detail.append(f"Outbound control ({len(outbound)})\n", style="bold")
        for item in outbound[:12]:
            detail.append(f"  {item.relationship} → {_name(item.target)}\n")
        detail.append(f"\nInbound control ({len(inbound)})\n", style="bold")
        for item in inbound[:12]:
            detail.append(f"  {_name(item.source)} → {item.relationship}\n")
        if (len(outbound) + len(inbound)) > 24:
            detail.append("\nAdditional relationships omitted from this bounded inspector.")
        self.query_one("#entity-inspector", Static).update(detail)
        if not render_graph:
            return
        relationships = focused_relationships(
            self.index,
            node_id,
            excluded_relationships=self.excluded_relationships,
        )
        if self.hide_evidence:
            relationships = tuple(item for item in relationships if item.traversable)
        graph_nodes, relationships = compress_fanout(node_id, relationships)
        if not preserve_path:
            self._update_path_tree(None)
        graph_view = self.query_one("#graph-view", Static)
        self._request_graph(
            graph_nodes,
            relationships,
            width=max(24, int((graph_view.size.width - 2) * self.graph_zoom)),
            height=max(8, int((graph_view.size.height - 2) * self.graph_zoom)),
            selected_id=node_id,
            layout=self.graph_layout,
        )

    def _request_graph(self, nodes, relationships, *, width: int | None = None, height: int | None = None, selected_id: str = "", layout: str | None = None) -> None:
        self.query_one("#graph-status", Static).update("Laying out focused graph…")
        self.graph_generation += 1
        generation = self.graph_generation
        safe_nodes = tuple(dict(node) for node in nodes)
        safe_relationships = tuple(relationships)
        graph_view = self.query_one("#graph-view", Static)
        width = width or max(24, int((graph_view.size.width - 2) * self.graph_zoom))
        height = height or max(8, int((graph_view.size.height - 2) * self.graph_zoom))
        layout = layout or self.graph_layout

        def render() -> None:
            result = render_focused_graph(
                safe_nodes,
                safe_relationships,
                width=width,
                height=height,
                force_fallback=not self.use_graphviz,
                layout=layout,
                selected_id=selected_id,
                compact_labels=self.compact_graph_labels,
            )
            self.app.call_from_thread(self._apply_graph, generation, result)

        self.run_worker(render, thread=True, exclusive=True, group="ad-graph")

    def _apply_graph(self, generation: int, result: GraphRenderResult) -> None:
        if generation != self.graph_generation:
            return
        graph_view = self.query_one("#graph-view", Static)
        graph_view.set_class(result.backend == "graphviz", "graphviz-active")
        graph_view.update(result.text)
        status = "Graphviz focused graph" if result.backend == "graphviz" else "Outline fallback"
        if result.warning:
            status += f" | {result.warning}"
        self.query_one("#graph-status", Static).update(status)

    def _update_path_tree(self, path: ADPathRow | None) -> None:
        tree = self.query_one("#path-tree", Tree)
        tree.clear()
        tree.root.set_label("Selected path")
        if not path:
            tree.root.add_leaf("Set endpoints and press p")
            tree.root.expand()
            return
        branch = tree.root
        for index, node in enumerate(path.nodes):
            label = _name(node)
            if index:
                label = f"{path.steps[index - 1].relationship} → {label}"
            branch = branch.add(label, data=str(node.get("id") or ""), expand=True)
        tree.root.expand()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        value = str(getattr(event.row_key, "value", event.row_key))
        if event.data_table.id in {"paths", "saved-paths"}:
            self.app.action_open_ad_path(value)
        elif event.data_table.id == "workspace-exposures":
            self.app.action_open_ad_exposure(value)
        elif event.data_table.id == "search-results" and value in self.index.nodes:
            self._focus_node(value)

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        node_id = str(event.node.data or "")
        if node_id in self.index.nodes:
            self._focus_node(node_id, preserve_path=True)


class ADExposureQueueScreen(Screen):
    """Aggregated administrative membership, control, and local-admin exposures."""

    BINDINGS = [
        Binding("enter", "open_exposure", "Inspect", priority=True),
        Binding("escape", "app.pop_screen", "Back"),
    ]

    CSS = """
    #exposure-summary { height: auto; padding: 1 2; border-bottom: solid $primary; }
    #exposures { height: 1fr; }
    #exposure-help { height: auto; padding: 0 2; color: $text-muted; }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="exposure-summary")
        yield DataTable(id="exposures")
        yield Static(
            "Start with ACT NOW, then CRITICAL. Targets are controlled objects; "
            "effective actors inherit the grant. Enter opens the evidence.",
            id="exposure-help",
        )
        yield Footer()

    def on_mount(self) -> None:
        rows = self.app.ad_index.exposures[:1000]
        broad = sum(
            1 for row in rows
            if row.category in {"broad_admin_membership", "computer_admin_membership"}
        )
        controls = sum(1 for row in rows if row.category == "privileged_control")
        local_admin = sum(1 for row in rows if row.category == "local_admin_access")
        posture = sum(
            row.category in {
                "asrep_roastable", "kerberoastable", "unconstrained_delegation",
                "non_expiring_password",
            }
            for row in rows
        )
        self.query_one("#exposure-summary", Static).update(
            f" Privilege Exposure  |  Administrative memberships {broad}  |  "
            f"Privileged controls {controls}  |  Local-admin grants {local_admin}  |  "
            f"Account posture {posture}"
        )

        table = self.query_one("#exposures", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_column("Priority", width=11)
        table.add_column("Exposure", width=24)
        table.add_column("Controlled by")
        table.add_column("Relationship", width=20)
        table.add_column("Targets", width=8)
        table.add_column("Effective actors", width=17)
        table.add_column("Owned", width=7)
        for row in rows:
            table.add_row(
                _priority_text(row.priority),
                _EXPOSURE_LABELS.get(row.category, row.category.replace("_", " ")),
                _entity_text(row.principal, owned=row.owned),
                row.relationship,
                str(row.target_count),
                str(row.effective_count),
                "yes" if row.owned else "",
                key=row.exposure_id,
            )
        if not rows:
            self.query_one("#exposure-help", Static).update(
                "No privilege exposures were identified in the collected data. "
                "Review collection gaps before treating this as a clean result."
            )

    @property
    def selected_exposure_id(self) -> str | None:
        table = self.query_one("#exposures", DataTable)
        row_index = table.cursor_row
        rows = self.app.ad_index.exposures[:1000]
        if row_index is None or not 0 <= row_index < len(rows):
            return None
        return rows[row_index].exposure_id

    def action_open_exposure(self) -> None:
        if self.selected_exposure_id:
            self.app.action_open_ad_exposure(self.selected_exposure_id)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.app.action_open_ad_exposure(
            str(getattr(event.row_key, "value", event.row_key))
        )


class ADExposureDetailScreen(Screen):
    """Exact targets, privilege context, and effective actors for one exposure."""

    BINDINGS = [
        Binding("n", "pivot_target", "Pivot Target"),
        Binding("s", "pivot_source", "Pivot Source"),
        Binding("x", "explore_target", "Explore Target"),
        Binding("v", "open_exposures", "Exposures"),
        Binding("o", "app.assume_owned", "Assume Owned"),
        Binding("e", "app.export_ad", "Export"),
        Binding("escape", "app.pop_screen", "Back"),
    ]

    CSS = """
    #exposure-heading { height: auto; max-height: 9; padding: 1 2; border-bottom: solid $primary; }
    #exposure-targets { height: 1fr; min-height: 8; }
    #exposure-detail { height: 15; padding: 1 2; border-top: solid $panel; overflow-y: auto; }
    """

    def __init__(self, exposure: ADExposureRow) -> None:
        super().__init__()
        self.exposure = exposure

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="exposure-heading")
        yield DataTable(id="exposure-targets")
        with VerticalScroll(id="exposure-detail"):
            yield Static()
        yield Footer()

    def on_mount(self) -> None:
        row = self.exposure
        heading = Text()
        heading.append_text(_priority_text(row.priority))
        heading.append("  ")
        heading.append(
            _EXPOSURE_LABELS.get(row.category, row.category.replace("_", " ")) + "\n",
            style="bold",
        )
        heading.append_text(_entity_text(row.principal, owned=row.owned))
        heading.append(f" --{row.relationship}--> {row.target_count:,} targets")
        heading.append(f" | {row.effective_count:,} effective actors\n")
        heading.append(f"{row.summary}\n")
        heading.append(f"Why it matters: {row.why}\n")
        heading.append(f"Caveat: {row.caveat}")
        self.query_one("#exposure-heading", Static).update(heading)

        table = self.query_one("#exposure-targets", DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True
        table.add_column("#", width=5)
        table.add_column("Target")
        table.add_column("Type", width=12)
        table.add_column("Privilege / Scope")
        for index, target in enumerate(row.targets[:1000]):
            entity = target.get("entity") or {}
            contexts = []
            for membership in target.get("privileged_memberships") or []:
                group = membership.get("group") or {}
                mode = membership.get("membership") or "effective"
                contexts.append(f"{group.get('name', '?')} ({mode})")
            if target.get("target_class") not in {None, "computer"}:
                contexts.append(str(target["target_class"]).replace("_", " "))
            if target.get("membership"):
                contexts.append(str(target["membership"]))
            table.add_row(
                str(index + 1),
                _entity_text(entity, target=True),
                str(entity.get("type") or "?"),
                ", ".join(contexts) or "direct target",
                key=str(index),
            )
        if row.targets:
            self._show_target(0)

    def _selected_target(self) -> int:
        selected = self.query_one("#exposure-targets", DataTable).cursor_row
        return selected if selected is not None and 0 <= selected < len(self.exposure.targets) else 0

    def _show_target(self, index: int) -> None:
        target = self.exposure.targets[index]
        entity = target.get("entity") or {}
        detail = Text()
        detail.append(f"Target: {_name(entity)} [{entity.get('type', '?')}]\n", style="bold")
        detail.append(f"Exact ID: {entity.get('id', '')}\n")
        memberships = target.get("privileged_memberships") or []
        if memberships:
            detail.append("Privileged through:\n", style="bold")
            for membership in memberships[:20]:
                group = membership.get("group") or {}
                via = " -> ".join(
                    _name(item) for item in membership.get("via") or []
                ) or "direct"
                detail.append(
                    f"  {_name(group)} [{membership.get('membership', 'effective')}] via {via}\n"
                )
        via = target.get("via") or []
        if via:
            detail.append("Target via: " + " -> ".join(_name(item) for item in via) + "\n")

        actors = self.exposure.effective_principals
        if actors:
            detail.append(f"Effective actors ({self.exposure.effective_count:,}):\n", style="bold")
            for actor in actors[:50]:
                actor_entity = actor.get("entity") or actor
                actor_via = " -> ".join(_name(item) for item in actor.get("via") or [])
                detail.append(f"  {_name(actor_entity)}")
                if actor_via:
                    detail.append(f" via {actor_via}")
                detail.append(f" | ID {actor_entity.get('id', '')}\n")
            if self.exposure.effective_count > 50:
                detail.append(
                    f"  … {self.exposure.effective_count - 50:,} more actors omitted from this bounded pane"
                )
        self.query_one("#exposure-detail Static", Static).update(detail)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        value = str(getattr(event.row_key, "value", event.row_key))
        if value.isdigit() and int(value) < len(self.exposure.targets):
            self._show_target(int(value))

    def action_pivot_target(self) -> None:
        if self.exposure.targets:
            entity = self.exposure.targets[self._selected_target()].get("entity") or {}
            self.app.action_open_ad_node(str(entity.get("id") or ""))

    def action_pivot_source(self) -> None:
        self.app.action_open_ad_node(str(self.exposure.principal.get("id") or ""))

    def action_explore_target(self) -> None:
        if self.exposure.targets:
            entity = self.exposure.targets[self._selected_target()].get("entity") or {}
            self.app.action_explore_ad_node(str(entity.get("id") or ""))

    def action_open_exposures(self) -> None:
        self.app.action_show_ad_workspace("exposures")

class ADPathScreen(Screen):
    """Focused chain plus exact step evidence."""

    BINDINGS = [
        Binding("n", "pivot_node", "Pivot Target"),
        Binding("x", "explore_node", "Explore Target"),
        Binding("s", "set_source", "Set Source"),
        Binding("t", "set_target", "Set Target"),
        Binding("v", "open_exposures", "Exposures"),
        Binding("o", "app.assume_owned", "Assume Owned"),
        Binding("e", "app.export_ad", "Export"),
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
        detail.append(
            "allow-listed" if step.traversable else "evidence only",
            style="green" if step.traversable else "red",
        )
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

    def _selected_node_id(self, endpoint: str = "target") -> str:
        if not self.path.steps:
            return ""
        step = self.path.steps[self._selected_step()]
        return str((step.source if endpoint == "source" else step.target).get("id") or "")

    def action_explore_node(self) -> None:
        self.app.action_explore_ad_node(self._selected_node_id())

    def action_set_source(self) -> None:
        self.app.action_explore_ad_node(self._selected_node_id("source"), "source")

    def action_set_target(self) -> None:
        self.app.action_explore_ad_node(self._selected_node_id(), "target")

    def action_open_exposures(self) -> None:
        self.app.action_show_ad_workspace("exposures")


class ADNodeScreen(Screen):
    """Bounded inbound/outbound relationship pivot for one AD node."""

    BINDINGS = [
        Binding("x", "explore_node", "Explore"),
        Binding("s", "set_source", "Set Source"),
        Binding("t", "set_target", "Set Target"),
        Binding("v", "open_exposures", "Exposures"),
        Binding("o", "app.assume_owned", "Assume Owned"),
        Binding("e", "app.export_ad", "Export"),
        Binding("g", "toggle_graph_renderer", "Graph / Outline"),
        Binding("escape", "app.pop_screen", "Back"),
    ]

    CSS = """
    #node-heading { height: auto; max-height: 3; padding: 0 1; border-bottom: solid $primary; }
    #node-direction-help { height: 2; padding: 0 1; color: $text-muted; }
    #node-graph-status { height: 1; padding: 0 1; color: $text-muted; }
    #node-graph { height: 11; overflow: auto; }
    #node-graph.graphviz-active { padding: 0; }
    #node-edges { height: 1fr; }
    #node-paths { height: 1; padding: 0 1; color: $text-muted; }
    """

    def __init__(self, node_id: str) -> None:
        super().__init__()
        self.node_id = node_id

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="node-heading")
        yield Static(id="node-direction-help")
        yield Static(id="node-graph-status")
        yield Static(id="node-graph")
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
        self.query_one("#node-direction-help", Static).update(
            f"← ways into {_name(pivot.entity)}   ★ you are here   "
            f"what {_name(pivot.entity)} can reach →"
        )
        table = self.query_one("#node-edges", DataTable)
        table.cursor_type = "row"
        table.add_column("Operator view", width=23)
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
                "What this can reach" if direction == "outbound" else "Ways into this object",
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
        self.use_graphviz = True
        self.call_after_refresh(self._request_graph)

    def _request_graph(self) -> None:
        relationships = focused_relationships(self.app.ad_index, self.node_id)
        nodes, relationships = compress_fanout(self.node_id, relationships)
        graph_view = self.query_one("#node-graph", Static)
        self.query_one("#node-graph-status", Static).update("Laying out focused graph…")
        width = max(24, graph_view.size.width)
        height = max(8, graph_view.size.height)

        def render() -> None:
            result = render_focused_graph(
                nodes,
                relationships,
                width=width,
                height=height,
                selected_id=self.node_id,
                layout="pivot",
                force_fallback=not self.use_graphviz,
            )
            self.app.call_from_thread(self._apply_graph, result)

        self.run_worker(render, thread=True, exclusive=True, group="ad-node-graph")

    def _apply_graph(self, result: GraphRenderResult) -> None:
        graph = self.query_one("#node-graph", Static)
        graph.set_class(result.backend == "graphviz", "graphviz-active")
        graph.update(result.text)
        self.query_one("#node-graph-status", Static).update(
            "Graphviz focused graph" if result.backend == "graphviz" else "Terminal outline"
        )

    def action_toggle_graph_renderer(self) -> None:
        self.use_graphviz = not self.use_graphviz
        self._request_graph()

    def action_explore_node(self) -> None:
        self.app.action_explore_ad_node(self.node_id)

    def action_set_source(self) -> None:
        self.app.action_explore_ad_node(self.node_id, "source")

    def action_set_target(self) -> None:
        self.app.action_explore_ad_node(self.node_id, "target")

    def action_open_exposures(self) -> None:
        self.app.action_show_ad_workspace("exposures")


class RelationshipFilterScreen(ModalScreen[str | None]):
    """Replace the case-insensitive set of excluded Explore relationships."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    CSS = """
    RelationshipFilterScreen { align: center middle; }
    #filter-box { width: 90; height: auto; border: round $accent; background: $surface; padding: 1 2; }
    """

    def __init__(self, excluded: list[str], available: list[str]) -> None:
        super().__init__()
        self.excluded = excluded
        self.available = available

    def compose(self) -> ComposeResult:
        with Vertical(id="filter-box"):
            yield Static(
                "Excluded relationship types (comma separated; empty includes all allow-listed edges):"
            )
            yield Static("Available: " + ", ".join(self.available[:40]))
            yield Input(value=", ".join(self.excluded), id="filter-input")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value)

    def action_cancel(self) -> None:
        self.dismiss(None)


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
