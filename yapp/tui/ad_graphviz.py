"""Secure, bounded Graphviz layout with a terminal-safe fallback renderer."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

from .state import ADRelationship

_MAX_NODES = 60
_MAX_EDGES = 120
_MAX_DOT_BYTES = 64 * 1024
_MAX_OUTPUT_BYTES = 1024 * 1024


@dataclass(frozen=True)
class GraphRenderResult:
    text: str
    backend: str
    warning: str = ""


def graphviz_available() -> bool:
    """Return whether the Graphviz ``dot`` executable is available."""
    return shutil.which("dot") is not None


def render_focused_graph(
    nodes: Sequence[Mapping],
    relationships: Sequence[ADRelationship],
    *,
    width: int = 100,
    height: int = 24,
    executable: str | None = None,
    force_fallback: bool = False,
    layout: str = "pivot",
    selected_id: str = "",
    compact_labels: bool = False,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> GraphRenderResult:
    """Lay out and render a small graph; never pass collection text to a shell."""
    safe_nodes = _bounded_nodes(nodes, relationships)
    safe_edges = tuple(relationships[:_MAX_EDGES])
    if not safe_nodes:
        return GraphRenderResult("Select an object or calculate a path.", "empty")
    if force_fallback:
        return GraphRenderResult(
            _fallback(safe_nodes, safe_edges),
            "fallback",
            "Terminal outline selected by operator.",
        )
    dot = _build_dot(safe_nodes, safe_edges, layout=layout, selected_id=selected_id)
    command = executable or shutil.which("dot")
    if not command:
        return GraphRenderResult(
            _fallback(safe_nodes, safe_edges),
            "fallback",
            "Graphviz 'dot' was not found; showing the relationship outline.",
        )
    # ``which`` already returns a resolved path. Do not rewrite a supplied
    # Windows executable path: this module is also exercised from WSL tests.
    command = str(command)
    try:
        completed = runner(
            [command, "-Tplain"],
            input=dot,
            text=True,
            capture_output=True,
            timeout=5,
            check=True,
        )
        output = completed.stdout
        if len(output.encode("utf-8", errors="replace")) > _MAX_OUTPUT_BYTES:
            raise ValueError("Graphviz output exceeded the 1 MiB limit")
        rendered = _render_plain(
            output, safe_nodes, width=width, height=height,
            selected_id=selected_id, compact_labels=compact_labels,
        )
        return GraphRenderResult(rendered, "graphviz")
    except (OSError, subprocess.SubprocessError, ValueError, IndexError) as exc:
        detail = _error_detail(exc)
        return GraphRenderResult(
            _fallback(safe_nodes, safe_edges),
            "fallback",
            f"Graphviz layout unavailable ({detail}); showing the relationship outline.",
        )


def _error_detail(exc: Exception) -> str:
    """Return a bounded Graphviz failure reason suitable for the operator UI."""
    if isinstance(exc, subprocess.CalledProcessError):
        stderr = str(exc.stderr or "").strip().replace("\n", " ")
        if stderr:
            return stderr[:240]
        return f"dot exited with status {exc.returncode}"
    return str(exc)[:240] or type(exc).__name__


def _bounded_nodes(
    nodes: Sequence[Mapping],
    relationships: Sequence[ADRelationship],
) -> tuple[dict, ...]:
    by_id = {}
    for node in nodes:
        node_id = str(node.get("id") or "")
        if node_id and node_id not in by_id and len(by_id) < _MAX_NODES:
            by_id[node_id] = dict(node)
    for edge in relationships[:_MAX_EDGES]:
        for node in (edge.source, edge.target):
            node_id = str(node.get("id") or "")
            if node_id and node_id not in by_id and len(by_id) < _MAX_NODES:
                by_id[node_id] = dict(node)
    return tuple(by_id.values())


def _dot_quote(value: object, limit: int = 80) -> str:
    text = str(value or "")[:limit]
    text = "".join(char if char >= " " else " " for char in text)
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _build_dot(
    nodes: Sequence[Mapping],
    relationships: Sequence[ADRelationship],
    *,
    layout: str = "pivot",
    selected_id: str = "",
) -> str:
    ids = {str(node.get("id") or ""): f"n{index}" for index, node in enumerate(nodes)}
    lines = [
        "digraph yapp {",
        'graph [rankdir="LR", splines="polyline", overlap="false", nodesep="0.35", ranksep="0.7"];',
        'node [shape="box", style="rounded,filled", fillcolor="#202530", color="#7f8c98"];',
        'edge [color="#7f8c98", fontname="sans", fontsize="9"];',
    ]
    colors = {
        "user": "#124e66",
        "group": "#665512",
        "computer": "#123d66",
        "domain": "#551266",
    }
    for node in nodes:
        node_id = str(node.get("id") or "")
        alias = ids[node_id]
        kind = str(node.get("type") or "").casefold()
        label = str(node.get("name") or node_id)
        lines.append(
            f"{alias} [label={_dot_quote(label)}, fillcolor={_dot_quote(colors.get(kind, '#303640'))}];"
        )
    if layout == "cluster":
        for kind in sorted({str(node.get("type") or "object").casefold() for node in nodes}):
            members = " ".join(ids[str(node.get("id") or "")] for node in nodes if str(node.get("type") or "").casefold() == kind)
            if members:
                lines.append(f"subgraph cluster_{len(lines)} {{ label={_dot_quote(kind.title())}; color=\"#59636e\"; {members}; }}")
    if selected_id in ids:
        lines.append(f"{ids[selected_id]} [penwidth=3, color=\"#ffffff\"];")
    for edge in relationships:
        source = ids.get(str(edge.source.get("id") or ""))
        target = ids.get(str(edge.target.get("id") or ""))
        if not source or not target:
            continue
        color = "#4caf50" if edge.traversable else "#ef5350"
        lines.append(
            f"{source} -> {target} [label={_dot_quote(edge.relationship, 40)}, color={_dot_quote(color)}];"
        )
    lines.append("}")
    output = "\n".join(lines)
    if len(output.encode("utf-8")) > _MAX_DOT_BYTES:
        raise ValueError("Focused graph exceeded the 64 KiB DOT limit")
    return output


def _render_plain(
    output: str,
    nodes: Sequence[Mapping],
    *,
    width: int,
    height: int,
    selected_id: str = "",
    compact_labels: bool = False,
) -> str:
    width = max(24, min(width, 180))
    height = max(8, min(height, 50))
    aliases = {f"n{index}": node for index, node in enumerate(nodes)}
    positions = {}
    edge_rows = []
    graph_width = graph_height = 1.0
    for raw_line in output.splitlines():
        try:
            fields = shlex.split(raw_line)
        except ValueError:
            continue
        if not fields:
            continue
        if fields[0] == "graph" and len(fields) >= 4:
            graph_width, graph_height = float(fields[2]), float(fields[3])
        elif fields[0] == "node" and len(fields) >= 4 and fields[1] in aliases:
            positions[fields[1]] = (float(fields[2]), float(fields[3]))
        elif fields[0] == "edge" and len(fields) >= 5:
            count = int(fields[3])
            points = [
                (float(fields[4 + index * 2]), float(fields[5 + index * 2]))
                for index in range(count)
            ]
            cursor = 4 + count * 2
            label = ""
            label_point = None
            if len(fields) >= cursor + 3:
                try:
                    label = fields[cursor]
                    label_point = (float(fields[cursor + 1]), float(fields[cursor + 2]))
                except ValueError:
                    label = ""
                    label_point = None
            edge_rows.append((fields[1], fields[2], points, label, label_point))
    if not positions:
        raise ValueError("Graphviz returned no node positions")

    canvas = [[" " for _ in range(width)] for _ in range(height)]

    def project(point: tuple[float, float]) -> tuple[int, int]:
        x = int(1 + point[0] / max(graph_width, 0.1) * (width - 3))
        y = int((1 - point[1] / max(graph_height, 0.1)) * (height - 2))
        return max(0, min(width - 1, x)), max(0, min(height - 1, y))

    for tail, head, points, label, label_point in edge_rows:
        for start, end in zip(points, points[1:]):
            start_cell = project(start)
            end_cell = project(end)
            edge_char = _edge_char(start_cell, end_cell)
            _draw_line(canvas, start_cell, end_cell, edge_char)
        if label and label_point:
            x, y = project(label_point)
            token = label[:14]
            start = max(0, min(width - len(token), x - len(token) // 2))
            for offset, char in enumerate(token):
                canvas[y][start + offset] = char
        if tail in positions and head in positions:
            start_x, start_y = project(positions[tail])
            end_x, end_y = project(positions[head])
            if abs(end_x - start_x) >= abs(end_y - start_y):
                marker = ">" if end_x >= start_x else "<"
            else:
                marker = "v" if end_y >= start_y else "^"
            canvas[end_y][end_x] = marker
    for alias, point in positions.items():
        x, y = project(point)
        node = aliases[alias]
        kind = str(node.get("type") or "").casefold()
        marker = {"user": "●", "group": "◆", "computer": "▣", "domain": "◎", "summary": "◌"}.get(kind, "○")
        label_limit = 7 if compact_labels else 14
        label = str(node.get("name") or node.get("id") or "?")[:label_limit]
        selected = str(node.get("id") or "") == selected_id
        token = f"{'★' if selected else marker}{label}"
        start = max(0, min(width - len(token), x - len(token) // 2))
        for offset, char in enumerate(token):
            canvas[y][start + offset] = char
    return "\n".join("".join(row).rstrip() for row in canvas).rstrip()


def _draw_line(
    canvas: list[list[str]],
    start: tuple[int, int],
    end: tuple[int, int],
    char: str,
) -> None:
    x1, y1 = start
    x2, y2 = end
    dx = abs(x2 - x1)
    dy = -abs(y2 - y1)
    sx = 1 if x1 < x2 else -1
    sy = 1 if y1 < y2 else -1
    error = dx + dy
    while True:
        if canvas[y1][x1] == " ":
            canvas[y1][x1] = char
        if (x1, y1) == (x2, y2):
            break
        twice = 2 * error
        if twice >= dy:
            error += dy
            x1 += sx
        if twice <= dx:
            error += dx
            y1 += sy


def _edge_char(start: tuple[int, int], end: tuple[int, int]) -> str:
    """Choose an obvious terminal-safe connector for one Graphviz segment."""
    x1, y1 = start
    x2, y2 = end
    if y1 == y2:
        return "─"
    if x1 == x2:
        return "│"
    return "╲" if (x2 - x1) * (y2 - y1) > 0 else "╱"


def _fallback(
    nodes: Sequence[Mapping],
    relationships: Sequence[ADRelationship],
) -> str:
    if relationships:
        return "\n".join(
            f"[{edge.source.get('name', '?')}] --{edge.relationship}--> "
            f"[{edge.target.get('name', '?')}]"
            for edge in relationships[:40]
        )
    node = nodes[0]
    return f"[{node.get('name') or node.get('id') or '?'}]"
