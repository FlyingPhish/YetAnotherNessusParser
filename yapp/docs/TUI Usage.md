# YAPP TUI Usage (No SQL)

## Purpose

`yapp tui` provides two focused, serverless operator modes:

- Nessus high-volume finding triage.
- BloodHound/Active Directory attack-path investigation.

AD mode combines a decision-first mission queue with a focused exploration workspace. It prioritizes bounded routes, supports arbitrary object-to-object pathfinding, explains every relationship, and provides node pivots without requiring Neo4j or a BloodHound server.

## Launch

### Nessus

```bash
yapp tui -i scan.nessus
```

### BloodHound / Active Directory

A `.zip` input is detected as AD mode automatically. Bounded path analysis is enabled by default. Startup prints elapsed phase progress before Textual opens. AD mode computes one nearest high-value route per source for the prioritized queue, avoiding exhaustive source-target expansion on large owned-user sets.

```bash
yapp tui -i bloodhound.zip
yapp tui -i bloodhound.zip --owned alice@corp.local --owned CORP\\bob
yapp tui -i bloodhound.zip --owned-users owned.txt
```

Use `--no-paths` only when bounded path analysis is intentionally not required.

### Graphviz

Graphviz is strongly recommended for the Explore workspace. Install the Graphviz system package, ensure `dot` is on `PATH`, and verify it with:

```bash
dot -V
```

Official installers and platform package commands are listed on the [Graphviz download page](https://graphviz.org/download/). Graphviz is a system executable rather than a Python package, so it is not installed by `pip` or `pipx`. If it is missing or fails, YAPP remains usable and displays a bounded relationship outline instead. The mission banner and graph status identify which renderer is active.

## AD Operator Workflow

### Your first minute

1. Read the collection-gap banner; absent data is never treated as a clean result.
2. Inspect the first `ACT NOW` or `HIGH` route with `Enter`.
3. Press `2` or `x` to Explore: search an object, set source with `s`, target with `t`, then press `p`.
4. Press `3` or `v` and review `ACT NOW`, then `CRITICAL`, privilege exposures.
5. Press `o` whenever your foothold changes; routes and owned controls recompute in-session.

The persistent workspace has four tabs:

- **Mission**: prioritized high-value routes and collection gaps.
- **Explore**: global object search, source/target pathfinding, a focused Graphviz layout, a path tree, and a persistent object inspector.
- **Exposures**: broad administrative membership, privileged-object control, local-admin fan-out, and every actionable account/delegation/security-posture finding, such as Kerberoasting and AS-REP roasting.
- **Saved**: bookmarked investigation paths.

Missing collection data is displayed as unknown or not collected.

The Privilege Exposure queue aggregates broad or explicit administrative membership, control over privileged identities and groups, local-administrator fan-out, and direct posture findings: Kerberoastable SPN accounts, AS-REP roastable accounts, unconstrained delegation, credential-material readers, privileged sessions, LAPS/gMSA/shadow-credential exposure, and password posture. Any new actionable non-path AD rule is retained as **Security posture**, rather than silently omitted. Drill-down retains exact targets, effective actors, inherited `via` paths, privilege context, object IDs, and operational caveats.

Terminology:

- `ACT NOW`: the controlling principal or route source is currently assumed owned.
- `HIGH`, `CRITICAL`, `MEDIUM`, `REVIEW`: posture priorities, not proof of exploitability.
- **Target**: a unique object affected by the displayed grant.
- **Effective actor**: a user or computer that receives the grant directly or through group membership.
- **Evidence only**: visible relationship data that is not allow-listed for path traversal.

Controls:

- `1` / `2` / `3` / `4`: open Mission / Explore / Exposures / Saved.
- `Enter`: inspect the selected attack path or exposure.
- `/` or `x`: open Explore and focus object search.
- `v`: open Privilege Exposures.
- `s` / `t`: set the focused Explore object as path source / target.
- `p`: find one shortest allow-listed path between the selected endpoints.
- `f`: replace the comma-separated set of excluded relationship types.
- `g`: toggle the focused Explore graph between Graphviz and the terminal-safe relationship outline.
- `l`: cycle focused-graph layouts: pivot (inbound/outbound), cluster (object types), and path.
- `z`: switch between normal and compact graph labels.
- `h`: hide or show evidence-only graph edges.
- `[` / `]`: zoom the scrollable focused graph out or in.
- `Ctrl` + left/right: shrink/grow the Explore search pane; `Alt` + left/right: shrink/grow the inspector. The graph keeps a 36% minimum width.
- Node pivots reuse the same focused graph renderer as Explore; `g` switches that pivot between Graphviz and the terminal outline.
- `r`: reverse Explore endpoints; outside Explore, recompute the current analysis.
- `n`: pivot from a selected path step or exposure target.
- `s` in exposure detail: pivot into its controlling principal.
- A node pivot starts with **You are here**, then separates **Ways into this object** (who may gain influence over it) from **What this object can reach** (what becomes available when it is controlled). Press `x` to take the object into Explore, or `s` / `t` to use it as a path endpoint. Path and exposure detail views also provide `x` to return to Explore.
- `o`: replace the assumed-owned user set and recompute owned controls and paths.
- `m`: cycle path triage state.
- `b`: bookmark or unbookmark a path.
- `r`: recompute the current AD analysis.
- `e`: export the existing AD JSON, mapped API output, and Excel workbook.
- `Esc`: return from path or node detail.
- `q`: quit from the mission screen.

Green path relationships are explicitly allow-listed as traversable by the core AD policy. Red relationships remain visible as evidence only and are never assumed exploitable. Interactive pathfinding is capped at eight steps and 100,000 visited objects. Focused graphs are capped at 60 nodes and 120 edges; node relationship views remain capped at 500 rows and queues at 1,000 rows.

Assumed-owned identities, path triage, and bookmarks are stored in `<collection>.ad-tui.json` beside the input. Writes are atomic and use restrictive file permissions.

## Nessus Controls

- `/`: search.
- `f`: severity filter.
- `s`: cycle sort.
- `[` / `]`: previous/next page.
- `m`: cycle triage state.
- `h`: host pivot.
- `e`: export loaded outputs.
- `q`: quit.

## Security and Behavior

- No SQL or external graph server.
- Graphviz is invoked as `dot -Tplain` with a fixed argument vector, bounded input/output, a five-second timeout, and no shell.
- Unknown AD relationships are evidence-only.
- Credential-bearing directory attribute values are not placed in TUI state.
- Collection and node views are bounded.
- Existing JSON/API/Excel reporting implementations are reused.
