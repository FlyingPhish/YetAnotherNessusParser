# YAPP TUI Usage (No SQL)

## Purpose

`yapp tui` provides two focused, serverless operator modes:

- Nessus high-volume finding triage.
- BloodHound/Active Directory attack-path investigation.

AD mode is a decision console, not a whole-domain graph renderer. It prioritizes bounded routes, explains every relationship, and provides node pivots without requiring Neo4j or a BloodHound server.

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

Use `--no-paths` only when Kuzu path analysis is intentionally not required.

## AD Operator Workflow

The mission screen shows critical/high findings, owned principals, privileged exposure, prioritized paths, choke points, and collection gaps. Missing collection data is displayed as unknown or not collected.

Controls:

- `Enter`: inspect the selected attack path.
- `n`: pivot from a selected path step into the target node.
- `o`: replace the assumed-owned user set and recompute owned controls and paths.
- `m`: cycle path triage state.
- `b`: bookmark or unbookmark a path.
- `r`: recompute the current AD analysis.
- `e`: export the existing AD JSON, mapped API output, and Excel workbook.
- `Esc`: return from path or node detail.
- `q`: quit from the mission screen.

Green path relationships are explicitly allow-listed as traversable by the core AD policy. Red relationships remain visible as evidence only and are never assumed exploitable. Node relationship views are capped at 500 rows and the attack-path queue at 1,000 rows.

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
- No shell execution from the TUI.
- Unknown AD relationships are evidence-only.
- Credential-bearing directory attribute values are not placed in TUI state.
- Collection and node views are bounded.
- Existing JSON/API/Excel reporting implementations are reused.
