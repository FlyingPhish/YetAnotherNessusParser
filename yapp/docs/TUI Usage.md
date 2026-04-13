# YAPP TUI Usage (No SQL)

## Purpose
`yapp tui` is a Nessus-first triage frontend built for high-volume operator workflows without adding a database layer.

## Launch
```bash
yapp tui -i scan.nessus
```

### Build in-memory exports for later actions
```bash
yapp tui -i scan.nessus -c -a -x
```

## Main Controls
- `/` focus search
- `f` focus severity toggles
- `s` cycle sort mode (`severity`, `risk`, `hosts`, `plugin`, `name`)
- `[` previous page
- `]` next page
- `m` cycle triage state (`new`, `in_progress`, `triaged`, `accepted_risk`)
- `h` host pivot for selected finding
- `e` export current loaded outputs using existing YAPP writer flow
- `Ctrl+e` export filtered findings snapshot JSON
- `q` quit

## Severity Filter
- Use visible severity checkboxes (`Critical`, `High`, `Medium`, `Low`, `Info`)
- `f` jumps focus to severity toggles, then `Space` toggles the current one
- If all severities are checked, the filter behaves as `all`
- If a subset is checked, only those severities are shown
- If none are checked, no findings are shown

## Default View
- No severity filter on startup (`all`)
- Startup sort is `severity` (critical -> high -> medium -> low -> info)
- Findings table focuses on operator signal columns: Severity, Risk, Hosts, Plugin, Name, Exploit, Triage
- Active filters are shown in the filters bar (search, severity, sort, page size)

## Export Notes
- `Export` writes outputs from the loaded in-memory pipeline (`parsed`, optional `consolidated`, optional `api`, optional `excel`) to the selected output folder.
- `Export Filtered` writes `<name>_FilteredFindings.json` containing only currently filtered plugins for focused review.

## Security/Behavior
- No SQL backend
- No shell execution
- Triage states are persisted in `.yapp-tui/<scan>_<fingerprint>_triage.json`
