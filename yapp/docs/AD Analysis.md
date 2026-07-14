# Offline Active Directory Analysis

YAPP can analyse a BloodHound collection ZIP without running BloodHound or
Neo4j. Direct rules need no graph dependency. Bounded path rules use the
optional embedded Kuzu backend.

```bash
pip install "yapp[ad]"
yapp ad -i collection.zip
yapp ad -i collection.zip --paths
```

## Owned users

Mark users as assumed compromised to map their outbound control:

```bash
yapp ad -i collection.zip --owned alice@corp.local
yapp ad -i collection.zip --owned CORP\\alice --owned S-1-5-21-1234
yapp ad -i collection.zip --owned-users owned.txt
yapp ad -i collection.zip --owned-users owned.txt --paths
```

Owned-user files contain one SID, UPN, distinguished name, or qualified
username per line. Blank lines and lines beginning with `#` are ignored.
Ambiguous short names are reported and never guessed.

Direct analysis reports allow-listed ACLs, local administration, remote
access, credential access, delegation, group control, and composite DCSync
rights. With `--paths`, YAPP also emits bounded attack paths from resolved
owned users to high-value nodes. Unknown relationship types are retained in
the graph but are not assumed to be exploitable.

## API mapping and Excel

YAPP ships `yapp/config/default_ad_rules.json` with every stable AD finding ID.
The default internal vulnerability IDs are intentionally `null` because those
IDs are organization-specific. Copy the file, assign your real IDs, and pass it as
`ad-rules.json`:

```json
{
  "ad_rules": [
    {
      "rule_name": "asrep_roastable_accounts",
      "title": "AS-REP Roastable Accounts",
      "internal_vulnerability_id": 412,
      "finding_ids": ["ad.kerberos.asrep_roastable"],
      "enabled": true,
      "api_output": true
    }
  ]
}
```

`412` is an example only; replace it with the corresponding ID from your internal
vulnerability catalogue.

Generate the normal findings JSON, compatible stock API JSON, and Excel report:

```bash
yapp ad -i collection.zip -r ad-rules.json --api-output --excel
```

The files are written as `*_AD_Findings.json`, `*_AD_API.json`, and
`*_AD_Report.xlsx`. Excel automatically uses the packaged catalogue; use `--excel` alone when
internal vulnerability IDs are not needed. API output requires a custom `--rules-file` with
your internal IDs and retains the existing `type`, `finding_id`, and
`affected_entities` contract.

Mappings use exact finding IDs rather than title patterns. Multiple finding IDs
can map to one internal vulnerability. A finding ID cannot belong to two enabled
rules. Owned-principal and path findings are excluded unless they are explicitly
included in the mapping file.
