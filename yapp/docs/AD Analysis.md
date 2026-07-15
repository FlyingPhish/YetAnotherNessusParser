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

## Administrative posture

Every run also reports effective administrative membership and allow-listed control
permissions. Findings cover excessive Domain Admins, privileged users outside
Protected Users, old user and KRBTGT passwords, computer accounts in administrative
groups, likely legacy-password TimeRoast targets, control over high-privilege
objects, and effective DCSync rights. DCSync paths include nested group membership
and combine GetChanges with GetChangesAll even when the rights come from different
groups. `--paths` additionally identifies paths whose target is Domain Admins.

The JSON contains `privilege_analysis.memberships`, `permissions`, and
`dcsync_paths`. These are filtered to administrative/high-value scope so normal
directory membership does not become finding noise. The Excel report exposes the
same data in Administrative Memberships, Administrative Permissions, Paths, and
Path Steps sheets.

Policy thresholds can be changed per run:

```bash
yapp ad -i collection.zip \
  --max-domain-admins 5 \
  --max-password-age-days 365 \
  --max-krbtgt-password-age-days 180 \
  --user-dormancy-days 90 \
  --computer-dormancy-days 90 \
  --max-local-admin-hosts 10
```

TimeRoast results are candidates rather than proof of a weak password. The default
requires a computer password older than 30 days whose password-set timestamp is
within one day of account creation; evidence includes the legacy lowercase,
14-character machine-name password candidate.

## Operator inventories and coverage

`operator_analysis` keeps useful inventory separate from risk findings. Fleet access
contains `AdminTo` and `CanRDP` grants expanded to effective users and computers,
but suppresses principals whose configured sensitive group has `expected_admin: true`.
Non-standard access remains in JSON and Excel; only computer-account administration
and grants exceeding `--max-local-admin-hosts` become API-mappable findings.

The same section records dormant accounts, SIDHistory, legacy compatibility-group
members, delegation, LAPS/gMSA/key-credential readers, privileged sessions, and a
limited AD CS presence/administrative-access inventory. `coverage` reports
`complete`, `partial`, `collected`, or `not_collected` for optional source data. This
prevents an absent field from being mistaken for a clean result. Values from
password-bearing attributes are never copied into evidence.

`path_analysis.choke_points` counts reused DCSync path steps by domain and target
class; `--paths` adds bounded high-value paths to the same summary. Only steps
shared by at least two collected paths are included. Excel
adds Fleet Access, Collection Coverage, Account Inventory, Delegation, Credential
Access, AD CS, and Choke Points sheets.

## API mapping and Excel

YAPP ships `yapp/config/default_ad_rules.json` with every stable AD finding ID.
The packaged catalogue contains stable finding IDs and starter internal vulnerability IDs. Copy it when your internal catalogue uses different IDs, then pass the copy as `ad-rules.json`:

```json
{
  "sensitive_groups": [
    {
      "key": "domain_admins",
      "names": ["domain admins"],
      "sid_suffixes": ["-512"],
      "classification": "tier_zero",
      "expected_admin": true
    },
    {
      "key": "custom_tier_zero",
      "names": ["cloud platform admins"],
      "sid_suffixes": [],
      "classification": "tier_zero",
      "expected_admin": false
    }
  ],
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
vulnerability catalogue. `sensitive_groups` is one shared SID/name registry for
membership, permission, session, delegation, and fleet filtering. `expected_admin`
controls only whether routine fleet access is suppressed. Custom entries extend the packaged defaults; a matching `key` intentionally overrides
that default. If the registry is omitted, the packaged defaults are used.

Generate the normal findings JSON, compatible stock API JSON, and Excel report:

```bash
yapp ad -i collection.zip -r ad-rules.json --api-output --excel
```

The files are written as `*_AD_Findings.json`, `*_AD_API.json`, and
`*_AD_Report.xlsx`. Excel and API output use the packaged catalogue by default. Use `--rules-file` to override its starter IDs. API output retains the existing `type`, `finding_id`, and
`affected_entities` contract.

Mappings use exact finding IDs rather than title patterns. Multiple finding IDs
can map to one internal vulnerability. A finding ID cannot belong to two enabled
rules. Owned-principal and path findings are excluded unless they are explicitly
included in the mapping file.
