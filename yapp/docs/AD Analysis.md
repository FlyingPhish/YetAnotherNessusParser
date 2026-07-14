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
