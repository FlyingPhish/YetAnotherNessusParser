"""Small, shared configuration primitives for offline AD analysis."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence


DEFAULT_SENSITIVE_GROUPS: Sequence[Mapping[str, Any]] = (
    {
        "key": "domain_admins",
        "names": ("domain admins",),
        "sid_suffixes": ("-512",),
        "classification": "tier_zero",
        "expected_admin": True,
    },
    {
        "key": "domain_controllers",
        "names": ("domain controllers",),
        "sid_suffixes": ("-516",),
        "classification": "tier_zero",
        "expected_admin": True,
    },
    {
        "key": "schema_admins",
        "names": ("schema admins",),
        "sid_suffixes": ("-518",),
        "classification": "tier_zero",
        "expected_admin": True,
    },
    {
        "key": "enterprise_admins",
        "names": ("enterprise admins",),
        "sid_suffixes": ("-519",),
        "classification": "tier_zero",
        "expected_admin": True,
    },
    {
        "key": "group_policy_creator_owners",
        "names": ("group policy creator owners",),
        "sid_suffixes": ("-520",),
        "classification": "sensitive",
        "expected_admin": True,
    },
    {
        "key": "key_admins",
        "names": ("key admins",),
        "sid_suffixes": ("-526",),
        "classification": "tier_zero",
        "expected_admin": True,
    },
    {
        "key": "enterprise_key_admins",
        "names": ("enterprise key admins",),
        "sid_suffixes": ("-527",),
        "classification": "tier_zero",
        "expected_admin": True,
    },
    {
        "key": "administrators",
        "names": ("administrators",),
        "sid_suffixes": ("-544",),
        "classification": "tier_zero",
        "expected_admin": True,
    },
    {
        "key": "account_operators",
        "names": ("account operators",),
        "sid_suffixes": ("-548",),
        "classification": "sensitive",
        "expected_admin": True,
    },
    {
        "key": "server_operators",
        "names": ("server operators",),
        "sid_suffixes": ("-549",),
        "classification": "sensitive",
        "expected_admin": True,
    },
    {
        "key": "print_operators",
        "names": ("print operators",),
        "sid_suffixes": ("-550",),
        "classification": "sensitive",
        "expected_admin": True,
    },
    {
        "key": "backup_operators",
        "names": ("backup operators",),
        "sid_suffixes": ("-551",),
        "classification": "sensitive",
        "expected_admin": True,
    },
    {
        "key": "dns_admins",
        "names": ("dnsadmins", "dns admins"),
        "sid_suffixes": (),
        "classification": "sensitive",
        "expected_admin": False,
    },
)


def normalize_sensitive_groups(
    raw_groups: Optional[Sequence[Mapping[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Validate and normalize the name/SID registry used by all AD checks."""
    groups = DEFAULT_SENSITIVE_GROUPS if raw_groups is None else raw_groups
    if not isinstance(groups, (list, tuple)):
        raise ValueError("sensitive_groups must be a list")

    normalized: List[Dict[str, Any]] = []
    keys = set()
    for index, raw in enumerate(groups):
        if not isinstance(raw, Mapping):
            raise ValueError(f"sensitive_groups entry {index} must be an object")
        key = raw.get("key")
        if not isinstance(key, str) or not key.strip():
            raise ValueError(f"sensitive_groups entry {index} has no valid key")
        key = key.strip().casefold()
        if key in keys:
            raise ValueError(f"duplicate sensitive_groups key: {key}")

        names = raw.get("names", [])
        suffixes = raw.get("sid_suffixes", [])
        if not isinstance(names, (list, tuple)) or any(
            not isinstance(value, str) or not value.strip() for value in names
        ):
            raise ValueError(f"sensitive group '{key}' has invalid names")
        if not isinstance(suffixes, (list, tuple)) or any(
            not isinstance(value, str) or not value.strip() for value in suffixes
        ):
            raise ValueError(f"sensitive group '{key}' has invalid sid_suffixes")
        if not names and not suffixes:
            raise ValueError(f"sensitive group '{key}' needs a name or SID suffix")

        classification = raw.get("classification", "sensitive")
        if classification not in {"sensitive", "tier_zero"}:
            raise ValueError(
                f"sensitive group '{key}' classification must be sensitive or tier_zero"
            )
        expected_admin = raw.get("expected_admin", False)
        if not isinstance(expected_admin, bool):
            raise ValueError(
                f"sensitive group '{key}' expected_admin must be a boolean"
            )

        keys.add(key)
        normalized.append({
            "key": key,
            "names": sorted({value.strip().casefold() for value in names}),
            "sid_suffixes": sorted({
                value.strip().upper() if value.strip().upper().startswith("S-1-")
                else value.strip()
                for value in suffixes
            }),
            "classification": classification,
            "expected_admin": expected_admin,
        })
    if raw_groups is None:
        return normalized
    merged = {entry["key"]: entry for entry in normalize_sensitive_groups()}
    for entry in normalized:
        merged[entry["key"]] = entry
    return list(merged.values())


def match_sensitive_group(
    sid: str,
    name: str,
    registry: Sequence[Mapping[str, Any]],
) -> Optional[Mapping[str, Any]]:
    """Return the first matching registry entry for a group."""
    sid_key = sid.strip().upper()
    name_key = name.split("@", 1)[0].strip().casefold()
    for entry in registry:
        if name_key in entry.get("names", ()):
            return entry
        if any(sid_key.endswith(suffix.upper()) for suffix in entry.get("sid_suffixes", ())):
            return entry
    return None
