"""Offline privilege-escalation path scanner and report renderer."""
from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .permissions import (
    evaluate_action,
    is_administrator,
    statements_from_document,
    statements_from_permissions,
)
from .rules import rules_for


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _get(mapping: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in mapping:
            return mapping[key]
    return default


def _identity_type(identity: Dict[str, Any]) -> str:
    explicit = str(
        _get(identity, "type", "Type", "identity_type", "IdentityType", default="")
    ).lower()
    if explicit in ("user", "role"):
        return explicit
    if _get(identity, "RoleName", "role_name", "role"):
        return "role"
    return "user"


def _identity_name(identity: Dict[str, Any]) -> str:
    return str(
        _get(
            identity,
            "name",
            "Name",
            "UserName",
            "user_name",
            "RoleName",
            "role_name",
            default="unknown",
        )
    )


def _identity_arn(identity: Dict[str, Any], account_id: str, identity_type: str) -> str:
    arn = _get(identity, "arn", "Arn", "ARN")
    if arn:
        return str(arn)
    name = _identity_name(identity)
    return "arn:aws:iam::{}:{}/{}".format(account_id, identity_type, name)


def _identity_groups(identity: Dict[str, Any]) -> List[str]:
    groups = _get(identity, "groups", "Groups", "group_names", default=[]) or []
    result = []
    for group in groups:
        if isinstance(group, str):
            result.append(group)
        elif isinstance(group, dict):
            name = _get(group, "GroupName", "group_name", "name", "Name")
            if name:
                result.append(str(name))
    return result


def _policy_items(identity: Dict[str, Any]) -> List[Any]:
    policies = (
        _get(identity, "policies", "Policies", "policy_documents", "PolicyDocuments")
        or []
    )
    if isinstance(policies, dict):
        return [policies]
    return list(policies)


def _statements_from_policy_item(item: Any, source: str) -> List[Dict[str, Any]]:
    if not isinstance(item, dict):
        return statements_from_document(item, source)
    if "Statement" in item:
        return statements_from_document(item, source)
    document = _get(item, "Document", "PolicyDocument", "policy_document")
    if document is None:
        return []
    label = _get(item, "Source", "source", "PolicyName", "PolicyArn", default=source)
    return statements_from_document(document, "{}:{}".format(source, label))


def _statements_from_identity(
    identity: Dict[str, Any], group_statements: Dict[str, List[Dict[str, Any]]]
) -> List[Dict[str, Any]]:
    statements: List[Dict[str, Any]] = []
    permissions = _get(identity, "permissions", "Permissions")
    if permissions:
        statements.extend(
            statements_from_permissions(permissions, _identity_name(identity))
        )

    for index, policy in enumerate(_policy_items(identity)):
        statements.extend(
            _statements_from_policy_item(
                policy, "{}:policy-{}".format(_identity_name(identity), index)
            )
        )

    groups = _get(identity, "groups", "Groups", default=[]) or []
    for group in groups:
        if isinstance(group, str):
            statements.extend(group_statements.get(group, []))
            continue
        if not isinstance(group, dict):
            continue
        group_name = _get(group, "GroupName", "group_name", "name", "Name")
        if group_name:
            statements.extend(group_statements.get(str(group_name), []))
        for index, policy in enumerate(_policy_items(group)):
            statements.extend(
                _statements_from_policy_item(
                    policy,
                    "group:{}:policy-{}".format(group_name or "unknown", index),
                )
            )
    return statements


def _account_groups(account: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    groups = _get(account, "groups", "Groups", default=[]) or []
    if isinstance(groups, dict):
        groups = [
            {"GroupName": name, **(value if isinstance(value, dict) else {})}
            for name, value in groups.items()
        ]

    result: Dict[str, List[Dict[str, Any]]] = {}
    for group in groups:
        if not isinstance(group, dict):
            continue
        name = _get(group, "GroupName", "group_name", "name", "Name")
        if not name:
            continue
        statements: List[Dict[str, Any]] = []
        permissions = _get(group, "permissions", "Permissions")
        if permissions:
            statements.extend(statements_from_permissions(permissions, "group:{}".format(name)))
        for index, policy in enumerate(_policy_items(group)):
            statements.extend(
                _statements_from_policy_item(
                    policy, "group:{}:policy-{}".format(name, index)
                )
            )
        result[str(name)] = statements
    return result


def _account_identities(account: Dict[str, Any]) -> List[Dict[str, Any]]:
    identities = _get(account, "identities", "Identities", default=None)
    if identities is not None:
        return [identity for identity in identities if isinstance(identity, dict)]

    result = []
    for key, identity_type in (
        ("users", "user"),
        ("Users", "user"),
        ("roles", "role"),
        ("Roles", "role"),
    ):
        values = account.get(key) or []
        for value in values:
            if not isinstance(value, dict):
                continue
            item = dict(value)
            item.setdefault("Type", identity_type)
            result.append(item)
    return result


def _infer_account_id(account: Dict[str, Any], identities: List[Dict[str, Any]]) -> str:
    account_id = _get(account, "account_id", "AccountId", "account")
    if account_id:
        return str(account_id)
    for identity in identities:
        arn = str(_get(identity, "arn", "Arn", default=""))
        parts = arn.split(":")
        if len(parts) > 4 and parts[4]:
            return parts[4]
    return "unknown"


def _collection_state(account: Dict[str, Any]) -> Dict[str, Any]:
    collection = _get(account, "collection", "Collection", default={}) or {}
    denied_actions = list(
        _get(collection, "denied_actions", "DeniedActions", default=[]) or []
    )
    complete = _get(
        collection,
        "complete",
        "Complete",
        default=_get(account, "collection_complete", "CollectionComplete", default=True),
    )
    if denied_actions:
        complete = False
    return {
        "complete": bool(complete),
        "denied_actions": sorted(set(str(action) for action in denied_actions)),
        "notes": _get(collection, "notes", "Notes", default=[]),
        "permission_checks": _get(
            collection, "permission_checks", "PermissionChecks", default={}
        ),
    }


def _identity_permissions_known(
    identity: Dict[str, Any], account_complete: bool
) -> bool:
    value = _get(
        identity,
        "permissions_confirmed",
        "PermissionsConfirmed",
        "confirmed",
        default=None,
    )
    if value is None:
        return account_complete
    return bool(value) and account_complete


def _path_from_rule(
    identity: Dict[str, Any],
    rule: Dict[str, Any],
    statements: List[Dict[str, Any]],
    permissions_known: bool,
) -> Optional[Dict[str, Any]]:
    checks = [
        evaluate_action(statements, action, known=permissions_known)
        for action in rule["required_actions"]
    ]

    if any(check["decision"] == "denied" for check in checks):
        return None

    explicit_allows = [check for check in checks if check["allowed"]]
    if not explicit_allows:
        return None

    missing = [
        check["action"] for check in checks if check["decision"] in ("unknown", "not_allowed")
    ]
    restricted = [
        check["action"]
        for check in checks
        if check["allowed"] and (check["restricted"] or check["conditional"])
    ]

    if permissions_known and missing:
        return None

    confirmed = (
        permissions_known
        and all(check["decision"] == "allowed" for check in checks)
    )
    status = "confirmed" if confirmed else "potential"

    if status == "confirmed":
        reason = "All required actions are explicitly allowed without conditions."
    elif not permissions_known:
        reason = "Policy collection is incomplete; the path could not be confirmed."
    elif restricted:
        reason = "Required actions are allowed only on restricted resources or under conditions."
    else:
        reason = "Some required actions were not confirmed by the collected evidence."

    return {
        "method": rule["method"],
        "title": rule["title"],
        "severity": rule["severity"],
        "status": status,
        "confidence": status,
        "permissions_confirmed": permissions_known,
        "identity": {
            "type": _identity_type(identity),
            "name": _identity_name(identity),
            "arn": _get(identity, "arn", "Arn", "ARN", default=""),
        },
        "required_permissions": checks,
        "optional_permissions": [
            evaluate_action(statements, action, known=permissions_known)
            for action in rule["optional_actions"]
        ],
        "missing_permissions": missing,
        "restricted_permissions": restricted,
        "reason": reason,
        "description": rule["description"],
        "impact": rule["impact"],
    }


def scan_account(account: Dict[str, Any]) -> Dict[str, Any]:
    """Scan one account snapshot and return findings plus validation data."""
    identities = _account_identities(account)
    account_id = _infer_account_id(account, identities)
    collection = _collection_state(account)
    group_statements = _account_groups(account)

    paths: List[Dict[str, Any]] = []
    admins: List[Dict[str, Any]] = []
    identities_scanned = 0

    for identity in identities:
        identity_type = _identity_type(identity)
        if identity_type not in ("user", "role"):
            continue
        identities_scanned += 1
        permissions_known = _identity_permissions_known(
            identity, collection["complete"]
        )
        statements = _statements_from_identity(identity, group_statements)
        arn = _identity_arn(identity, account_id, identity_type)
        identity_view = {
            "type": identity_type,
            "name": _identity_name(identity),
            "arn": arn,
        }

        if is_administrator(statements, permissions_known):
            admins.append(identity_view)
            continue

        for rule in rules_for(identity_type):
            finding = _path_from_rule(
                identity, rule, statements, permissions_known
            )
            if finding is None:
                continue
            finding["identity"] = identity_view
            finding["account_id"] = account_id
            paths.append(finding)

    paths.sort(
        key=lambda item: (
            -SEVERITY_ORDER.get(item["severity"], 0),
            item["identity"]["name"],
            item["method"],
        )
    )

    return {
        "account_id": account_id,
        "name": str(_get(account, "name", "Name", default=account_id)),
        "collection": collection,
        "identities_scanned": identities_scanned,
        "admin_identities": admins,
        "paths": paths,
    }


def scan_accounts(accounts: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    scanned = [scan_account(account) for account in accounts]
    scanned.sort(key=lambda account: account["account_id"])
    all_paths = [path for account in scanned for path in account["paths"]]
    permission_checks = [
        check
        for account in scanned
        for check in account["collection"].get("permission_checks", {}).values()
    ]
    return {
        "schema_version": "1.0",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "accounts": scanned,
        "summary": {
            "accounts": len(scanned),
            "identities": sum(account["identities_scanned"] for account in scanned),
            "findings": len(all_paths),
            "confirmed_findings": sum(
                1 for path in all_paths if path["status"] == "confirmed"
            ),
            "potential_findings": sum(
                1 for path in all_paths if path["status"] == "potential"
            ),
            "incomplete_accounts": sum(
                1 for account in scanned if not account["collection"]["complete"]
            ),
            "permission_checks": len(permission_checks),
            "permission_checks_denied": sum(
                1 for check in permission_checks if check.get("status") == "denied"
            ),
            "permission_checks_errored": sum(
                1 for check in permission_checks if check.get("status") == "error"
            ),
        },
    }


def filter_report(report: Dict[str, Any], min_severity: str = "low") -> Dict[str, Any]:
    threshold = SEVERITY_ORDER.get(min_severity.lower(), 1)
    filtered_accounts = []
    for account in report["accounts"]:
        item = dict(account)
        item["paths"] = [
            path
            for path in account["paths"]
            if SEVERITY_ORDER.get(path["severity"], 0) >= threshold
        ]
        filtered_accounts.append(item)

    paths = [path for account in filtered_accounts for path in account["paths"]]
    result = dict(report)
    result["accounts"] = filtered_accounts
    result["summary"] = dict(report["summary"])
    result["summary"].update(
        {
            "findings": len(paths),
            "confirmed_findings": sum(
                1 for path in paths if path["status"] == "confirmed"
            ),
            "potential_findings": sum(
                1 for path in paths if path["status"] == "potential"
            ),
        }
    )
    return result


def render_markdown(report: Dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# IAM Privilege Escalation Path Report",
        "",
        "Generated: `{}`".format(report["generated_at"]),
        "",
        "## Summary",
        "",
        "- Accounts: **{}**".format(summary["accounts"]),
        "- Identities scanned: **{}**".format(summary["identities"]),
        "- Findings: **{}** ({} confirmed, {} potential)".format(
            summary["findings"],
            summary["confirmed_findings"],
            summary["potential_findings"],
        ),
        "- Accounts with incomplete collection: **{}**".format(
            summary["incomplete_accounts"]
        ),
        "- Read-permission checks: **{}** ({} denied, {} errored)".format(
            summary.get("permission_checks", 0),
            summary.get("permission_checks_denied", 0),
            summary.get("permission_checks_errored", 0),
        ),
        "",
    ]

    for account in report["accounts"]:
        complete = "complete" if account["collection"]["complete"] else "incomplete"
        lines.extend(
            [
                "## Account `{}` ({})".format(account["account_id"], account["name"]),
                "",
                "- Collection: **{}**".format(complete),
                "- Identities scanned: **{}**".format(account["identities_scanned"]),
                "- Already-administrator identities: **{}**".format(
                    len(account["admin_identities"])
                ),
            ]
        )
        denied = account["collection"].get("denied_actions") or []
        if denied:
            lines.append(
                "- Permission checks denied: {}".format(
                    ", ".join("`{}`".format(action) for action in denied)
                )
            )
        lines.append("")

        checks = account["collection"].get("permission_checks") or {}
        if checks:
            lines.extend(
                [
                    "**Permission checks**",
                    "",
                    "| IAM action | Result | Detail |",
                    "| --- | --- | --- |",
                ]
            )
            for action, check in sorted(checks.items()):
                lines.append(
                    "| `{}` | {} | {} |".format(
                        action,
                        check.get("status", "unknown"),
                        check.get("detail", "") or "-",
                    )
                )
            lines.append("")

        if not account["paths"]:
            lines.extend(["No privilege-escalation paths found.", ""])
            continue

        for path in account["paths"]:
            identity = path["identity"]
            lines.extend(
                [
                    "### {}: {} ({}, {})".format(
                        identity["name"],
                        path["title"],
                        path["method"],
                        path["status"],
                    ),
                    "",
                    "- Severity: **{}**".format(path["severity"].upper()),
                    "- Identity: `{}` (`{}`)".format(
                        identity["arn"], identity["type"]
                    ),
                    "- Description: {}".format(path["description"]),
                    "- Impact: {}".format(path["impact"]),
                    "- Reason: {}".format(path["reason"]),
                    "",
                    "| Required action | Decision | Evidence |",
                    "| --- | --- | --- |",
                ]
            )
            for check in path["required_permissions"]:
                evidence = "<br>".join(check["evidence"]) or "-"
                lines.append(
                    "| `{}` | {} | {} |".format(
                        check["action"], check["decision"], evidence
                    )
                )
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_report(
    report: Dict[str, Any], output_dir: Path, output_format: str = "both"
) -> Dict[str, str]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    paths: Dict[str, str] = {}
    if output_format in ("json", "both"):
        json_path = output_dir / "iam__enum_privesc_paths-{}.json".format(stamp)
        with json_path.open("w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
        paths["json"] = str(json_path)
    if output_format in ("markdown", "both"):
        markdown_path = output_dir / "iam__enum_privesc_paths-{}.md".format(stamp)
        markdown_path.write_text(render_markdown(report), encoding="utf-8")
        paths["markdown"] = str(markdown_path)
    return paths


def _normalize_accounts_payload(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    if isinstance(payload.get("accounts"), list):
        return [item for item in payload["accounts"] if isinstance(item, dict)]
    if isinstance(payload.get("Accounts"), list):
        return [item for item in payload["Accounts"] if isinstance(item, dict)]
    if payload and all(
        isinstance(key, str) and key.isdigit() and isinstance(value, dict)
        for key, value in payload.items()
    ):
        result = []
        for account_id, account in payload.items():
            item = dict(account)
            item.setdefault("account_id", account_id)
            result.append(item)
        return result
    return [payload]


def _account_from_confirmed_permissions(payload: Dict[str, Any]) -> Dict[str, Any]:
    if "UserName" in payload:
        identity_type = "user"
        name = payload["UserName"]
    elif "RoleName" in payload:
        identity_type = "role"
        name = payload["RoleName"]
    else:
        return payload

    identity = dict(payload)
    identity["Type"] = identity_type
    identity["Name"] = name
    arn = payload.get("Arn")
    account_id = "unknown"
    if isinstance(arn, str) and len(arn.split(":")) > 4:
        account_id = arn.split(":")[4]
    return {
        "account_id": account_id,
        "name": account_id,
        "identities": [identity],
        "collection": {
            "complete": bool(
                payload.get("PermissionsConfirmed", payload.get("permissions_confirmed", True))
            ),
            "denied_actions": [],
            "notes": ["Loaded from an iam__enum_permissions confirmed-permissions file."],
        },
    }


def load_accounts_from_paths(paths: Iterable[str]) -> List[Dict[str, Any]]:
    files: List[Path] = []
    for raw_path in paths:
        path = Path(raw_path).expanduser()
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError("Input path does not exist: {}".format(path))

    accounts: List[Dict[str, Any]] = []
    for file_path in files:
        with file_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        for account in _normalize_accounts_payload(payload):
            accounts.append(_account_from_confirmed_permissions(account))

    merged: Dict[str, Dict[str, Any]] = {}
    for account in accounts:
        account_id = str(account.get("account_id", "unknown"))
        if account_id not in merged:
            merged[account_id] = account
            continue
        existing = merged[account_id]
        existing.setdefault("identities", []).extend(account.get("identities", []))
        existing.setdefault("groups", []).extend(account.get("groups", []))
        existing_collection = existing.setdefault("collection", {})
        incoming_collection = account.get("collection", {})
        existing_collection["complete"] = bool(
            existing_collection.get("complete", True)
            and incoming_collection.get("complete", True)
        )
        existing_collection["denied_actions"] = sorted(
            set(existing_collection.get("denied_actions", []))
            | set(incoming_collection.get("denied_actions", []))
        )
        existing_collection.setdefault("permission_checks", {}).update(
            incoming_collection.get("permission_checks", {})
        )
        existing_collection.setdefault("notes", []).extend(
            incoming_collection.get("notes", [])
        )
    return list(merged.values())
