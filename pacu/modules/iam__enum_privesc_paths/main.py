#!/usr/bin/env python3
"""Read-only IAM privilege-escalation path enumeration and reporting."""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from pacu.core.lib import downloads_dir, strip_lines
from .scanner import (
    filter_report,
    load_accounts_from_paths,
    scan_accounts,
    write_report,
)


module_info: Dict[str, Any] = {
    "name": "iam__enum_privesc_paths",
    "author": "Pacu Contributors",
    "category": "ENUM",
    "one_liner": "Enumerates IAM identities and reports validated privilege-escalation paths.",
    "description": strip_lines(
        """
        This read-only module enumerates IAM users, roles, groups, and their
        attached and inline policies, validates the actions required by known
        privilege-escalation primitives, and writes JSON and Markdown reports.

        Every finding contains the evidence used to validate its required
        permissions. Results are marked "confirmed" only when policy collection
        is complete and every required action is explicitly allowed without a
        restrictive condition. Otherwise they are marked "potential".

        Use --offline with --folder/--input to scan previously collected JSON
        evidence without making AWS API calls. The module never changes IAM
        resources.
    """
    ),
    "services": ["IAM", "STS"],
    "prerequisite_modules": [],
    "arguments_to_autocomplete": [
        "--offline",
        "--folder",
        "--input",
        "--output-dir",
        "--format",
        "--min-severity",
        "--strict",
    ],
}


parser = argparse.ArgumentParser(add_help=False, description=module_info["description"])
parser.add_argument(
    "--offline",
    action="store_true",
    default=False,
    help="Do not make AWS API calls. Requires --folder or --input.",
)
parser.add_argument(
    "--folder",
    "--input",
    dest="input_paths",
    nargs="+",
    default=None,
    help="JSON file(s) or directory containing account/identity evidence.",
)
parser.add_argument(
    "--output-dir",
    default=None,
    help="Report output directory. Defaults to the active Pacu session downloads directory.",
)
parser.add_argument(
    "--format",
    choices=("json", "markdown", "both"),
    default="both",
    help="Report format. Defaults to both.",
)
parser.add_argument(
    "--min-severity",
    choices=("low", "medium", "high", "critical"),
    default="low",
    help="Only include findings at or above this severity.",
)
parser.add_argument(
    "--strict",
    action="store_true",
    default=False,
    help="Exit without producing a report when permission validation is incomplete.",
)


def _error_code(error: ClientError) -> str:
    return str(error.response.get("Error", {}).get("Code", "Unknown"))


def _mark(
    checks: Dict[str, Dict[str, Any]],
    action: str,
    status: str,
    detail: Optional[str] = None,
) -> None:
    rank = {"ok": 0, "denied": 1, "error": 2}
    current = checks.get(action)
    if current and rank[current["status"]] > rank[status]:
        return
    checks[action] = {"status": status, "detail": detail or ""}


def _mark_error(checks: Dict[str, Dict[str, Any]], action: str, error: ClientError) -> None:
    code = _error_code(error)
    status = "denied" if code in ("AccessDenied", "AccessDeniedException") else "error"
    _mark(checks, action, status, code)


def _paged(
    client: Any,
    operation: str,
    result_key: str,
    action: str,
    checks: Dict[str, Dict[str, Any]],
    **kwargs: Any,
) -> Tuple[List[Dict[str, Any]], bool]:
    items: List[Dict[str, Any]] = []
    request = dict(kwargs)
    while True:
        try:
            response = getattr(client, operation)(**request)
        except ClientError as error:
            _mark_error(checks, action, error)
            return items, False
        items.extend(response.get(result_key, []))
        if not response.get("IsTruncated"):
            break
        marker = response.get("Marker")
        if not marker:
            break
        request["Marker"] = marker
    _mark(checks, action, "ok")
    return items, True


def _call(
    client: Any,
    operation: str,
    action: str,
    checks: Dict[str, Dict[str, Any]],
    **kwargs: Any,
) -> Tuple[Optional[Dict[str, Any]], bool]:
    try:
        response = getattr(client, operation)(**kwargs)
    except ClientError as error:
        _mark_error(checks, action, error)
        return None, False
    _mark(checks, action, "ok")
    return response, True


def _attached_policy_document(
    iam: Any,
    policy_arn: str,
    checks: Dict[str, Dict[str, Any]],
    cache: Dict[str, Optional[Dict[str, Any]]],
) -> Tuple[Optional[Dict[str, Any]], bool]:
    if policy_arn in cache:
        document = cache[policy_arn]
        return document, document is not None

    policy_response, policy_ok = _call(
        iam, "get_policy", "iam:GetPolicy", checks, PolicyArn=policy_arn
    )
    if not policy_ok or not policy_response:
        cache[policy_arn] = None
        return None, False

    policy = policy_response.get("Policy") or {}
    version_id = policy.get("DefaultVersionId")
    if not version_id:
        cache[policy_arn] = None
        return None, False

    version_response, version_ok = _call(
        iam,
        "get_policy_version",
        "iam:GetPolicyVersion",
        checks,
        PolicyArn=policy_arn,
        VersionId=version_id,
    )
    document = None
    if version_ok and version_response:
        document = (version_response.get("PolicyVersion") or {}).get("Document")
    cache[policy_arn] = document
    return document, document is not None


def _inline_document(
    iam: Any,
    operation: str,
    action: str,
    checks: Dict[str, Dict[str, Any]],
    **kwargs: Any,
) -> Tuple[Optional[Dict[str, Any]], bool]:
    response, ok = _call(iam, operation, action, checks, **kwargs)
    if not ok or not response:
        return None, False
    return response.get("PolicyDocument"), True


def _attached_policies(
    iam: Any,
    operation: str,
    action: str,
    checks: Dict[str, Dict[str, Any]],
    cache: Dict[str, Optional[Dict[str, Any]]],
    **kwargs: Any,
) -> Tuple[List[Dict[str, Any]], bool]:
    attached, ok = _paged(
        iam, operation, "AttachedPolicies", action, checks, **kwargs
    )
    documents = []
    for policy in attached:
        arn = policy.get("PolicyArn")
        if not arn:
            continue
        document, document_ok = _attached_policy_document(
            iam, arn, checks, cache
        )
        if document is None:
            ok = False
            continue
        documents.append(
            {
                "Source": "attached:{}".format(arn),
                "PolicyArn": arn,
                "Document": document,
            }
        )
    return documents, ok


def _identity_policies(
    iam: Any,
    identity_type: str,
    name: str,
    checks: Dict[str, Dict[str, Any]],
    policy_cache: Dict[str, Optional[Dict[str, Any]]],
) -> Tuple[List[Dict[str, Any]], bool]:
    policies: List[Dict[str, Any]] = []
    ok = True

    if identity_type == "user":
        inline_operation = "list_user_policies"
        inline_action = "iam:ListUserPolicies"
        inline_get_operation = "get_user_policy"
        inline_get_action = "iam:GetUserPolicy"
        inline_name_key = "UserName"
        attached_operation = "list_attached_user_policies"
        attached_action = "iam:ListAttachedUserPolicies"
    else:
        inline_operation = "list_role_policies"
        inline_action = "iam:ListRolePolicies"
        inline_get_operation = "get_role_policy"
        inline_get_action = "iam:GetRolePolicy"
        inline_name_key = "RoleName"
        attached_operation = "list_attached_role_policies"
        attached_action = "iam:ListAttachedRolePolicies"

    names, names_ok = _paged(
        iam,
        inline_operation,
        "PolicyNames",
        inline_action,
        checks,
        **{inline_name_key: name},
    )
    ok = ok and names_ok
    for policy_name in names:
        document, document_ok = _inline_document(
            iam,
            inline_get_operation,
            inline_get_action,
            checks,
            **{inline_name_key: name, "PolicyName": policy_name},
        )
        if document is None:
            ok = False
            continue
        policies.append(
            {
                "Source": "inline:{}".format(policy_name),
                "PolicyName": policy_name,
                "Document": document,
            }
        )

    attached, attached_ok = _attached_policies(
        iam,
        attached_operation,
        attached_action,
        checks,
        policy_cache,
        **{inline_name_key: name},
    )
    ok = ok and attached_ok
    policies.extend(attached)
    return policies, ok


def _group_policies(
    iam: Any,
    name: str,
    checks: Dict[str, Dict[str, Any]],
    policy_cache: Dict[str, Optional[Dict[str, Any]]],
) -> Tuple[List[Dict[str, Any]], bool]:
    policies: List[Dict[str, Any]] = []
    names, names_ok = _paged(
        iam,
        "list_group_policies",
        "PolicyNames",
        "iam:ListGroupPolicies",
        checks,
        GroupName=name,
    )
    ok = names_ok
    for policy_name in names:
        document, document_ok = _inline_document(
            iam,
            "get_group_policy",
            "iam:GetGroupPolicy",
            checks,
            GroupName=name,
            PolicyName=policy_name,
        )
        if document is None:
            ok = False
            continue
        policies.append(
            {
                "Source": "inline:{}".format(policy_name),
                "PolicyName": policy_name,
                "Document": document,
            }
        )

    attached, attached_ok = _attached_policies(
        iam,
        "list_attached_group_policies",
        "iam:ListAttachedGroupPolicies",
        checks,
        policy_cache,
        GroupName=name,
    )
    ok = ok and attached_ok
    policies.extend(attached)
    return policies, ok


def _caller_identity(iam: Any, sts: Any, checks: Dict[str, Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    response, ok = _call(
        sts, "get_caller_identity", "sts:GetCallerIdentity", checks
    )
    if not ok or not response:
        return None
    arn = str(response.get("Arn", ""))
    if ":user/" in arn:
        identity_type = "user"
        name = arn.split(":user/")[-1].split("/")[-1]
    elif ":assumed-role/" in arn:
        identity_type = "role"
        remainder = arn.split(":assumed-role/")[-1].split("/")
        name = remainder[-2] if len(remainder) > 1 else remainder[0]
    else:
        return None
    return {
        "Type": identity_type,
        "Name": name,
        "Arn": arn,
        "AccountId": response.get("Account"),
        "UserId": response.get("UserId"),
    }


def _add_or_get(
    collection: Dict[str, Dict[str, Any]], identity: Dict[str, Any]
) -> Dict[str, Any]:
    name = str(identity.get("Name") or identity.get("RoleName") or "unknown")
    existing = collection.get(name)
    if existing is None:
        existing = {
            key: value for key, value in identity.items() if value is not None
        }
        existing.setdefault("Name", name)
        collection[name] = existing
    else:
        for key, value in identity.items():
            if value is not None and not existing.get(key):
                existing[key] = value
    return existing


def collect_online_account(pacu_main: Any, print_fn: Any) -> Optional[Dict[str, Any]]:
    """Collect a read-only IAM snapshot using the active Pacu credentials."""
    iam = pacu_main.get_boto3_client("iam")
    sts = pacu_main.get_boto3_client("sts")
    if iam is None or sts is None:
        return None

    checks: Dict[str, Dict[str, Any]] = {}
    caller = _caller_identity(iam, sts, checks)
    if caller is None:
        print_fn("Permission validation failed: sts:GetCallerIdentity was not usable.")
        return None

    account_id = str(caller.get("AccountId") or "unknown")
    print_fn("Enumerating IAM identities in account {}...".format(account_id))

    users_raw, users_ok = _paged(
        iam, "list_users", "Users", "iam:ListUsers", checks
    )
    roles_raw, roles_ok = _paged(
        iam, "list_roles", "Roles", "iam:ListRoles", checks
    )
    groups_raw, _ = _paged(
        iam, "list_groups", "Groups", "iam:ListGroups", checks
    )

    users = {
        str(item.get("UserName")): dict(item, Type="user")
        for item in users_raw
        if item.get("UserName")
    }
    roles = {
        str(item.get("RoleName")): dict(item, Type="role")
        for item in roles_raw
        if item.get("RoleName")
    }
    groups = {
        str(item.get("GroupName")): dict(item, Type="group")
        for item in groups_raw
        if item.get("GroupName")
    }

    if caller["Type"] == "user" and (
        not users_ok or caller["Name"] in users
    ):
        _add_or_get(users, caller)
    elif caller["Type"] == "role" and (
        not roles_ok or caller["Name"] in roles
    ):
        _add_or_get(roles, caller)

    policy_cache: Dict[str, Optional[Dict[str, Any]]] = {}
    group_ok: Dict[str, bool] = {}

    for name, group in groups.items():
        policies, ok = _group_policies(iam, name, checks, policy_cache)
        group["Policies"] = policies
        group["PermissionsConfirmed"] = ok
        group_ok[name] = ok

    for name, user in users.items():
        arn = user.get("Arn") or "arn:aws:iam::{}:user/{}".format(account_id, name)
        memberships, memberships_ok = _paged(
            iam,
            "list_groups_for_user",
            "Groups",
            "iam:ListGroupsForUser",
            checks,
            UserName=name,
        )
        for item in memberships:
            group_name = item.get("GroupName")
            if not group_name or group_name in groups:
                continue
            policies, ok = _group_policies(iam, group_name, checks, policy_cache)
            groups[group_name] = {
                "GroupName": group_name,
                "Type": "group",
                "Policies": policies,
                "PermissionsConfirmed": ok,
            }
            group_ok[group_name] = ok
        user["Groups"] = [
            {"GroupName": item["GroupName"]}
            for item in memberships
            if item.get("GroupName")
        ]
        policies, policies_ok = _identity_policies(
            iam, "user", name, checks, policy_cache
        )
        user.update(
            {
                "Type": "user",
                "Name": name,
                "Arn": arn,
                "Policies": policies,
                "PermissionsConfirmed": (
                    memberships_ok
                    and policies_ok
                    and all(
                        group_ok.get(item["GroupName"], False)
                        for item in user["Groups"]
                    )
                ),
            }
        )

    for name, role in roles.items():
        arn = role.get("Arn") or "arn:aws:iam::{}:role/{}".format(account_id, name)
        policies, policies_ok = _identity_policies(
            iam, "role", name, checks, policy_cache
        )
        role.update(
            {
                "Type": "role",
                "Name": name,
                "Arn": arn,
                "Policies": policies,
                "PermissionsConfirmed": policies_ok,
            }
        )

    statuses = [item["status"] for item in checks.values()]
    denied_actions = sorted(
        action for action, item in checks.items() if item["status"] == "denied"
    )
    complete = all(status == "ok" for status in statuses)
    print_fn(
        "Permission checks: {} allowed, {} denied, {} error(s).".format(
            statuses.count("ok"),
            statuses.count("denied"),
            statuses.count("error"),
        )
    )
    if denied_actions:
        print_fn(
            "  Incomplete evidence due to denied read actions: {}".format(
                ", ".join(denied_actions)
            )
        )

    return {
        "account_id": account_id,
        "name": account_id,
        "identities": list(users.values()) + list(roles.values()),
        "groups": list(groups.values()),
        "collection": {
            "complete": complete,
            "denied_actions": denied_actions,
            "permission_checks": checks,
            "notes": ["Read-only live IAM collection."],
        },
    }


def main(module_args: List[str], pacu_main: Any) -> Optional[Dict[str, Any]]:
    args = parser.parse_args(module_args)
    print_fn = pacu_main.print

    if args.offline and not args.input_paths:
        default_folder = downloads_dir() / "confirmed_permissions"
        if default_folder.is_dir():
            args.input_paths = [str(default_folder)]
            print_fn(
                "No --folder/--input supplied; using {}".format(default_folder)
            )
        else:
            print_fn(
                "--offline requires --folder or --input (or run "
                "iam__enum_permissions --all-users --all-roles first)."
            )
            return None

    if args.input_paths:
        try:
            accounts = load_accounts_from_paths(args.input_paths)
        except (OSError, ValueError) as error:
            print_fn("Unable to load offline evidence: {}".format(error))
            return None
        if not accounts:
            print_fn("No account evidence was found in the supplied path(s).")
            return None
        print_fn(
            "Loaded {} account(s) from offline evidence; no AWS API calls will be made.".format(
                len(accounts)
            )
        )
    else:
        if args.offline:
            print_fn("--offline requires --folder or --input.")
            return None
        account = collect_online_account(pacu_main, print_fn)
        if account is None:
            return None
        accounts = [account]

    report = scan_accounts(accounts)
    report = filter_report(report, min_severity=args.min_severity)

    if args.strict and report["summary"]["incomplete_accounts"]:
        print_fn(
            "Strict mode: permission validation is incomplete for {} account(s).".format(
                report["summary"]["incomplete_accounts"]
            )
        )
        return None

    if args.output_dir:
        output_dir = Path(args.output_dir).expanduser()
    else:
        output_dir = downloads_dir()

    report_paths = write_report(report, output_dir, args.format)
    print_fn(
        "Findings: {} confirmed, {} potential.".format(
            report["summary"]["confirmed_findings"],
            report["summary"]["potential_findings"],
        )
    )
    for report_type, report_path in report_paths.items():
        print_fn("{} report: {}".format(report_type.capitalize(), report_path))

    return {
        "accounts": report["summary"]["accounts"],
        "identities": report["summary"]["identities"],
        "findings": report["summary"]["findings"],
        "confirmed": report["summary"]["confirmed_findings"],
        "potential": report["summary"]["potential_findings"],
        "incomplete_accounts": report["summary"]["incomplete_accounts"],
        "report_paths": report_paths,
    }


def summary(data: Dict[str, Any], pacu_main: Any) -> str:
    lines = [
        "  Scanned {} account(s) and {} identity/identities.".format(
            data["accounts"], data["identities"]
        ),
        "  Found {} path(s): {} confirmed, {} potential.".format(
            data["findings"], data["confirmed"], data["potential"]
        ),
    ]
    if data["incomplete_accounts"]:
        lines.append(
            "  Warning: {} account(s) had incomplete permission evidence.".format(
                data["incomplete_accounts"]
            )
        )
    for report_type, report_path in data.get("report_paths", {}).items():
        lines.append("  {} report: {}".format(report_type.capitalize(), report_path))
    return "\n".join(lines) + "\n"
