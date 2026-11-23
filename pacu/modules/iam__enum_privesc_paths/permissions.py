"""IAM policy normalization and permission evaluation.

The scanner deliberately keeps this logic independent from boto3 so that the
same decisions can be made for live enumeration and for offline evidence.
"""
from __future__ import annotations

import fnmatch
import json
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional


def load_policy_document(document: Any) -> Dict[str, Any]:
    """Return a policy document from the shapes used by boto3 and Pacu."""
    if document is None:
        return {}
    if isinstance(document, dict):
        if "PolicyDocument" in document:
            return load_policy_document(document["PolicyDocument"])
        if "Document" in document and "Statement" not in document:
            return load_policy_document(document["Document"])
        return document
    if isinstance(document, bytes):
        document = document.decode("utf-8", errors="replace")
    if isinstance(document, str):
        text = urllib.parse.unquote(document.strip())
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _action_matches(pattern: Any, action: str) -> bool:
    if not isinstance(pattern, str):
        return False
    return fnmatch.fnmatchcase(action.lower(), pattern.strip().lower())


def _statement_matches_action(statement: Dict[str, Any], action: str) -> bool:
    actions = statement.get("actions") or []
    not_actions = statement.get("not_actions") or []
    if actions:
        return any(_action_matches(pattern, action) for pattern in actions)
    if not_actions:
        return not any(_action_matches(pattern, action) for pattern in not_actions)
    return False


def _resource_matches(pattern: Any, resource: str) -> bool:
    if not isinstance(pattern, str):
        return False
    return fnmatch.fnmatchcase(resource, pattern)


def _statement_resources(statement: Dict[str, Any]) -> List[str]:
    return [str(item) for item in statement.get("resources", [])]


def _statement_not_resources(statement: Dict[str, Any]) -> List[str]:
    return [str(item) for item in statement.get("not_resources", [])]


def _resource_is_unrestricted(statement: Dict[str, Any], resource: Optional[str]) -> bool:
    if statement.get("conditions"):
        return False
    resources = _statement_resources(statement)
    not_resources = _statement_not_resources(statement)
    if resource is not None:
        return (
            not not_resources
            and bool(resources)
            and all(item == "*" for item in resources)
        )
    return not not_resources and resources == ["*"]


def _statement_matches_resource(
    statement: Dict[str, Any], resource: Optional[str]
) -> bool:
    if resource is None:
        return True

    not_resources = _statement_not_resources(statement)
    if any(_resource_matches(pattern, resource) for pattern in not_resources):
        return False

    resources = _statement_resources(statement)
    return not resources or any(
        _resource_matches(pattern, resource) for pattern in resources
    )


def _normalize_statement(
    raw_statement: Dict[str, Any], source: str
) -> Optional[Dict[str, Any]]:
    effect = str(raw_statement.get("Effect", "")).strip().lower()
    if effect not in ("allow", "deny"):
        return None

    actions = [
        str(item).strip()
        for item in _as_list(raw_statement.get("Action"))
        if isinstance(item, str)
    ]
    not_actions = [
        str(item).strip()
        for item in _as_list(raw_statement.get("NotAction"))
        if isinstance(item, str)
    ]
    resources = [
        str(item)
        for item in _as_list(raw_statement.get("Resource"))
        if isinstance(item, str)
    ]
    not_resources = [
        str(item)
        for item in _as_list(raw_statement.get("NotResource"))
        if isinstance(item, str)
    ]
    conditions = raw_statement.get("Condition") or {}
    if not isinstance(conditions, dict):
        conditions = {"raw": str(conditions)}

    if not actions and not not_actions:
        return None
    if not resources and not not_resources:
        resources = ["*"]

    return {
        "effect": effect,
        "actions": actions,
        "not_actions": not_actions,
        "resources": resources,
        "not_resources": not_resources,
        "conditions": conditions,
        "source": source,
    }


def statements_from_document(document: Any, source: str) -> List[Dict[str, Any]]:
    """Normalize an IAM policy document into a list of statements."""
    policy = load_policy_document(document)
    statements = _as_list(policy.get("Statement"))
    normalized = []
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            continue
        item = _normalize_statement(statement, "{}[{}]".format(source, index))
        if item is not None:
            normalized.append(item)
    return normalized


def statements_from_permissions(
    permissions: Optional[Dict[str, Any]], source: str
) -> List[Dict[str, Any]]:
    """Normalize Pacu's confirmed-permissions format.

    Example:
        {"Allow": {"iam:createaccesskey": {"Resources": ["*"]}}, "Deny": {}}
    """
    if not isinstance(permissions, dict):
        return []

    normalized = []
    for effect in ("Allow", "Deny"):
        actions = permissions.get(effect) or {}
        if not isinstance(actions, dict):
            continue
        for action, details in actions.items():
            if not isinstance(action, str) or not action:
                continue
            details = details if isinstance(details, dict) else {}
            resources = (
                details.get("Resources")
                or details.get("Resource")
                or details.get("resources")
                or ["*"]
            )
            if isinstance(resources, str):
                resources = [resources]
            resources = [str(item) for item in _as_list(resources)] or ["*"]
            conditions = (
                details.get("Conditions")
                or details.get("Condition")
                or details.get("conditions")
                or {}
            )
            if not isinstance(conditions, dict):
                conditions = {"raw": str(conditions)}
            normalized.append(
                {
                    "effect": effect.lower(),
                    "actions": [action],
                    "not_actions": [],
                    "resources": resources,
                    "not_resources": [],
                    "conditions": conditions,
                    "source": "{}:{}".format(source, effect.lower()),
                }
            )
    return normalized


def _evidence(statement: Dict[str, Any], resource: Optional[str]) -> str:
    actions = statement.get("actions") or statement.get("not_actions") or []
    resources = statement.get("resources") or statement.get("not_resources") or ["*"]
    suffix = ""
    if statement.get("conditions"):
        suffix = " (conditional)"
    return "{} {} on {}{} [{}]".format(
        statement.get("effect", "?").capitalize(),
        ", ".join(str(item) for item in actions),
        ", ".join(str(item) for item in resources),
        suffix,
        statement.get("source", "unknown"),
    )


def evaluate_action(
    statements: Iterable[Dict[str, Any]],
    action: str,
    resource: Optional[str] = None,
    known: bool = True,
) -> Dict[str, Any]:
    """Evaluate one IAM action against a set of normalized statements.

    ``known`` is false when policy collection was incomplete. In that case an
    absent Allow is reported as unknown rather than as a definitive denial.
    """
    action = str(action)
    matching_allow = []
    matching_deny = []
    allow_resources = set()
    deny_resources = set()
    allow_restricted = False
    deny_restricted = False

    for statement in statements:
        if not _statement_matches_action(statement, action):
            continue
        if not _statement_matches_resource(statement, resource):
            continue

        if statement.get("effect") == "allow":
            matching_allow.append(statement)
            allow_resources.update(_statement_resources(statement))
            if not _resource_is_unrestricted(statement, resource):
                allow_restricted = True
        elif statement.get("effect") == "deny":
            matching_deny.append(statement)
            deny_resources.update(_statement_resources(statement))
            if not _resource_is_unrestricted(statement, resource):
                deny_restricted = True

    evidence = [
        _evidence(statement, resource)
        for statement in matching_allow + matching_deny
    ]

    if matching_deny and not deny_restricted:
        decision = "denied"
    elif matching_allow and not allow_restricted and not matching_deny:
        decision = "allowed"
    elif matching_allow:
        decision = "conditional"
    elif known:
        decision = "not_allowed"
    else:
        decision = "unknown"

    return {
        "action": action,
        "decision": decision,
        "allowed": bool(matching_allow),
        "denied": bool(matching_deny and not deny_restricted),
        "restricted": bool(allow_restricted or deny_restricted),
        "conditional": any(
            statement.get("conditions")
            for statement in matching_allow + matching_deny
        ),
        "resources": sorted(allow_resources),
        "denied_resources": sorted(deny_resources),
        "evidence": evidence,
    }


def is_administrator(statements: Iterable[Dict[str, Any]], known: bool) -> bool:
    """Return true only when *:* on * is explicitly allowed and not denied."""
    decision = evaluate_action(statements, "*", "*", known=known)
    return decision["decision"] == "allowed"
