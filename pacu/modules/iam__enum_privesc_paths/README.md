# iam__enum_privesc_paths

Read-only IAM privilege-escalation path enumeration for Pacu. The module
collects IAM users, roles, groups, inline policies, and attached policies,
validates the actions required by known escalation primitives, and writes a
JSON and Markdown report.

## Usage

Live collection with the active Pacu credentials:

```text
run iam__enum_privesc_paths
```

Offline scan of a folder containing account evidence or Pacu
`confirmed_permissions/user-*.json` / `role-*.json` files:

```text
run iam__enum_privesc_paths --offline --folder /path/to/evidence --output-dir /tmp/report
```

Useful options:

- `--format json|markdown|both` controls report output (default: `both`).
- `--min-severity low|medium|high|critical` filters findings.
- `--strict` refuses to produce a report when permission collection is
  incomplete.

## Permission validation

The online collector records the result of every IAM read action it attempts.
An `AccessDenied` response is stored in `collection.denied_actions` and makes
the account evidence incomplete. The scanner also evaluates each required
action against Allow and Deny statements, including wildcard actions,
`NotAction`, `NotResource`, and policy conditions.

A finding is `confirmed` only when collection is complete and every required
action is explicitly allowed on `*` without a restrictive condition.
Restricted, conditional, or incomplete evidence produces a `potential`
finding instead. The module never modifies IAM resources.

## Offline account schema

The minimal schema is:

```json
{
  "account_id": "111122223333",
  "name": "example",
  "collection": {
    "complete": true,
    "denied_actions": []
  },
  "groups": [
    {
      "GroupName": "Developers",
      "Policies": [
        {
          "Document": {
            "Version": "2012-10-17",
            "Statement": [
              {
                "Effect": "Allow",
                "Action": "iam:AttachUserPolicy",
                "Resource": "*"
              }
            ]
          }
        }
      ]
    }
  ],
  "identities": [
    {
      "Type": "user",
      "Name": "alice",
      "Arn": "arn:aws:iam::111122223333:user/alice",
      "Groups": ["Developers"],
      "Policies": [],
      "PermissionsConfirmed": true
    }
  ]
}
```

An input file may contain one account, a list of accounts, or a top-level
`{"accounts": [...]}` object. Existing Pacu confirmed-permissions files are
also accepted and grouped by account ID.
