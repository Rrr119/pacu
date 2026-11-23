import json
from pathlib import Path

from pacu.modules.iam__enum_privesc_paths import main as module
from pacu.modules.iam__enum_privesc_paths.scanner import (
    load_accounts_from_paths,
    render_markdown,
    scan_accounts,
    write_report,
)


FIXTURES = Path(__file__).parent / "fixtures" / "privesc_accounts"


def _load_fixture(name):
    with (FIXTURES / name).open(encoding="utf-8") as handle:
        return json.load(handle)


def _account(report, account_id):
    return {
        account["account_id"]: account for account in report["accounts"]
    }[account_id]


class FakePacu:
    def __init__(self):
        self.messages = []

    def print(self, message):
        self.messages.append(str(message))


def test_account_one_reports_confirmed_paths_and_skips_admin():
    report = scan_accounts(
        load_accounts_from_paths([str(FIXTURES / "account-111122223333.json")])
    )
    account = _account(report, "111122223333")
    findings = {
        (path["identity"]["name"], path["method"]): path
        for path in account["paths"]
    }

    assert account["collection"]["complete"] is True
    assert findings[("alice", "CreateAccessKey")]["status"] == "confirmed"
    assert findings[("alice", "AttachUserPolicy")]["status"] == "confirmed"
    assert findings[("deployer", "CreateEC2WithExistingIP")]["status"] == "confirmed"
    assert [item["name"] for item in account["admin_identities"]] == ["platform-admin"]


def test_account_two_explicit_deny_blocks_a_path_and_missing_actions_are_excluded():
    report = scan_accounts(
        load_accounts_from_paths([str(FIXTURES / "account-444455556666.json")])
    )
    account = _account(report, "444455556666")
    findings = {
        (path["identity"]["name"], path["method"]): path
        for path in account["paths"]
    }

    assert ("blocked", "CreateAccessKey") not in findings
    assert findings[("blocked", "AttachUserPolicy")]["status"] == "confirmed"
    assert not [
        path for path in account["paths"] if path["identity"]["name"] == "stuck"
    ]


def test_account_three_incomplete_collection_is_potential_only():
    report = scan_accounts(
        load_accounts_from_paths([str(FIXTURES / "account-777788889999.json")])
    )
    account = _account(report, "777788889999")
    findings = {
        (path["identity"]["name"], path["method"]): path
        for path in account["paths"]
    }

    assert account["collection"]["complete"] is False
    assert account["collection"]["denied_actions"] == ["iam:ListUsers"]
    assert (
        account["collection"]["permission_checks"]["iam:ListUsers"]["status"]
        == "denied"
    )
    assert findings[("partial-user", "PassExistingRoleToNewLambdaThenInvoke")][
        "status"
    ] == "potential"
    assert all(path["status"] != "confirmed" for path in account["paths"])


def test_three_account_scan_and_report_rendering(tmp_path):
    accounts = load_accounts_from_paths([str(FIXTURES)])
    report = scan_accounts(accounts)

    assert report["summary"]["accounts"] == 3
    assert {account["account_id"] for account in report["accounts"]} == {
        "111122223333",
        "444455556666",
        "777788889999",
    }
    markdown = render_markdown(report)
    assert "# IAM Privilege Escalation Path Report" in markdown
    assert "111122223333" in markdown
    assert "CreateAccessKey" in markdown

    paths = write_report(report, tmp_path, "both")
    assert Path(paths["json"]).is_file()
    assert Path(paths["markdown"]).is_file()
    written = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert written["summary"]["findings"] == report["summary"]["findings"]


def test_offline_module_run_uses_three_account_evidence(tmp_path):
    pacu = FakePacu()
    result = module.main(
        [
            "--offline",
            "--folder",
            str(FIXTURES),
            "--output-dir",
            str(tmp_path),
            "--format",
            "both",
        ],
        pacu,
    )

    assert result["accounts"] == 3
    assert result["confirmed"] > 0
    assert result["potential"] > 0
    assert result["incomplete_accounts"] == 1
    assert Path(result["report_paths"]["json"]).is_file()
    assert Path(result["report_paths"]["markdown"]).is_file()
    assert any("Loaded 3 account(s)" in message for message in pacu.messages)


def test_confirmed_permissions_files_merge_into_one_account(tmp_path):
    user = {
        "UserName": "alice",
        "Arn": "arn:aws:iam::111122223333:user/alice",
        "PermissionsConfirmed": True,
        "Permissions": {
            "Allow": {
                "iam:createaccesskey": {
                    "Resources": ["*"],
                    "Conditions": {},
                }
            },
            "Deny": {},
        },
    }
    role = {
        "RoleName": "deployer",
        "Arn": "arn:aws:iam::111122223333:role/deployer",
        "PermissionsConfirmed": True,
        "Permissions": {
            "Allow": {
                "iam:passrole": {
                    "Resources": ["*"],
                    "Conditions": {},
                },
                "ec2:runinstances": {
                    "Resources": ["*"],
                    "Conditions": {},
                },
            },
            "Deny": {},
        },
    }
    (tmp_path / "user-alice.json").write_text(json.dumps(user), encoding="utf-8")
    (tmp_path / "role-deployer.json").write_text(json.dumps(role), encoding="utf-8")

    accounts = load_accounts_from_paths([str(tmp_path)])
    report = scan_accounts(accounts)

    assert len(accounts) == 1
    assert report["summary"]["identities"] == 2
    assert {
        path["method"] for path in report["accounts"][0]["paths"]
    } >= {"CreateAccessKey", "CreateEC2WithExistingIP"}
