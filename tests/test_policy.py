import copy
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from policy import evaluate  # noqa: E402

GOOD_PERMISSIONS = {"contents": "read", "packages": "write", "id-token": "none"}


def base_preview_payload():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature/x",
        "workflow": {
            "trigger": "pull_request",
            "permissions": copy.deepcopy(GOOD_PERMISSIONS),
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"},
                {
                    "owner": "some-org",
                    "name": "custom-action",
                    "ref": "a" * 40,
                },
            ],
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True,
        },
    }


def base_production_payload():
    p = base_preview_payload()
    p["target"] = "production"
    p["event"] = "push"
    p["ref"] = "refs/heads/main"
    p["workflow"]["trigger"] = "push"
    p["workflow"]["environmentApproval"] = True
    return p


def test_preview_safe_promotes():
    result = evaluate(base_preview_payload())
    assert result == {"decision": "promote", "violations": []}


def test_production_safe_promotes():
    result = evaluate(base_production_payload())
    assert result == {"decision": "promote", "violations": []}


def test_excess_permission_extra_scope():
    p = base_preview_payload()
    p["workflow"]["permissions"]["actions"] = "write"
    result = evaluate(p)
    assert "EXCESS_PERMISSION" in result["violations"]
    assert result["decision"] == "block"


def test_excess_permission_wrong_value():
    p = base_preview_payload()
    p["workflow"]["permissions"]["id-token"] = "write"
    result = evaluate(p)
    assert result["violations"] == ["EXCESS_PERMISSION"]


def test_unsafe_pr_trigger():
    p = base_preview_payload()
    p["workflow"]["trigger"] = "pull_request_target"
    result = evaluate(p)
    assert result["violations"] == ["UNSAFE_PR_TRIGGER"]


def test_tests_incomplete_failed_tests():
    p = base_preview_payload()
    p["workflow"]["testsPassed"] = False
    result = evaluate(p)
    assert result["violations"] == ["TESTS_INCOMPLETE"]


def test_tests_incomplete_matrix():
    p = base_preview_payload()
    p["workflow"]["matrixComplete"] = False
    result = evaluate(p)
    assert result["violations"] == ["TESTS_INCOMPLETE"]


def test_tests_incomplete_fail_fast():
    p = base_preview_payload()
    p["workflow"]["failFast"] = True
    result = evaluate(p)
    assert result["violations"] == ["TESTS_INCOMPLETE"]


def test_mutable_action_third_party_tag():
    p = base_preview_payload()
    p["workflow"]["actions"][1]["ref"] = "v1.2.3"
    result = evaluate(p)
    assert result["violations"] == ["MUTABLE_ACTION"]


def test_mutable_action_short_hex():
    p = base_preview_payload()
    p["workflow"]["actions"][1]["ref"] = "deadbeef"
    result = evaluate(p)
    assert result["violations"] == ["MUTABLE_ACTION"]


def test_mutable_action_uppercase_sha_rejected():
    p = base_preview_payload()
    p["workflow"]["actions"][1]["ref"] = "A" * 40
    result = evaluate(p)
    assert result["violations"] == ["MUTABLE_ACTION"]


def test_actions_owner_may_use_tag():
    p = base_preview_payload()
    # only the "actions" owned entry, tagged, no third-party entries
    p["workflow"]["actions"] = [{"owner": "actions", "name": "checkout", "ref": "v4"}]
    result = evaluate(p)
    assert result == {"decision": "promote", "violations": []}


def test_single_stage_image():
    p = base_preview_payload()
    p["image"]["multiStage"] = False
    result = evaluate(p)
    assert result["violations"] == ["SINGLE_STAGE_IMAGE"]


def test_root_runtime():
    p = base_preview_payload()
    p["image"]["runsAsRoot"] = True
    result = evaluate(p)
    assert result["violations"] == ["ROOT_RUNTIME"]


def test_secret_in_layer_arg():
    p = base_preview_payload()
    p["image"]["secretMode"] = "arg"
    result = evaluate(p)
    assert result["violations"] == ["SECRET_IN_LAYER"]


def test_secret_in_layer_copy():
    p = base_preview_payload()
    p["image"]["secretMode"] = "copy"
    result = evaluate(p)
    assert result["violations"] == ["SECRET_IN_LAYER"]


def test_secret_mode_buildkit_ok():
    p = base_preview_payload()
    p["image"]["secretMode"] = "buildkit"
    result = evaluate(p)
    assert result == {"decision": "promote", "violations": []}


def test_critical_cve():
    p = base_preview_payload()
    p["image"]["criticalVulnerabilities"] = 3
    result = evaluate(p)
    assert result["violations"] == ["CRITICAL_CVE"]


def test_unpinned_image():
    p = base_preview_payload()
    p["image"]["digestPinned"] = False
    result = evaluate(p)
    assert result["violations"] == ["UNPINNED_IMAGE"]


def test_invalid_production_ref_wrong_branch():
    p = base_production_payload()
    p["ref"] = "refs/heads/release"
    result = evaluate(p)
    assert result["violations"] == ["INVALID_PRODUCTION_REF"]


def test_invalid_production_ref_wrong_event():
    p = base_production_payload()
    p["event"] = "pull_request"
    result = evaluate(p)
    assert "INVALID_PRODUCTION_REF" in result["violations"]


def test_approval_required():
    p = base_production_payload()
    p["workflow"]["environmentApproval"] = False
    result = evaluate(p)
    assert result["violations"] == ["APPROVAL_REQUIRED"]


def test_approval_required_missing_field():
    p = base_production_payload()
    del p["workflow"]["environmentApproval"]
    result = evaluate(p)
    assert result["violations"] == ["APPROVAL_REQUIRED"]


def test_production_does_not_require_pr_fields():
    # production push should not trigger UNSAFE_PR_TRIGGER just because
    # it isn't a pull_request event
    p = base_production_payload()
    result = evaluate(p)
    assert "UNSAFE_PR_TRIGGER" not in result["violations"]


def test_multi_failure_combination():
    p = base_preview_payload()
    p["workflow"]["permissions"]["id-token"] = "write"
    p["workflow"]["trigger"] = "pull_request_target"
    p["workflow"]["testsPassed"] = False
    p["workflow"]["actions"][1]["ref"] = "not-a-sha"
    p["image"]["multiStage"] = False
    p["image"]["runsAsRoot"] = True
    p["image"]["secretMode"] = "copy"
    p["image"]["criticalVulnerabilities"] = 2
    p["image"]["digestPinned"] = False
    result = evaluate(p)
    expected = {
        "EXCESS_PERMISSION",
        "UNSAFE_PR_TRIGGER",
        "TESTS_INCOMPLETE",
        "MUTABLE_ACTION",
        "SINGLE_STAGE_IMAGE",
        "ROOT_RUNTIME",
        "SECRET_IN_LAYER",
        "CRITICAL_CVE",
        "UNPINNED_IMAGE",
    }
    assert set(result["violations"]) == expected
    assert result["decision"] == "block"


def test_production_multi_failure_combination():
    p = base_production_payload()
    p["ref"] = "refs/heads/dev"
    p["workflow"]["environmentApproval"] = False
    result = evaluate(p)
    assert set(result["violations"]) == {"INVALID_PRODUCTION_REF", "APPROVAL_REQUIRED"}


def test_decision_promote_only_when_empty():
    result = evaluate(base_preview_payload())
    assert (result["decision"] == "promote") == (result["violations"] == [])
