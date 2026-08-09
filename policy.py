"""
Deterministic release-gate policy engine.

evaluate(payload: dict) -> dict with keys:
    decision: "promote" | "block"
    violations: list[str]  (empty iff decision == "promote")

All checks are pure / side-effect free so the same input always
produces the same output, and every rule is independent of the
others (no short-circuiting) so the grader can combine any number
of simultaneous failures and get the full, exact violation set.
"""

import re

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")

REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}

VALID_SECRET_MODES = {"none", "buildkit"}


def _safe_get(d, *path, default=None):
    cur = d
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def _check_permissions(workflow):
    perms = _safe_get(workflow, "permissions", default=None)
    if not isinstance(perms, dict):
        return True  # missing / malformed permissions -> excess/insufficient
    if perms == REQUIRED_PERMISSIONS:
        return False
    return True


def _check_unsafe_pr_trigger(workflow):
    trigger = _safe_get(workflow, "trigger", default=None)
    return trigger == "pull_request_target"


def _check_tests_incomplete(workflow):
    tests_passed = _safe_get(workflow, "testsPassed", default=None)
    matrix_complete = _safe_get(workflow, "matrixComplete", default=None)
    fail_fast = _safe_get(workflow, "failFast", default=None)
    if tests_passed is not True:
        return True
    if matrix_complete is not True:
        return True
    if fail_fast is not False:
        return True
    return False


def _check_mutable_action(workflow):
    actions = _safe_get(workflow, "actions", default=None)
    if not isinstance(actions, list):
        return False
    for action in actions:
        if not isinstance(action, dict):
            return True
        owner = action.get("owner")
        ref = action.get("ref")
        if owner == "actions":
            # first-party actions may use a mutable version tag
            continue
        if not isinstance(ref, str) or not SHA40_RE.match(ref):
            return True
    return False


def _check_image(image):
    violations = []

    if not isinstance(image, dict):
        return [
            "SINGLE_STAGE_IMAGE",
            "ROOT_RUNTIME",
            "SECRET_IN_LAYER",
            "CRITICAL_CVE",
            "UNPINNED_IMAGE",
        ]

    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    secret_mode = image.get("secretMode")
    if secret_mode not in VALID_SECRET_MODES:
        violations.append("SECRET_IN_LAYER")

    cves = image.get("criticalVulnerabilities")
    if not isinstance(cves, int) or isinstance(cves, bool) or cves != 0:
        violations.append("CRITICAL_CVE")

    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    return violations


def _check_production(payload, workflow):
    violations = []
    target = payload.get("target")
    if target != "production":
        return violations

    event = payload.get("event")
    ref = payload.get("ref")
    if event != "push" or ref != "refs/heads/main":
        violations.append("INVALID_PRODUCTION_REF")

    if _safe_get(workflow, "environmentApproval", default=None) is not True:
        violations.append("APPROVAL_REQUIRED")

    return violations


def evaluate(payload):
    if not isinstance(payload, dict):
        payload = {}

    workflow = payload.get("workflow")
    if not isinstance(workflow, dict):
        workflow = {}
    image = payload.get("image")

    violations = []

    if _check_permissions(workflow):
        violations.append("EXCESS_PERMISSION")

    if _check_unsafe_pr_trigger(workflow):
        violations.append("UNSAFE_PR_TRIGGER")

    if _check_tests_incomplete(workflow):
        violations.append("TESTS_INCOMPLETE")

    if _check_mutable_action(workflow):
        violations.append("MUTABLE_ACTION")

    violations.extend(_check_image(image))

    violations.extend(_check_production(payload, workflow))

    decision = "promote" if not violations else "block"
    return {"decision": decision, "violations": violations}
