#!/usr/bin/env python3
"""Operator helper: require every PR head check to succeed before merging.

Branch protection is the final server authority. No force/admin bypass flag.
"""

import argparse
import json
import subprocess

EXPECTED = {"quality", "security-lab", "merge-gate"}


def gh(*args):
    return json.loads(subprocess.check_output(["gh", *args], text=True))


def validate(pr):
    if pr["state"] != "OPEN" or pr["isDraft"] or pr["baseRefName"] != "main":
        raise ValueError("Expected an open, ready PR targeting main")
    checks = pr["statusCheckRollup"] or []
    names = {c.get("name") or c.get("context") for c in checks}
    if not EXPECTED <= names:
        raise ValueError(f"Required checks have not run: {EXPECTED - names}")
    for check in checks:
        if check.get("__typename") == "CheckRun":
            passed = check.get("status") == "COMPLETED" and check.get("conclusion") == "SUCCESS"
        else:
            passed = check.get("state") == "SUCCESS"
        if not passed:
            raise ValueError(f"Check did not succeed: {check}")
    if pr["mergeStateStatus"] != "CLEAN":
        raise ValueError(f"PR is not current/mergeable: {pr['mergeStateStatus']}")
    return pr["headRefOid"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pr")
    args = parser.parse_args()
    pr = gh(
        "pr",
        "view",
        args.pr,
        "--json",
        "state,isDraft,baseRefName,statusCheckRollup,headRefOid,mergeStateStatus",
    )
    sha = validate(pr)
    subprocess.run(
        ["gh", "pr", "merge", args.pr, "--merge", "--match-head-commit", sha], check=True
    )


if __name__ == "__main__":
    main()
