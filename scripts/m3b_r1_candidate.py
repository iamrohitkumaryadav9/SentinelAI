#!/usr/bin/env python3
"""M3B R1: confirm the checkout under test is the approved M3B candidate.

HEAD may be the candidate itself or a descendant whose only changes since the candidate are R1 validation
tooling (the files below). Any other changed path (M3B source, collectors, contract, M2, build) or a modified
tracked file is refused, so the runtime evidence always describes the candidate's implementation.

Usage: m3b_r1_candidate.py REPO CANDIDATE_SHA    (exit 0 and prints the HEAD sha, or exit 3 with the reason)
"""

import subprocess
import sys

TOOLING = ("scripts/m3b_r1_validate.sh", "scripts/m3b_r1_validate.py", "scripts/m3b_r1_compare.py",
           "scripts/m3b_r1_candidate.py", "tests/ebpf/test_r1_compare.py", "tests/ebpf/test_r1_candidate.py")


def git(repo, *args):
    p = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    return p.returncode, p.stdout.strip()


def check(repo: str, candidate: str):
    """Returns (ok, head_sha_or_reason)."""
    rc, head = git(repo, "rev-parse", "HEAD")
    if rc:
        return False, "not a git checkout"
    rc, cand = git(repo, "rev-parse", "--verify", f"{candidate}^{{commit}}")
    if rc:
        return False, f"candidate {candidate} not found"
    if git(repo, "merge-base", "--is-ancestor", cand, head)[0]:
        return False, f"HEAD {head} does not descend from candidate {cand}"
    _, changed = git(repo, "diff", "--name-only", cand, head)
    other = sorted(p for p in changed.splitlines() if p and p not in TOOLING)
    if other:
        return False, f"paths changed since candidate {cand[:7]} beyond R1 tooling: {other}"
    _, dirty = git(repo, "status", "--porcelain", "--untracked-files=no")
    if dirty:
        return False, f"tracked files modified: {dirty.splitlines()}"
    return True, head


if __name__ == "__main__":
    ok, msg = check(sys.argv[1], sys.argv[2])
    print(msg)
    sys.exit(0 if ok else 3)
