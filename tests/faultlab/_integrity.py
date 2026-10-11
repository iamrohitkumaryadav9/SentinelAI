"""Phase 1C M4 integrity policy (AMD-18): exact-path change control for code and FaultLab data.

check(repo, policy) returns a sorted list of violations; [] means the repository satisfies the policy.

- Every change since the fixed anchor commit inside the governed scope must be an exact allowed path, an append-only
  raw dataset file, the dataset manifest, or a pinned file whose content matches its SHA-256 pin.
- Rename detection is off and all git output is NUL-separated, so renames show as delete + add and paths with
  whitespace stay whole. Global and system git configuration is ignored.
- Only regular files (mode 100644) may be added or modified: no symlinks, executables or submodules.
- Raw files are append-only across every commit after the anchor, and every raw file is listed in the manifest with
  its SHA-256. Manifest entries are never rewritten or dropped.
- The working tree may not hold tracked modifications, or untracked or ignored files inside the working-tree scope
  (apart from the listed build-output prefixes and __pycache__ directories).
Read-only: uses git rev-parse/merge-base/diff/log/ls-tree/ls-files/cat-file only (no index writes).
"""
import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple

GIT_ENV = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0",
           "GIT_OPTIONAL_LOCKS": "0"}
RUN_ID = r"[A-Z0-9]+(?:-[A-Z0-9]+)*-s[0-9]+"           # run_id = <scenario_id>-s<seed> (design §8)
REGULAR = "100644"


@dataclass(frozen=True)
class Policy:
    anchor: str                                       # approved commit; everything after it is governed
    add_or_modify: FrozenSet[str] = frozenset()       # exact paths that may be added or modified
    add_only: FrozenSet[str] = frozenset()            # exact paths that may only be added (never changed later)
    pinned: Dict[str, str] = field(default_factory=dict)   # exact path -> required SHA-256 of its HEAD content
    diff_scope: Tuple[str, ...] = ("src/", "tests/", "scripts/", "ebpf/", "contract/", "datasets/", "experiments/",
                                   "docs/EVIDENCE_CONTRACT.md")
    tree_scope: Tuple[str, ...] = ("src", "ebpf", "contract", "scripts", "tests", "datasets")
    ignored_ok: Tuple[str, ...] = ("ebpf/build/",)
    raw_root: str = "datasets/faultlab/v1/raw/"
    manifest: str = "datasets/faultlab/v1/manifest.json"

    def raw_re(self):
        return re.compile(re.escape(self.raw_root) + RUN_ID + r"/[a-z0-9_]+\.jsonl\.gz")


def git(repo, *args, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env={**os.environ, **GIT_ENV},
                          check=check)


def _z(out: bytes) -> List[str]:
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


def _blob(repo, rev, path) -> Optional[bytes]:
    r = git(repo, "cat-file", "blob", f"{rev}:{path}", check=False)
    return r.stdout if r.returncode == 0 else None


def _manifest(repo, rev, path) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    blob = _blob(repo, rev, path)
    if blob is None:
        return None, None
    try:
        files = json.loads(blob)["files"]
        if not isinstance(files, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in files.items()):
            raise ValueError
        return files, None
    except (ValueError, KeyError, TypeError):
        return None, f"manifest at {rev[:12]} malformed"


def history_statuses(repo, anchor, paths) -> List[Tuple[str, str]]:
    """(status, path) for every commit after anchor touching paths, rename detection off."""
    t = _z(git(repo, "log", "--no-renames", "-z", "--format=", "--name-status", f"{anchor}..HEAD", "--", *paths).stdout)
    return list(zip(t[0::2], t[1::2]))


def check(repo, policy: Policy) -> List[str]:
    anchor = policy.anchor
    if git(repo, "rev-parse", "--verify", "--quiet", f"{anchor}^{{commit}}", check=False).returncode:
        return [f"anchor {anchor} not present (shallow clone or rewritten history)"]
    if git(repo, "merge-base", "--is-ancestor", anchor, "HEAD", check=False).returncode:
        return [f"anchor {anchor} is not an ancestor of HEAD"]
    v: List[str] = []
    raw_re = policy.raw_re()
    in_scope = lambda p: p.startswith(policy.diff_scope)

    # 1. every governed change since the anchor (renames appear as D + A)
    t = _z(git(repo, "diff", "--no-renames", "-z", "--name-status", anchor, "HEAD").stdout)
    changes = [(s, p) for s, p in zip(t[0::2], t[1::2]) if in_scope(p)]
    for status, path in changes:
        if path in policy.pinned:
            if status not in ("A", "M"):
                v.append(f"pinned path has status {status}: {path!r}")
        elif path in policy.add_only:
            if status != "A":
                v.append(f"add-only path has status {status}: {path!r}")
        elif path in policy.add_or_modify:
            if status not in ("A", "M"):
                v.append(f"allowed path has status {status}: {path!r}")
        elif raw_re.fullmatch(path):
            if status != "A":
                v.append(f"raw file not append-only: {status} {path!r}")
        elif path == policy.manifest:
            if status not in ("A", "M"):
                v.append(f"manifest has status {status}")
        else:
            v.append(f"path not allowed: {status} {path!r}")

    # 2. pins hold at HEAD whether or not the file changed
    for path, sha in sorted(policy.pinned.items()):
        blob = _blob(repo, "HEAD", path)
        if blob is None or hashlib.sha256(blob).hexdigest() != sha:
            v.append(f"pinned content mismatch: {path!r}")

    # 3. add-only and raw paths: no later commit may modify, delete or retype them
    for status, path in history_statuses(repo, anchor, [policy.raw_root, *sorted(policy.add_only)]):
        if status != "A":
            v.append(f"history not append-only: {status} {path!r}")

    # 4. modes of everything added or modified in scope
    touched = [p for s, p in changes if s in ("A", "M")]
    if touched:
        for line in _z(git(repo, "ls-tree", "-z", "HEAD", "--", *touched).stdout):
            meta, path = line.split("\t", 1)
            if meta.split()[0] != REGULAR:
                v.append(f"mode {meta.split()[0]} not allowed: {path!r}")

    # 5. manifest covers every raw file with its SHA-256; its history only ever adds entries
    raw_head = _z(git(repo, "ls-tree", "-r", "-z", "--name-only", "HEAD", "--", policy.raw_root).stdout)
    files, err = _manifest(repo, "HEAD", policy.manifest)
    if err:
        v.append(err)
    elif raw_head or files is not None:
        files = files or {}
        for p in raw_head:
            blob = _blob(repo, "HEAD", p)
            if p not in files:
                v.append(f"raw file not in manifest: {p!r}")
            elif blob is None or hashlib.sha256(blob).hexdigest() != files[p]:
                v.append(f"sha256 mismatch: {p!r}")
        for p in sorted(set(files) - set(raw_head)):
            v.append(f"manifest lists missing file: {p!r}")
    prev = _manifest(repo, anchor, policy.manifest)[0] or {}
    for rev in git(repo, "rev-list", "--reverse", f"{anchor}..HEAD", "--", policy.manifest).stdout.decode().split():
        cur, err = _manifest(repo, rev, policy.manifest)
        if err or cur is None:
            v.append(err or f"manifest removed at {rev[:12]}")
            continue
        for p, h in prev.items():
            if cur.get(p) != h:
                v.append(f"manifest entry rewritten or dropped at {rev[:12]}: {p!r}")
        prev = cur

    # 6. working tree: nothing uncommitted anywhere; nothing untracked or ignored inside the tree scope
    for args in (("diff", "-z", "--no-renames", "--name-only"), ("diff", "-z", "--no-renames", "--name-only", "--cached")):
        for p in _z(git(repo, *args).stdout):
            v.append(f"uncommitted tracked change: {p!r}")
    for p in _z(git(repo, "ls-files", "-z", "--others", "--exclude-standard", "--", *policy.tree_scope).stdout):
        v.append(f"untracked file in scope: {p!r}")
    for p in _z(git(repo, "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--",
                    *policy.tree_scope).stdout):
        if "__pycache__/" in p or p.startswith(policy.ignored_ok):
            continue
        v.append(f"ignored file in scope: {p!r}")
    return sorted(set(v))
