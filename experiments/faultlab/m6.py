"""Phase 1C M6 batch runner and dataset writer (FZ-M6-PLAN; AMD-29).

    sudo taskset -c 0-15 .venv/bin/python experiments/faultlab/m6.py lifecycle --campaign C --cycle K --execute
    sudo taskset -c 0-15 .venv/bin/python experiments/faultlab/m6.py run --campaign C --run-id M6-sNNNNNN --execute
    sudo taskset -c 0-15 .venv/bin/python experiments/faultlab/m6.py smoke --campaign C --family OV-1 --execute
    .venv/bin/python experiments/faultlab/m6.py batch-ids --batch K
    .venv/bin/python experiments/faultlab/m6.py pack --campaign C
    .venv/bin/python experiments/faultlab/m6.py unpack datasets/faultlab/v1/raw/M6-sNNNNNN OUT_DIR

Every run goes through pilot.ctrl (variant m6) with its committed matrix entry; every PI-0 cycle through
pilot.lifecycle. Runs and cycles are staged in results/phase1c_m6/<campaign>/ (ignored by git); `pack` turns each
finished directory into the committed raw dataset: datasets/faultlab/v1/raw/<run id>/<name>.jsonl.gz, gzip with a
fixed header, exact bytes, listed with its SHA-256 in datasets/faultlab/v1/manifest.json (append-only, AMD-18, U-6 A).

Collection rules (FZ-M6-PLAN): the matrix is committed before any run and must regenerate byte-identically from the
approved record; from the commit that adds it, only dataset paths and M6 documents may change, so the code is pinned
for all of M6; each batch is its own campaign with 5 PI-0 cycles at its commit; a run directory is never reused, a
failed run is kept and its seed never reused. Smoke runs (one per family, seeds 800001..) are never packed.
"""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pilot as P  # noqa: E402
import matrix as M  # noqa: E402

ROOT = HERE.parents[1]
STAGING = ROOT / "results" / "phase1c_m6"
DATASET = ROOT / "datasets" / "faultlab" / "v1"
RAW, MANIFEST, MATRIX = DATASET / "raw", DATASET / "manifest.json", DATASET / "matrix.json"
MATRIX_REL = "datasets/faultlab/v1/matrix.json"
MANIFEST_FORMAT = "sentinelai.faultlab.dataset.v1.manifest"
SMOKE_SEED_BASE = 800001
STREAMS = {"evidence/ticks.jsonl": "ticks", "evidence/client.jsonl": "client", "evidence/ebpf.jsonl": "ebpf",
           "ops.jsonl": "ops"}
RUN_DIR = re.compile(r"M6-s[0-9]{6}|PI0-[1-5]")
PINNED_OK = re.compile(r"datasets/faultlab/v1/(?:raw/.+|manifest\.json)|docs/PHASE_1C_M6_[A-Z0-9_]+\.md")


# ------------------------------------------------------------------------------------------ matrix and pin
def git(*args) -> str:
    """Read-only git as the invoking user (root may not read a user's repository: safe.directory)."""
    env = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C", "GIT_OPTIONAL_LOCKS": "0",
           "PATH": "/usr/bin:/bin"}
    pre = []
    if os.geteuid() == 0:
        pre = ["setpriv", f"--reuid={os.environ['SUDO_UID']}", f"--regid={os.environ['SUDO_GID']}", "--init-groups",
               "--"]
    return subprocess.run(pre + ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True,
                          env=env).stdout


def committed_matrix() -> dict:
    """The committed matrix, refused unless it is tracked, unchanged in the tree and regenerates byte-identically."""
    data = MATRIX.read_bytes()
    if git("ls-files", "--", MATRIX_REL).strip() != MATRIX_REL or git("status", "--porcelain", "--", MATRIX_REL):
        P.refuse("the matrix is not committed unchanged")
    if data != M.dump(M.generate(M.load())):
        P.refuse("the committed matrix does not regenerate from the approved record")
    return json.loads(data)


def pin_violations() -> list:
    """Paths changed since the commit that added the matrix, other than dataset paths and M6 documents."""
    adds = git("log", "--diff-filter=A", "--format=%H", "--", MATRIX_REL).split()
    if len(adds) != 1:
        P.refuse(f"the matrix must have been added exactly once (found {len(adds)})")
    changed = git("diff", "--name-only", adds[0], "HEAD").split()
    return [p for p in changed if not PINNED_OK.fullmatch(p)]


def entry(m: dict, run_id: str) -> dict:
    e = next((r for r in m["runs"] if r["run_id"] == run_id), None)
    if e is None:
        P.refuse(f"{run_id} is not a matrix run")
    return e


def smoke_entry(m: dict, family: str) -> dict:
    fams = sorted({r["family"] for r in m["runs"]}, key=lambda f: (len(f), f))
    if family not in fams:
        P.refuse(f"family {family!r} not in the matrix {fams}")
    e = dict(next(r for r in m["runs"] if r["family"] == family))
    seed = SMOKE_SEED_BASE + fams.index(family)
    return dict(e, seed=seed, run_id=f"M6-s{seed}", split="smoke", batch=0)


# ------------------------------------------------------------------------------------------ privileged stages
def staging_campaign(campaign: str) -> Path:
    if not P.CAMPAIGN.fullmatch(campaign or ""):
        P.refuse(f"campaign {campaign!r} is not a UTC stamp YYYYMMDDTHHMMSSZ")
    for d in (STAGING, STAGING / campaign):
        if d.is_symlink() or (d.exists() and not d.is_dir()):
            P.refuse(f"{d} is not a real directory")
    return STAGING / campaign


def new_dir(c: Path, name: str) -> Path:
    if not RUN_DIR.fullmatch(name):
        P.refuse(f"run name {name!r} not allowed")
    out = c / name
    if os.path.lexists(out):
        P.refuse(f"{out} already exists; a run directory is never reused")
    return out


def run_stage(a, run_preflight=None) -> int:
    """The gate in front of every host mutation: invocation, matrix and pin, run path, privileged preflight (full
    stage: every decision mandatory), PI-0 order."""
    P.check_invocation()
    c = staging_campaign(a.campaign)
    if a.cmd == "lifecycle":
        if not 1 <= a.cycle <= 5:
            P.refuse("PI-0 has cycles 1..5")
        out, e = new_dir(c, f"PI0-{a.cycle}"), None
    elif a.cmd == "smoke":
        e = smoke_entry(M.generate(M.load()), a.family)            # before the matrix is committed; never packed
        out = new_dir(c, e["run_id"])
    else:
        m = committed_matrix()
        bad = pin_violations()
        if bad:
            P.refuse(f"code changed since the matrix was committed: {bad[:8]}")
        e = entry(m, a.run_id)
        out = new_dir(c, e["run_id"])
    import preflight as PF
    rep = P.require_preflight(run_preflight or (lambda: PF.Preflight(PF.ReadOnlyHost(), str(P.DECISIONS),
                                                                     stage="full").run()))
    commit = next(x["observed"] for x in rep["checks"] if x["id"] == "INT-HEAD")
    if a.cmd != "lifecycle":
        P.require_pi0(c, commit)
    for d in (STAGING, c):
        if not d.exists():
            d.mkdir(mode=0o755)
            P.hand_over(d)
    try:
        rc = P.lifecycle(out, a.cycle, commit) if a.cmd == "lifecycle" else \
            P.ctrl(out, e["seed"], commit, variant="m6", scenario=e)
    finally:
        if out.is_dir() and not out.is_symlink():
            P.write_new(out / "preflight.json", P.dump(rep))
            P.hand_over(out)
    return rc


# ------------------------------------------------------------------------------------------ dataset writer
def gz(data: bytes) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0, compresslevel=9) as f:
        f.write(data)
    return buf.getvalue()


def raw_files(run_dir: Path) -> dict:
    """{raw name: gzip bytes}: each stream file as is; every other file as one line of documents.jsonl
    (path, sha256, exact content as utf-8 text or base64). Transport copies (lg/, collector/) are left out only when
    they are byte-identical to their evidence/ counterparts."""
    files, docs = {}, []
    for p in sorted(x for x in run_dir.rglob("*") if x.is_file() and not x.is_symlink()):
        rel = p.relative_to(run_dir).as_posix()
        data = p.read_bytes()
        top = rel.split("/", 1)[0]
        if top in ("lg", "collector"):
            twin = run_dir / "evidence" / rel.split("/", 1)[1]
            if not (twin.is_file() and twin.read_bytes() == data):
                raise SystemExit(f"{run_dir.name}/{rel}: transport copy differs from its evidence copy")
            continue
        if rel in STREAMS:
            files[f"{STREAMS[rel]}.jsonl.gz"] = gz(data)
            continue
        try:
            text, enc = data.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            text, enc = base64.b64encode(data).decode(), "base64"
        docs.append(json.dumps({"path": rel, "sha256": hashlib.sha256(data).hexdigest(), "encoding": enc,
                                "data": text}, sort_keys=True))
    files["documents.jsonl.gz"] = gz(("\n".join(docs) + "\n").encode())
    return files


def raw_id(campaign: str, name: str) -> str:
    """Dataset run id: the matrix run id, or PI0-<campaign>-s<cycle> for a PI-0 cycle (gate evidence)."""
    return f"PI0-{campaign}-s{name[4:]}" if name.startswith("PI0-") else name


def pack(campaign: str, m=None) -> dict:
    """Append every finished run of a campaign to the raw dataset and the manifest; never rewrites an entry."""
    m = m or json.loads(MATRIX.read_bytes())
    ids = {r["run_id"] for r in m["runs"]}
    c = staging_campaign(campaign)
    manifest = json.loads(MANIFEST.read_bytes()) if MANIFEST.exists() else {"format": MANIFEST_FORMAT, "files": {}}
    added, skipped = [], []
    for d in sorted(x for x in c.iterdir() if x.is_dir() and not x.is_symlink()):
        if not RUN_DIR.fullmatch(d.name) or (d.name.startswith("M6-") and d.name not in ids):
            skipped.append(d.name)                                    # smoke runs and anything else: never packed
            continue
        if not ((d / "evidence" / "run.json").exists() or (d / "run.json").exists()):
            skipped.append(d.name)
            continue
        rid = raw_id(campaign, d.name)
        dest = RAW / rid
        if dest.exists():
            skipped.append(d.name)                                    # append-only: already packed
            continue
        dest.mkdir(parents=True)
        for name, data in sorted(raw_files(d).items()):
            path = dest / name
            with open(path, "xb") as fh:
                fh.write(data)
            rel = path.relative_to(ROOT).as_posix()
            if rel in manifest["files"]:
                raise SystemExit(f"manifest already lists {rel}")
            manifest["files"][rel] = hashlib.sha256(data).hexdigest()
        added.append(rid)
    manifest["files"] = dict(sorted(manifest["files"].items()))
    tmp = MANIFEST.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    os.replace(tmp, MANIFEST)
    return {"campaign": campaign, "added": added, "skipped": skipped}


def unpack(raw_dir: Path, out: Path) -> list:
    """Rebuild a run directory byte-for-byte from its raw files (every document's SHA-256 checked)."""
    inv = {v: k for k, v in STREAMS.items()}
    written = []
    for f in sorted(raw_dir.glob("*.jsonl.gz")):
        data = gzip.decompress(f.read_bytes())
        if f.name == "documents.jsonl.gz":
            for line in data.decode().splitlines():
                d = json.loads(line)
                b = d["data"].encode() if d["encoding"] == "utf-8" else base64.b64decode(d["data"])
                if hashlib.sha256(b).hexdigest() != d["sha256"]:
                    raise SystemExit(f"{d['path']}: SHA-256 mismatch")
                written.append(_write(out / d["path"], b))
        else:
            written.append(_write(out / inv[f.name[:-len(".jsonl.gz")]], data))
    return sorted(written)


def _write(p: Path, data: bytes) -> str:
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "xb") as fh:
        fh.write(data)
    return str(p)


# ------------------------------------------------------------------------------------------ CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("lifecycle", "run", "smoke"):
        p = sub.add_parser(name)
        p.add_argument("--campaign", required=True)
        p.add_argument("--execute", action="store_true", help="required: this mutates the host")
        if name == "lifecycle":
            p.add_argument("--cycle", type=int, required=True)
        elif name == "run":
            p.add_argument("--run-id", required=True)
        else:
            p.add_argument("--family", required=True)
    b = sub.add_parser("batch-ids")
    b.add_argument("--batch", type=int, required=True)
    pk = sub.add_parser("pack")
    pk.add_argument("--campaign", required=True)
    up = sub.add_parser("unpack")
    up.add_argument("raw_dir")
    up.add_argument("out")
    a = ap.parse_args(argv)
    if a.cmd == "batch-ids":
        m = json.loads(MATRIX.read_bytes())
        ids = [r["run_id"] for r in m["runs"] if r["batch"] == a.batch]
        if not ids:
            P.refuse(f"batch {a.batch} is empty")
        print(" ".join(ids))
        return 0
    if a.cmd == "pack":
        if os.geteuid() == 0:
            P.refuse("pack runs as the invoking user, not root")
        print(json.dumps(pack(a.campaign)))
        return 0
    if a.cmd == "unpack":
        print(json.dumps(unpack(Path(a.raw_dir), Path(a.out))))
        return 0
    if not a.execute:
        P.refuse("--execute not given")
    return run_stage(a)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except P.Refused as r:
        sys.exit(r.code)
