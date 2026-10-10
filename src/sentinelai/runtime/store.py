"""Filesystem artifact store: one write-once directory per run, <root>/<incident_id>/<run_key>/.

  * root is an existing absolute directory chosen by the caller; nothing is written outside it;
  * incident_id and run_key are single safe path segments (no separators, no '.'/'..', no absolute paths);
  * the run directory must not exist; files are created relative to its directory fd with
    O_CREAT | O_EXCL | O_NOFOLLOW (no overwrite, no symlink following, no silent replacement);
  * only the registered artifact names are accepted; events.jsonl is the single append-only file;
  * manifest.json (sha256 + size of every artifact) is written last and seals the run.
A run without manifest.json is incomplete. verify_run() recomputes every hash from disk.
"""

import hashlib
import json
import os
import stat
from typing import Dict

from ..diagnostic.contract.serialize import canonical_bytes
from .context import check_segment

MANIFEST = "manifest.json"
EVENTS = "events.jsonl"
ARTIFACTS = ("context.json", "acquisition.json", "ticks.jsonl", "snapshot.json", "parameter_set.json",
             "diagnosis.json", EVENTS, MANIFEST)
RUN_FORMAT = "sentinelai.run.v1"
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW


class StoreError(RuntimeError):
    """A store operation was refused (never partially applied silently)."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


class ArtifactStore:
    def __init__(self, root: str):
        if not isinstance(root, str) or not os.path.isabs(root):
            raise StoreError(f"store root must be an absolute path: {root!r}")
        real = os.path.realpath(root)
        if not os.path.isdir(real):
            raise StoreError(f"store root is not an existing directory: {root!r}")
        self.root = real

    def create_run(self, incident_id: str, run_key: str) -> "RunWriter":
        try:
            check_segment(incident_id, "incident_id")
            check_segment(run_key, "run_key")
        except ValueError as exc:
            raise StoreError(str(exc)) from None
        root_fd = os.open(self.root, _DIR_FLAGS)
        try:
            try:
                os.mkdir(incident_id, 0o755, dir_fd=root_fd)
            except FileExistsError:
                pass
            inc_fd = os.open(incident_id, _DIR_FLAGS, dir_fd=root_fd)      # refuses a symlinked incident dir
        finally:
            os.close(root_fd)
        try:
            try:
                os.mkdir(run_key, 0o755, dir_fd=inc_fd)
            except FileExistsError:
                raise StoreError(f"run {incident_id}/{run_key} already exists (write-once)") from None
            run_fd = os.open(run_key, _DIR_FLAGS, dir_fd=inc_fd)
        finally:
            os.close(inc_fd)
        return RunWriter(run_fd, os.path.join(self.root, incident_id, run_key))


class RunWriter:
    def __init__(self, dir_fd: int, path: str):
        self._fd, self.path = dir_fd, path
        self._hashes: Dict[str, str] = {}
        self._sizes: Dict[str, int] = {}
        self._events = None          # running sha256 of events.jsonl once created
        self._sealed = False

    def _check(self, name: str, *, events=False) -> None:
        if self._sealed:
            raise StoreError(f"run is sealed (manifest written): {name}")
        if name not in ARTIFACTS:
            raise StoreError(f"not a registered artifact name: {name!r}")
        if (name == EVENTS) != events:
            raise StoreError(f"{name}: use {'append_event' if name == EVENTS else 'write_bytes'}")
        if name == MANIFEST:
            raise StoreError("manifest.json is written only by seal()")

    def _create(self, name: str, data: bytes, extra_flags: int = 0) -> None:
        fd = os.open(name, _NEW_FILE | extra_flags, 0o644, dir_fd=self._fd)
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)

    def write_bytes(self, name: str, data: bytes) -> str:
        self._check(name)
        if not isinstance(data, bytes):
            raise StoreError(f"{name}: data must be bytes")
        if name in self._hashes:
            raise StoreError(f"{name} already written (write-once)")
        try:
            self._create(name, data)
        except FileExistsError:
            raise StoreError(f"{name} already exists (write-once)") from None
        self._hashes[name], self._sizes[name] = _sha(data), len(data)
        return self._hashes[name]

    def write_json(self, name: str, obj) -> str:
        """Contract canonical form (sorted keys; arrays as sets), the same bytes canonical_bytes() gives."""
        return self.write_bytes(name, canonical_bytes(obj))

    def append_event(self, line: str) -> None:
        self._check(EVENTS, events=True)
        if not isinstance(line, str) or "\n" in line:
            raise StoreError("an event is exactly one line")
        data = (line + "\n").encode("utf-8")
        if self._events is None:
            try:
                self._create(EVENTS, data)
            except FileExistsError:
                raise StoreError(f"{EVENTS} already exists") from None
            self._events, self._sizes[EVENTS] = hashlib.sha256(data), len(data)
        else:
            fd = os.open(EVENTS, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, dir_fd=self._fd)
            try:
                _write_all(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
            self._events.update(data)
            self._sizes[EVENTS] += len(data)

    def seal(self, meta: dict) -> str:
        """Write manifest.json last: sha256 and size of every artifact written, plus caller metadata."""
        if self._sealed:
            raise StoreError("run already sealed")
        files = {n: {"sha256": h, "bytes": self._sizes[n]} for n, h in self._hashes.items()}
        if self._events is not None:
            files[EVENTS] = {"sha256": self._events.hexdigest(), "bytes": self._sizes[EVENTS]}
        data = canonical_bytes({"format": RUN_FORMAT, "files": files, "meta": meta})
        try:
            self._create(MANIFEST, data)
        except FileExistsError:
            raise StoreError("manifest.json already exists") from None
        self._sealed = True
        os.close(self._fd)
        return _sha(data)

    def abandon(self) -> None:
        """Stop writing without a manifest: the run stays visibly incomplete."""
        if not self._sealed:
            self._sealed = True
            os.close(self._fd)


MAX_ARTIFACT_BYTES = 256 << 20


def read_artifact(run_dir: str, name: str) -> bytes:
    """Read-only: one registered artifact of a run, a regular file only, never through a symlink."""
    if name not in ARTIFACTS:
        raise StoreError(f"not a registered artifact name: {name!r}")
    try:
        fd = os.open(os.path.join(run_dir, name), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise StoreError(f"{name}: cannot open ({exc.strerror})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise StoreError(f"{name}: not a regular file")
        if st.st_size > MAX_ARTIFACT_BYTES:
            raise StoreError(f"{name}: larger than {MAX_ARTIFACT_BYTES} bytes")
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def verify_run(path: str) -> dict:
    """Read-only: complete iff manifest.json exists; ok iff the manifest is well formed, every listed file is a
    registered regular file whose sha256 and size match, and nothing unlisted is present."""
    names = sorted(os.listdir(path))
    if MANIFEST not in names:
        return {"complete": False, "ok": False, "reason": "manifest.json absent: run incomplete", "files": names}
    bad = lambda why: {"complete": True, "ok": False, "reason": why, "mismatch": [], "missing": [], "extra": []}
    try:
        manifest = json.loads(read_artifact(path, MANIFEST))
    except (StoreError, ValueError, UnicodeDecodeError) as exc:
        return bad(f"manifest.json unreadable: {exc}")
    listed = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(listed, dict) or not all(isinstance(r, dict) for r in listed.values()):
        return bad("manifest.json malformed: no files table")
    if manifest.get("format") != RUN_FORMAT:
        return bad(f"manifest.json format is not {RUN_FORMAT}")
    mismatch, missing = [], []
    for name, rec in sorted(listed.items()):
        if name == MANIFEST or name not in ARTIFACTS:
            mismatch.append(name)
            continue
        try:
            data = read_artifact(path, name)
        except StoreError:
            missing.append(name)
            continue
        if _sha(data) != rec.get("sha256") or len(data) != rec.get("bytes"):
            mismatch.append(name)
    extra = [n for n in names if n != MANIFEST and n not in listed]
    ok = not (mismatch or missing or extra)
    return {"complete": True, "ok": ok, "mismatch": mismatch, "missing": missing, "extra": extra}
