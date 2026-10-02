"""Read-only acquisition. The live reader can only read files under /proc and /sys.

There is no write, exec, network or privileged path in this module: files are opened with mode
"rb", directory listings and symlink reads are allowed, and every path is checked against an
allowlist before use.
"""

import errno
import os
from typing import Dict, List, Optional, Tuple, Union

from .errors import Bad, CollectorError, Status

ALLOWED_PREFIXES = ("/proc/", "/sys/")
MAX_BYTES = 1 << 20


def check_path(path: str) -> str:
    if not path.startswith(ALLOWED_PREFIXES) or "/../" in path or path.endswith("/..") or "\x00" in path:
        raise CollectorError(f"path outside the read-only allowlist: {path!r}")
    return path


def _bad(exc: OSError) -> Bad:
    if exc.errno in (errno.EACCES, errno.EPERM):
        return Bad(Status.DENIED, exc.strerror or "permission denied")
    return Bad(Status.ABSENT, exc.strerror or "not present")


class LiveReader:
    """Reads the running host. Read-only by construction."""

    def read(self, path: str) -> Union[str, Bad]:
        check_path(path)
        try:
            with open(path, "rb") as fh:
                data = fh.read(MAX_BYTES)
        except OSError as exc:
            return _bad(exc)
        try:
            return data.decode("ascii")
        except UnicodeDecodeError:
            return Bad(Status.MALFORMED, "non-ASCII content")

    def listdir(self, path: str) -> Union[List[str], Bad]:
        check_path(path)
        try:
            return sorted(os.listdir(path))
        except OSError as exc:
            return _bad(exc)

    def readlink(self, path: str) -> Union[str, Bad]:
        check_path(path)
        try:
            return os.readlink(path)
        except OSError as exc:
            return _bad(exc)


class FixtureReader:
    """Serves fixture content. files: path -> text | Bad; dirs: path -> [names] | Bad; links likewise."""

    def __init__(self, files: Dict[str, Union[str, Bad]], dirs: Optional[Dict] = None, links: Optional[Dict] = None):
        self.files, self.dirs, self.links = dict(files), dict(dirs or {}), dict(links or {})

    def read(self, path):
        check_path(path)
        return self.files.get(path, Bad(Status.ABSENT, "not present"))

    def listdir(self, path):
        check_path(path)
        v = self.dirs.get(path, Bad(Status.ABSENT, "not present"))
        return sorted(v) if isinstance(v, list) else v

    def readlink(self, path):
        check_path(path)
        return self.links.get(path, Bad(Status.ABSENT, "not present"))
