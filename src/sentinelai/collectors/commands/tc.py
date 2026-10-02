"""Read-only qdisc statistics: the single permitted command, ``tc -s -j qdisc show dev <interface>``.

Safety contract (M3A-C1):
  * the argv is fixed except for the interface; it is checked against the exact allowed pattern
    before every execution, and no other tc subcommand or option can be built;
  * argv-style execution with ``shell=False``; no shell, no command string, minimal environment,
    stdin closed;
  * the interface must be a plain interface name (no '/', whitespace, shell metacharacters or
    leading '-'), and must not be protected: any physical interface (its sysfs device is not under
    /devices/virtual/net/) or an interface listed in data/protected_interfaces.json is refused;
  * a short timeout (TIMEOUT_S); every failure becomes a structured Bad, never an exception that
    stops the observation tick.
"""

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Callable, Tuple, Union

from ..errors import Bad, CollectorError, Status

TC_PATH = "/usr/sbin/tc"
TIMEOUT_S = 2.0
MAX_OUTPUT = 1 << 20
ENV = {"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"}
ALLOWED_PREFIX = ("-s", "-j", "qdisc", "show", "dev")
FORBIDDEN_TOKENS = frozenset({"add", "change", "replace", "delete", "del", "class", "filter", "netem", "ingress",
                              "egress", "link", "exec", "-b", "-batch", "-force", "-n", "-netns"})
_IFNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$")      # Linux IFNAMSIZ: at most 15 characters
VIRTUAL_NET = "/devices/virtual/net/"
PROTECTED = frozenset(json.loads((Path(__file__).resolve().parents[1] / "data" / "protected_interfaces.json")
                                 .read_text(encoding="utf-8"))["protected"])


class CommandRefused(CollectorError):
    """The requested command or interface is outside the read-only allowlist."""


def valid_ifname(name) -> bool:
    return isinstance(name, str) and bool(_IFNAME.fullmatch(name)) and name not in (".", "..") \
        and name not in FORBIDDEN_TOKENS


def argv_for(ifname: str) -> Tuple[str, ...]:
    if not valid_ifname(ifname):
        raise CommandRefused(f"invalid interface name {ifname!r}")
    if ifname in PROTECTED:
        raise CommandRefused(f"interface {ifname!r} is protected")
    argv = (TC_PATH,) + ALLOWED_PREFIX + (ifname,)
    check_argv(argv)
    return argv


def check_argv(argv) -> None:
    """Accept exactly (TC_PATH, -s, -j, qdisc, show, dev, <valid unprotected interface>)."""
    argv = tuple(argv)
    if (len(argv) != 7 or argv[0] != TC_PATH or argv[1:6] != ALLOWED_PREFIX or not valid_ifname(argv[6])
            or argv[6] in PROTECTED or any(a in FORBIDDEN_TOKENS for a in argv)):
        raise CommandRefused(f"command not allowed: {argv!r}")


def physical_or_unknown(reader, ifname: str) -> Union[None, Bad]:
    """Generic physical-NIC protection: only interfaces whose sysfs device lives under
    /devices/virtual/net/ are eligible. Unreadable or unexpected links fail closed."""
    if not valid_ifname(ifname):
        return Bad(Status.REFUSED, f"invalid interface name {ifname!r}")
    if ifname in PROTECTED:
        return Bad(Status.REFUSED, f"interface {ifname} is protected")
    link = reader.readlink(f"/sys/class/net/{ifname}")
    if isinstance(link, Bad):
        return Bad(Status.REFUSED, f"cannot establish that {ifname} is virtual ({link.status.value})")
    if VIRTUAL_NET not in link or not link.endswith("/" + ifname):
        return Bad(Status.REFUSED, f"{ifname} is not a virtual interface; physical interfaces are protected")
    return None


def run_qdisc_show(ifname: str, runner: Callable = subprocess.run) -> Union[str, Bad]:
    """Execute the read-only command. Returns stdout text, or Bad (never raises for runtime failures)."""
    try:
        argv = argv_for(ifname)
    except CommandRefused as exc:
        return Bad(Status.REFUSED, str(exc))
    if not os.path.isfile(TC_PATH):
        return Bad(Status.ABSENT, "tc is not installed")
    try:
        r = runner(list(argv), shell=False, stdin=subprocess.DEVNULL, capture_output=True, timeout=TIMEOUT_S,
                   check=False, env=dict(ENV), close_fds=True)
    except subprocess.TimeoutExpired:
        return Bad(Status.TIMEOUT, f"tc did not answer within {TIMEOUT_S} s")
    except PermissionError as exc:
        return Bad(Status.DENIED, str(exc))
    except OSError as exc:
        return Bad(Status.ABSENT, f"tc could not be executed: {exc}")
    err = (r.stderr or b"").decode("ascii", "replace").strip()
    if r.returncode != 0:
        if "not permitted" in err or "Permission denied" in err:
            return Bad(Status.DENIED, err[:200])
        return Bad(Status.ABSENT, f"tc exit {r.returncode}: {err[:200]}")
    out = r.stdout or b""
    if len(out) > MAX_OUTPUT:
        return Bad(Status.MALFORMED, "tc output too large")
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        return Bad(Status.MALFORMED, "tc output is not UTF-8")
