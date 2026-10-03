#!/usr/bin/env python3
"""SentinelAI R2-A: FaultLab infrastructure-only validation helpers (pure; no host mutation).

Subcommands (used by scripts/r2a_lab_validate.sh; they only read files and git):
  candidate REPO BASE              HEAD is BASE or a descendant adding only R2-A tooling; tracked tree clean
  compare BASE_DIR OTHER_DIR [NS…]  host snapshots identical except /run/netns gaining exactly NS…
  validate-lab DIR                 the captured lab state matches the lab specification
Every subcommand prints JSON and exits 0 only when every check passes.
"""

import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import m3b_r1_compare as hostcmp  # noqa: E402  (bridge-timer-aware interface comparison, committed in c2ac7e5)

# The lab, fully specified (the shell script defines the same values; a test keeps them equal).
LAB = {
    "ns_a": "sentinel-lab-a", "ns_b": "sentinel-lab-b",
    "if_a": "sentlab-a0", "if_b": "sentlab-b0",
    "ip_a": "10.199.0.1", "ip_b": "10.199.0.2", "prefix": 24, "subnet": "10.199.0.0/24",
}
PROTECTED = ("enp0s31f6", "docker0")
SYSCTLS = ("kernel/unprivileged_bpf_disabled", "kernel/perf_event_paranoid", "kernel/bpf_stats_enabled",
           "net/core/bpf_jit_enable", "net/core/default_qdisc", "net/ipv4/ip_forward",
           "net/ipv4/conf/all/forwarding", "net/ipv4/conf/all/rp_filter", "net/ipv6/conf/all/forwarding",
           "net/ipv6/conf/all/disable_ipv6")
TOOLING = ("scripts/r2a_lab.py", "scripts/r2a_lab_validate.sh", "tests/faultlab/__init__.py",
           "tests/faultlab/test_r2a_lab.py")


# ------------------------------------------------------------------------------------------ candidate
def git(repo, *args):
    p = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    return p.returncode, p.stdout.strip()


def candidate(repo, base):
    rc, head = git(repo, "rev-parse", "HEAD")
    rc2, b = git(repo, "rev-parse", "--verify", f"{base}^{{commit}}")
    if rc or rc2:
        return {"ok": False, "reason": "HEAD or base not resolvable"}
    if git(repo, "merge-base", "--is-ancestor", b, head)[0]:
        return {"ok": False, "reason": f"HEAD {head} does not descend from {b}"}
    _, changed = git(repo, "diff", "--name-only", b, head)
    other = sorted(p for p in changed.splitlines() if p and p not in TOOLING)
    if other:
        return {"ok": False, "reason": f"changed since {b[:7]} beyond R2-A tooling: {other}"}
    _, dirty = git(repo, "status", "--porcelain", "--untracked-files=no")
    if dirty:
        return {"ok": False, "reason": f"tracked files modified: {dirty.splitlines()}"}
    return {"ok": True, "head": head, "base": b}


# ------------------------------------------------------------------------------------------ host snapshots
def load(d):
    d = Path(d)
    j = lambda n: json.loads((d / f"{n}.json").read_text() or "[]")
    return {"links": j("links"), "addrs": j("addrs"), "routes4": j("routes4"), "routes6": j("routes6"),
            "qdiscs": j("qdiscs"), "netns": sorted(n["name"] for n in j("netns")),
            "run_netns": sorted(l for l in (d / "run_netns.txt").read_text().split() if l),
            "sysctls": (d / "sysctls.txt").read_text(),
            "bpf_progs": j("bpf_progs"), "bpf_links": j("bpf_links"), "bpf_maps": j("bpf_maps")}


def compare(base, other, expected_new_netns=()):
    """Host netns state must be identical except that /run/netns gains exactly expected_new_netns."""
    shared = {k: base[k] for k in ("links", "addrs", "routes4", "routes6", "sysctls", "bpf_progs", "bpf_links",
                                    "bpf_maps")}
    shared_o = {k: other[k] for k in shared}
    r = hostcmp.compare({**shared, "netns": ""}, {**shared_o, "netns": ""})
    r.pop("netns_identical")
    r.pop("ignored_volatile_fields")
    q = lambda s: {(x.get("dev"), x.get("handle"), x.get("parent", "root")): x for x in s["qdiscs"]}
    qb, qo = q(base), q(other)
    r["qdiscs_identical"] = qb == qo
    r["protected_qdiscs_identical"] = all({k: v for k, v in qb.items() if k[0] == p} ==
                                          {k: v for k, v in qo.items() if k[0] == p} for p in PROTECTED)
    added = sorted(set(other["netns"]) - set(base["netns"]))
    removed = sorted(set(base["netns"]) - set(other["netns"]))
    r["netns_added"], r["netns_removed"] = added, removed
    r["netns_as_expected"] = added == sorted(expected_new_netns) and not removed and \
        sorted(set(other["run_netns"]) - set(base["run_netns"])) == sorted(expected_new_netns) and \
        not set(base["run_netns"]) - set(other["run_netns"])
    r["no_lab_interface_in_host"] = not [l["ifname"] for l in other["links"] if l["ifname"].startswith("sentlab")]
    must = ("interfaces_identical", "enp0s31f6_identical", "docker0_identical", "addresses_identical",
            "routes_identical", "sysctls_identical", "bpf_progs_identical", "bpf_links_identical",
            "bpf_maps_identical", "qdiscs_identical", "protected_qdiscs_identical", "netns_as_expected",
            "no_lab_interface_in_host")
    r["ok"] = all(r[k] for k in must) and not r["sn_programs_left"]
    return r


# ------------------------------------------------------------------------------------------ lab state
def validate_lab(d):
    """Checks on the captured lab state (files written by the shell script inside the lab namespaces)."""
    d = Path(d)
    j = lambda n: json.loads((d / f"{n}.json").read_text() or "[]")
    t = lambda n: (d / f"{n}.txt").read_text() if (d / f"{n}.txt").exists() else ""
    c = {}
    names = sorted(n["name"] for n in j("netns"))
    c["namespaces_exist"] = {LAB["ns_a"], LAB["ns_b"]} <= set(names)
    for side, peer in (("a", "b"), ("b", "a")):
        ns, ifn, ip = LAB[f"ns_{side}"], LAB[f"if_{side}"], LAB[f"ip_{side}"]
        links = {l["ifname"]: l for l in j(f"{side}_links")}
        veth = links.get(ifn, {})
        c[f"{side}_only_lo_and_veth"] = sorted(links) == sorted(["lo", ifn])
        c[f"{side}_veth_type"] = veth.get("linkinfo", {}).get("info_kind") == "veth"
        c[f"{side}_veth_up"] = "UP" in veth.get("flags", []) and veth.get("operstate") == "UP"
        c[f"{side}_veth_peer_in_other_ns"] = "link_netnsid" in veth
        c[f"{side}_lo_up"] = "UP" in links.get("lo", {}).get("flags", [])
        addrs = [(i["family"], i["local"], i["prefixlen"]) for a in j(f"{side}_addrs") if a["ifname"] == ifn
                 for i in a.get("addr_info", []) if i["family"] == "inet"]
        c[f"{side}_address"] = addrs == [("inet", ip, LAB["prefix"])]
        routes = j(f"{side}_routes4")
        c[f"{side}_routes_lab_only"] = [(r.get("dst"), r.get("dev")) for r in routes] == [(LAB["subnet"], ifn)]
        c[f"{side}_no_default_route"] = not any(r.get("dst") == "default" for r in routes + j(f"{side}_routes6"))
        c[f"{side}_no_external_path"] = "unreachable" in t(f"{side}_route_get_external").lower()
        c[f"{side}_loopback_ping"] = " 0% packet loss" in t(f"{side}_ping_lo")
        c[f"{side}_ping_peer"] = " 0% packet loss" in t(f"{side}_ping_peer")
        c[f"{side}_no_netem_qdisc"] = not any(q.get("kind") == "netem" for q in j(f"{side}_qdiscs"))
    c["tcp_echo"] = t("tcp_result").strip() == "ECHO-OK"
    host_links = [l["ifname"] for l in j("host_links")]
    c["host_has_no_lab_interface"] = not [n for n in host_links if n.startswith("sentlab")]
    return {"ok": all(c.values()), "checks": c}


def main(argv):
    cmd = argv[1]
    if cmd == "candidate":
        out = candidate(argv[2], argv[3])
    elif cmd == "compare":
        out = compare(load(argv[2]), load(argv[3]), argv[4:])
    elif cmd == "validate-lab":
        out = validate_lab(argv[2])
    else:
        raise SystemExit(f"unknown subcommand {cmd}")
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0 if out["ok"] else 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
