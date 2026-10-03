#!/usr/bin/env python3
"""M3B R1: compare read-only host snapshots taken before and after a validation run.

Interfaces are compared on configuration fields only. Traffic counters (stats/stats64) are not compared, and
neither are the bridge's free-running countdown timers below, which change every second without any
configuration change (R1 run 20261003T072203Z: docker0 differed only in gc_timer, 98.58 -> 96.44 s).
Every other field, addresses, routes, /run/netns, sysctls and BPF object ids must be identical.

Usage: m3b_r1_compare.py OUT_DIR    (reads OUT_DIR/host_before and OUT_DIR/host_after; prints JSON)
"""

import json
import sys

LINK_FIELDS = ("ifname", "flags", "mtu", "qdisc", "operstate", "linkmode", "group", "txqlen", "link_type", "address",
               "broadcast", "promiscuity", "num_tx_queues", "num_rx_queues", "gso_max_size", "linkinfo")
# The only ignored fields: remaining time of bridge timers (IFLA_BR_{HELLO,TCN,TOPOLOGY_CHANGE,GC}_TIMER).
VOLATILE_BRIDGE_TIMERS = ("hello_timer", "tcn_timer", "topology_change_timer", "gc_timer")


def link_config(link):
    out = {k: link.get(k) for k in LINK_FIELDS}
    info = out.get("linkinfo")
    if isinstance(info, dict) and info.get("info_kind") == "bridge" and isinstance(info.get("info_data"), dict):
        data = {k: v for k, v in info["info_data"].items() if k not in VOLATILE_BRIDGE_TIMERS}
        out["linkinfo"] = {**info, "info_data": data}
    return out


def links(entries):
    return {l["ifname"]: link_config(l) for l in entries}


def addrs(entries):
    return {a["ifname"]: sorted((i.get("family"), i.get("local"), i.get("prefixlen")) for i in a.get("addr_info", []))
            for a in entries}


def ids(entries):
    return sorted(e["id"] for e in entries)


def compare(before: dict, after: dict) -> dict:
    """before/after: {'links','addrs','routes4','routes6' (parsed JSON), 'netns','sysctls' (text),
    'bpf_progs','bpf_links','bpf_maps' (parsed JSON)}."""
    lb, la = links(before["links"]), links(after["links"])
    return {
        "interfaces_identical": lb == la,
        "enp0s31f6_identical": lb.get("enp0s31f6") == la.get("enp0s31f6"),
        "docker0_identical": lb.get("docker0") == la.get("docker0"),
        "interfaces_differing": sorted(n for n in set(lb) | set(la) if lb.get(n) != la.get(n)),
        "addresses_identical": addrs(before["addrs"]) == addrs(after["addrs"]),
        "routes_identical": before["routes4"] == after["routes4"] and before["routes6"] == after["routes6"],
        "netns_identical": before["netns"] == after["netns"],
        "sysctls_identical": before["sysctls"] == after["sysctls"],
        "bpf_progs_identical": ids(before["bpf_progs"]) == ids(after["bpf_progs"]),
        "bpf_links_identical": ids(before["bpf_links"]) == ids(after["bpf_links"]),
        "bpf_maps_identical": ids(before["bpf_maps"]) == ids(after["bpf_maps"]),
        "sn_programs_left": [p["name"] for p in after["bpf_progs"] if str(p.get("name", "")).startswith("sn_")],
        "ignored_volatile_fields": [f"linkinfo.info_data.{t} (bridge)" for t in VOLATILE_BRIDGE_TIMERS],
    }


def load(d: str) -> dict:
    j = lambda n: json.load(open(f"{d}/{n}.json"))
    t = lambda n: open(f"{d}/{n}.txt").read()
    return {"links": j("links"), "addrs": j("addrs"), "routes4": j("routes4"), "routes6": j("routes6"),
            "netns": t("netns"), "sysctls": t("sysctls"), "bpf_progs": j("bpf_progs"), "bpf_links": j("bpf_links"),
            "bpf_maps": j("bpf_maps")}


if __name__ == "__main__":
    out = sys.argv[1]
    print(json.dumps(compare(load(f"{out}/host_before"), load(f"{out}/host_after")), indent=1))
