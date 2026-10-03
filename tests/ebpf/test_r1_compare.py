"""R1.1: the host before/after comparison ignores only the documented bridge countdown timers and still detects
every configuration change (interfaces, qdisc, addresses, routes, namespaces, sysctls, BPF objects)."""

import copy
import importlib.util
import unittest
from pathlib import Path

_PATH = Path(__file__).resolve().parents[2] / "scripts" / "m3b_r1_compare.py"
_spec = importlib.util.spec_from_file_location("m3b_r1_compare", _PATH)
cmp_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cmp_mod)

BRIDGE_DATA = {"forward_delay": 1500, "stp_state": 0, "priority": 32768, "vlan_filtering": 0,
               "hello_timer": 0.0, "tcn_timer": 0.0, "topology_change_timer": 0.0, "gc_timer": 98.58}


def host():
    return {
        "links": [
            {"ifname": "lo", "flags": ["LOOPBACK", "UP"], "mtu": 65536, "qdisc": "noqueue", "operstate": "UNKNOWN",
             "stats64": {"rx": {"bytes": 1}}},
            {"ifname": "enp0s31f6", "flags": ["BROADCAST", "MULTICAST", "UP"], "mtu": 1500, "qdisc": "fq_codel",
             "operstate": "UP", "address": "4c:d7:17:87:53:ae", "promiscuity": 0, "stats64": {"rx": {"bytes": 2}}},
            {"ifname": "docker0", "flags": ["NO-CARRIER", "BROADCAST", "MULTICAST", "UP"], "mtu": 1500,
             "qdisc": "noqueue", "operstate": "DOWN", "address": "3e:21:b8:b7:ee:35",
             "linkinfo": {"info_kind": "bridge", "info_data": dict(BRIDGE_DATA)}},
        ],
        "addrs": [{"ifname": "enp0s31f6", "addr_info": [{"family": "inet", "local": "192.168.192.151", "prefixlen": 20,
                                                          "valid_life_time": 3600}]}],
        "routes4": [{"dst": "default", "gateway": "192.168.192.11", "dev": "enp0s31f6"}],
        "routes6": [],
        "netns": "",
        "sysctls": "kernel/unprivileged_bpf_disabled=2\nkernel/perf_event_paranoid=4\n",
        "bpf_progs": [{"id": 10, "name": "sd_devices"}], "bpf_links": [{"id": 3}], "bpf_maps": [{"id": 7}],
    }


def link(h, name):
    return next(l for l in h["links"] if l["ifname"] == name)


class TestVolatileFieldsOnly(unittest.TestCase):
    def test_timer_and_counter_only_differences_are_equivalent(self):
        b, a = host(), host()
        d = link(a, "docker0")["linkinfo"]["info_data"]
        d.update(gc_timer=96.44, hello_timer=1.5, tcn_timer=0.2, topology_change_timer=3.0)   # countdowns moved
        link(a, "enp0s31f6")["stats64"] = {"rx": {"bytes": 999}}                              # traffic counters
        a["addrs"][0]["addr_info"][0]["valid_life_time"] = 3500                                # DHCP lease countdown
        r = cmp_mod.compare(b, a)
        for k in ("interfaces_identical", "enp0s31f6_identical", "docker0_identical", "addresses_identical",
                  "routes_identical", "netns_identical", "sysctls_identical", "bpf_progs_identical",
                  "bpf_links_identical", "bpf_maps_identical"):
            self.assertTrue(r[k], k)
        self.assertEqual((r["interfaces_differing"], r["sn_programs_left"]), ([], []))

    def test_ignored_set_is_exactly_the_documented_bridge_timers(self):
        self.assertEqual(cmp_mod.VOLATILE_BRIDGE_TIMERS, ("hello_timer", "tcn_timer", "topology_change_timer",
                                                          "gc_timer"))

    def test_timer_named_field_on_a_non_bridge_link_is_not_ignored(self):
        b, a = host(), host()
        for h, v in ((b, 1.0), (a, 2.0)):
            link(h, "enp0s31f6")["linkinfo"] = {"info_kind": "vxlan", "info_data": {"gc_timer": v}}
        self.assertFalse(cmp_mod.compare(b, a)["enp0s31f6_identical"])


class TestRealChangesDetected(unittest.TestCase):
    def changed(self, mutate):
        b, a = host(), host()
        mutate(a)
        return cmp_mod.compare(b, a)

    def test_protected_interface_changes(self):
        cases = {
            "enp0s31f6 mtu": (lambda h: link(h, "enp0s31f6").update(mtu=9000), "enp0s31f6_identical"),
            "enp0s31f6 qdisc": (lambda h: link(h, "enp0s31f6").update(qdisc="netem"), "enp0s31f6_identical"),
            "enp0s31f6 promisc": (lambda h: link(h, "enp0s31f6").update(promiscuity=1), "enp0s31f6_identical"),
            "enp0s31f6 down": (lambda h: link(h, "enp0s31f6").update(operstate="DOWN"), "enp0s31f6_identical"),
            "docker0 mtu": (lambda h: link(h, "docker0").update(mtu=1400), "docker0_identical"),
            "docker0 qdisc": (lambda h: link(h, "docker0").update(qdisc="tbf"), "docker0_identical"),
            "docker0 bridge config": (lambda h: link(h, "docker0")["linkinfo"]["info_data"].update(stp_state=1),
                                      "docker0_identical"),
        }
        for name, (mutate, key) in cases.items():
            with self.subTest(name):
                r = self.changed(mutate)
                self.assertFalse(r[key])
                self.assertFalse(r["interfaces_identical"])

    def test_new_interface_detected(self):
        r = self.changed(lambda h: h["links"].append({"ifname": "veth0", "mtu": 1500, "qdisc": "noqueue"}))
        self.assertFalse(r["interfaces_identical"])
        self.assertEqual(r["interfaces_differing"], ["veth0"])

    def test_addresses_routes_namespaces_sysctls_bpf(self):
        cases = {
            "address": (lambda h: h["addrs"][0]["addr_info"].append({"family": "inet", "local": "10.0.0.1",
                                                                     "prefixlen": 24}), "addresses_identical"),
            "route": (lambda h: h["routes4"].append({"dst": "10.0.0.0/24", "dev": "docker0"}), "routes_identical"),
            "ipv6 route": (lambda h: h["routes6"].append({"dst": "fd00::/64"}), "routes_identical"),
            "netns": (lambda h: h.update(netns="lab\n"), "netns_identical"),
            "sysctl": (lambda h: h.update(sysctls="kernel/unprivileged_bpf_disabled=0\nkernel/perf_event_paranoid=4\n"),
                       "sysctls_identical"),
            "bpf prog": (lambda h: h["bpf_progs"].append({"id": 99, "name": "x"}), "bpf_progs_identical"),
            "bpf link": (lambda h: h["bpf_links"].append({"id": 9}), "bpf_links_identical"),
            "bpf map": (lambda h: h["bpf_maps"].append({"id": 8}), "bpf_maps_identical"),
        }
        for name, (mutate, key) in cases.items():
            with self.subTest(name):
                self.assertFalse(self.changed(mutate)[key])

    def test_leftover_m3b_program_reported(self):
        r = self.changed(lambda h: h["bpf_progs"].append({"id": 50, "name": "sn_sched_switc"}))
        self.assertEqual(r["sn_programs_left"], ["sn_sched_switc"])

    def test_input_not_mutated(self):
        b, a = host(), host()
        bc, ac = copy.deepcopy(b), copy.deepcopy(a)
        cmp_mod.compare(b, a)
        self.assertEqual((b, a), (bc, ac))


if __name__ == "__main__":
    unittest.main()
