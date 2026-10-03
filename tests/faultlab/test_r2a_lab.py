"""R2-A tooling: the lab script mutates only dedicated lab objects, the host comparison accepts exactly the lab
namespaces, and the lab validator rejects anything that is not the isolated, fault-free topology."""

import copy
import importlib.util
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("r2a_lab", ROOT / "scripts" / "r2a_lab.py")
lab = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lab)
SCRIPT = (ROOT / "scripts" / "r2a_lab_validate.sh").read_text()
L = lab.LAB


def code_lines(text):
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


class TestScriptSafety(unittest.TestCase):
    def test_lab_constants_match_the_helper(self):
        for var, key in (("NS_A", "ns_a"), ("NS_B", "ns_b"), ("IF_A", "if_a"), ("IF_B", "if_b"), ("IP_A", "ip_a"),
                         ("IP_B", "ip_b"), ("PREFIX", "prefix")):
            self.assertRegex(SCRIPT, rf"(?m)^{var}={re.escape(str(L[key]))}$")
        self.assertEqual(len(L["if_a"]) <= 15 and len(L["if_b"]) <= 15, True)      # IFNAMSIZ

    def test_every_mutation_targets_only_lab_objects(self):
        runs = [l for l in code_lines(SCRIPT) if re.match(r"(?:if \(\( CREATED_\w \)\); then )?run ", l)]
        self.assertGreaterEqual(len(runs), 10)
        for l in runs:
            cmd = re.sub(r"^.*?run ", "", l)
            with self.subTest(cmd=cmd):
                self.assertRegex(cmd, r'^ip (netns (add|del) "\$NS_[AB]"|link add "\$IF_A" netns "\$NS_A" type veth '
                                      r'peer name "\$IF_B" netns "\$NS_B"|-n "\$NS_[AB]" (addr add|link set) )')
                self.assertNotRegex(cmd, r"enp0s31f6|docker0|default|8\.8\.8\.8")

    def test_no_fault_injection_or_host_configuration_commands(self):
        code = "\n".join(code_lines(SCRIPT))
        for pat in (r"\bnetem\b", r"\btc\b(?! -j qdisc show)(?! -n \"\$ns\" -j qdisc show)(?! -V)", r"\bsysctl\b",
                    r">\s*/proc/sys", r"\biptables\b", r"\bnft\b", r"\bdocker\b", r"\bethtool\b", r"\bbrctl\b",
                    r"\bip (route|addr) (add|del|change|replace)\b", r"\bip link (del|change|replace|set)\b",
                    r"\bip -n \"\$ns\" (addr|link|route) (add|del|change|replace|set)\b",
                    r"\bstress", r"\bcgcreate\b", r"cgroup\.(procs|max)", r"enp0s31f6", r"docker0"):
            with self.subTest(pattern=pat):
                self.assertIsNone(re.search(pat, code))
        self.assertEqual(sorted(set(re.findall(r"\btc [^>\n]*", code))),
                         ['tc -V', 'tc -j qdisc show ', 'tc -n "$ns" -j qdisc show '])

    def test_probes_stay_inside_the_lab(self):
        code = "\n".join(code_lines(SCRIPT))
        for m in re.findall(r"ping [^>\n]*", code):
            self.assertRegex(m, r"127\.0\.0\.1|\$peer")
        self.assertIn('ip -n "$ns" route get 8.8.8.8', code)                    # route lookup, sends nothing
        self.assertIn("ip netns exec \"$NS_A\"", code)
        self.assertNotRegex(code, r"(?<!-n \"\$ns\" )route get")

    def test_refuses_existing_objects_and_cleans_only_its_own(self):
        self.assertIn("REFUSING: namespace $n already exists", SCRIPT)
        self.assertIn("REFUSING: interface $n exists in the host", SCRIPT)
        self.assertIn("trap finish EXIT", SCRIPT)
        self.assertRegex(SCRIPT, r'if \(\( CREATED_A \)\); then run ip netns del "\$NS_A"')


def host():
    return {
        "links": [{"ifname": "lo", "mtu": 65536, "qdisc": "noqueue"},
                  {"ifname": "enp0s31f6", "mtu": 1500, "qdisc": "fq_codel", "flags": ["UP"]},
                  {"ifname": "docker0", "mtu": 1500, "qdisc": "noqueue",
                   "linkinfo": {"info_kind": "bridge", "info_data": {"stp_state": 0, "gc_timer": 10.0}}}],
        "addrs": [{"ifname": "enp0s31f6", "addr_info": [{"family": "inet", "local": "192.168.192.151", "prefixlen": 20}]}],
        "routes4": [{"dst": "default", "gateway": "192.168.192.11", "dev": "enp0s31f6"}], "routes6": [],
        "qdiscs": [{"kind": "noqueue", "handle": "0:", "dev": "lo"},
                   {"kind": "fq_codel", "handle": "0:", "dev": "enp0s31f6", "options": {"limit": 10240}},
                   {"kind": "noqueue", "handle": "0:", "dev": "docker0"}],
        "netns": [], "run_netns": [], "sysctls": "net/ipv4/ip_forward=1\n",
        "bpf_progs": [{"id": 1, "name": "sd_x"}], "bpf_links": [], "bpf_maps": [],
    }


class TestHostCompare(unittest.TestCase):
    def test_identical_and_timer_only(self):
        a = host()
        a["links"][2]["linkinfo"]["info_data"]["gc_timer"] = 3.0
        self.assertTrue(lab.compare(host(), a)["ok"])

    def test_exactly_the_lab_namespaces_are_allowed(self):
        a = host()
        a["netns"] = a["run_netns"] = [L["ns_a"], L["ns_b"]]
        self.assertTrue(lab.compare(host(), a, [L["ns_a"], L["ns_b"]])["ok"])
        self.assertFalse(lab.compare(host(), a)["ok"])                            # not expected -> fail
        a["netns"] = a["run_netns"] = [L["ns_a"], L["ns_b"], "intruder"]
        self.assertFalse(lab.compare(host(), a, [L["ns_a"], L["ns_b"]])["ok"])

    def test_pre_existing_namespace_removed_fails(self):
        b = host()
        b["netns"] = b["run_netns"] = ["existing"]
        self.assertFalse(lab.compare(b, host())["ok"])

    def test_host_changes_detected(self):
        cases = {
            "enp0s31f6 qdisc": lambda h: h["qdiscs"][1].update(kind="netem"),
            "enp0s31f6 qdisc options": lambda h: h["qdiscs"][1]["options"].update(limit=1),
            "docker0 qdisc added": lambda h: h["qdiscs"].append({"kind": "tbf", "handle": "1:", "dev": "docker0"}),
            "enp0s31f6 mtu": lambda h: h["links"][1].update(mtu=9000),
            "docker0 config": lambda h: h["links"][2]["linkinfo"]["info_data"].update(stp_state=1),
            "route": lambda h: h["routes4"].append({"dst": "10.199.0.0/24", "dev": "sentlab-a0"}),
            "address": lambda h: h["addrs"][0]["addr_info"].append({"family": "inet", "local": "10.199.0.1",
                                                                   "prefixlen": 24}),
            "sysctl": lambda h: h.update(sysctls="net/ipv4/ip_forward=0\n"),
            "lab veth leaked into host": lambda h: h["links"].append({"ifname": "sentlab-a0", "mtu": 1500}),
            "bpf prog": lambda h: h["bpf_progs"].append({"id": 2, "name": "x"}),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                a = host()
                mutate(a)
                self.assertFalse(lab.compare(host(), a)["ok"])


def lab_dir(d, mutate=None):
    """Synthetic capture of a correct lab, written the way capture_lab writes it."""
    files = {"netns.json": [{"name": L["ns_b"], "id": 1}, {"name": L["ns_a"], "id": 0}],
             "host_links.json": [{"ifname": "lo"}, {"ifname": "enp0s31f6"}, {"ifname": "docker0"}],
             "tcp_result.txt": "ECHO-OK\n"}
    for s, ifn, ip in (("a", L["if_a"], L["ip_a"]), ("b", L["if_b"], L["ip_b"])):
        files[f"{s}_links.json"] = [{"ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"], "operstate": "UNKNOWN"},
                                    {"ifname": ifn, "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                                     "operstate": "UP", "link_netnsid": 1, "linkinfo": {"info_kind": "veth"}}]
        files[f"{s}_addrs.json"] = [{"ifname": ifn, "addr_info": [{"family": "inet", "local": ip, "prefixlen": 24},
                                                                  {"family": "inet6", "local": "fe80::1",
                                                                   "prefixlen": 64}]}]
        files[f"{s}_routes4.json"] = [{"dst": L["subnet"], "dev": ifn, "protocol": "kernel", "scope": "link"}]
        files[f"{s}_routes6.json"] = [{"dst": "fe80::/64", "dev": ifn}]
        files[f"{s}_qdiscs.json"] = [{"kind": "noqueue", "dev": ifn}]
        files[f"{s}_route_get_external.txt"] = "RTNETLINK answers: Network is unreachable\n"
        files[f"{s}_ping_lo.txt"] = "2 packets transmitted, 2 received, 0% packet loss, time 1001ms\n"
        files[f"{s}_ping_peer.txt"] = "3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n"
    if mutate:
        mutate(files)
    for name, v in files.items():
        (Path(d) / name).write_text(v if isinstance(v, str) else json.dumps(v))


class TestLabValidation(unittest.TestCase):
    def check(self, mutate=None):
        with tempfile.TemporaryDirectory() as d:
            lab_dir(d, mutate)
            return lab.validate_lab(d)

    def test_correct_lab_passes(self):
        r = self.check()
        self.assertTrue(r["ok"], [k for k, v in r["checks"].items() if not v])

    def test_rejections(self):
        cases = {
            "default route": lambda f: f["a_routes4.json"].append({"dst": "default", "gateway": "10.199.0.254"}),
            "netem qdisc": lambda f: f["b_qdiscs.json"].append({"kind": "netem", "dev": L["if_b"]}),
            "packet loss to peer": lambda f: f.update({"a_ping_peer.txt": "3 transmitted, 2 received, 33% packet loss"}),
            "loopback down": lambda f: f["b_links.json"][0].update(flags=["LOOPBACK"]),
            "veth down": lambda f: f["a_links.json"][1].update(operstate="DOWN"),
            "wrong address": lambda f: f["a_addrs.json"][0]["addr_info"][0].update(local="10.199.0.9"),
            "extra interface": lambda f: f["a_links.json"].append({"ifname": "eth9", "flags": []}),
            "external path": lambda f: f.update({"b_route_get_external.txt": "8.8.8.8 via 10.199.0.254 dev x"}),
            "tcp echo failed": lambda f: f.update({"tcp_result.txt": "ECHO-BAD\n"}),
            "namespace missing": lambda f: f.update({"netns.json": [{"name": L["ns_a"]}]}),
            "veth in host": lambda f: f["host_links.json"].append({"ifname": L["if_a"]}),
            "not a veth": lambda f: f["a_links.json"][1].update(linkinfo={"info_kind": "dummy"}),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                self.assertFalse(self.check(mutate)["ok"])


class TestCandidate(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.repo = self.d.name
        self.git("init", "-q")
        (Path(self.repo) / "src.py").write_text("v1\n")
        self.base = self.commit()

    def tearDown(self):
        self.d.cleanup()

    def git(self, *a):
        return subprocess.run(["git", "-C", self.repo, "-c", "user.name=t", "-c", "user.email=t@t", *a],
                              capture_output=True, text=True, check=True).stdout.strip()

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "c")
        return self.git("rev-parse", "HEAD")

    def test_tooling_descendant_ok_other_change_refused(self):
        (Path(self.repo) / "scripts").mkdir()
        (Path(self.repo) / "scripts" / "r2a_lab.py").write_text("x\n")
        self.commit()
        self.assertTrue(lab.candidate(self.repo, self.base)["ok"])
        (Path(self.repo) / "src.py").write_text("v2\n")
        self.assertFalse(lab.candidate(self.repo, self.base)["ok"])               # dirty tracked file
        self.commit()
        self.assertFalse(lab.candidate(self.repo, self.base)["ok"])               # implementation changed


if __name__ == "__main__":
    unittest.main()
