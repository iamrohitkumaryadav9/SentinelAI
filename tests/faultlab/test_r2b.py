"""R2-B tooling: the only possible fault is netem loss (1 % or 5 %) on sentlab-a0 in sentinel-lab-a; it is always
removed; the analysis and the M2 call never change the evidence."""

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
_spec = importlib.util.spec_from_file_location("r2b_fault", ROOT / "scripts" / "r2b_fault.py")
F = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(F)
WRAPPER = (ROOT / "scripts" / "r2b_validate.sh").read_text()
DRIVER = (ROOT / "scripts" / "r2b_driver.py").read_text()


def code_lines(text):
    return [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


class TestCommandGuards(unittest.TestCase):
    def test_exact_fault_commands(self):
        self.assertEqual(F.netem_add(1.0), ["tc", "-n", "sentinel-lab-a", "qdisc", "add", "dev", "sentlab-a0", "root",
                                            "netem", "loss", "1%"])
        self.assertEqual(F.netem_add(5), ["tc", "-n", "sentinel-lab-a", "qdisc", "add", "dev", "sentlab-a0", "root",
                                          "netem", "loss", "5%"])
        self.assertEqual(F.netem_del(), ["tc", "-n", "sentinel-lab-a", "qdisc", "del", "dev", "sentlab-a0", "root"])
        self.assertEqual(F.qdisc_show(), ["tc", "-n", "sentinel-lab-a", "-s", "-j", "qdisc", "show", "dev",
                                          "sentlab-a0"])

    def test_unapproved_levels_refused(self):
        for bad in (0, 0.5, 2, 10, 50, 100, -1, True, "1", None, float("nan")):
            with self.subTest(bad=bad), self.assertRaises(F.FaultRefused):
                F.netem_add(bad)

    def test_unapproved_fault_types_refused(self):
        for fault in ("delay", "reorder", "corrupt", "duplicate", "rate", "slot", "LOSS", ""):
            with self.subTest(fault=fault), self.assertRaises(F.FaultRefused):
                F.netem_add(1.0, fault=fault)

    def test_check_argv_rejects_everything_else(self):
        bad = [
            ["tc", "qdisc", "add", "dev", "enp0s31f6", "root", "netem", "loss", "1%"],
            ["tc", "-n", "sentinel-lab-a", "qdisc", "add", "dev", "enp0s31f6", "root", "netem", "loss", "1%"],
            ["tc", "qdisc", "add", "dev", "docker0", "root", "netem", "loss", "1%"],
            ["tc", "qdisc", "del", "dev", "enp0s31f6", "root"],
            ["tc", "qdisc", "add", "dev", "sentlab-a0", "root", "netem", "loss", "1%"],          # no explicit netns
            ["tc", "-n", "sentinel-lab-b", "qdisc", "add", "dev", "sentlab-b0", "root", "netem", "loss", "1%"],
            ["tc", "-n", "sentinel-lab-a", "qdisc", "add", "dev", "sentlab-a0", "root", "netem", "loss", "2%"],
            ["tc", "-n", "sentinel-lab-a", "qdisc", "add", "dev", "sentlab-a0", "root", "netem", "delay", "10ms"],
            F.netem_add(1.0) + ["delay", "10ms"],
            F.netem_add(1.0) + ["corrupt", "1%"],
            ["tc", "-n", "sentinel-lab-a", "qdisc", "change", "dev", "sentlab-a0", "root", "netem", "loss", "1%"],
            ["tc", "-n", "sentinel-lab-a", "qdisc", "replace", "dev", "sentlab-a0", "root", "netem", "loss", "5%"],
            ["ip", "link", "set", "enp0s31f6", "down"],
            ["sh", "-c", "tc qdisc del dev enp0s31f6 root"],
            "tc -n sentinel-lab-a qdisc del dev sentlab-a0 root",
        ]
        for argv in bad:
            with self.subTest(argv=argv), self.assertRaises(F.FaultRefused):
                F.check_argv(argv)
        for argv in (F.netem_add(1.0), F.netem_add(5.0), F.netem_del(), F.qdisc_show(), F.qdisc_show_text()):
            self.assertEqual(F.check_argv(argv), argv)

    def test_protected_interfaces_refused_by_their_own_check(self):
        """Defence in depth: the protected-interface check refuses on its own, before the allowlist is consulted."""
        for p in ("enp0s31f6", "docker0"):
            for argv in (["tc", "-n", "sentinel-lab-a", "qdisc", "del", "dev", p, "root"],
                         F.netem_add(1.0)[:-4] + [p, "root", "netem", "loss", "1%"]):
                with self.subTest(p=p, argv=argv), self.assertRaisesRegex(F.FaultRefused, "protected interface"):
                    F.check_argv(argv)

    def test_execute_validates_before_running_and_never_uses_a_shell(self):
        calls = []
        runner = lambda argv, **kw: calls.append((argv, kw)) or SimpleNamespace(returncode=0, stdout="[]", stderr="")
        with self.assertRaises(F.FaultRefused):
            F.execute(["tc", "qdisc", "del", "dev", "enp0s31f6", "root"], runner=runner)
        self.assertEqual(calls, [])
        F.execute(F.netem_del(), runner=runner)
        self.assertEqual(calls[0][0], F.netem_del())
        self.assertIs(calls[0][1]["shell"], False)


NETEM_JSON = json.dumps([{"kind": "netem", "handle": "8001:", "root": True, "refcnt": 2, "options": {"limit": 1000},
                          "bytes": 5792000, "packets": 4000, "drops": 41, "overlimits": 0, "requeues": 0}])
CLEAN_JSON = json.dumps([{"kind": "noqueue", "handle": "0:", "root": True, "refcnt": 2, "options": {},
                          "bytes": 0, "packets": 0, "drops": 0, "overlimits": 0, "requeues": 0}])


class TestGroundTruth(unittest.TestCase):
    def test_parse_is_deterministic(self):
        self.assertEqual(F.parse_qdiscs(NETEM_JSON), F.parse_qdiscs(NETEM_JSON))
        self.assertEqual(F.parse_qdiscs(NETEM_JSON)[0]["drops"], 41)
        self.assertEqual(F.parse_qdiscs(""), [])

    def test_clean_state(self):
        self.assertTrue(F.is_clean(F.parse_qdiscs(CLEAN_JSON)))
        self.assertFalse(F.is_clean(F.parse_qdiscs(NETEM_JSON)))
        self.assertFalse(F.is_clean([]))

    def test_netem_readback(self):
        q = F.parse_qdiscs(NETEM_JSON)
        gt = F.netem_ground_truth(q, "qdisc netem 8001: root refcnt 2 limit 1000 loss 1%\n", 1.0)
        self.assertEqual((gt["loss_pct"], gt["packets"], gt["drops"]), (1.0, 4000, 41))
        bad = [("qdisc netem 8001: root refcnt 2 limit 1000 loss 5%", 1.0),                 # wrong level
               ("qdisc netem 8001: root refcnt 2 limit 1000 delay 10ms loss 1%", 1.0),      # extra impairment
               ("qdisc netem 8001: root refcnt 2 limit 1000 loss 1% duplicate 1%", 1.0),
               ("qdisc netem 8001: root refcnt 2 limit 1000", 1.0)]                         # no loss
        for text, loss in bad:
            with self.subTest(text=text), self.assertRaises(ValueError):
                F.netem_ground_truth(q, text, loss)
        with self.assertRaises(ValueError):
            F.netem_ground_truth(F.parse_qdiscs(CLEAN_JSON), "qdisc noqueue 0: root refcnt 2", 1.0)


def wd(retrans=0, kfree=None, stats=None):
    return {"retrans": retrans, "kfree": kfree or {}, "stats": stats or {}}


class TestAttribution(unittest.TestCase):
    def test_faulted_run(self):
        a = wd(390, {4: 400, 2: 3})
        b = wd(0, {2: 1}, {"retrans_other_netns": 390, "kfree_other_netns": 450})
        r = F.attribution_checks(1.0, 401, a, b, 4)
        self.assertTrue(r["ok"], r)

    def test_failures(self):
        cases = {
            "qdisc drops leak into B": (1.0, 400, wd(390, {4: 400}), wd(0, {4: 5}, {"retrans_other_netns": 390})),
            "B sees target retransmissions": (1.0, 400, wd(390, {4: 400}), wd(3, {}, {"retrans_other_netns": 390})),
            "kfree QDISC_DROP far from the qdisc counter": (1.0, 400, wd(390, {4: 300}),
                                                             wd(0, {}, {"retrans_other_netns": 390})),
            "no retransmission under loss": (1.0, 400, wd(0, {4: 400}), wd(0, {}, {})),
            "A events not seen as other by B": (1.0, 400, wd(390, {4: 400}), wd(0, {}, {"retrans_other_netns": 10})),
            "baseline with qdisc drops": (0, 3, wd(0, {4: 3}), wd(0, {}, {})),
            "baseline with retransmissions": (0, 0, wd(2, {}), wd(0, {}, {"retrans_other_netns": 2})),
        }
        for name, (loss, qd, a, b) in cases.items():
            with self.subTest(name):
                self.assertFalse(F.attribution_checks(loss, qd, a, b, 4)["ok"])

    def test_prediction(self):
        n = {"DROP_ABS_MIN": 10.0, "DROP_FRAC_MIN": 0.001}
        self.assertEqual(F.predict_m2(0, 0, 4000, n)["decision"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(F.predict_m2(1.0, 40.0, 3960, n)["decision"], "network_packet_loss")
        self.assertEqual(F.predict_m2(1.0, 4.0, 396, n)["decision"], "INSUFFICIENT_EVIDENCE")   # below DROP_ABS_MIN


def lab_files(d, mutate=None):
    f = {}
    for s, ifn, ip in (("a", "sentlab-a0", "10.199.0.1"), ("b", "sentlab-b0", "10.199.0.2")):
        f[f"{s}_links"] = [{"ifname": "lo", "mtu": 65536, "flags": ["UP"]},
                           {"ifname": ifn, "mtu": 1500, "flags": ["UP"], "operstate": "UP", "qdisc": "noqueue",
                            "linkinfo": {"info_kind": "veth"}, "stats64": {"tx": {"packets": 1}}}]
        f[f"{s}_addrs"] = [{"ifname": ifn, "addr_info": [{"family": "inet", "local": ip, "prefixlen": 24}]}]
        f[f"{s}_routes4"] = [{"dst": "10.199.0.0/24", "dev": ifn}]
        f[f"{s}_routes6"] = [{"dst": "fe80::/64", "dev": ifn}]
        f[f"{s}_qdiscs"] = [{"kind": "noqueue", "dev": ifn, "handle": "0:", "root": True, "packets": 0}]
    if mutate:
        mutate(f)
    for k, v in f.items():
        (Path(d) / f"{k}.json").write_text(json.dumps(v))


class TestLabRestoration(unittest.TestCase):
    def compare(self, mutate):
        with tempfile.TemporaryDirectory() as b, tempfile.TemporaryDirectory() as a:
            lab_files(b)
            lab_files(a, mutate)
            return F.lab_compare(b, a)

    def test_counters_only_is_restored(self):
        def m(f):
            f["a_links"][1]["stats64"] = {"tx": {"packets": 99999}}
            f["a_qdiscs"][0]["packets"] = 12345
        self.assertTrue(self.compare(m)["ok"])

    def test_leftovers_detected(self):
        cases = {
            "netem left": lambda f: f.update(a_qdiscs=[{"kind": "netem", "dev": "sentlab-a0", "handle": "8001:",
                                                        "root": True}]),
            "address changed": lambda f: f["b_addrs"][0]["addr_info"].append({"family": "inet", "local": "10.199.0.9",
                                                                              "prefixlen": 24}),
            "route added": lambda f: f["a_routes4"].append({"dst": "default", "gateway": "10.199.0.2"}),
            "link down": lambda f: f["b_links"][1].update(operstate="DOWN"),
            "mtu changed": lambda f: f["a_links"][1].update(mtu=1400),
        }
        for name, mutate in cases.items():
            with self.subTest(name):
                self.assertFalse(self.compare(mutate)["ok"])


class TestScriptSafety(unittest.TestCase):
    def test_wrapper_mutations_are_lab_only(self):
        runs = [re.sub(r"^.*?run ", "", l) for l in code_lines(WRAPPER)
                if re.match(r"(?:if \(\( CREATED_\w \)\); then )?run (?!=)", l)]
        self.assertGreaterEqual(len(runs), 10)
        for cmd in runs:
            with self.subTest(cmd=cmd):
                self.assertRegex(cmd, r'^ip (netns (add|del) "\$NS_[AB]"|link add "\$IF_A" netns "\$NS_A" type veth '
                                      r'peer name "\$IF_B" netns "\$NS_B"|-n "\$NS_[AB]" (addr add|link set) )')

    def test_wrapper_never_injects_or_configures_the_host(self):
        code = "\n".join(code_lines(WRAPPER))
        for pat in (r"\bnetem\b", r"\bsysctl\b", r">\s*/proc/sys", r"\biptables\b", r"\bnft\b", r"\bdocker\b",
                    r"\bethtool\b", r"enp0s31f6", r"docker0", r"\bip (route|addr) (add|del|change|replace)\b",
                    r"\bip link (del|change|replace|set)\b", r"\bstress", r"cgroup\.(procs|max)"):
            with self.subTest(pattern=pat):
                self.assertIsNone(re.search(pat, code))
        self.assertEqual(sorted(set(re.findall(r"\btc [^>;\n]*", code))),
                         ['tc -V', 'tc -j qdisc show ', 'tc -n "$ns" -s -j qdisc show '])
        mounts = re.findall(r"\bmount\b[^\n]*", code)
        self.assertEqual(mounts, ["mount -t cgroup2 -o ro,nosuid,nodev,noexec cgroup2 /sys/fs/cgroup && exec \"$@\"' \\"])
        self.assertIn('ip netns exec "$NS_A" /bin/sh -c \'mount -t cgroup2 -o ro', code)  # only inside the lab netns

    def test_wrapper_order_and_cleanup(self):
        code = "\n".join(code_lines(WRAPPER))
        self.assertIn("trap finish EXIT", code)
        self.assertIn("REFUSING: namespace $n already exists", code)
        i_valid = code.index('validate-lab "$R/lab_clean"')
        i_drv = code.index("r2b_driver.py")
        i_restore = code.index("lab-compare")
        i_destroy = code.index("destroy_lab\nsleep 2")
        i_host = code.index('compare "$OUT/host_baseline" "$R/host_after"')
        self.assertTrue(i_valid < i_drv < i_restore < i_destroy < i_host)
        self.assertIn('if (( STATUS )); then echo "[$label] a check failed: stopping"', code)

    def test_driver_executes_tc_only_through_the_guard(self):
        code = "\n".join(code_lines(DRIVER))
        self.assertNotRegex(code, r"\[\s*\"tc\"")                               # no hand-built tc argv
        self.assertEqual(re.findall(r"subprocess\.\w+\(", code), ["subprocess.Popen("])
        self.assertIn('subprocess.Popen(["ip", "netns", "exec", F.NS_B, "python3", "-c", RECEIVER]', code)
        self.assertNotRegex(code, r"shell\s*=\s*True|os\.system")
        self.assertRegex(code, r"finally:\nif fault\[\"installed\"\]:.*\nrc, _, err = F\.execute\(F\.netem_del\(\)\)")
        self.assertIn('raise SystemExit(f"REFUSING: driver must run inside netns {F.NS_A}")', code)
        self.assertNotRegex(code, r"[\"'](delay|reorder|corrupt|duplicate|rate)[\"']")   # no impairment literal


class TestDriverM2Call(unittest.TestCase):
    """R2-B run 20261003T100833Z: diagnose() refused code_commit='r2b' (EngineInfo requires a git hash)."""

    def test_driver_passes_the_validated_git_hash(self):
        code = "\n".join(code_lines(DRIVER))
        self.assertIn("d = diagnose(snap, params(), code_commit=a.commit)", code)
        self.assertIn('if not re.fullmatch(r"[0-9a-f]{7,40}", a.commit):', code)
        self.assertIn('--commit "$HEAD"', WRAPPER)

    def test_engine_accepts_a_hash_and_refuses_a_label(self):
        from rules._fixtures import params, scenario, snapshot
        from sentinelai.diagnostic.rules import diagnose
        snap = snapshot(scenario())
        self.assertEqual(diagnose(snap, params(), code_commit="683d87a").result.engine.code_commit, "683d87a")
        with self.assertRaises(Exception):
            diagnose(snap, params(), code_commit="r2b")


class TestFaultTiming(unittest.TestCase):
    def test_fault_applied_once_right_after_the_last_baseline_tick(self):
        import r2b_driver as D
        from sentinelai.collectors.clock import SystemClock
        fired = []
        orig = SystemClock.sleep_until
        SystemClock.sleep_until = lambda self, mono: None
        try:
            clk = D.FaultClock(lambda: fired.append(clk.calls))
            for k in range(D.NB + D.NW + 1):
                clk.sleep_until(float(k))
        finally:
            SystemClock.sleep_until = orig
        self.assertEqual(fired, [D.NB + 1])     # before sleeping to tick NB+1, i.e. after tick NB was sampled


class TestM2WithoutMutation(unittest.TestCase):
    def test_summary_and_snapshot_unchanged(self):
        import r2b_driver as D
        from rules._fixtures import COMMIT, run, scenario
        from sentinelai.diagnostic.contract.serialize import canonical_bytes
        d = run(scenario())
        before = canonical_bytes(d.snapshot)
        s = D.m2_summary(d)
        self.assertEqual(canonical_bytes(d.snapshot), before)
        self.assertEqual(s["decision"], d.result.decision.value)
        self.assertIn("candidates", s)
        self.assertNotIn("diagnostic", D.__dict__.get("__file__", ""))


class TestCandidate(unittest.TestCase):
    def test_allowlist(self):
        with tempfile.TemporaryDirectory() as repo:
            g = lambda *a: subprocess.run(["git", "-C", repo, "-c", "user.name=t", "-c", "user.email=t@t", *a],
                                          capture_output=True, text=True, check=True).stdout.strip()
            g("init", "-q")
            (Path(repo) / "x.py").write_text("1\n")
            g("add", "-A")
            g("commit", "-q", "-m", "base")
            base = g("rev-parse", "HEAD")
            (Path(repo) / "scripts").mkdir()
            (Path(repo) / "scripts" / "r2b_fault.py").write_text("1\n")
            g("add", "-A")
            g("commit", "-q", "-m", "tooling")
            self.assertTrue(F.candidate(repo, base)["ok"])
            (Path(repo) / "x.py").write_text("2\n")
            g("add", "-A")
            g("commit", "-q", "-m", "impl")
            self.assertFalse(F.candidate(repo, base)["ok"])


if __name__ == "__main__":
    unittest.main()
