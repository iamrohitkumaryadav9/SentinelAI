"""M3A-C1: read-only qdisc evidence. Parser fixtures, safety S1-S9, quality semantics, determinism."""

import json
import os
import subprocess
import sys
import time
import unittest

from sentinelai.collectors import Bad, ParseError, Status
from sentinelai.collectors.commands import tc
from sentinelai.collectors.parsers.tc import qdiscs
from sentinelai.collectors.reader import FixtureReader, LiveReader
from sentinelai.diagnostic.contract import Quality as Q
from sentinelai.diagnostic.contract.serialize import canonical_bytes

from ._world import NB, NW, World, build, meas

IF = "iface:lab/eth0"
Q1 = '{"kind":"fq_codel","handle":"0:","root":true,"refcnt":2,"options":{"limit":10240},"bytes":10,"packets":2,' \
     '"drops":%d,"overlimits":0,"requeues":0,"backlog":0,"qlen":0}'
MALICIOUS = ("eth0;rm", "eth0 && something", "$(command)", "../../x", "-i", "eth 0", "eth0|x", "eth0`x`", "a/b",
             "", "x" * 16, "eth0\n", "..", "add", "del", "netem", "eth0'", 'eth0"', "eth0>f", "*", "-s")


class Spy:
    """A runner that records calls instead of executing anything."""

    def __init__(self, result=None, exc=None):
        self.calls, self.result, self.exc = [], result, exc

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        if self.exc:
            raise self.exc
        return self.result or subprocess.CompletedProcess(argv, 0, ("[" + Q1 % 0 + "]").encode(), b"")


# ------------------------------------------------------------------------------------ parser fixtures
class TestParserFixtures(unittest.TestCase):
    def test_1_zero_drops(self):
        (q,) = qdiscs("[" + Q1 % 0 + "]")
        self.assertEqual((q.kind, q.handle, q.root, q.drops), ("fq_codel", "0:", True, 0))

    def test_2_nonzero_drops(self):
        self.assertEqual(qdiscs("[" + Q1 % 4242 + "]")[0].drops, 4242)

    def test_3_multiple_qdiscs(self):
        text = ('[{"kind":"mq","handle":"0:","root":true,"drops":7},'
                '{"kind":"fq_codel","handle":"0:","parent":":1","drops":3},'
                '{"kind":"fq_codel","handle":"0:","parent":":2","drops":4}]')
        self.assertEqual([(q.kind, q.root, q.drops) for q in qdiscs(text)],
                         [("mq", True, 7), ("fq_codel", False, 3), ("fq_codel", False, 4)])

    def test_4_malformed_json(self):
        for text in ("[{", "not json", "", "[" + Q1 % 0 + "", "{]"):
            with self.subTest(text=text[:10]), self.assertRaises(ParseError):
                qdiscs(text)

    def test_5_missing_fields(self):
        for obj in ({"handle": "0:", "drops": 1}, {"kind": "x", "drops": 1}, {"kind": "x", "handle": "0:"}):
            with self.subTest(obj=obj), self.assertRaises(ParseError):
                qdiscs(json.dumps([obj]))

    def test_6_unexpected_types(self):
        for text in ('{"kind":"x"}', '[1]', '[{"kind":"x","handle":"0:","drops":"5"}]',
                     '[{"kind":"x","handle":"0:","drops":5.0}]', '[{"kind":"x","handle":"0:","drops":true}]',
                     '[{"kind":"x","handle":"0:","drops":-1}]', '[{"kind":"x","handle":"0:","drops":1,"root":"yes"}]',
                     '[{"kind":7,"handle":"0:","drops":1}]'):
            with self.subTest(text=text), self.assertRaises(ParseError):
                qdiscs(text)

    def test_7_unknown_fields_ignored(self):
        self.assertEqual(qdiscs('[{"kind":"x","handle":"1:","root":true,"drops":2,"future":{"a":[1]}}]')[0].drops, 2)

    def test_8_empty_result(self):
        self.assertEqual(qdiscs("[]"), ())


# ------------------------------------------------------------------------------------ safety S1-S9
class TestS1NoShell(unittest.TestCase):
    def test_argv_list_and_shell_false(self):
        spy = Spy()
        tc.run_qdisc_show("lo", runner=spy)
        ((argv, kw),) = spy.calls
        self.assertIsInstance(argv, list)
        self.assertIs(kw["shell"], False)
        self.assertEqual(argv, [tc.TC_PATH, "-s", "-j", "qdisc", "show", "dev", "lo"])
        self.assertIs(kw["stdin"], subprocess.DEVNULL)
        self.assertEqual(kw["env"], {"PATH": "/usr/sbin:/usr/bin", "LC_ALL": "C"})


class TestS2OnlyQdiscShow(unittest.TestCase):
    def test_exact_pattern_accepted(self):
        tc.check_argv((tc.TC_PATH, "-s", "-j", "qdisc", "show", "dev", "veth0"))

    def test_everything_else_rejected(self):
        base = [tc.TC_PATH, "-s", "-j", "qdisc", "show", "dev", "veth0"]
        variants = [
            [tc.TC_PATH, "-s", "-j", "qdisc", "add", "dev", "veth0"],
            [tc.TC_PATH, "qdisc", "add", "dev", "veth0", "root", "netem", "loss", "5%"],
            [tc.TC_PATH, "-s", "-j", "qdisc", "change", "dev", "veth0"],
            [tc.TC_PATH, "-s", "-j", "qdisc", "replace", "dev", "veth0"],
            [tc.TC_PATH, "-s", "-j", "qdisc", "del", "dev", "veth0"],
            [tc.TC_PATH, "-s", "-j", "qdisc", "delete", "dev", "veth0"],
            [tc.TC_PATH, "-s", "-j", "class", "show", "dev", "veth0"],
            [tc.TC_PATH, "-s", "-j", "filter", "show", "dev", "veth0"],
            [tc.TC_PATH, "-s", "-j", "qdisc", "show", "dev", "ingress"],
            [tc.TC_PATH, "-s", "-j", "qdisc", "show", "dev", "egress"],
            [tc.TC_PATH, "-b", "/tmp/batch"], [tc.TC_PATH, "-force", "-batch", "x"],
            ["/bin/sh", "-c", "tc qdisc show"], ["tc", "-s", "-j", "qdisc", "show", "dev", "veth0"],
            ["/usr/bin/tc"] + base[1:], base + ["root"], base[:-1], base[:3] + ["show", "qdisc"] + base[5:],
            [tc.TC_PATH, "-s", "-j", "-n", "x", "qdisc", "show"],
        ]
        for argv in variants:
            with self.subTest(argv=argv), self.assertRaises(tc.CommandRefused):
                tc.check_argv(argv)


class TestS2DefenceInDepth(unittest.TestCase):
    """Each layer refuses on its own, so no single defect opens a mutation path."""

    def test_argv_for_revalidates_its_own_construction(self):
        from unittest import mock
        for bad_prefix in (("-s", "-j", "qdisc", "add", "dev"), ("-s", "-j", "qdisc", "del", "dev"),
                           ("-s", "-j", "class", "change", "dev")):
            with self.subTest(prefix=bad_prefix), mock.patch.object(tc, "ALLOWED_PREFIX", bad_prefix):
                with self.assertRaises(tc.CommandRefused):
                    tc.argv_for("veth0")
                spy = Spy()
                self.assertIs(tc.run_qdisc_show("veth0", runner=spy).status, Status.REFUSED)
                self.assertEqual(spy.calls, [])

    def test_each_protection_layer_refuses_alone(self):
        with self.assertRaisesRegex(tc.CommandRefused, "protected"):         # argv_for's own check
            tc.argv_for("enp0s31f6")
        with self.assertRaisesRegex(tc.CommandRefused, "not allowed"):       # check_argv's own check
            tc.check_argv((tc.TC_PATH, "-s", "-j", "qdisc", "show", "dev", "enp0s31f6"))
        self.assertIn("protected", tc.physical_or_unknown(FixtureReader({}), "enp0s31f6").detail)


class TestS3PhysicalNic(unittest.TestCase):
    def test_protected_by_explicit_list(self):
        self.assertIn("enp0s31f6", tc.PROTECTED)
        spy = Spy()
        r = tc.run_qdisc_show("enp0s31f6", runner=spy)
        self.assertIsInstance(r, Bad)
        self.assertIs(r.status, Status.REFUSED)
        self.assertEqual(spy.calls, [])
        with self.assertRaises(tc.CommandRefused):
            tc.check_argv((tc.TC_PATH, "-s", "-j", "qdisc", "show", "dev", "enp0s31f6"))

    def test_protected_even_if_sysfs_claims_virtual(self):
        fr = FixtureReader({}, links={"/sys/class/net/enp0s31f6": "../../devices/virtual/net/enp0s31f6"})
        self.assertIs(tc.physical_or_unknown(fr, "enp0s31f6").status, Status.REFUSED)

    def test_any_physical_interface_refused_generically(self):
        fr = FixtureReader({}, links={"/sys/class/net/eth9": "../../devices/pci0000:00/0000:00:1f.6/net/eth9"})
        self.assertIs(tc.physical_or_unknown(fr, "eth9").status, Status.REFUSED)

    def test_unknown_or_mismatched_link_fails_closed(self):
        fr = FixtureReader({}, links={"/sys/class/net/a0": Bad(Status.DENIED, "x"),
                                      "/sys/class/net/a1": "../../devices/virtual/net/other"})
        for name in ("a0", "a1", "a2"):     # denied, link names another device, absent
            with self.subTest(name):
                self.assertIs(tc.physical_or_unknown(fr, name).status, Status.REFUSED)

    def test_real_host_physical_nic_is_refused_by_sysfs(self):
        if not os.path.exists("/sys/class/net/enp0s31f6"):
            self.skipTest("this host's NIC not present")
        list_free = tc.PROTECTED - {"enp0s31f6"}
        r = LiveReader()
        link = r.readlink("/sys/class/net/enp0s31f6")
        self.assertNotIn(tc.VIRTUAL_NET, link)               # generic detection alone protects it
        self.assertFalse(list_free & {"enp0s31f6"})

    def test_physical_interface_never_measured_in_a_snapshot(self):
        w = World()
        r = w.reader
        def reader(k):
            x = r(k)
            x.links["/sys/class/net/eth0"] = "../../devices/pci0000:00/0000:00:1f.6/net/eth0"
            return x
        w.reader = reader
        s = build(w)
        m = meas(s, "net.drop.qdisc", IF)
        self.assertIs(m.quality, Q.MISSING)
        self.assertTrue(any("refused" in x.reason for x in s.missing_measurements if x.feature_id == "net.drop.qdisc"))


class TestS4MaliciousInterfaces(unittest.TestCase):
    def test_rejected_before_execution(self):
        for name in MALICIOUS:
            spy = Spy()
            with self.subTest(name=name):
                r = tc.run_qdisc_show(name, runner=spy)
                self.assertIs(r.status, Status.REFUSED)
                self.assertEqual(spy.calls, [])
                self.assertFalse(tc.valid_ifname(name))
                self.assertIs(tc.physical_or_unknown(FixtureReader({}), name).status, Status.REFUSED)

    def test_fixture_reader_applies_the_same_allowlist(self):
        for name in MALICIOUS:
            with self.subTest(name=name):
                self.assertIs(FixtureReader({}, qdisc={name: "[]"}).tc_qdisc(name).status, Status.REFUSED)


class TestS5Timeout(unittest.TestCase):
    def test_timeout_is_structured(self):
        spy = Spy(exc=subprocess.TimeoutExpired(["tc"], tc.TIMEOUT_S))
        r = tc.run_qdisc_show("lo", runner=spy)
        self.assertIs(r.status, Status.TIMEOUT)
        self.assertLessEqual(spy.calls[0][1]["timeout"], 2.0)

    def test_hanging_process_is_terminated(self):
        def hanging(argv, **kw):   # same kwargs, but the "tc" never answers
            return subprocess.run([sys.executable, "-c", "import time; time.sleep(30)"], **kw)
        t = time.monotonic()
        r = tc.run_qdisc_show("lo", runner=hanging)
        self.assertLess(time.monotonic() - t, tc.TIMEOUT_S + 1.5)
        self.assertIs(r.status, Status.TIMEOUT)

    def test_runtime_failures_are_structured(self):
        cases = ((Spy(exc=FileNotFoundError("tc")), Status.ABSENT), (Spy(exc=PermissionError("x")), Status.DENIED),
                 (Spy(subprocess.CompletedProcess([], 1, b"", b'Cannot find device "lo"')), Status.ABSENT),
                 (Spy(subprocess.CompletedProcess([], 2, b"", b"RTNETLINK answers: Operation not permitted")),
                  Status.DENIED),
                 (Spy(subprocess.CompletedProcess([], 0, b"\xff\xfe", b"")), Status.MALFORMED))
        for spy, status in cases:
            with self.subTest(status=status):
                self.assertIs(tc.run_qdisc_show("lo", runner=spy).status, status)


def _world_with(texts):
    w = World()
    for k in range(NB + NW + 1):
        w.qdisc_overrides[("eth0", k)] = texts(k)
    return w


class TestS6S7S8Semantics(unittest.TestCase):
    def test_s6_malformed_json_is_invalid(self):
        m = meas(build(_world_with(lambda k: "[{" if k >= NB else "[" + Q1 % 0 + "]")), "net.drop.qdisc", IF)
        self.assertIs(m.quality, Q.INVALID)
        self.assertIsNone(m.value)

    def test_s6_unexpected_schema_is_invalid(self):
        m = meas(build(_world_with(lambda k: '[{"kind":"x","handle":"0:","root":true,"drops":"0"}]')),
                 "net.drop.qdisc", IF)
        self.assertIs(m.quality, Q.INVALID)

    def test_s7_counter_decrease_invalidates_the_interval(self):
        drops = lambda k: 100 + 5 * k if k < 15 else 5 * (k - 15)          # reset at tick 15, then counting
        s = build(_world_with(lambda k: "[" + Q1 % drops(k) + "]"))
        m = meas(s, "net.drop.qdisc", IF)
        self.assertIs(m.quality, Q.PARTIAL)
        self.assertAlmostEqual(m.coverage, 0.9)
        self.assertEqual(m.value, 5.0)                                      # never a negative or clamped rate
        self.assertEqual(s.data_quality.counter_resets, 1)

    def test_s8_empty_output_is_missing_not_zero(self):
        s = build(_world_with(lambda k: "[]"))
        m = meas(s, "net.drop.qdisc", IF)
        self.assertIs(m.quality, Q.MISSING)
        self.assertIsNone(m.value)
        self.assertTrue(any("no qdisc" in x.reason for x in s.missing_measurements if x.feature_id == "net.drop.qdisc"))

    def test_single_non_root_qdisc_is_invalid(self):
        m = meas(build(_world_with(lambda k: '[{"kind":"fq_codel","handle":"0:","parent":":1","drops":0}]')),
                 "net.drop.qdisc", IF)
        self.assertIs(m.quality, Q.INVALID)

    def test_qdisc_tree_is_not_aggregated(self):
        tree = ('[{"kind":"mq","handle":"0:","root":true,"drops":7},'
                '{"kind":"fq_codel","handle":"0:","parent":":1","drops":3}]')
        s = build(_world_with(lambda k: tree))
        m = meas(s, "net.drop.qdisc", IF)
        self.assertIs(m.quality, Q.MISSING)
        self.assertTrue(any("no aggregation" in x.reason for x in s.missing_measurements
                            if x.feature_id == "net.drop.qdisc"))

    def test_tc_unavailable_is_missing(self):
        m = meas(build(_world_with(lambda k: Bad(Status.ABSENT, "tc is not installed"))), "net.drop.qdisc", IF)
        self.assertIs(m.quality, Q.MISSING)

    def test_timeout_is_missing(self):
        m = meas(build(_world_with(lambda k: Bad(Status.TIMEOUT, "x"))), "net.drop.qdisc", IF)
        self.assertIs(m.quality, Q.MISSING)

    def test_netns_guard_applies(self):
        w = World()
        r = w.reader
        def reader(k):
            x = r(k)
            x.links["/proc/100/ns/net"] = "net:[4026532999]"
            return x
        w.reader = reader
        self.assertIs(meas(build(w), "net.drop.qdisc", IF).quality, Q.MISSING)

    def test_valid_measurement(self):
        w = World()
        w.window_rates["tc.drops"] = 40
        s = build(w)
        m = meas(s, "net.drop.qdisc", IF)
        self.assertEqual((m.quality, m.value), (Q.OK, 40.0))
        self.assertEqual((m.baseline.median, m.baseline.n), (0.0, NB))
        self.assertEqual(m.provenance.source.value, "TC")
        self.assertEqual(m.provenance.locator, "tc -s -j qdisc show dev eth0 -> drops (single root qdisc)")
        self.assertEqual(m.provenance.collector, "m3a.tc.qdisc")


class TestS9NoMutation(unittest.TestCase):
    def test_only_read_only_argv_reachable(self):
        spy = Spy()
        for name in ("lo", "veth0", "br-lab", "dummy0") + MALICIOUS:
            tc.run_qdisc_show(name, runner=spy)
        self.assertTrue(spy.calls)
        for argv, kw in spy.calls:
            self.assertEqual(argv[:6], [tc.TC_PATH, "-s", "-j", "qdisc", "show", "dev"])
            self.assertEqual(len(argv), 7)
            self.assertIs(kw["shell"], False)
            self.assertFalse(set(argv) & tc.FORBIDDEN_TOKENS)

    @unittest.skipUnless(os.path.isfile(tc.TC_PATH) and os.path.exists("/sys/class/net/lo"), "needs tc and lo")
    def test_live_lo_read_leaves_qdisc_configuration_unchanged(self):
        before = tc.run_qdisc_show("lo")
        for _ in range(3):
            tc.run_qdisc_show("lo")
        after = tc.run_qdisc_show("lo")
        self.assertIsInstance(before, str)
        strip = lambda t: [{k: v for k, v in q.items() if k in ("kind", "handle", "root", "options", "refcnt")}
                           for q in json.loads(t)]
        self.assertEqual(strip(before), strip(after))
        self.assertTrue(qdiscs(before)[0].root)


class TestDeterminism(unittest.TestCase):
    def test_identical_fixture_identical_output(self):
        w = World()
        w.window_rates["tc.drops"] = 40
        a, b = build(w), build(w)
        self.assertEqual(canonical_bytes(meas(a, "net.drop.qdisc", IF)), canonical_bytes(meas(b, "net.drop.qdisc", IF)))
        self.assertEqual(canonical_bytes(a), canonical_bytes(b))

    def test_key_order_in_tc_json_irrelevant(self):
        w1, w2 = World(), World()
        w2.qdisc_overrides.update({("eth0", k): json.dumps(dict(reversed(list(json.loads(w1.qdisc(k))[0].items())))
                                                           ).join("[]") for k in range(NB + NW + 1)})
        self.assertEqual(canonical_bytes(build(w1)), canonical_bytes(build(w2)))


if __name__ == "__main__":
    unittest.main()
