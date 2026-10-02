"""Parsers: valid, malformed, partial, unexpected-field and unit cases for every source format."""

import unittest

from sentinelai.collectors import ParseError
from sentinelai.collectors.parsers import cgroup as pc
from sentinelai.collectors.parsers import proc as pp

from ._world import World


class TestProcStat(unittest.TestCase):
    def test_valid(self):
        p = pp.proc_stat(World().files(3)["/proc/stat"])
        self.assertEqual(sorted(k for k in p["cpus"] if k != "all"), [0, 1])
        self.assertEqual(p["cpus"][0]["softirq"], 1_000_000 + 15)
        self.assertEqual(p["ctxt"], 1_000_000 + 12000)
        self.assertEqual(p["procs_running"], 3)

    def test_unexpected_lines_and_guest_columns_tolerated(self):
        text = "cpu  1 2 3 4 5 6 7 8 9 10 11\ncpu0 1 2 3 4 5 6 7 8\nweird 1 2\nctxt 5\n"
        p = pp.proc_stat(text)
        self.assertEqual(p["cpus"]["all"]["steal"], 8)

    def test_malformed(self):
        for text in ("cpu  1 2 3\n", "cpu  1 2 3 4 5 6 7 x\n", "cpu0 1 2 3 4 5 6 7 8\n",   # short / non-int / no aggregate
                     "cpu  1 2 3 4 5 6 7 8\ncpu0 1 2 3 4 5 6 7 8\ncpu0 1 2 3 4 5 6 7 8\n",   # duplicate cpu
                     "cpu  1 2 3 4 5 6 7 -8\n", "cpu  1 2 3 4 5 6 7 8\nctxt 5 6\n", ""):
            with self.subTest(text=text), self.assertRaises(ParseError):
                pp.proc_stat(text)


class TestSchedstat(unittest.TestCase):
    def test_valid_field8(self):
        p = pp.schedstat("version 15\ntimestamp 1\ncpu0 0 0 0 0 0 0 13001258287241 38697429301 19982755\n"
                         "domain0 000003 0 0\ncpu3 0 0 0 0 0 0 1 77 1\n")
        self.assertEqual(p, {0: 38697429301, 3: 77})

    def test_unsupported_version_and_malformed(self):
        for text in ("version 16\ncpu0 0 0 0 0 0 0 1 2 3\n", "cpu0 0 0 0 0 0 0 1 2 3\n",
                     "version 15\ncpu0 0 0 0\n", "version 15\ncpu0 0 0 0 0 0 0 1 x 3\n", "version 15\n"):
            with self.subTest(text=text), self.assertRaises(ParseError):
                pp.schedstat(text)


class TestSoftnet(unittest.TestCase):
    def test_hex_and_cpu_identity_from_column(self):
        rows = ("0000dbc2 00000003 0000000a " + "00000000 " * 9 + "00000005 00000000 00000000\n"
                "00000010 00000000 00000001 " + "00000000 " * 9 + "00000009 00000000 00000000\n")
        p = pp.softnet_stat(rows)
        self.assertEqual(p, {5: {"processed": 0xdbc2, "dropped": 3, "time_squeeze": 10},
                             9: {"processed": 16, "dropped": 0, "time_squeeze": 1}})   # rows != CPU index

    def test_rejects_rows_without_cpu_id(self):
        with self.assertRaises(ParseError):   # pre-5.10 layout: rows cannot be attributed to CPUs
            pp.softnet_stat("0000dbc2 00000000 00000000 00000000 00000000\n")

    def test_malformed(self):
        good = "00000001 " * 12 + "00000000\n"
        for text in ("zz" + good, good + good, ""):    # non-hex / duplicate cpu / empty
            with self.subTest(text=text[:20]), self.assertRaises(ParseError):
                pp.softnet_stat(text)


class TestSnmp(unittest.TestCase):
    def test_parsed_by_header_name(self):
        text = "Tcp: RtoMin OutSegs MaxConn RetransSegs\nTcp: 200 900 -1 7\nUdp: X\nUdp: 1\n"
        p = pp.snmp_table(text, "Tcp", "snmp")
        self.assertEqual((p["OutSegs"], p["RetransSegs"], p["MaxConn"]), (900, 7, -1))

    def test_column_order_irrelevant(self):
        a = pp.snmp_table("Tcp: OutSegs RetransSegs\nTcp: 5 6\n", "Tcp", "snmp")
        b = pp.snmp_table("Tcp: RetransSegs OutSegs\nTcp: 6 5\n", "Tcp", "snmp")
        self.assertEqual(a, b)

    def test_malformed(self):
        for text in ("Udp: X\nUdp: 1\n", "Tcp: A B\nTcp: 1\n", "Tcp: A\n", "Tcp: A A\nTcp: 1 2\n", "Tcp: A\nTcp: z\n"):
            with self.subTest(text=text), self.assertRaises(ParseError):
                pp.snmp_table(text, "Tcp", "snmp")


class TestSoftirqs(unittest.TestCase):
    def test_valid(self):
        p = pp.softirqs("    CPU0  CPU1\n  HI: 0 0\n NET_TX: 5 6\n NET_RX: 7 8\n")
        self.assertEqual(p, {"NET_TX": {0: 5, 1: 6}, "NET_RX": {0: 7, 1: 8}})

    def test_malformed(self):
        for text in ("CPU0 CPU1\nNET_TX: 5\nNET_RX: 7 8\n", "CPU0\nNET_TX: 5\n", "foo bar\n", ""):
            with self.subTest(text=text), self.assertRaises(ParseError):
                pp.softirqs(text)


class TestPsiMeminfoVmstat(unittest.TestCase):
    def test_psi(self):
        p = pp.psi("some avg10=0.00 avg60=0.00 avg300=0.00 total=49072\nfull avg10=0.00 total=12\n", "x")
        self.assertEqual(p, {"some": 49072, "full": 12})
        for text in ("full total=1\n", "some avg10=0.00\n", "some total=x\n", "other total=1\n"):
            with self.subTest(text=text), self.assertRaises(ParseError):
                pp.psi(text, "x")

    def test_meminfo(self):
        self.assertEqual(pp.meminfo("MemTotal: 100 kB\nMemAvailable: 40 kB\nHugePages_Total: 0\n")["MemAvailable"], 40)
        for text in ("MemTotal: 100 kB\n", "MemTotal: 0 kB\nMemAvailable: 0 kB\n"):
            with self.subTest(text=text), self.assertRaises(ParseError):
                pp.meminfo(text)

    def test_keyed(self):
        self.assertEqual(pp.vmstat("a 1\nb 2\n"), {"a": 1, "b": 2})
        for text in ("a 1\na 2\n", "a\n", "a -1\n", "a 1 2\n", ""):
            with self.subTest(text=text), self.assertRaises(ParseError):
                pp.vmstat(text)


class TestTaskFiles(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(pp.task_schedstat("1 22 3\n"), 22)
        self.assertEqual(pp.task_sched_migrations("x (1, #threads: 1)\nse.nr_migrations    :   112\n"), 112)
        self.assertEqual(pp.task_status_nonvol("Name:\tx\nnonvoluntary_ctxt_switches:\t9\n"), 9)
        stat = "77 (a (weird) name) S " + " ".join(["0"] * 35) + " 6 " + " ".join(["0"] * 13)
        self.assertEqual(pp.task_stat_processor(stat), 6)          # comm with spaces and parentheses

    def test_malformed(self):
        for fn, text in ((pp.task_schedstat, "1 2\n"), (pp.task_schedstat, "1 x 3\n"),
                         (pp.task_sched_migrations, "se.other : 1\n"), (pp.task_status_nonvol, "Name: x\n"),
                         (pp.task_stat_processor, "77 (x) S 1 2\n"), (pp.task_stat_processor, "no parens\n")):
            with self.subTest(fn=fn.__name__, text=text), self.assertRaises(ParseError):
                fn(text)


class TestCgroup(unittest.TestCase):
    def test_cpu_max_three_states(self):
        self.assertIsNone(pc.cpu_max("max 100000\n"))               # unlimited (a real value)
        self.assertEqual(pc.cpu_max("50000 100000\n"), (50000, 100000))
        for text in ("", "max\n", "0 100000\n", "50000 0\n", "abc 100000\n", "1 2 3\n"):   # malformed
            with self.subTest(text=text), self.assertRaises(ParseError):
                pc.cpu_max(text)

    def test_memory_max_and_singles(self):
        self.assertIsNone(pc.memory_max("max\n"))
        self.assertEqual(pc.memory_max("4096\n"), 4096)
        for text in ("", "-1\n", "1 2\n", "12k\n"):
            with self.subTest(text=text), self.assertRaises(ParseError):
                pc.single(text, "memory.current")

    def test_cpuset_list(self):
        self.assertEqual(pc.cpuset_list("0-3,8\n"), (0, 1, 2, 3, 8))
        for text in ("", "3-1", "a", "0-"):
            with self.subTest(text=text), self.assertRaises(ParseError):
                pc.cpuset_list(text)


if __name__ == "__main__":
    unittest.main()
