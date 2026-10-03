"""Correlation and accounting semantics of the kernel handlers (sentinel_core.h), exercised through the
replay harness, which compiles the exact handler code the BPF program runs."""

import unittest

from sentinelai.collectors.ebpf import HIST_BUCKETS, KFREE_SLOTS, VECTORS, bucket_hi, bucket_index, bucket_lo

from ._replay import MS, NETNS, OTHER_NS, S, US, Script, ensure_built, last, meta, replay


def setUpModule():
    ensure_built()


def hist(sample):
    return {i: c for i, c in sample["sched"]["hist"]}


def sirq(sample):
    return {(c, VECTORS[v]): (ns, n) for c, v, ns, n in sample["softirq"] if n or ns}


def kfree(sample):
    return {s: c for s, c in sample["kfree"]}


class TestScheduler(unittest.TestCase):
    def test_wakeup_to_switch_latency(self):
        s = last(Script().at(1000).cpu(0).wakeup(101, 1).at(1000 + 50 * US).switch(0, 101).dump())
        self.assertEqual(hist(s), {bucket_index(50 * US): 1})
        self.assertEqual((s["stats"]["wake_recorded"], s["stats"]["lat_recorded"]), (1, 1))

    def test_multiple_tasks_interleaved(self):
        sc = Script().at(0).cpu(0).wakeup(201, 1).at(10 * US).wakeup(202, 1).at(20 * US).wakeup(203, 1)
        sc.at(30 * US).switch(0, 202).at(1 * MS).switch(202, 201).at(5 * MS).switch(201, 203).dump()
        s = last(sc)
        want = {}
        for lat in (20 * US, 1 * MS, 5 * MS - 20 * US):          # 202: 30-10 us, 201: 1 ms - 0, 203: 5 ms - 20 us
            want[bucket_index(lat)] = want.get(bucket_index(lat), 0) + 1
        self.assertEqual(hist(s), want)
        self.assertEqual(s["stats"]["lat_recorded"], 3)

    def test_migration_woken_on_one_cpu_run_on_another(self):
        s = last(Script().at(0).cpu(0).wakeup(301, 1).cpu(1).at(80 * US).switch(0, 301).dump())
        self.assertEqual(hist(s), {bucket_index(80 * US): 1})
        self.assertEqual((s["stats"]["lat_migrated"], s["stats"]["lat_recorded"]), (1, 1))

    def test_stale_wakeup_discarded(self):
        s = last(Script(lat_stale=1 * S).at(0).cpu(0).wakeup(401, 1).at(2 * S).switch(0, 401).dump())
        self.assertEqual(hist(s), {})
        self.assertEqual((s["stats"]["lat_stale"], s["stats"]["lat_recorded"]), (1, 0))

    def test_unmatched_switch_records_nothing(self):
        s = last(Script().at(0).cpu(0).switch(0, 501).at(10 * US).switch(501, 502).dump())
        self.assertEqual(hist(s), {})
        self.assertEqual(s["stats"]["lat_recorded"], 0)

    def test_repeated_wakeup_keeps_the_earliest(self):
        s = last(Script().at(0).cpu(0).wakeup(601, 1).at(40 * US).wakeup(601, 1).at(100 * US).switch(0, 601).dump())
        self.assertEqual(hist(s), {bucket_index(100 * US): 1})              # measured from the first wakeup
        self.assertEqual((s["stats"]["wake_repeat"], s["stats"]["lat_recorded"]), (1, 1))

    def test_wakeup_of_a_running_task_is_cancelled_at_switch_out(self):
        """ttwu on a task that is still running: it never waited, and its stale timestamp must not be used
        for its next real wakeup."""
        sc = Script().at(0).cpu(0).switch(0, 701).at(10 * US).wakeup(701, 1)       # woken while running
        sc.at(2 * MS).switch(701, 0)                                              # switched out: cancelled
        sc.at(3 * MS).wakeup(701, 1).at(3 * MS + 30 * US).switch(0, 701).dump()   # real wakeup: 30 us
        s = last(sc)
        self.assertEqual(hist(s), {bucket_index(30 * US): 1})
        self.assertEqual(s["stats"]["wake_cancelled_running"], 1)

    def test_wakeup_new_replaces_a_dead_tasks_entry(self):
        """tid reuse: a new task (wakeup_new) never inherits the pending entry of an earlier holder."""
        sc = Script().at(0).cpu(0).wakeup(801, 1)                 # holder exits without running (entry left)
        sc.at(5 * S).wakeup_new(801, 1).at(5 * S + 20 * US).switch(0, 801).dump()
        s = last(sc)
        self.assertEqual(hist(s), {bucket_index(20 * US): 1})
        self.assertEqual((s["stats"]["wake_new"], s["stats"]["wake_new_replaced"]), (1, 1))

    def test_non_target_and_idle_tasks_ignored(self):
        sc = Script().at(0).cpu(0).wakeup(901, 0).wakeup(0, 1).at(10 * US).switch(0, 901).switch(901, 0).dump()
        s = last(sc)
        self.assertEqual(hist(s), {})
        self.assertEqual(sum(s["stats"].values()), 0)

    def test_negative_latency_discarded(self):
        s = last(_negative())                                  # clock forced backwards between wakeup and switch
        self.assertEqual(hist(s), {})
        self.assertEqual(s["stats"]["lat_negative"], 1)

    def test_bounded_state_lru_eviction(self):
        """The pending-wakeup map is bounded: with capacity 4, a 5th pending wakeup evicts the least
        recently used entry, whose task then records nothing (no unbounded per-tid state)."""
        sc = Script().at(0).cpu(0)
        for tid in range(1101, 1106):
            sc.wakeup(tid, 1)
        sc.at(50 * US)
        for tid in range(1101, 1106):
            sc.switch(0, tid)
        s = last(sc.dump(), capacity=4)
        self.assertEqual(s["stats"]["wake_recorded"], 5)
        self.assertEqual(s["stats"]["lat_recorded"], 4)                 # tid 1101 was evicted
        self.assertEqual(hist(s), {bucket_index(50 * US): 4})

    def test_histogram_buckets_match_python(self):
        """C bucket index (sn_hist_index) == Python bucket_index for boundary latencies, and every value
        lies inside its bucket's [lo, hi]."""
        vals = [1, 15, 16, 17, 31, 32, 33, 1000, 4095, 4096, 65535, 65536, 999_999, 1_000_000, 123_456_789,
                9_999_999_999]
        sc = Script(lat_stale=20 * S).cpu(0)
        t = 0
        for i, v in enumerate(vals):
            t += 1
            sc.at(t).wakeup(2000 + i, 1)
            t += v
            sc.at(t).switch(0, 2000 + i)
        s = last(sc.dump())
        want = {}
        for v in vals:
            want[bucket_index(v)] = want.get(bucket_index(v), 0) + 1
            self.assertTrue(bucket_lo(bucket_index(v)) <= v <= bucket_hi(bucket_index(v)), v)
        self.assertEqual(hist(s), want)

    def test_quantile_is_nearest_rank_upper_edge(self):
        """Project convention (normalize.baseline_stats): the ceil(q*n)-th smallest sample; reported as the upper
        edge of its bucket."""
        from sentinelai.collectors.ebpf import quantile_ns
        a, b, c = bucket_index(10), bucket_index(1000), bucket_index(100_000)
        h = {a: 1, b: 1, c: 1}
        self.assertEqual(quantile_ns(h, 0.50), bucket_hi(b))            # ceil(1.5) = 2nd
        self.assertEqual(quantile_ns(h, 0.99), bucket_hi(c))            # ceil(2.97) = 3rd
        self.assertEqual(quantile_ns(h, 0.10), bucket_hi(a))            # ceil(0.3) = 1st
        self.assertEqual(quantile_ns({a: 99, c: 1}, 0.99), bucket_hi(a))   # 99th of 100
        self.assertEqual(quantile_ns({a: 98, c: 2}, 0.99), bucket_hi(c))
        self.assertEqual(quantile_ns({b: 4}, 0.5), bucket_hi(b))
        self.assertIsNone(quantile_ns({}, 0.5))
        self.assertIsNone(quantile_ns({a: 0}, 0.99))

    def test_bucket_geometry(self):
        self.assertEqual(HIST_BUCKETS, 528)
        for i in range(HIST_BUCKETS - 1):
            self.assertEqual(bucket_hi(i) + 1, bucket_lo(i + 1))          # contiguous, no gaps or overlaps
        for i in range(16, HIST_BUCKETS):
            self.assertLessEqual((bucket_hi(i) - bucket_lo(i) + 1) / bucket_lo(i), 1 / 16 + 1e-12)


def _negative():
    return Script().at(5 * MS).cpu(0).wakeup(1001, 1).__getattr__("t!")(0).switch(0, 1001).dump()


class TestSoftirq(unittest.TestCase):
    def test_net_rx_net_tx_and_non_network_stay_distinct(self):
        sc = Script().cpu(0).at(0).entry("NET_RX").at(2 * MS).exit("NET_RX")
        sc.at(3 * MS).entry("TIMER").at(4 * MS).exit("TIMER")
        sc.cpu(1).at(5 * MS).entry("NET_TX").at(5 * MS + 500 * US).exit("NET_TX").dump()
        self.assertEqual(sirq(last(sc)), {(0, "NET_RX"): (2 * MS, 1), (0, "TIMER"): (1 * MS, 1),
                                          (1, "NET_TX"): (500 * US, 1)})

    def test_every_cpu_vector_cell_reported(self):
        s = last(Script().dump(), ncpu=3)
        self.assertEqual(len(s["softirq"]), 3 * len(VECTORS))

    def test_entry_exit_robustness(self):
        sc = Script().cpu(0).at(0).exit("NET_RX")                          # exit without entry
        sc.at(1 * MS).entry("NET_RX").at(2 * MS).exit("NET_TX")            # vector mismatch
        sc.at(3 * MS).entry("NET_RX").at(4 * MS).entry("NET_RX").at(5 * MS).exit("NET_RX")   # lost exit
        sc.sirq_entry(10).sirq_exit(17)                                     # vec >= NR_SOFTIRQS
        s = last(sc.dump())
        st = s["stats"]
        self.assertEqual((st["sirq_unmatched_exit"], st["sirq_mismatch"], st["sirq_entry_overwritten"],
                          st["sirq_invalid_vec"], st["sirq_recorded"]), (1, 1, 1, 2, 1))
        self.assertEqual(sirq(s), {(0, "NET_RX"): (1 * MS, 1)})            # only the matched pair (4->5 ms)

    def test_stale_softirq_discarded(self):
        s = last(Script(sirq_stale=1 * MS).cpu(0).at(0).entry("NET_RX").at(5 * MS).exit("NET_RX").dump())
        self.assertEqual((sirq(s), s["stats"]["sirq_stale"]), ({}, 1))

    def test_per_cpu_pending_entries_are_independent(self):
        sc = Script().cpu(0).at(0).entry("NET_RX").cpu(1).at(1 * MS).entry("NET_TX")
        sc.at(3 * MS).exit("NET_TX").cpu(0).at(4 * MS).exit("NET_RX").dump()
        self.assertEqual(sirq(last(sc)), {(0, "NET_RX"): (4 * MS, 1), (1, "NET_TX"): (2 * MS, 1)})


class TestRetransmissions(unittest.TestCase):
    def test_counts_target_netns_events_only(self):
        sc = Script()
        for _ in range(7):
            sc.retrans(NETNS)
        sc.retrans(OTHER_NS).retrans(OTHER_NS).retrans(0).dump()
        s = last(sc)
        self.assertEqual(s["retrans"], 7)
        self.assertEqual((s["stats"]["retrans_other_netns"], s["stats"]["retrans_unattributed"]), (2, 1))


class TestKfree(unittest.TestCase):
    def test_reasons_never_collapse(self):
        m = meta(Script().dump())
        slot = {name: i for i, name in m["reasons"]}
        sc = Script()
        for r, n in (("NOT_SPECIFIED", 3), ("QDISC_DROP", 2), ("TCP_CSUM", 1)):
            for _ in range(n):
                sc.kfree(NETNS, r)
        s = last(sc.dump())
        self.assertEqual(kfree(s), {slot["NOT_SPECIFIED"]: 3, slot["QDISC_DROP"]: 2, slot["TCP_CSUM"]: 1})

    def test_attribution_and_overflow(self):
        sc = Script().kfree(OTHER_NS, "QDISC_DROP").kfree(0, "QDISC_DROP").kfree(NETNS, 70000).kfree(NETNS, 70001)
        s = last(sc.dump())
        self.assertEqual(kfree(s), {KFREE_SLOTS: 2})                          # subsystem reasons: overflow slot
        st = s["stats"]
        self.assertEqual((st["kfree_other_netns"], st["kfree_unattributed"], st["kfree_overflow"]), (1, 1, 2))

    def test_reason_names_come_from_kernel_btf(self):
        names = {name for _, name in meta(Script().dump())["reasons"]}
        self.assertLessEqual({"NOT_SPECIFIED", "QDISC_DROP", "CPU_BACKLOG", "NETFILTER_DROP", "TCP_CSUM"}, names)
        self.assertNotIn("MAX", names)


class TestHarnessInputValidation(unittest.TestCase):
    def test_malformed_script_rejected(self):
        for body in ("wakeup 1 1\n", "cfg 1 2 3 4 5\nbogus 1\n", "cfg 1 2 3 4 5\nt 10\nt 5\n",
                     "cfg 1 2 3 4 5\ncpu 9\n", "cfg 1 2 3 4 5\nkfree 3 NO_SUCH_REASON\n"):
            with self.subTest(body=body):
                sc = Script()
                sc.lines = body.strip().splitlines()
                self.assertEqual(replay(sc, check=False).returncode, 65)


if __name__ == "__main__":
    unittest.main()
