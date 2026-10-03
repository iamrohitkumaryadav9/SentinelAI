"""Strict validation of the loader line protocol, and the process boundary (sentinelai.ebpf)."""

import json
import tempfile
import unittest
from pathlib import Path

from sentinelai.collectors.ebpf import (EBPF_SOURCES, OVERFLOW_REASON, EbpfStream, EbpfTarget, ProtocolError,
                                        parse_meta, parse_sample)
from sentinelai.collectors.errors import Bad, Status
from sentinelai.ebpf import LoaderRefused, ProcessEbpfSource, loader_argv, replay_argv
from sentinelai.ebpf.loader import DEFAULT_LOADER, DEFAULT_REPLAY

from ._replay import NETNS, S, TGT, Script, ensure_built, lines


def setUpModule():
    ensure_built()


def base_lines():
    return lines(Script().retrans(NETNS).kfree(NETNS, "QDISC_DROP").at(1).dump().at(2).dump())


def mutate(line, fn):
    d = json.loads(line)
    fn(d)
    return json.dumps(d)


class TestMeta(unittest.TestCase):
    def setUp(self):
        self.meta_line = base_lines()[0]

    def test_valid(self):
        m = parse_meta(self.meta_line)
        self.assertEqual((m.producer, m.target, m.ncpu), ("sentinel_replay", TGT, 2))
        self.assertTrue(m.libbpf.startswith("1."))
        self.assertEqual(len(m.reasons), 129)
        self.assertEqual(m.reasons[-1], OVERFLOW_REASON)

    def test_rejections(self):
        cases = {
            "protocol version": lambda d: d.update(v=2),
            "libbpf 0.x": lambda d: d.update(libbpf="0.5"),
            "geometry": lambda d: d["hist"].update(sub_bits=3),
            "vectors": lambda d: d.update(vectors=d["vectors"][::-1]),
            "stats": lambda d: d.update(stats=d["stats"][:-1]),
            "extra key": lambda d: d.update(extra=1),
            "missing cfg key": lambda d: d["cfg"].pop("netns_inum"),
            "producer": lambda d: d.update(producer="bpftool"),
            "version": lambda d: d.update(version="m3b-0.9"),
            "bad reason name": lambda d: d["reasons"].append([120, "lower-case"]),
            "duplicate reason slot": lambda d: d["reasons"].append(list(d["reasons"][0])),
            "placeholder collision": lambda d: d["reasons"].append([121, "UNKNOWN_121"]),
            "negative": lambda d: d["cfg"].update(cgroup_id=-1),
            "bool as int": lambda d: d.update(ncpu=True),
        }
        for name, fn in cases.items():
            with self.subTest(name), self.assertRaises(ProtocolError):
                parse_meta(mutate(self.meta_line, fn))
        for bad in ("", "not json", "[]", '{"v":1,"type":"sample"}',
                    '{"v":1,"type":"unavailable","reason":"BPF load failed"}'):
            with self.subTest(line=bad), self.assertRaises(ProtocolError):
                parse_meta(bad)


class TestSample(unittest.TestCase):
    def setUp(self):
        ls = base_lines()
        self.meta = parse_meta(ls[0])
        self.line = ls[1]

    def test_valid(self):
        s = parse_sample(self.line, self.meta)
        self.assertEqual((s.retrans, len(s.softirq)), (1, 20))

    def test_rejections(self):
        cases = {
            "bucket out of range": lambda d: d["sched"]["hist"].append([528, 1]),
            "duplicate bucket": lambda d: d["sched"]["hist"].extend([[3, 1], [3, 1]]),
            "cpu out of range": lambda d: d["softirq"].append([2, 0, 0, 0]),
            "softirq cell missing": lambda d: d["softirq"].pop(),
            "softirq duplicate": lambda d: d["softirq"].__setitem__(1, d["softirq"][0]),
            "kfree slot > overflow": lambda d: d["kfree"].append([129, 1]),
            "negative count": lambda d: d.update(retrans=-1),
            "float count": lambda d: d.update(retrans=1.5),
            "stats missing": lambda d: d["stats"].pop("lat_recorded"),
            "extra key": lambda d: d.update(diagnosis="softirq_overload"),
            "type": lambda d: d.update(type="meta"),
        }
        for name, fn in cases.items():
            with self.subTest(name), self.assertRaises(ProtocolError):
                parse_sample(mutate(self.line, fn), self.meta)


class TestStream(unittest.TestCase):
    def test_sequence_and_clock_must_advance(self):
        ls = base_lines()
        st = EbpfStream(TGT)
        self.assertIsNone(st.start(ls[0]))
        self.assertIsInstance(st.observe(ls[1])["ebpf.retrans"], dict)
        replayed = st.observe(ls[1])
        self.assertTrue(all(isinstance(v, Bad) and v.status is Status.MALFORMED for v in replayed.values()))

    def test_bad_lines_are_bad_observations(self):
        ls = base_lines()
        st = EbpfStream(TGT)
        st.start(ls[0])
        for line, status in ((None, Status.TIMEOUT), ("garbage", Status.MALFORMED),
                             ('{"v":1,"type":"end","reason":"max-seconds reached"}', Status.ABSENT)):
            with self.subTest(line=line):
                obs = st.observe(line)
                self.assertEqual(set(obs), set(EBPF_SOURCES))
                self.assertTrue(all(v.status is status for v in obs.values()))

    def test_unavailable_first_line(self):
        st = EbpfStream(TGT)
        reason = st.start('{"v":1,"type":"unavailable","reason":"BPF load failed (privileges or verifier)"}')
        self.assertIn("BPF load failed", reason)
        self.assertTrue(all(v.status is Status.ABSENT for v in st.observe(None).values()))


class TestUnavailableSource(unittest.TestCase):
    def test_every_source_bad_with_reason(self):
        from sentinelai.collectors.ebpf import UnavailableEbpfSource
        obs = UnavailableEbpfSource("BPF load failed (privileges or verifier)").sample()
        self.assertEqual(set(obs), set(EBPF_SOURCES))
        for v in obs.values():
            self.assertIsInstance(v, Bad)
            self.assertEqual((v.status, v.detail), (Status.DENIED, "BPF load failed (privileges or verifier)"))


class TestProcessBoundary(unittest.TestCase):
    def script(self, sc):
        fh = tempfile.NamedTemporaryFile("w", suffix=".sn", delete=False)
        fh.write(sc.text())
        fh.close()
        self.addCleanup(Path(fh.name).unlink)
        return fh.name

    def test_serves_samples_on_request(self):
        path = self.script(Script().retrans(NETNS).at(1 * S).dump().retrans(NETNS).at(2 * S).dump())
        src = ProcessEbpfSource(replay_argv(path, ncpu=2), TGT)
        self.assertIsNone(src.start())
        self.assertEqual(src.sample()["ebpf.retrans"], {"target": 1.0})
        self.assertEqual(src.sample()["ebpf.retrans"], {"target": 2.0})
        after = src.sample()                                                 # script finished: never zeros
        self.assertTrue(all(isinstance(v, Bad) for v in after.values()))
        src.close()
        self.assertEqual(src.proc.returncode, 0)

    def test_target_mismatch_refuses_stream(self):
        path = self.script(Script().at(1).dump())
        src = ProcessEbpfSource(replay_argv(path), EbpfTarget(9, 9, 9))
        self.assertIn("configured for", src.start())
        self.assertTrue(all(v.status is Status.UNVERIFIED for v in src.sample().values()))

    def test_argv_allowlist(self):
        ok = loader_argv(TGT, 60)
        self.assertEqual(ok[0], str(DEFAULT_LOADER))
        self.assertEqual(ok[1:], ["--cgroup-id", "777", "--cgroup-level", "2", "--netns-inum", str(NETNS),
                                  "--max-seconds", "60"])
        refused = [
            lambda: loader_argv(TGT, 0), lambda: loader_argv(TGT, 86401),
            lambda: loader_argv(EbpfTarget(0, 2, NETNS), 60), lambda: loader_argv(EbpfTarget(1, 65, NETNS), 60),
            lambda: loader_argv(TGT, 60, binary="sentinel_loader"),                      # relative
            lambda: loader_argv(TGT, 60, binary="/usr/bin/bpftool"),                     # other binary
            lambda: replay_argv("relative.sn"),
            lambda: ProcessEbpfSource(["/bin/sh", "-c", "true"], TGT),
            lambda: ProcessEbpfSource([str(DEFAULT_LOADER), "--cgroup-id", "1", "--exec", "x"], TGT),
            lambda: ProcessEbpfSource([str(DEFAULT_REPLAY), "--cgroup-id", "1"], TGT),
            lambda: ProcessEbpfSource("sentinel_loader --version", TGT),
        ]
        for i, fn in enumerate(refused):
            with self.subTest(i=i), self.assertRaises(LoaderRefused):
                fn()

    def test_oversized_line_is_dropped_not_buffered(self):
        from unittest import mock
        from sentinelai.ebpf import loader as loader_mod
        sc = Script()
        for _ in range(3):
            sc.kfree(NETNS, "QDISC_DROP")
        path = self.script(sc.at(1).dump())
        src = ProcessEbpfSource(replay_argv(path, ncpu=2), TGT, timeout_s=0.5)
        self.assertIsNone(src.start())
        with mock.patch.object(loader_mod, "MAX_LINE", 200):             # a sample line is far longer
            obs = src.sample()
        self.assertTrue(all(isinstance(v, Bad) for v in obs.values()))
        self.assertLessEqual(len(src._buf), 200)
        src.close()

    def test_start_failure_is_unavailable(self):
        src = ProcessEbpfSource([str(DEFAULT_REPLAY.with_name("missing") / "sentinel_replay"), "--serve", "/x"], TGT)
        self.assertIn("could not start", src.start())
        self.assertTrue(all(isinstance(v, Bad) for v in src.sample().values()))


if __name__ == "__main__":
    unittest.main()
