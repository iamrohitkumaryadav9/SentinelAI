"""Lossless ticks.jsonl: exact typed round trip, Bad states, float edge cases, and byte-identical snapshot rebuild."""

import math
import struct
import unittest
from datetime import datetime, timedelta, timezone

from collectors._world import TARGET, World, params
from sentinelai.collectors import build_snapshot
from sentinelai.collectors.ebpf import EBPF_FEATURES, FixtureEbpfSource
from sentinelai.collectors.errors import Bad, Status
from sentinelai.collectors.normalize import Tick
from sentinelai.diagnostic.contract.serialize import canonical_bytes
from sentinelai.runtime.ticks import (FORMAT, TickFormatError, decode_tick, decode_ticks, decode_value,
                                      encode_tick, encode_ticks, encode_value)

from ebpf._replay import TGT, ensure_built, lines
from ebpf.test_measurements import workload

T0 = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
FLOATS = (0.0, -0.0, 5e-324, -5e-324, 2.2250738585072014e-308, 1.7976931348623157e308, float("inf"), float("-inf"),
          0.1, 1 / 3, 1e16, 123456789.0, 1048576.0)
NANS = (float("nan"), struct.unpack(">d", bytes.fromhex("fff8000000000000"))[0],
        struct.unpack(">d", bytes.fromhex("7ff0000000000001"))[0])


def same(a, b) -> bool:
    """Type-strict deep equality: 1 != 1.0 != True, -0.0 != 0.0, NaN bit patterns compared, dict order compared."""
    if type(a) is not type(b):
        return False
    if type(a) is float:
        return struct.pack(">d", a) == struct.pack(">d", b)
    if type(a) is dict:
        return list(a) == list(b) and all(type(k) is type(j) for k, j in zip(a, b)) and \
            all(same(a[k], b[k]) for k in a)
    if type(a) in (list, tuple):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    if type(a) is Bad:
        return a.status is b.status and a.detail == b.detail
    if type(a) is datetime:
        return a == b and a.utcoffset() == b.utcoffset()
    return a == b


def same_ticks(xs, ys) -> bool:
    return len(xs) == len(ys) and all(type(y) is Tick and x.index == y.index and same(x.mono, y.mono)
                                      and same(x.wall, y.wall) and same(x.obs, y.obs) for x, y in zip(xs, ys))


def rich_obs():
    return {"floats": {f"f{k}": x for k, x in enumerate(FLOATS)}, "nans": list(NANS),
            "keys": {1: 1.0, "1": 1, 0: True, "0": None, -7: "x", 10 ** 30: "big"},
            "ints": (0, -1, 2 ** 53 + 1, 10 ** 30), "bools": [True, False], "str": "ünïcode ☃ \"q\" \\",
            "bad": {s.value: Bad(s, f"detail {s.value}") for s in Status}, "bad_top": Bad(Status.TIMEOUT, ""),
            "nested": {"a": [{"b": (1.5, Bad(Status.DENIED, "x"))}], "empty": {}, "el": [], "et": ()},
            "none": None}


class TestRoundTrip(unittest.TestCase):
    def test_rich_tick_exact(self):
        t = Tick(0, 1234.5, T0.replace(microsecond=123000), rich_obs())
        line = encode_tick(t)
        back = decode_tick(line)
        self.assertTrue(same_ticks([t], [back]))
        self.assertEqual(encode_tick(back), line)                      # canonical: same tick -> same bytes

    def test_float_edge_cases(self):
        for x in FLOATS + NANS:
            back = decode_value(encode_value(x))
            self.assertTrue(same(x, back), repr(x))
        self.assertEqual(encode_value(-0.0), {"f": "-0x0.0p+0"})
        self.assertNotEqual(encode_value(-0.0), encode_value(0.0))

    def test_bad_states_kept(self):
        for s in Status:
            back = decode_value(encode_value(Bad(s, "why")))
            self.assertIs(type(back), Bad)
            self.assertIs(back.status, s)
            self.assertEqual(back.detail, "why")

    def test_missing_values_not_defaulted(self):
        obs = {"src": Bad(Status.ABSENT, "no file"), "g": {"x": None}, "empty": {}}
        back = decode_value(encode_value(obs))
        self.assertTrue(same(obs, back))
        self.assertIsNone(back["g"]["x"])
        self.assertEqual(back["empty"], {})

    def test_types_not_conflated(self):
        for v in (1, 1.0, True, "1", None, [1], (1,), {1: 1}, {"1": 1}):
            self.assertTrue(same(v, decode_value(encode_value(v))), repr(v))
        d = decode_value(encode_value({1: "int", "1": "str"}))
        self.assertEqual([type(k) for k in d], [int, str])

    def test_world_ticks_with_faults_rebuild_identically(self):
        w = World()
        w.override(f"/sys/fs/cgroup{TARGET.cgroup_path}/memory.pressure", range(3, 6), Bad(Status.DENIED, "x"))
        w.override("/proc/vmstat", [12], "garbage")
        w.override("/proc/meminfo", [14], Bad(Status.ABSENT, "gone"))
        ticks = w.ticks(TARGET)
        back = decode_ticks(encode_ticks(ticks))
        self.assertTrue(same_ticks(ticks, back))
        self.assertTrue(any(isinstance(v, Bad) for t in back for v in t.obs.values()))
        self.assertEqual(canonical_bytes(build_snapshot(back, TARGET, params())),
                         canonical_bytes(build_snapshot(ticks, TARGET, params())))

    def test_ebpf_ticks_rebuild_identically(self):
        ensure_built()
        src = FixtureEbpfSource(lines(workload(), capacity=256), TGT)
        ticks = World().ticks(TARGET)
        for t in ticks:
            t.obs.update(src.sample())
        back = decode_ticks(encode_ticks(ticks))
        self.assertTrue(same_ticks(ticks, back))
        p = params(**{f"floor[{f}]": 1e-3 for f in EBPF_FEATURES})
        self.assertEqual(canonical_bytes(build_snapshot(back, TARGET, p, ebpf=True)),
                         canonical_bytes(build_snapshot(ticks, TARGET, p, ebpf=True)))


class TestRefusals(unittest.TestCase):
    def test_unsupported_types_raise(self):
        for v in (object(), {1.5: "x"}, {(1,): "x"}, {None: 1}, b"bytes", set(), datetime(2026, 1, 1),
                  {"x": Bad("absent", "string status")}, timedelta(1)):
            with self.assertRaises(TickFormatError, msg=repr(v)):
                encode_value(v)

    def test_malformed_values_raise(self):
        for obj in ({}, {"f": 1.0}, {"f": "nan"}, {"nan": "7ff0000000000000"}, {"nan": "zz"}, {"d": [[{"x": 1}, 1]]},
                    {"d": [[{"s": "a"}, 1], [{"s": "a"}, 2]]}, {"d": [[{"i": "1"}, 1]]}, {"bad": ["nope", ""]},
                    {"bad": ["absent"]}, {"dt": "2026-01-01T00:00:00"}, {"q": 1}, {"f": "0x1p0", "l": []}, [1, 2],
                    1.5):
            with self.assertRaises(TickFormatError, msg=repr(obj)):
                decode_value(obj)

    def test_malformed_lines_raise(self):
        good = encode_tick(Tick(0, 1.0, T0, {"a": 1.0}))
        for line in ("not json", "{}", good.replace(FORMAT, "other.v9"), good.replace('"index":0', '"index":0.0'),
                     good.replace('"index":0', '"index":true'), good[:-1], good.replace(",", ", ", 1),
                     good.replace('{"dt"', '{"f":"0x1p0","dt"', 1)):
            with self.assertRaises(TickFormatError, msg=line):
                decode_tick(line)

    def test_sequence_and_framing(self):
        t0, t1 = Tick(0, 1.0, T0, {}), Tick(1, 2.0, T0, {})
        with self.assertRaises(TickFormatError):
            encode_ticks([t1])
        with self.assertRaises(TickFormatError):
            decode_ticks(encode_ticks([t0, t1]).replace(b"\n", b"", 1))
        data = encode_ticks([t0, t1])
        with self.assertRaises(TickFormatError):
            decode_ticks(data[:-1])                                        # no final newline: truncated
        lines_ = data.decode().splitlines()
        with self.assertRaises(TickFormatError):
            decode_ticks((lines_[1] + "\n" + lines_[0] + "\n").encode())
        with self.assertRaises(TickFormatError):
            encode_tick(Tick(0, 1, T0, {}))                                 # int mono
        self.assertEqual(decode_ticks(b""), [])


if __name__ == "__main__":
    unittest.main()
