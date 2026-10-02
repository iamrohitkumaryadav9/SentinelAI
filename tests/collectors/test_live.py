"""Short read-only collection on the real host -> valid snapshot -> M2 (the full smoke run is scripts/m3a_smoke.py)."""

import os
import unittest

from sentinelai.collectors import LiveReader, collect_snapshot, resolve_target
from sentinelai.diagnostic.contract import Quality
from sentinelai.diagnostic.rules import diagnose

from ._world import params


def _own_cgroup():
    with open("/proc/self/cgroup") as fh:
        for line in fh:
            if line.startswith("0::"):
                return line.strip()[3:]
    return None


@unittest.skipUnless(os.path.exists("/proc/stat") and os.path.exists("/sys/fs/cgroup/cgroup.controllers"),
                     "needs a Linux host with cgroup v2")
class TestLiveHost(unittest.TestCase):
    def test_live_snapshot_validates_and_m2_accepts_it(self):
        cg = _own_cgroup()
        target = resolve_target(LiveReader(), "self", cg)
        p = params(W=2.0, B=4.0, N_BASE_MIN=3.0)
        snap, stats = collect_snapshot(target, p)
        self.assertGreater(len(snap.measurements), 40)
        self.assertTrue(any(m.quality is Quality.OK for m in snap.measurements))
        d = diagnose(snap, p, code_commit="f7fb0c8")
        self.assertEqual(d.result.snapshot_id, snap.snapshot_id)
        self.assertLess(stats.cpu_s, stats.wall_s)


if __name__ == "__main__":
    unittest.main()
