"""R1.1 regression guard for the verifier rejection of sn_sched_switch (R1, 2026-10-03: "R0 unbounded memory
access"). Not verifier proof: the kernel verifier only runs at load time (fresh R1). This checks the emitted BPF
instructions for the defect pattern, and the clamp semantics through the replay harness."""

import re
import subprocess
import unittest

from sentinelai.collectors.ebpf import HIST_BUCKETS, bucket_index

from ._replay import BPF_OBJ, S, Script, ensure_built, last

# The instruction sequence the 6.8 verifier rejected (results/phase1c_m3b_r1/20261003T072203Z/verifier_log.txt,
# insns 157-167 of sn_sched_switch, object of commit 118ee6d): the bound is learned on r2, a zero-extended copy,
# and the access re-extends r1, which carries no bound.
REJECTED_118EE6D = """
     157:	r2 = r1
     158:	r2 <<= 32
     159:	r2 >>= 32
     160:	r3 = 527
     161:	if r3 > r2 goto +1 <LBB2_43>
     162:	r1 = 527
     163:	r1 <<= 32
     164:	r1 >>= 32
     165:	r1 <<= 3
     166:	r0 += r1
     167:	r1 = *(u64 *)(r0 + 0)
"""
MAX_INDEX = HIST_BUCKETS - 1                       # 527


def instructions(text):
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*\d+:\s+(.*?)\s*$", line)
        if m:
            out.append(re.sub(r"\s*<[^>]*>$", "", m.group(1)))
    return out


def histogram_access_check(insns):
    """Locate the histogram write (the only 'r0 += rX' in sn_sched_switch: pointer into the map value plus a
    register offset) and check that the register used as the offset is the register that was compared with
    the bound and clamped to 527, with no re-extension between the comparison and the access.
    Returns (ok, reason)."""
    adds = [i for i, s in enumerate(insns) if re.fullmatch(r"r0 \+= r\d+", s)]
    if len(adds) != 1:
        return False, f"expected one variable-offset map-value access, found {len(adds)}"
    a = adds[0]
    reg = insns[a].split()[-1]
    if insns[a - 1] != f"{reg} <<= 3":
        return False, f"offset {reg} is not scaled by 8 immediately before the access"
    cmp_i = None
    for i in range(a - 1, -1, -1):
        s = insns[i]
        m = re.fullmatch(r"if (r\d+) (>|>=) (r\d+|\d+) goto [+-]\d+", s)
        if m:
            cmp_i = i
            break
    if cmp_i is None:
        return False, "no bounds comparison before the access"
    lhs, _, rhs = re.fullmatch(r"if (r\d+) (>|>=) (r\d+|\d+) goto [+-]\d+", insns[cmp_i]).groups()
    bound_ok = (rhs == reg and any(insns[j] == f"{lhs} = {MAX_INDEX}" for j in range(max(0, cmp_i - 3), cmp_i))) or \
               (lhs == reg and rhs in (str(MAX_INDEX), str(MAX_INDEX - 1)))
    if not bound_ok:
        return False, f"bound compared on '{insns[cmp_i]}', not on the access register {reg}"
    between = insns[cmp_i + 1:a - 1]
    if between != [f"{reg} = {MAX_INDEX}"]:
        return False, f"instructions between comparison and access re-derive the offset: {between}"
    return True, "bounded offset register reaches the access unchanged"


def sched_switch_insns(obj):
    p = subprocess.run(["llvm-objdump", "-d", "--no-show-raw-insn", "-j", "tp_btf/sched_switch", str(obj)],
                       capture_output=True, text=True, check=True)
    return instructions(p.stdout)


class TestEmittedBytecode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_built()

    def test_checker_flags_the_rejected_118ee6d_sequence(self):
        ok, reason = histogram_access_check(instructions(REJECTED_118EE6D))
        self.assertFalse(ok)
        self.assertIn("not on the access register r1", reason)

    def test_current_object_keeps_bound_and_access_on_one_register(self):
        ok, reason = histogram_access_check(sched_switch_insns(BPF_OBJ))
        self.assertTrue(ok, reason)

    def test_source_uses_a_64bit_index_and_barrier(self):
        from ._replay import EBPF
        core = (EBPF / "include" / "sentinel_core.h").read_text()
        body = core[core.index("static __always_inline void sn_on_switch"):core.index("/* softirq_entry")]
        self.assertIn("__u64 now, ts, d, i;", body)
        self.assertRegex(body, r"if \(i >= SN_HIST_BUCKETS\)\n\t\ti = SN_HIST_BUCKETS - 1;\n\tbarrier_var\(i\);\n"
                               r"\th->slots\[i\] \+= 1;")
        self.assertEqual(core.count("barrier_var(i)"), 1)                      # no other barrier added


class TestClampSemantics(unittest.TestCase):
    """The index invariant 0 <= i <= 527 through the handler code itself (replay harness)."""

    @classmethod
    def setUpClass(cls):
        ensure_built()

    def test_latencies_beyond_the_histogram_range_land_in_the_last_bucket(self):
        lats = [(1 << 36) - 1, 1 << 36, (1 << 36) + 12345, 1 << 38, 199 * S]   # last four exceed the clamp
        sc = Script(lat_stale=300 * S).cpu(0)                                 # all five below the stale cut-off
        t = 0
        for i, lat in enumerate(lats):
            t += 1
            sc.at(t).wakeup(3000 + i, 1)
            t += lat
            sc.at(t).switch(0, 3000 + i)
        s = last(sc.dump())
        self.assertEqual({b: c for b, c in s["sched"]["hist"]}, {MAX_INDEX: len(lats)})
        self.assertEqual({bucket_index(v) for v in lats}, {MAX_INDEX})        # Python mirror agrees
        self.assertEqual(s["stats"]["lat_recorded"], len(lats))

    def test_index_never_exceeds_the_last_bucket(self):
        for v in [0, 1, 15, 16, 2 ** 20, 2 ** 35, 2 ** 36 - 1, 2 ** 36, 2 ** 50, 2 ** 64 - 1]:
            with self.subTest(v=v):
                self.assertTrue(0 <= bucket_index(v) <= MAX_INDEX)


if __name__ == "__main__":
    unittest.main()
