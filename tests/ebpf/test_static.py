"""Static safety audit of the M3B sources: observation only, bounded, no mutation, no diagnosis."""

import re
import unittest
from pathlib import Path

from sentinelai.diagnostic.contract import FAULT_LABELS

REPO = Path(__file__).resolve().parents[2]
EBPF = REPO / "ebpf"
BPF_SRC = (EBPF / "bpf" / "sentinel.bpf.c").read_text()
CORE = (EBPF / "include" / "sentinel_core.h").read_text()
SHARED = (EBPF / "include" / "sentinel_shared.h").read_text()
HOST = (EBPF / "include" / "sentinel_host.h").read_text()
LOADER = (EBPF / "loader" / "sentinel_loader.c").read_text()
REPLAY = (EBPF / "harness" / "sentinel_replay.c").read_text()
MAKEFILE = (EBPF / "Makefile").read_text()
C_ALL = {"sentinel.bpf.c": BPF_SRC, "sentinel_core.h": CORE, "sentinel_shared.h": SHARED,
         "sentinel_host.h": HOST, "sentinel_loader.c": LOADER, "sentinel_replay.c": REPLAY}
PY = {p.relative_to(REPO / "src").as_posix(): p.read_text()
      for p in [REPO / "src/sentinelai/collectors/ebpf.py", *sorted((REPO / "src/sentinelai/ebpf").glob("*.py"))]}
KERNEL_SIDE = {"sentinel.bpf.c": BPF_SRC, "sentinel_core.h": CORE, "sentinel_shared.h": SHARED}


def strip_c_comments(code):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", code, flags=re.S)


def strip_py_comments(code):
    code = re.sub(r'"""[\s\S]*?"""', "", code)
    return re.sub(r"#[^\n]*", "", code)


def macro(name):
    m = re.search(rf"#define {name} (\d+)", SHARED)
    return int(m.group(1)) if m else None


class TestBpfProgram(unittest.TestCase):
    def test_exactly_the_approved_tracepoints(self):
        secs = re.findall(r'SEC\("([^"]+)"\)', BPF_SRC)
        progs = sorted(s for s in secs if s not in ("license", ".maps"))
        self.assertEqual(progs, sorted(f"tp_btf/{t}" for t in ("sched_wakeup", "sched_wakeup_new", "sched_switch",
                                                                "softirq_entry", "softirq_exit", "tcp_retransmit_skb",
                                                                "kfree_skb")))

    def test_no_network_capable_or_mutating_program_types(self):
        for pat in (r'SEC\("(xdp|tc|classifier|action|cgroup|sockops|sk_msg|sk_skb|lsm|fmod_ret|kprobe|uprobe|'
                    r'struct_ops|flow_dissector|netfilter|iter|syscall)', r"BPF_PROG_TYPE_"):
            self.assertIsNone(re.search(pat, BPF_SRC), pat)

    def test_no_mutating_or_unbounded_helpers(self):
        banned = ("bpf_probe_write_user", "bpf_override_return", "bpf_send_signal", "bpf_sys_bpf",
                  "bpf_skb_store_bytes", "bpf_l3_csum_replace", "bpf_l4_csum_replace", "bpf_redirect",
                  "bpf_clone_redirect", "bpf_skb_change", "bpf_xdp_adjust", "bpf_setsockopt", "bpf_sk_assign",
                  "bpf_set_retval", "bpf_ringbuf", "bpf_perf_event_output", "bpf_loop", "bpf_for", "bpf_timer",
                  "bpf_spin_lock", "bpf_copy_from_user", "bpf_d_path", "bpf_snprintf", "bpf_trace_printk",
                  "bpf_printk", "bpf_task_storage")
        for name, code in KERNEL_SIDE.items():
            for b in banned:
                with self.subTest(file=name, helper=b):
                    self.assertNotIn(b, strip_c_comments(code))

    def test_no_loops_in_kernel_code(self):
        for name, code in KERNEL_SIDE.items():
            with self.subTest(file=name):
                self.assertIsNone(re.search(r"\b(for|while)\s*\(|\bgoto\b", strip_c_comments(code)))

    def test_maps_bounded_and_of_allowed_types(self):
        maps = re.findall(r"struct \{\s*__uint\(type, (BPF_MAP_TYPE_\w+)\);\s*__uint\(max_entries, ([^)]+)\);"
                          r".*?\} (\w+) SEC\(\"\.maps\"\);", BPF_SRC, re.S)
        self.assertEqual(len(maps), len(re.findall(r'SEC\("\.maps"\)', BPF_SRC)))
        self.assertEqual({n for _, _, n in maps}, {"sn_wake", "sn_hist", "sn_stats", "sn_sirq_start", "sn_sirq_acc",
                                                   "sn_retrans", "sn_kfree"})
        for mtype, entries, name in maps:
            with self.subTest(map=name):
                self.assertIn(mtype, ("BPF_MAP_TYPE_LRU_HASH", "BPF_MAP_TYPE_PERCPU_ARRAY"))
                self.assertNotIn("BPF_F_NO_PREALLOC", BPF_SRC)                  # preallocated: no runtime growth
        types = {n: t for t, _, n in maps}
        self.assertEqual([n for n, t in types.items() if t.endswith("HASH")], ["sn_wake"])   # only per-tid state
        self.assertEqual(macro("SN_WAKE_MAX"), 16384)

    def test_only_the_pending_wakeup_map_is_keyed_by_task(self):
        self.assertEqual(re.findall(r"bpf_map_update_elem\(&(\w+)", BPF_SRC), ["sn_wake"])
        self.assertEqual(re.findall(r"bpf_map_delete_elem\(&(\w+)", BPF_SRC), ["sn_wake"])

    def test_kernel_field_extraction(self):
        """What fixtures cannot see: each program reads the contract-relevant kernel fields (CO-RE)."""
        code = strip_c_comments(BPF_SRC)
        for needle in ("sn_on_wakeup((__u32)BPF_CORE_READ(p, pid), sn_task_in_target(p), 0)",
                       "sn_on_wakeup((__u32)BPF_CORE_READ(p, pid), sn_task_in_target(p), 1)",
                       "sn_on_switch((__u32)BPF_CORE_READ(prev, pid), (__u32)BPF_CORE_READ(next, pid))",
                       "BPF_CORE_READ(p, cgroups, dfl_cgrp)", "&cg->ancestors[0]", "BPF_CORE_READ(anc, kn, id) == sn_cfg.cgroup_id",
                       "sn_on_softirq_entry(vec_nr)", "sn_on_softirq_exit(vec_nr)",
                       "ns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum)",
                       "ns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum)",
                       "if (ns == 0 && BPF_CORE_READ(skb, sk))",
                       "ns = BPF_CORE_READ(skb, sk, __sk_common.skc_net.net, ns.inum)",
                       "sn_on_kfree(ns, (__u32)reason)"):
            self.assertIn(needle, code)

    def test_gpl_compatible_license(self):
        self.assertIn('char LICENSE[] SEC("license") = "Dual BSD/GPL";', BPF_SRC)


class TestUserspaceC(unittest.TestCase):
    def test_no_process_privilege_or_network_primitives(self):
        banned = (r"\bsystem\(", r"\bpopen\(", r"\bexec[lv]p?e?\(", r"\bfork\(", r"\bvfork\(", r"\bsetuid\(",
                  r"\bsetgid\(", r"\bcapset\(", r"\bcap_set", r"\bprctl\(", r"\bptrace\(", r"\bsetns\(",
                  r"\bunshare\(", r"\bsocket\(", r"\bioctl\(", r"\bsysctl\b", r"enp0s31f6", r"docker0",
                  r"\bsudo\b", r"\bsetcap\b", r"\bkill\(")
        for name, code in C_ALL.items():
            for pat in banned:
                with self.subTest(file=name, pattern=pat):
                    self.assertIsNone(re.search(pat, strip_c_comments(code)))

    def test_no_writes_to_sys_proc_or_files(self):
        for name, code in C_ALL.items():
            c = strip_c_comments(code)
            with self.subTest(file=name):
                self.assertIsNone(re.search(r'"/(sys|proc)/', c))
                self.assertEqual([m for m in re.findall(r'fopen\([^)]*\)', c) if '"r"' not in m], [])
                self.assertIsNone(re.search(r"\b(open|creat|unlink|rename|mkdir|chmod|chown|truncate)\(", c))

    def test_loader_is_bounded(self):
        self.assertRegex(LOADER, r"#define SN_MAX_SECONDS_LIMIT 86400")
        self.assertIn("deadline", LOADER)
        self.assertIn("char buf[64];", LOADER)                                 # fixed request buffer, no queue
        self.assertIn('sn_print_terminal(stdout, "unavailable"', LOADER)       # fails closed with a reason


class TestMakefile(unittest.TestCase):
    def test_no_privileged_or_network_commands(self):
        for pat in (r"\bsudo\b", r"\bsetcap\b", r"\bip\s+(link|netns|route|addr)", r"\btc\s+(qdisc|filter|class)",
                    r"\bnetem\b", r"\bsysctl\b", r"bpftool\s+prog\s+load", r"\bprog\s+(load|attach)\b"):
            self.assertIsNone(re.search(pat, MAKEFILE), pat)


class TestPython(unittest.TestCase):
    def test_single_execution_site_without_shell(self):
        users = [n for n, c in PY.items() if re.search(r"\bsubprocess\b", c)]
        self.assertEqual(users, ["sentinelai/ebpf/loader.py"])
        code = PY["sentinelai/ebpf/loader.py"]
        self.assertEqual(len(re.findall(r"self\._runner\(", code)), 1)
        self.assertIn("shell=False", code)
        self.assertNotRegex(code, r"shell\s*=\s*True")
        self.assertNotRegex(code, r"subprocess\.(call|run|check_output|check_call|getoutput|getstatusoutput)\b")

    def test_no_dangerous_primitives(self):
        banned = (r"\bos\.system\b", r"\bos\.popen\b", r"\bos\.exec", r"\bos\.spawn", r"\bos\.kill\b",
                  r"\bctypes\b", r"\bsudo\b", r"\bsetcap\b", r"\bnsenter\b", r"\bunshare\b", r"\bsetns\b",
                  r"enp0s31f6", r"docker0", r"\.write_text\(", r"\.write_bytes\(", r"\bopen\(", r"\bshutil\b",
                  r"\bimport\s+socket\b", r"\bsocket\.socket\b")
        for name, code in PY.items():
            for pat in banned:
                with self.subTest(file=name, pattern=pat):
                    self.assertIsNone(re.search(pat, code))

    def test_imports_allowlisted(self):
        allowed = {"collections", "dataclasses", "json", "math", "os", "pathlib", "re", "select", "subprocess",
                   "typing"}
        for name, code in PY.items():
            for mod in re.findall(r"^\s*(?:from|import)\s+([\w.]+)", code, re.M):
                with self.subTest(file=name, module=mod):
                    self.assertTrue(mod.startswith(".") or mod in allowed, mod)
        self.assertNotIn("subprocess", PY["sentinelai/collectors/ebpf.py"])

    def test_bounded_userspace_buffers(self):
        self.assertRegex(PY["sentinelai/collectors/ebpf.py"], r"MAX_LINE = 1 << 22")
        loader = PY["sentinelai/ebpf/loader.py"]
        self.assertIn("if len(self._buf) > MAX_LINE:", loader)
        self.assertIn("select.select", loader)                                 # read timeout, never blocks forever
        for name, code in PY.items():                                         # no per-task state in userspace
            self.assertIsNone(re.search(r"\btids?\b", code), name)


class TestNoDiagnosis(unittest.TestCase):
    def test_no_labels_thresholds_or_rule_engine(self):
        """Code (comments and docstrings removed) names no fault label, no rule threshold or reason set,
        never calls or imports the rule engine, and never builds evidence items."""
        labels = [l.value for l in FAULT_LABELS]
        sources = {**{n: strip_c_comments(c) for n, c in C_ALL.items()},
                   **{n: strip_py_comments(c) for n, c in PY.items()}}
        for name, code in sources.items():
            for word in labels + ["INSUFFICIENT_EVIDENCE", "KFREE_REASONS_LOSS", "SI_ABS_MIN", "DROP_ABS_MIN",
                                  "RT_RATE_MIN", "IMPACT_MIN"]:
                with self.subTest(file=name, word=word):
                    self.assertNotRegex(code, rf"\b{re.escape(word)}\b")
            with self.subTest(file=name):
                self.assertNotRegex(code, r"\bdiagnos(e|is|ing)\b|diagnostic\.rules|\.rules\b|EvidenceItem|"
                                          r"evidence_item|Label\b")


if __name__ == "__main__":
    unittest.main()
