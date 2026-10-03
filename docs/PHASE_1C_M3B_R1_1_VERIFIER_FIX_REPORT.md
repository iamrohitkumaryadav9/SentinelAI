# Phase 1C — M3B-R1.1 Report: Verifier Fix (build/mutation gate)

| | |
|---|---|
| Baseline | `118ee6df8f05ef44291f2a39c3c7826e10ed90a7` (feat(ebpf): add M3B observation layer) |
| Trigger | M3B R1 runtime gate NO-GO: `sn_sched_switch` rejected by the kernel verifier (`docs/PHASE_1C_M3B_RUNTIME_VALIDATION_REPORT.md`, evidence `results/phase1c_m3b_r1/20261003T072203Z/`) |
| Authorised change | Option 1 only: one 64-bit index register for clamp and write, with the minimum compiler barrier |
| Privileged activity | **None.** No BPF loaded or attached, no sudo, no runtime validation. |
| Gate | **M3B-R1.1 VERIFIER-FIX GATE: GO** (end of report) |

## 1. Baseline and working tree

`git rev-parse HEAD` = `118ee6d`, with no tracked modifications. The working tree was classified before any change:

| Class | Paths |
|---|---|
| M3B commit | `118ee6d` (unchanged; not rewritten) |
| R1 validation artifacts (preserved, uncommitted) | `docs/PHASE_1C_M3B_RUNTIME_VALIDATION_REPORT.md`, `scripts/m3b_r1_validate.{sh,py}`, `results/phase1c_m3b_r1/20261003T072203Z/` (evidence files not modified) |
| FaultLab (untouched) | `experiments/faultlab/docker/{Dockerfile,workload.py}`; sha256 `168c6ed5…`, `dde118e0…`, unchanged |
| R1.1 changes | §14 |

## 2. Exact verifier failure (from `verifier_log.txt`)

```text
libbpf: prog 'sn_sched_switch': BPF program load failed: Permission denied
...
155: (4f) r1 |= r6                    ; R1_w=scalar() R6_w=scalar(smin=smin32=0,smax=umax=smax32=umax32=15,var_off=(0x0; 0xf))
156: (07) r1 += 16                    ; R1=scalar()
; if (i >= SN_HIST_BUCKETS)
157: (bf) r2 = r1                     ; R1=scalar(id=13) R2_w=scalar(id=13)
158: (67) r2 <<= 32
159: (77) r2 >>= 32                   ; R2_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
160: (b7) r3 = 527
161: (2d) if r3 > r2 goto pc+1 163: ... R1=scalar(id=13) R2=scalar(smin=smin32=0,smax=umax=smax32=umax32=526,...)
; h->slots[i] += 1;
163: (67) r1 <<= 32
164: (77) r1 >>= 32                   ; R1_w=scalar(smin=0,smax=umax=0xffffffff,var_off=(0x0; 0xffffffff))
165: (67) r1 <<= 3
166: (0f) r0 += r1                    ; R0_w=map_value(map=sn_hist,ks=4,vs=4224,smin=0,smax=umax=0x7fffffff8,...)
167: (79) r1 = *(u64 *)(r0 +0)
R0 unbounded memory access, make sure to bounds check any such access
processed 190 insns (limit 1000000) ...
libbpf: prog 'sn_sched_switch': failed to load: -13
```

The failing access is the scheduler histogram write `h->slots[i] += 1` in `sn_on_switch` (`ebpf/include/sentinel_core.h`). The map is `sn_hist` (value size 4224 = 528 × 8).

| Role | Instructions | Register |
|---|---|---|
| Index computed (`sn_hist_index`) | 155–156 | `r1` |
| Copy for the comparison | 157 | `r2 = r1` (verifier links them: same id 13) |
| Zero-extension of the copy | 158–159 | `r2` (a new value: the id link to `r1` is lost) |
| Bounds check | 160–161 | compares `r2` with 527; the verifier learns `r2 ≤ 526` on fall-through |
| Clamp | 162 | `r1 = 527` (taken path only) |
| **Re-extension of the original** | **163–164** | **`r1` zero-extended again: a new value, unbounded** |
| Access | 165–167 | `r1 << 3` added to the map-value pointer, then load |

## 3. Root cause

`i` was declared `__u32`. In BPF's 64-bit registers, clang 14 materialises a 32-bit value's zero-extension explicitly (`<<= 32; >>= 32`):
- for the comparison, on a **copy** (`r2`);
- separately, for the address computation, on the **original** (`r1`).

The verifier tracks bounds per register value and links copies only while they hold the identical value. Each shift pair creates a new value, so the bound proved on `r2` never reaches `r1`. On the path where the clamp did not fire, `r1` is still unbounded at the access, and the verifier rejects it.

The arithmetic was always safe (`sn_hist_index` cannot exceed 527); the emitted instruction sequence just doesn't let the verifier prove it.

## 4. Exact code change (`ebpf/include/sentinel_core.h`, the only BPF source change)

```diff
+/* Same definition as libbpf's bpf_helpers.h, for the userspace build of this file. */
+#ifndef barrier_var
+#define barrier_var(var) asm volatile("" : "+r"(var))
+#endif
 ...
 static __always_inline void sn_on_switch(__u32 prev_tid, __u32 next_tid)
 {
     struct sn_wake *w;
     struct sn_hist *h;
-    __u64 now, ts, d;
-    __u32 wcpu, i;
+    __u64 now, ts, d, i;
+    __u32 wcpu;
 ...
+    /* R1.1: a 64-bit index, so the clamp and the array offset use one register. ... */
     i = sn_hist_index(d);
     if (i >= SN_HIST_BUCKETS)
         i = SN_HIST_BUCKETS - 1;
+    barrier_var(i);
     h->slots[i] += 1;
```

- `i` becomes `__u64`. `sn_hist_index` still returns `__u32`; it is zero-extended once, at the assignment.
- One `barrier_var(i)`, the libbpf definition (`asm volatile("" : "+r"(var))`), sits between the clamp and the write. The BPF build uses libbpf's `bpf_helpers.h` definition. The userspace replay build of the same file uses the identical fallback definition, so the harness keeps compiling the exact handler code.
- The comparison (`>= SN_HIST_BUCKETS`), the clamp value (`SN_HIST_BUCKETS - 1`), the bucket function, the map and every other line are unchanged.

## 5. Generated BPF instruction comparison (`tp_btf/sched_switch`, clang 14)

| Before (118ee6d) | After (R1.1) |
|---|---|
| `155: r1 \|= r6` | `155: r1 \|= r6` |
| `156: r1 += 16` | `156: r1 += 16` |
| `157: r2 = r1` | `157: r1 <<= 32` |
| `158: r2 <<= 32` | `158: r1 >>= 32` |
| `159: r2 >>= 32` | `159: r2 = 527` |
| `160: r3 = 527` | `160: if r2 > r1 goto +1` |
| `161: if r3 > r2 goto +1` | `161: r1 = 527` |
| `162: r1 = 527` | `162: r1 <<= 3` |
| `163: r1 <<= 32` | `163: r0 += r1` |
| `164: r1 >>= 32` | `164: r1 = *(u64 *)(r0 + 0)` |
| `165: r1 <<= 3` | |
| `166: r0 += r1` | |
| `167: r1 = *(u64 *)(r0 + 0)` | |

After the change, a single register (`r1`) is zero-extended once (157–158), compared against the bound (160), clamped (161), scaled (162) and added to the map-value pointer (163). There is no copy and no re-extension between the check and the access. On the fall-through path the verifier learns `r1 ≤ 526`; on the taken path `r1 = 527`. Both are bounded, so the offset is at most 527 × 8 = 4216 < 4224.

**Scope of the change in the object:** compared with a build of `118ee6d`, the sections `tp_btf/sched_wakeup`, `sched_wakeup_new`, `softirq_entry`, `softirq_exit`, `tcp_retransmit_skb`, `kfree_skb`, `.maps`, `.rodata` and `license` are **byte-identical**. `tp_btf/sched_switch` is 1464 → 1440 bytes, and its disassembly diff is exactly the clamp block above plus the shifted jump offsets that follow from three fewer instructions.

**Other variable-offset accesses:** every `rX += rY` in all seven programs was inspected. Apart from the histogram write, they are CO-RE field offsets added to kernel pointers that are passed to `bpf_probe_read_kernel`, scalar arithmetic (`sn_log2_u64`), or `a->ns += d` on a loaded value. The histogram write is the only variable-offset access into a map value.

**Why the barrier, and why it is minimal.** With clang 14, the 64-bit index alone already produces the sequence above. A variant compiled without `barrier_var` emitted byte-identical instructions. The barrier is therefore not what fixes clang 14's output; the type change is. It is kept, as Option 1 specifies, as the minimum guard on the property the verifier depends on. `asm volatile("" : "+r"(i))` forces the clamped value into one register at that point and stops the compiler from folding the clamp into the address computation or recomputing `i` after it. It emits no instruction and changes no value. It is the only barrier in the program.

## 6. Semantic preservation

- **Index values are identical:** `sn_hist_index` returns a `__u32` in [0, 527]; widening to `__u64` preserves the value; `i >= 528 → 527` is the same comparison and clamp. The barrier is an empty asm.
- **Unchanged:** the bucket count (528), bucket boundaries, `sn_hist_index`/`sn_log2_u64`, the latency (`now − ts`), stale and negative handling, migration counting, the per-CPU `PERCPU_ARRAY` map, the `+= 1` increment, the wakeup/switch matching, the cgroup scope, feature IDs, the collector, the contract and M2.
- **Evidence:**
  - every pre-existing semantics test passes (§9);
  - the six other programs are byte-identical;
  - the replay harness compiles the changed handler with gcc and reproduces every expected histogram, including the new above-clamp cases (§8);
  - the mutation campaign kills mutants of the clamp, the index, the write and the bucket calculation (§11).

## 7. Build and linkage validation (approved build path, unchanged Makefile)

| Check | Result |
|---|---|
| Build (`make -C ebpf all`) | clang 14 `-Wall -Werror` BPF object, bpftool 7.4 skeleton, loader, harness, `min_core_btf` CO-RE check: all succeed |
| libbpf | `sentinel_loader --version` → compiled `1.4`, linked `1.4`, `match: true` |
| Static linkage | `readelf -d` NEEDED: `libelf.so.1`, `libz.so.1`, `libc.so.6` only; 189 libbpf API symbols defined inside the loader; 0 undefined |
| Skeleton | `--check-open` (libbpf 1.4 open, no `bpf()` syscall per strace) lists 7 programs and maps `sn_wake` 16384, `sn_hist` 1, `sn_stats` 22, `sn_sirq_start` 1, `sn_sirq_acc` 10, `sn_retrans` 1, `sn_kfree` 129, `.rodata` 1 |
| Sections | 7 `tp_btf/*`, `.maps`, `.rodata`, `license`, `.BTF`, `.BTF.ext` |
| Determinism | Clean rebuild into a fresh build directory: `sentinel.bpf.o` and `sentinel.skel.h` byte-identical |
| Artifact hashes | `sentinel.bpf.o` b0495486…, `sentinel.skel.h` 6238e0ad…, `sentinel_loader` 0c70a600… |

## 8. Targeted regression tests (`tests/ebpf/test_verifier_regression.py`, 5 tests)

1. **Defect-pattern checker on emitted bytecode.** `histogram_access_check` finds the single variable-offset map-value access in `tp_btf/sched_switch`. It then requires that the offset register is the one compared with the bound 527 and clamped, with nothing but the clamp between the comparison and the access.
   - Against the **actual 118ee6d object** (rebuilt from the commit) it reports `bound compared on 'if r3 > r2 goto +1', not on the access register r1` (FAIL).
   - Against the R1.1 object it reports `bounded offset register reaches the access unchanged` (PASS).
   - The rejected sequence from the verifier log is embedded in the test and must be flagged.
2. **The current object passes the checker.**
3. **Source guard:** `sn_on_switch` uses `__u64 … i`, the clamp is followed by exactly one `barrier_var(i)` and then the write, and there is no other barrier.
4. **Clamp semantics through the handler code (replay harness):** latencies of 2³⁶−1, 2³⁶, 2³⁶+12345, 2³⁸ ns and 199 s all land in bucket 527, which no earlier test reached. The Python mirror agrees.
5. **Invariant `0 ≤ bucket_index(v) ≤ 527`** for boundary values up to 2⁶⁴−1.

These are regression guards, **not verifier proof**. Kernel verifier acceptance can only be established by loading, in the next R1 run.

## 9–10. Test results

```text
M3B (tests/ebpf):            107/107  (94 existing + 5 verifier regression + 8 comparison tool)
M1  (tests/evidence):        228/228
M2  (tests/rules):            97/97
M3A (tests/collectors):      111/111
M3A-C1 (test_tc.py):          38/38
Full suite:                  567 run: 566 passed, 0 failed, 1 skipped (pre-existing root-only bpftrace test)
```

The 8 comparison-tool tests import `scripts/m3b_r1_compare.py`, which is R1 validation tooling and stays uncommitted (§14). In a checkout of the R1.1 commit alone, the M3B suite is 99 tests and the full suite is 559.

## 11. Mutation testing

The M3B harness runs on the R1.1 tree. Each mutant goes into a fresh copy of `src/`, `tests/`, `ebpf/` and `scripts/` (the repository is never mutated). The copy is rebuilt from scratch with `make`, and every suite except the Phase 1A host checks is run. The unmutated control passes: 543/543.

**Result: 69/69 killed, 0 survived.** This is the 55 original M3B mutants (one anchor adapted to the new code) plus 14 new ones.

Mutants around the histogram clamp, index, write and bucket calculation, and the comparison tool:

| # | Mutant | Result |
|---|---|---|
| C9 | histogram bucket off by one | killed (13 failures) |
| R1 | clamp removed (index bounded only by arithmetic) | killed (2 failures) |
| R2 | index back to __u32 (the R1 defect) | killed (2 failures) |
| R3 | barrier removed | killed (1 failures) |
| R4 | clamp value one past the end | killed (2 failures) |
| R5 | clamp comparison off by one | killed (2 failures) |
| R6 | write goes to a fixed bucket | killed (13 failures) |
| R7 | latency bucketed from the wakeup timestamp, not the delta | killed (11 failures) |
| T1 | qdisc not compared | killed (2 failures) |
| T2 | whole linkinfo ignored | killed (2 failures) |
| T3 | timers ignored on every link kind | killed (1 failures) |
| T4 | extra field ignored (stp_state) | killed (2 failures) |
| T5 | timers not ignored (the A1 false positive) | killed (1 failures) |
| T6 | routes not compared | killed (2 failures) |
| T7 | BPF prog ids not compared | killed (1 failures) |
| S1 | bucket sub-index mask wrong | killed (8 failures) |
| S2 | log2 drops the 16-bit step | killed (5 failures) |
| S3 | exact range shortened | killed (1 failures) |

Notes:
- **R1, R4, R5** are semantically equivalent at runtime (`sn_hist_index` never exceeds 527, so the clamp never fires), but each recreates an instruction sequence that is not provably bounded. The bytecode checker kills them.
- **R2** reintroduces the R1 defect and is killed by the bytecode checker and the source guard.
- **R3** (barrier removed) is bytecode-identical under clang 14 and is killed by the source guard only (§15, limitation 2).
- All 55 original mutants (kernel handlers, line protocol, BPF program, libbpf build guards, Python collector, snapshot integration, process boundary) remain killed.

## 12. docker0 comparison fix (R1 anomaly A1)

- **Cause:** the R1 comparison kept the whole `linkinfo` of each interface, including the bridge's remaining-time timers. `docker0`'s `gc_timer` counted down from 98.58 to 96.44 s between the two snapshots, so the run reported `docker0_identical: false` with no configuration change.
- **Fix:** the comparison moved from an inline heredoc in `scripts/m3b_r1_validate.sh` into `scripts/m3b_r1_compare.py`, which the wrapper now calls. Ignored: exactly `linkinfo.info_data.{hello_timer, tcn_timer, topology_change_timer, gc_timer}`, only when `info_kind == "bridge"`. These are the kernel's `IFLA_BR_*_TIMER` remaining-time values, listed in the module and echoed in the output (`ignored_volatile_fields`). Traffic counters were already excluded. Everything else is still compared: MTU, flags, qdisc, operstate, address, promiscuity, queues, every other bridge field, addresses, IPv4/IPv6 routes, `/run/netns`, sysctls, and BPF prog/link/map ids.
- **Regression (`tests/ebpf/test_r1_compare.py`, 8 tests):**
  - timer-, counter- and lease-countdown-only differences → equivalent;
  - `enp0s31f6` MTU, qdisc, promiscuity and operstate, and `docker0` MTU, qdisc and `stp_state`, a new interface, an address, an IPv4/IPv6 route, a namespace, a sysctl, and a new BPF prog, link or map → all detected;
  - a timer-named field on a non-bridge link is not ignored;
  - a leftover `sn_` program is reported;
  - the ignored set is exactly the four timers.
- **Re-check of the preserved R1 evidence (read-only, printed, not written):** every check is now `true`, `interfaces_differing: []`.

## 13. Safety analysis

- No privileged operation: no sudo, no BPF load or attach (strace: 0 `bpf()` calls in `--check-open`), no runtime validation.
- No namespace, veth, tc/netem, sysctl, cgroup or interface change. `enp0s31f6` and `docker0` untouched.
- M2 (`src/sentinelai/diagnostic/`) and the contract (`0.5.0-draft`) have no diff. No collector or feature semantics changed.
- R1 evidence (`results/phase1c_m3b_r1/20261003T072203Z/`) and the R1 runtime report are unmodified. FaultLab files are unchanged (hashes in §1).

## 14. Files changed

| File | Change | Commit |
|---|---|---|
| `ebpf/include/sentinel_core.h` | 64-bit histogram index plus one `barrier_var` (BPF source; +13/−2) | R1.1 commit |
| `tests/ebpf/test_verifier_regression.py` | New: 5 regression tests | R1.1 commit |
| `docs/PHASE_1C_M3B_R1_1_VERIFIER_FIX_REPORT.md` | This report | R1.1 commit |
| `scripts/m3b_r1_compare.py` | New: comparison module with the documented timer exclusions | **uncommitted** (R1 tooling) |
| `scripts/m3b_r1_validate.sh` | Calls `m3b_r1_compare.py` instead of the inline heredoc | **uncommitted** (R1 tooling) |
| `tests/ebpf/test_r1_compare.py` | New: 8 comparison regression tests (depends on the uncommitted script) | **uncommitted** (R1 tooling) |

Generated artifacts (`ebpf/build/`) are rebuilt and git-ignored.

## 15. Limitations

1. **Verifier acceptance is still unproven.** The fix removes the instruction pattern the verifier rejected, and the bytecode checker confirms the bound and the access share one register. Only a kernel load can show acceptance of `sn_sched_switch`, and of the four programs R1 never reached (`softirq_entry`, `softirq_exit`, `tcp_retransmit_skb`, `kfree_skb`).
2. **The barrier is bytecode-neutral under clang 14** (§5). Removing it is caught only by the source guard, not by the bytecode checker or the semantic tests (mutant R3). That is expected for a guard against future code generation.
3. **The bytecode checker is specific** to the clamp/scale/add shape of this one access. It is a regression guard for this defect, not a general verifier model.
4. **The comparison fix lives in uncommitted R1 tooling**, so its tests also stay uncommitted until the R1 tooling's commit is decided.

---

## M3B-R1.1 VERIFIER-FIX GATE: GO

- **Verifier defect corrected at the instruction level:** the bound and the access share one register (bytecode checker passes on R1.1 and fails on 118ee6d), and only `sn_sched_switch` changed.
- BPF builds; static linkage to the kernel-headers libbpf 1.4 is intact (no libbpf `NEEDED` entry, compiled == linked); the clean rebuild is deterministic.
- The targeted regression tests (5) and the comparison-tool regression tests (8) pass.
- Every existing suite passes: M3B 107/107, M1 228/228, M2 97/97, M3A 111/111, M3A-C1 38/38, full 567 run / 0 failed / 1 pre-existing skip.
- Mutation: 69/69 killed.
- No M2, contract or FaultLab change; no privileged runtime activity.

**STOP.** Kernel verifier acceptance is still to be proven by a fresh R1 run from the R1.1 commit, which waits for explicit authorisation.
