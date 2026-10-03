# Phase 1C — M3B R1 Runtime Validation, Attempt 1 (commit 118ee6d) — superseded by attempt 2 (f18e9fc), see PHASE_1C_M3B_RUNTIME_VALIDATION_REPORT.md

| | |
|---|---|
| Commit under test | `118ee6df8f05ef44291f2a39c3c7826e10ed90a7` (feat(ebpf): add M3B observation layer) |
| Run | `results/phase1c_m3b_r1/20261003T072203Z/` (2026-10-03 07:22:03 UTC), executed by the user with `sudo bash scripts/m3b_r1_validate.sh` |
| Gate | **M3B R1 RUNTIME GATE: NO-GO** |

## 1. Executive summary

The kernel verifier **rejected** the program `sn_sched_switch` (`R0 unbounded memory access`, EACCES). libbpf therefore failed to load the skeleton, and the loader failed closed: it printed `{"type":"unavailable","reason":"BPF load failed (privileges or verifier)"}` and exited with code 2.

The validation driver stopped before any collection, as designed:
- no program was attached;
- no runtime observation was produced, so feature, end-to-end, repeated-window and overhead validation were **not run**;
- no BPF object remained in the kernel;
- host networking and sysctls are unchanged.

The defect is in the BPF program's histogram index bounds check, which clang 14 compiles in a form the 6.8 verifier cannot prove safe (§5). As the R1 brief requires, the program was **not modified**.

## 2. Commit and environment

| Item | Value |
|---|---|
| Kernel | `Linux 6.8.0-138-generic #138~22.04.1-Ubuntu SMP PREEMPT_DYNAMIC` x86_64 |
| Loader | `ebpf/build/sentinel_loader` (committed build, not rebuilt): `libbpf_compiled 1.4`, `libbpf_linked 1.4`, match |
| BPF object | `ebpf/build/sentinel.bpf.o` (clang 14.0.0); code sections identical to a build of the committed source |
| Privilege | Interactive `sudo` by the user; the session has no non-interactive sudo |
| Lockdown / sysctls | Lockdown `none`; `unprivileged_bpf_disabled=2`, `perf_event_paranoid=4`, `bpf_stats_enabled=0`, `bpf_jit_enable=1` (read only, unchanged) |
| Target used | cgroup `/user.slice/user-1000.slice/session-136.scope` (kernfs id 2129446, level 3), host netns (inum 4026531840), no interfaces |

## 3. Runtime authorisation boundary

R1 authorised privileged loading, attaching and inspection only. The validation tooling (`scripts/m3b_r1_validate.sh` + `.py`, new and uncommitted) never runs tc/netem or `ip` changes, never creates namespaces or veth, never writes a sysctl or cgroup, and never sends traffic on `enp0s31f6`/`docker0`. Its baseline activity is local only: sleep/wake threads, `/bin/true`, and TCP on 127.0.0.1. In this run, none of that activity started, because the run stopped at load.

## 4. Preflight results (all PASS)

| Check | Result |
|---|---|
| HEAD | `118ee6d` (expected) |
| `git status --short` | `?? experiments/faultlab/` only, before the tooling was added |
| `git diff --check` | clean |
| Full test suite | 554 run, 553 passed, 0 failed, 1 skipped (pre-existing root-only bpftrace test) |
| Loader libbpf | compiled 1.4 = linked 1.4; no libbpf `NEEDED` entry |
| Artifacts vs committed source | All 7 program sections, `.maps`, `.rodata`, `license` and the full disassembly identical to a fresh build of the commit. The only differences are the absolute source paths embedded in BTF strings. |
| Wrapper refusals | Refuses non-root (verified); in the run it also checked HEAD, a clean tracked tree and libbpf 1.4 before loading |

## 5. BPF verifier result

```text
Verifier: FAIL
```

| Program | Verifier |
|---|---|
| `sn_sched_switch` | **REJECTED**: `R0 unbounded memory access, make sure to bounds check any such access` (processed 190 insns; limit 1000000) |
| `sn_sched_wakeup`, `sn_sched_wakeup_new` | No error logged. libbpf loads programs in object order and stops at the first failure, so these two were presumably accepted before `sn_sched_switch` failed. **Not proven:** libbpf logs only failures, and the objects were released immediately. |
| `sn_softirq_entry`, `sn_softirq_exit`, `sn_tcp_retransmit_skb`, `sn_kfree_skb` | **Not attempted** (after the failing program) |

Full log: `results/phase1c_m3b_r1/20261003T072203Z/verifier_log.txt` (200 lines). The failing sequence:

```text
; return SN_HIST_SUB + (msb - SN_HIST_SUB_BITS) * SN_HIST_SUB + ...
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
libbpf: prog 'sn_sched_switch': failed to load: -13
libbpf: failed to load object 'sentinel_bpf'
libbpf: failed to load BPF skeleton 'sentinel_bpf': -13
```

**Diagnosis.** Source: `ebpf/include/sentinel_core.h`, `sn_on_switch`:

```c
i = sn_hist_index(d);
if (i >= SN_HIST_BUCKETS)
	i = SN_HIST_BUCKETS - 1;
h->slots[i] += 1;
```

`i` is a `__u32` held in a 64-bit register. clang 14 zero-extends a **copy** (`r2`) for the comparison (157–161) and then zero-extends the **original** register (`r1`) again for the array offset (163–164). The verifier learns `r2 ≤ 526` on the fall-through path, but the shift pair on `r1` creates a new value with no link to that bound, so the offset into the 4224-byte map value is unbounded.

The arithmetic is safe; the value can never exceed 527. The verifier simply cannot prove it from this instruction sequence. The fixture tests and the userspace replay harness could not detect this: they compile the same handler with gcc and run it without a verifier. The build report stated this explicitly as limitation 15.1 ("Runtime unvalidated. The verifier has not seen the programs").

Everything before the faulting access passed verification. That includes the BTF-typed tracepoint arguments (`trusted_ptr_task_struct`), the CO-RE `pid` reads and the `sn_wake` map operations.

## 6. Program attachment table

| Program | Load | Attach |
|---|---|---|
| sched_wakeup | presumed verified (not proven; see §5) | NOT ATTACHED |
| sched_wakeup_new | presumed verified (not proven; see §5) | NOT ATTACHED |
| sched_switch | **FAIL (verifier)** | NOT ATTACHED |
| softirq_entry | not attempted | NOT ATTACHED |
| softirq_exit | not attempted | NOT ATTACHED |
| tcp_retransmit_skb | not attempted | NOT ATTACHED |
| kfree_skb | not attempted | NOT ATTACHED |

`sentinel_bpf__load` failed, so `sentinel_bpf__attach` was never reached and no link was created (bpftool link IDs identical before and after, §14).

## 7. Map / runtime status

- Skeleton open succeeded; `.rodata` configuration was applied before load.
- libbpf proceeded to program load, so CO-RE relocation against the running kernel had already run.
- No maps or programs remained after the failure: bpftool map, prog and link IDs are identical before and after.
- No `bpftool` "during" snapshot exists, because the loader never reported a loaded state.

## 8–11. Feature validation (scheduler, softirq, TCP retransmission, kfree_skb)

**NOT RUN.** No program was attached, so no kernel observation exists for any of the four features. Nothing is claimed for them at runtime.

## 12. End-to-end EvidenceSnapshot validation

**NOT RUN with kernel data.** The driver's phases B–E (end-to-end windows, restart, kill, overhead) were skipped after the load failure.

The same driver was dry-run beforehand without privileges, with the replay harness in place of the loader. That run passed every phase: contract checks, deterministic rebuild, independent recomputation and M2 acceptance. It validates the tooling, **not the kernel path**.

## 13. Repeated-window validation

**NOT RUN.**

## 14. Cleanup validation

```text
BPF cleanup: PASS (for the load attempt that occurred)
```

From `host_compare.txt` (bpftool before/after):

| Check | Result |
|---|---|
| `bpf_progs_identical` | true |
| `bpf_links_identical` | true |
| `bpf_maps_identical` | true |
| `sn_programs_left` | `[]` |

The loader exited with code 2 after printing the `unavailable` line, and nothing persisted. Cleanup after a *successful* attach and the kill-mid-window case (phase D) were **not exercised**.

## 15. Overhead measurements

**NOT MEASURED.** Overhead requires attached programs.

## 16. Failures and anomalies

1. **R1-F1 (critical, blocks the gate): `sn_sched_switch` rejected by the verifier.** See §5. This is a BPF code-generation and verifier defect in the committed program. It is not an environment or privilege problem, since the load reached the verifier, which processed 190 instructions.
2. **R1-A1 (tooling false positive, not a host change): `docker0_identical: false`.** The only differing field is `linkinfo.info_data.gc_timer`, the bridge's free-running garbage-collection countdown (98.58 → 96.44 s). Every configuration field of `docker0` is identical, as are its addresses, routes and flags. The comparison should exclude bridge timer fields. `interfaces_identical: false` has the same cause.
3. The driver stopped correctly. No collection was attempted on a partially loaded object.

## 17. Safety confirmation

- `enp0s31f6` is identical before and after; `docker0` configuration is unchanged (A1); interfaces `lo`, `enp0s31f6`, `docker0`; addresses, IPv4/IPv6 routes and `/run/netns` are identical.
- Sysctls are identical (`unprivileged_bpf_disabled=2`, `perf_event_paranoid=4`, `bpf_stats_enabled=0`, `bpf_jit_enable=1`, `ip_forward=1`).
- No tc/netem, namespace, veth, cgroup write, fault, contention or traffic on a physical interface.
- No BPF program remains loaded.
- M2 (`src/sentinelai/diagnostic/`) and the contract (`0.5.0-draft`) are unchanged. No M3B source was modified after the failure.

## 18. Known limitations of this run

- Only the first failing program has a verifier verdict. Verdicts for the four programs after it are unknown until the object loads.
- Acceptance of `sn_sched_wakeup`/`sn_sched_wakeup_new` is inferred from libbpf's load order, not proven.
- The softirq and kfree paths index their maps through `bpf_map_lookup_elem` keys, not through an array offset. They do not repeat the failing pattern, but this is unverified until they are loaded.

## 19. Evidence artifacts and commands

| Artifact | Content |
|---|---|
| `results/phase1c_m3b_r1/20261003T072203Z/r1.json` | Driver record (phase A: first line, exception, stderr, return code, bpftool state before/after) |
| `…/verifier_log.txt` | Full libbpf/verifier output (200 lines) |
| `…/environment.txt` | Commit, kernel, loader version, sha256 of loader/object/skeleton |
| `…/host_before/`, `…/host_after/` | `ip -j -d link`, `ip -j addr`, routes, `/run/netns`, sysctls, lockdown, bpftool prog/link/map JSON |
| `…/host_compare.txt` | Before/after comparison |
| `scripts/m3b_r1_validate.sh`, `scripts/m3b_r1_validate.py` | Validation tooling (new, uncommitted) |

Command run by the user: `cd /home/iiitd/sentinelai && sudo bash scripts/m3b_r1_validate.sh` (driver exit code 1: "load/attach FAILED; stopping before collection").

## 20. Gate decision

```text
M3B R1 RUNTIME GATE: NO-GO
```

**Blocker: R1-F1.** Verifier acceptance is not established (`sn_sched_switch` rejected), so no program attached, no runtime observation exists, and repeated collection, end-to-end validation, cleanup after attach and overhead could not be measured.

**Decision required (not taken here).** A correction requires an authorised change to the M3B program, which is outside R1. For review, options that keep the semantics identical:

1. **Index with the same register as the check.** Clamp and access through a 64-bit index with a compiler barrier, so the bounded register is the one used, e.g. `__u64 i = ...; if (i > SN_HIST_BUCKETS - 1) i = SN_HIST_BUCKETS - 1; barrier_var(i);`.
2. **Mask instead of compare.** Use a mask the verifier tracks directly (e.g. pad the histogram to 1024 slots and use `i & 1023`).
3. **Map key instead of array offset.** Make the histogram a `PERCPU_ARRAY` with `SN_HIST_BUCKETS` entries indexed through `bpf_map_lookup_elem`, as the other counters already are. This needs no array offset.

Any fix must keep the replay-harness semantics unchanged (the fixture and mutation suites guard this), be followed by a rebuild and a commit, and then rerun R1 from the start. The validation comparison should also exclude bridge timer fields (A1).

**STOP.** No fix, no rebuild and no further runtime step without explicit authorisation.
