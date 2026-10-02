# Phase 1C — M3A-C1 Report: Safe Read-Only Qdisc Evidence

| | |
|---|---|
| Base | `30a74fae9169a4b2c252a2a5f56665131dce75e8` (M3A). `git status`: `?? experiments/faultlab/` only |
| Versions | Contract `0.3.0-draft`, schema `0.2.0`, rules `m2-1.1.0` (unchanged). Collector `m3a-1.0.0` → `m3a-1.1.0` |
| Gate | **M3A-C1 GATE: GO** |

## A. Objective

This closes M3A condition **C-A**: `net.drop.qdisc` was not collected because M3A forbade `tc`. That left the minimum local drop set `{net.drop.qdisc, net.drop.iface_rx, net.drop.iface_tx}` incomplete. On real data, LOSS.LOCAL could be proven but never ruled out, so `tcp_retransmissions` could never be the decision.

M3A-C1 adds one read-only, command-backed source, `tc -s -j qdisc show dev <interface>`, mapped onto the existing registered feature `net.drop.qdisc`. That feature already has unit packets/s, aggregation RATE, scope iface and source TC. No contract, rule or evidence semantics changed.

## B. Changes

**New:**

| File | Purpose |
|---|---|
| `src/sentinelai/collectors/commands/tc.py` | The only command execution in SentinelAI. Fixed argv, exact-pattern check, interface validation, physical/protected-NIC refusal, 2 s timeout, structured failures. |
| `src/sentinelai/collectors/parsers/tc.py` | Pure JSON parser. Extracts only `kind`, `handle`, `root` and `drops`, with strict types. |
| `src/sentinelai/collectors/data/protected_interfaces.json` | Explicit protected list (`enp0s31f6`), defence in depth on top of the generic physical check |
| `tests/collectors/test_tc.py` | 38 tests: parser fixtures 1–8, S1–S9, quality semantics, defence in depth, determinism, live read-only check |
| `scripts/m3a_c1_smoke.py`, `results/phase1c_m3a_c1/` | Real-host smoke run and its artefacts |
| `docs/PHASE_1C_M3A_C1_REPORT.md` | This report |

**Modified:**

| File | Change |
|---|---|
| `errors.py` | Statuses `REFUSED` and `TIMEOUT`, both absence-class, so they become MISSING |
| `reader.py` | `LiveReader.tc_qdisc` delegates to `commands/tc.py`; `FixtureReader.tc_qdisc` applies the same allowlist |
| `probes.py` | `_qdisc`: physical/protected refusal, then read, then parse. 0 qdiscs → absent; >1 → unresolved (§H); single non-root → malformed. |
| `features.py` | A `net.drop.qdisc` entry per target interface, using the existing counter-rate machinery and the existing netns guard (tc runs in the collector's netns, like sysfs) |
| `snapshot.py` | qdisc removed from the not-collected list; `TC` no longer statically "unavailable" |

**Updated tests:**
- `test_safety.py`: `subprocess` is confined to exactly `commands/tc.py`, with a single execution site, `shell=False` and no other subprocess API. The banned-command scan still covers every file; only the forbidden-token literal itself is exempt.
- `test_snapshot.py`: qdisc now collected.
- `test_integration.py`: the old "retransmissions undecidable" test is kept with tc unavailable. Two tests are added: retransmissions become decidable with qdisc evidence, and qdisc drops prove loss.
- `_world.py`: tc fixture output, plus a virtual sysfs link.

## C. Safety

How a read-only collector is prevented from becoming a network mutation path:

1. **One argv, no shell.**
   - `argv_for()` builds `("/usr/sbin/tc", "-s", "-j", "qdisc", "show", "dev", <if>)` and re-checks its own construction with `check_argv()`.
   - The check accepts exactly 7 elements, a fixed absolute executable, the exact prefix, a valid unprotected interface, and no forbidden token (`add change replace delete del class filter netem ingress egress link exec -b -batch -force -n -netns`).
   - Execution uses `runner(list(argv), shell=False, stdin=DEVNULL, capture_output=True, timeout=2.0, env={PATH, LC_ALL=C}, close_fds=True)`. No command string is ever built.
2. **Interface validation.** The name must full-match `^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`: IFNAMSIZ length, no `/`, whitespace, shell metacharacters or leading `-`, and not `.`/`..`. It must also come from the resolved `Target.ifaces`. The tests caught and fixed one real bug here: `re.match` with `$` accepted a trailing newline (`"eth0\n"`), so `fullmatch` is now used.
3. **Physical NIC protection, generic.** An interface is eligible only if `/sys/class/net/<if>` resolves under `/devices/virtual/net/<if>`. Physical NICs (a PCI path), unreadable links and mismatched links are all **refused**. The explicit protected list adds `enp0s31f6` independently. Every layer refuses on its own; that is tested by injecting a mutated allowed-prefix constant and by per-layer assertions.
4. **Failures are structured.**

   | Failure | Status | Measurement |
   |---|---|---|
   | timeout | `TIMEOUT` | MISSING |
   | command unavailable | `ABSENT` | MISSING |
   | permission denied | `DENIED` | MISSING |
   | non-zero exit | `ABSENT` / `DENIED` | MISSING |
   | malformed JSON or unexpected schema | `MALFORMED` | INVALID |
   | empty output | `ABSENT` | MISSING |
   | refused interface | `REFUSED` | MISSING |

   A failing tc call never stops the tick.
5. **Static guarantees** (collector-wide tests):
   - no shell or `shell=True`;
   - no `Popen`, `call`, `check_output` or `os.system`;
   - no mutating-command text;
   - the NIC name appears in no `.py` file.

## D. Evidence: `net.drop.qdisc` is now observable

**Before (M3A).** `net.drop.qdisc` was never measured. It was listed in `missing_measurements` as "source TC (tc -s qdisc) is not permitted in M3A", with `TC` in `sources_unavailable`.

**After (real host, `results/phase1c_m3a_c1/summary.json`).** Both measurements are OK.

| Scope | Quality | Value | Coverage | Baseline | Measurement ID |
|---|---|---|---|---|---|
| `iface:self/lo` | OK | 0.0 /s | 1.0 | median 0.0, n 45, adequate | `690ae32486bc38cf` |
| `iface:self/docker0` | OK | 0.0 /s | 1.0 | median 0.0, n 45, adequate | `726b61df80c9eed2` |

Both have source `TC`, locator `tc -s -j qdisc show dev <if> -> drops (single root qdisc)` and collector `m3a.tc.qdisc`. `TC` no longer appears in `sources_unavailable`.

## E. Integration with LOSS.LOCAL and RT.R2

Neither the M2 engine nor the contract was changed.

**Real host, self target.**

| Candidate | M3A (before) | M3A-C1 (after) |
|---|---|---|
| network_packet_loss | NOT_EVALUABLE | **NOT_SUPPORTED** |
| tcp_retransmissions | NOT_SUPPORTED | NOT_SUPPORTED |

Network packet loss is NOT_SUPPORTED because local loss is now *ruled out*:
- `PL.R1/LOSS.LOCAL[net.drop.qdisc]` is NEGATIVE, as are iface_rx, iface_tx, err, softnet and socket;
- `RT.R2/EVALUATED[min_local_drop_set]` is **POSITIVE**;
- `RT.R2/LOSS.LOCAL` is NEGATIVE.

tcp_retransmissions stays NOT_SUPPORTED because RT.R1 is FALSE: there are no retransmissions.

**Fixtures (`test_integration.py`):**

| Scenario | Result |
|---|---|
| Qdisc drops 500/s in W | `PL.R1/LOSS.LOCAL[net.drop.qdisc]` POSITIVE → **LOSS.LOCAL TRUE** → decision `network_packet_loss` |
| High retransmissions, qdisc at baseline | Minimum drop set complete, LOSS.LOCAL FALSE → decision **`tcp_retransmissions`**. This was unreachable in M3A. |
| High retransmissions, tc unavailable | Still INSUFFICIENT_EVIDENCE (LOSS_VS_RETRANS_UNDECIDABLE): missing qdisc evidence never becomes "no loss" |

## F. Tests

```text
M3A tests (tests/collectors): 111/111   (70 before + 38 in test_tc.py + 3 in test_integration/test_safety)
M1 tests  (tests/evidence):   192/192
M2 tests  (tests/rules):       95/95
Full suite:                   422 run: 421 passed, 0 failed, 1 skipped
                              (the pre-existing intentional skip: test_phase1a bpftrace, root-only)
Mutation (qdisc safety):      20/20 killed, 0 survived (clean unmutated control)
Mutation (M3A regression):    19/19 killed
```

**Mutants attempted** (all killed):
- remove physical-NIC rejection (sysfs); remove protected-list rejection; probe skips the physical check;
- enable `shell=True`; command string instead of argv; `qdisc show` → `qdisc add`; argv self-check skipped; forbidden tokens unchecked;
- remove the timeout; raise the timeout to 60 s;
- bypass interface validation; `match` instead of `fullmatch`; inherit the full environment;
- malformed JSON read as zero; bypass parser type validation; empty output read as zero drops; qdisc tree summed; non-root single qdisc accepted;
- counter decrease treated as valid; qdisc netns guard removed.

Four mutants first survived:
- three were masked defence-in-depth layers: the protected-list check in `argv_for`, the argv self-check, and the forbidden-token check;
- one was missing coverage of a non-root qdisc.

I added a test for each layer on its own rather than claiming equivalence. The final count is 20/20 killed.

**Determinism:**
- an identical fixture gives an identical Measurement and an identical EvidenceSnapshot (canonical bytes);
- tc JSON key order, observation order and repeated builds give byte-identical output;
- IDs contain no timestamps, PIDs, timings or raw output; the locator is a fixed template.

## G. Real-host smoke

| | |
|---|---|
| Interfaces | `lo` and `docker0`, both under `/sys/devices/virtual/net`. No lab-owned interface exists on this host, and creating one would modify networking, so the existing virtual interfaces were used. |
| Command executed | `/usr/sbin/tc -s -j qdisc show dev lo` and `… dev docker0`, argv-style, once per tick (56 ticks × 2), plus before/after comparisons |
| Physical NIC | Never passed to the collector. A deliberate request for `enp0s31f6` returned `refused: interface 'enp0s31f6' is protected` and **0 commands were executed**. |
| Qdisc configuration | Unchanged before and after the run (kind/handle/root/refcnt/options compared) |
| Result | 220 measurements (213 OK, 7 MISSING; the 7 MISSING are the same M3A causes: no cpu controller, zero softirq median). Snapshot valid and re-validated from canonical JSON. `gate_passed = true`. |
| M2 | Accepted the snapshot: INSUFFICIENT_EVIDENCE (REQUIRED_EVIDENCE_MISSING), flag IMPACT_NOT_MEASURED, uncalibrated test parameters. No incident was manufactured. |
| Cost | 1.03 s CPU over 55 s, RSS 37.6 MB, slowest tick 39 ms (includes two tc executions) |

## H. Remaining limitations (observed)

1. **Qdisc trees are not resolved (contract ambiguity, reported rather than invented).**
   - The contract maps `tc … → drops` to one value per interface, but defines no aggregation when an interface carries several qdiscs (for example an `mq` root with per-queue `fq_codel` children, or a classful root with leaves).
   - Root-only, sum-of-leaves and sum-of-all give different numbers.
   - Such interfaces get `net.drop.qdisc` MISSING, with reason "the contract defines no aggregation for a qdisc tree".
   - A contract clarification is needed before multi-queue interfaces can contribute.
2. **Physical interfaces are never queried by design.** For a target whose traffic leaves through a physical NIC, that NIC's qdisc evidence stays MISSING, so the minimum drop set for it can't be completed.
3. **On this host, both eligible interfaces use `noqueue`.** It never queues, so its drop counter is structurally 0. The pipeline is proven end to end, but a non-zero qdisc drop was seen only in fixtures, not on the real host.
4. **A qdisc replaced mid-window with a higher counter can't be detected.** A replacement that resets the counter is detected as a reset.

## I. Git

One commit: `feat(collectors): add safe read-only qdisc evidence`. Its hash is reported in the gate response and by `git log -1`; a commit can't contain its own hash.

---

## M3A-C1 GATE: GO

Every criterion holds:
- qdisc evidence is collected;
- only the read-only `tc -s -j qdisc show dev <if>` path exists, and shell execution is impossible;
- the physical NIC is protected (generic sysfs check + explicit list);
- malicious interfaces are rejected; the 2 s timeout exists and is tested;
- malformed output becomes INVALID and empty output MISSING;
- counter resets invalidate their interval;
- contract and M2 semantics are unchanged;
- M1, M2 and M3A pass, and the full suite passes (only the intentional skip);
- output is deterministic;
- all 20 safety mutants are killed;
- no unrelated files changed.

Limitation H-1 is a reported contract ambiguity, and it fails closed. It is not a safety or correctness blocker.

**STOP.** M3B (eBPF) waits for explicit authorisation.
