# SentinelAI

An evidence-first diagnosis system for performance incidents on a single Linux host. It is built and
validated in gated phases, each ending at an explicit GO/NO-GO decision. Autonomous diagnosis and mitigation
remain the long-term aim; they are **not** current capabilities.

> **Status (14 October 2026).** Phase 1C's evaluation is complete. The deterministic diagnostic core (evidence
> contract M1, rule engine M2, Linux and eBPF collectors M3A/M3B) was calibrated on a FaultLab training split and
> evaluated once on a held-out test split (M4–M8).
>
> - **The primary system, rules alone, does not meet the design's quality gates.** Its macro F1 is **0.765**, below
>   the 0.80 of G-Q1, and the per-class recall gate G-Q2 fails for application bottleneck, memory pressure and TCP
>   retransmissions.
> - **It never guesses when nothing is wrong:** abstention 1.00 and false assertion 0.00 on 24 runs expected to
>   abstain (G-Q3).
> - The advisory, contract-gated ML classifier reaches 0.861 (G-Q1 passes) and also fails G-Q2.
>
> Details: [M8 report](docs/PHASE_1C_M8_REPORT.md). Phase 2A added a read-only runtime (replay, verification, one
> bounded live M3A acquisition). No LLM is in the decision path; M2 is the only diagnostic authority.

## Why this exists

When p99 latency spikes in a containerised service, most of the time goes into working out *which layer* is at
fault: the kernel, the network or the application. Two constraints shape the design:

- **Production telemetry often can't leave the machine.** Everything runs locally, with no cloud APIs.
- **A confident wrong diagnosis is worse than none.** Every decision must be backed by measured evidence with
  provenance, and the system must answer `INSUFFICIENT_EVIDENCE` instead of guessing. Today this abstention comes
  from the deterministic rule engine (M2), not from an LLM.

**Who it's for:** on-call / SRE engineers who need a trustworthy first diagnosis without sending sensitive data
to a third party.

## Key findings

**Phase 1B: no local LLM is adequate as the diagnostician (FAIL / NO-GO).** A pre-registered confirmatory test
(48 scenarios, fixed 70 % adequacy bar) overturned the first benchmark's winner. The best local 8–9B models
(qwen3:8b, qwen3.5:9b) scored **37.5 % and 43.8 %**, a non-robust difference (McNemar p = 0.55). They caught only
**1 of 6** TCP-retransmission incidents and guessed a fault in **9 of 13** ambiguous cases, with about 0.93
self-reported confidence whether right or wrong. The phase was declared **NO-GO**, and no primary model was
chosen. Details: [Phase 1B confirmatory report](docs/PHASE_1B_CONFIRMATORY_EVALUATION.md).

**Consequence: an LLM-independent core.** The LLM-centred Phase 1C plan was replaced by a deterministic,
evidence-first design ([Phase 1C design](docs/PHASE_1C_DESIGN.md)): versioned evidence contract → typed evidence
→ rule engine with explicit abstention. It has no LLM, RAG, agent or automated mitigation in the decision path.

**FaultLab validations (R2): controlled faults diagnosed correctly, within stated scope.** In network-namespace and
cgroup labs with independent ground truth, M2 diagnosed packet loss, CPU contention, CPU throttling and (scoped)
memory pressure. Softirq overload could not be produced under its registered design.

**Held-out evaluation (M8): strong on CPU and loss faults, weak on three classes; G-Q1 and G-Q2 fail for rules
alone.**
- The data is a 202-run FaultLab matrix (M6), with parameters calibrated on the training split only (M7) and the
  artefacts hash-locked before the test split was read.
- **What works:** CPU contention and CPU throttling were diagnosed 12/12 each, including the intensity never seen in
  training, and packet loss 11/12. Rules alone never asserted a fault in a run that should abstain.
- **Where it fails, for causes visible on the training split before testing:**
  - TCP retransmissions are diagnosed as application bottleneck in 7 of 12 runs: under heavy loss or rate limiting,
    TCP falls below the evaluability floor and the application clause is not blocked.
  - Memory pressure without user-visible latency impact abstains (7 of 12).
  - Application bottlenecks at the lower intensities (I1, I2) abstain (5 of 12).

  These are recorded findings, not tuned away. See the [M8 report](docs/PHASE_1C_M8_REPORT.md) and the
  [M7 calibration report](docs/PHASE_1C_M7_CALIBRATION_REPORT.md).

## Capabilities at a glance

| Category | What |
|---|---|
| **Implemented and committed** | Evidence contract and strict schema (M1); deterministic rule engine with abstention and precedence (M2); read-only `/proc` / `/sys` / cgroup collectors (M3A) plus read-only qdisc statistics (M3A-C1); CO-RE eBPF observation layer and loader (M3B); FaultLab lab tooling and validation drivers (R2-A–R2-F); FaultLab A–R–B lab, pilot, matrix and dataset (M4–M6); train-only calibration, advisory ML classifier and artefact lock (M7); one-time held-out evaluation (M8) |
| **Evaluated on the held-out test split (M8)** | Rules alone: macro F1 0.765 (G-Q1 fail); contention 12/12, throttling 12/12, loss 11/12, retransmissions 5/12, memory 5/12, application 7/12; no false assertion on 24 runs expected to abstain |
| **Experimentally validated** | `network_packet_loss` (R2-B), `cpu_contention` (R2-C), `cpu_throttling` (R2-D, documented limitation) |
| **Validated, scoped** | `memory_pressure` (R2-F): cgroup `memory.high` file-backed page-cache refault pressure, via the reclaim-and-refault path only |
| **Not validated** | `tcp_retransmissions` as a primary decision (seen only as CONTRIBUTING in R2-B); `softirq_overload` (R2-E NOT FEASIBLE); `application_bottleneck` (application metrics not collected) |
| **Implemented and committed (Phase 2A)** | Read-only runtime: pure core, write-once artifact store, snapshot replay and verification, raw-tick replay, live M3A acquisition (eBPF and interface sources refused) |
| **Live-verified once (bounded)** | One live M3A-only run on an idle service (Phase 2A.5): PARTIAL, abstention, `verify` and both replays MATCH; outside the validated configuration |
| **Future (not built)** | Any LLM or agent layer, which must not bypass M2; mitigation and verification loop; out-of-distribution evaluation |

## Held-out evaluation (M8)

The test split has 72 single-fault runs (12 per class, across three intensities including one never seen in training)
and 14 clean controls, all at run level. The full report, with every gate, limitation and deviation, is in
[`docs/PHASE_1C_M8_REPORT.md`](docs/PHASE_1C_M8_REPORT.md).

| Class | Rules alone: recall | Rules alone: precision | ML gated: recall |
|---|---|---|---|
| `cpu_contention` | 1.00 (12/12) | 1.00 | 1.00 |
| `cpu_throttling` | 1.00 (12/12) | 1.00 | 1.00 |
| `network_packet_loss` | 0.92 (11/12) | 1.00 | 1.00 |
| `tcp_retransmissions` | 0.42 (5/12) | 1.00 | 0.42 |
| `memory_pressure` | 0.42 (5/12) | 1.00 | 1.00 |
| `application_bottleneck` | 0.58 (7/12) | 0.50 | 0.58 |

- **Gates:**
  - G-Q1 macro F1 ≥ 0.80: rules **0.765, fail**; ML gated 0.861, pass.
  - G-Q2 per-class recall ≥ 0.70: **fails for both systems**.
  - G-Q3 abstention on runs that should abstain: pass (1.00 / 0.00).
  - G-Q4 coverage: pass (0.82 / 0.83).
  - G-C1 ML calibration: pass (ECE 0.046).
  - The validity, determinism and leakage gates (G-E1, G-E2, G-L1): pass.
- **Combined policy:** the ML is advisory. It flagged 50 of 258 windows and changed no decision.
- **Raw (ungated) ML:** classified every test run correctly. FaultLab's fault signatures are highly separable, and
  out-of-distribution data was not evaluated, so this is not field accuracy.

## Earlier validations (R2) and limitations

| Contract label | Status | Evidence | Limitations |
|---|---|---|---|
| `network_packet_loss` | Validated | [R2-B](docs/PHASE_1C_R2B_NETWORK_FAULT_VALIDATION_REPORT.md): `netem loss 1%` (3 runs) and `5%` (2 runs) on a lab veth; all 5 loss runs decided `network_packet_loss`; the baseline abstained (INSUFFICIENT_EVIDENCE) | Lab veth only; one host |
| `tcp_retransmissions` | Contributing only | R2-B: CONTRIBUTING under `network_packet_loss` (precedence PR-1) in 3 of 5 loss runs | Never the primary decision in validation |
| `cpu_contention` | Validated | [R2-C](docs/PHASE_1C_R2C_CPU_CONTENTION_VALIDATION_REPORT.md): `cpu.weight` contender on the target CPU; E2 (weight 400): ground truth established and M2 `cpu_contention` 3/3; controls abstained | E1 (weight 100): M2 diagnosed `cpu_contention` 3/3, but the pre-approved G4 median-lateness criterion was not met, so ground truth was not established; recorded as a disagreement and limitation, not a failed gate |
| `cpu_throttling` | Validated with documented limitation | [R2-D](docs/PHASE_1C_R2D_CPU_THROTTLING_VALIDATION_REPORT.md): CPU quota; PR-3 contention vs throttling resolved to `cpu_throttling` 3/3 | `throttle.quota_saturation` (supporting) was MISSING in all 9 throttled runs; behaviour under binding throttling is unvalidated |
| `memory_pressure` | Validated, **scoped** | [R2-F](docs/PHASE_1C_R2F_MEMORY_PRESSURE_VALIDATION_REPORT.md): M1×3 and M2×3 ground truth established and diagnosed; N1/N2 controls had 0 false positives | Reclaim/refault path only (PSI path untested); OOM, anonymous-memory and swap pressure untested; no graded severity (M1 ≈ M2); MEDIUM confidence |
| `softirq_overload` | **Not feasible** under the registered design | [R2-E](docs/PHASE_1C_R2E_SOFTIRQ_OVERLOAD_FEASIBILITY_REPORT.md): the loss-free load ladder reached 0.166 cores of NET_RX on the target CPU; 0.666 were required | Not a pass and not a fail; any revalidation needs a new design |
| `application_bottleneck` | Not validated | — | Application metrics are not collected |

Cross-cutting limitations:
- the R2 validations used engineering values (`r2c-validation-uncalibrated`). The M7 parameter set
  (`m7-calibrated-v1`) is calibrated on the FaultLab training split, except `THR_RATIO_MIN`, which is a declared
  value. The runtime's "validated configuration" still names the R2 pair (rules `m2-1.1.0`, contract `0.5.0-draft`),
  so 0.6.0 diagnoses are reported as unvalidated;
- `sched.run_delay_excess.target` assumes one runnable thread. With a multi-threaded target it is inflated under
  throttling (finding D-6, [M7 report](docs/PHASE_1C_M7_CALIBRATION_REPORT.md));
- M2 confidence is capped at MEDIUM (`IMPACT_NOT_MEASURED`);
- all results come from one host and kernel (6.8.0-138), one campaign per class;
- `cpu.util.cpuset` has a tick-accounting bias on a partially busy CPU;
- tick-sampled `/proc/stat` under-reports softirq time on this kernel.

Full list: [`docs/PROJECT_STATUS.json`](docs/PROJECT_STATUS.json).

## Architecture

```
/proc, /sys, cgroupfs ──► M3A collectors (read-only) ─┐
eBPF programs (root) ───► M3B loader + parser ────────┼─► normalised measurements ─► EvidenceSnapshot (M1 contract)
                                                      │                                      │
                                                      │                                      ▼
                                                      │                    M2 rule engine (sole diagnostic authority)
                                                      │                                      │
                                                      │                                      ▼
                                                      └── provenance ───────────► DiagnosticResult: decision | INSUFFICIENT_EVIDENCE,
                                                                                  supporting / negative / missing / conflicting evidence
```

- **M1 evidence contract** ([report](docs/PHASE_1C_M1_REPORT.md), PASS WITH CONDITIONS): versioned contract (now `0.6.0-draft`, schema `0.2.0`; evidence recorded under `0.5.0-draft` is evaluated under its archived contract, see the [contract revision](docs/PHASE_1C_M7_CONTRACT_REVISION.md)), strict Pydantic models, deterministic IDs and canonical serialisation. [Contract](docs/EVIDENCE_CONTRACT.md).
- **M2 rule engine** ([report](docs/PHASE_1C_M2_REPORT.md), PASS WITH CONDITIONS): pure and deterministic (rules `m2-1.2.0`; `m2-1.1.0` for 0.5.0 evidence); explicit abstention reasons and a closed precedence table; refuses missing or uncalibrated parameters.
- **M3A collectors** ([report](docs/PHASE_1C_M3A_REPORT.md), PASS WITH CONDITIONS; [M3A-C1](docs/PHASE_1C_M3A_C1_REPORT.md) GO): reads under `/proc` and `/sys` only. The single permitted command is `tc -s -j qdisc show` on non-protected interfaces. Absence is recorded as `Bad` states, never as zero.
- **M3B eBPF layer** ([audit](docs/PHASE_1C_M3B_REPORT.md) NO-GO, resolved by the [R1 runtime validation](docs/PHASE_1C_M3B_R1_RUNTIME_VALIDATION_REPORT.md) GO): CO-RE BPF programs and a loader linked to libbpf 1.4; root only; observation only.
- **FaultLab** ([R2-A infrastructure](docs/PHASE_1C_R2A_FAULTLAB_INFRASTRUCTURE_REPORT.md) GO): dedicated network namespaces, veth pairs and lab cgroups, with independent ground truth. Faults never touch protected interfaces or non-lab cgroups.
- **Evaluation pipeline (M4–M8):**
  - Lab and data: an A–R–B lab with a containerised workload and load generator. A deterministic 202-run matrix is
    collected into an append-only raw dataset with a SHA-256 manifest (M6).
  - Train-only calibration (M7): the contract parameters are set by objectives written before calibration.
  - Advisory ML (M7): a calibrated random forest. It is contract-gated and can never assert what the rules did not
    assert.
  - Hash lock: the artefacts are locked before the test split is read.
  - One-time evaluation (M8): rules alone, ML and the combined policy are evaluated on the held-out test split.
  - Every step passes integrity checks that admit changes only through owner-approved amendments.

**Runtime (Phase 2A; [report](docs/PHASE_2A_RUNTIME_REPORT.md)).** One read-only workflow: incident context → M3A
acquisition → `ticks.jsonl` → snapshot → M2 → `DiagnosisRecord` → write-once artifact store with manifest. It
supports offline replay from snapshots or ticks, and verification.
- **2A.1** pure core;
- **2A.2** replay/verify: all 58 replayable committed R2-C/D/F snapshots reproduce their recorded M2 results;
- **2A.3** raw-tick replay: no historical tick streams exist, so coverage is synthetic plus 70 committed eBPF streams;
- **2A.4** live read-only M3A acquisition: eBPF and interface-backed sources refused;
- **2A.5** first live acquisition (`/system.slice/cron.service`): exit 11, PARTIAL (structural `Bad` states from
  unlimited quotas and a denied namespace readlink), `INSUFFICIENT_EVIDENCE`; `verify` and both replay modes MATCH.
  Evidence and source provenance: [`results/phase2a_live/first-live-cron/`](results/phase2a_live/first-live-cron/PROVENANCE.json).

Live runs are M3A-only and therefore outside the validated (M3A + eBPF) configuration. Each live run requires its own
authorisation; BPF state during the first run was not verified (it needs root).

## Phase history

| Phase | Verdict | Report |
|---|---|---|
| 0: Infrastructure audit | PASS WITH CONSTRAINTS / GO | [PHASE_0_EVALUATION.md](docs/PHASE_0_EVALUATION.md) |
| 1A: Foundation | PASS WITH CONSTRAINTS / GO WITH CONDITIONS | [PHASE_1A_EVALUATION.md](docs/PHASE_1A_EVALUATION.md) |
| 1B: Local LLM selection | **FAIL / NO-GO** (no final primary) | [PHASE_1B_EVALUATION.md](docs/PHASE_1B_EVALUATION.md) (superseded), [PHASE_1B_CONFIRMATORY_EVALUATION.md](docs/PHASE_1B_CONFIRMATORY_EVALUATION.md) |
| 1C: Design (LLM-independent core) | Design document (status "DESIGN ONLY"; no separate design-gate verdict recorded); implementation began with M1. Pre-M2 audit GO WITH CONDITIONS; contract revision v0.2.0-draft approved; C-1 PASS | [PHASE_1C_DESIGN.md](docs/PHASE_1C_DESIGN.md), [pre-M2 audit](docs/PHASE_1C_PRE_M2_AUDIT.md), [contract revision](docs/PHASE_1C_CONTRACT_REVISION_REPORT.md), [C-1](docs/PHASE_1C_C1_REPORT.md) |
| 1C M1: Evidence contract | PASS WITH CONDITIONS | [M1](docs/PHASE_1C_M1_REPORT.md) |
| 1C M2: Rule engine | PASS WITH CONDITIONS | [M2](docs/PHASE_1C_M2_REPORT.md) |
| 1C M3A / M3A-C1: Collectors | PASS WITH CONDITIONS / GO | [M3A](docs/PHASE_1C_M3A_REPORT.md), [M3A-C1](docs/PHASE_1C_M3A_C1_REPORT.md) |
| 1C M3B: eBPF layer | Gate NO-GO, then R1 runtime validation GO | [M3B](docs/PHASE_1C_M3B_REPORT.md), [build](docs/PHASE_1C_M3B_BUILD_REPORT.md), [C0](docs/PHASE_1C_M3B_C0_REPORT.md), [C1](docs/PHASE_1C_M3B_C1_REPORT.md), [R1 attempt 1](docs/PHASE_1C_M3B_R1_ATTEMPT1_REPORT.md), [R1 attempt 2 (preliminary)](docs/PHASE_1C_M3B_R1_ATTEMPT2_PRELIMINARY_REPORT.md), [R1.1 verifier fix](docs/PHASE_1C_M3B_R1_1_VERIFIER_FIX_REPORT.md), [R1 runtime validation](docs/PHASE_1C_M3B_R1_RUNTIME_VALIDATION_REPORT.md) |
| 1C R2-A: FaultLab infrastructure | GO / CLOSED | [R2-A](docs/PHASE_1C_R2A_FAULTLAB_INFRASTRUCTURE_REPORT.md) |
| 1C R2-B: Packet loss | GO / CLOSED | [R2-B](docs/PHASE_1C_R2B_NETWORK_FAULT_VALIDATION_REPORT.md) |
| 1C R2-C: CPU contention | PASS / CLOSED | [R2-C](docs/PHASE_1C_R2C_CPU_CONTENTION_VALIDATION_REPORT.md) |
| 1C R2-D: CPU throttling | PASS WITH DOCUMENTED LIMITATION / CLOSED | [R2-D](docs/PHASE_1C_R2D_CPU_THROTTLING_VALIDATION_REPORT.md) |
| 1C R2-E: Softirq overload | **NOT FEASIBLE** under the registered design / CLOSED | [R2-E](docs/PHASE_1C_R2E_SOFTIRQ_OVERLOAD_FEASIBILITY_REPORT.md) |
| 1C R2-F: Memory pressure | PASS (scoped) / CLOSED | [R2-F](docs/PHASE_1C_R2F_MEMORY_PRESSURE_VALIDATION_REPORT.md) |
| 1C M4–M5: FaultLab lab and pilot | Pilot complete; Freeze-1 decisions approved and intensity levels frozen | [M5 pilot](docs/PHASE_1C_M5_PILOT_REPORT.md), [decision register](docs/PHASE_1C_FREEZE1_DECISION_REGISTER.md) |
| 1C M6: Matrix collection | COMPLETE: 202/202 runs (78 train, 106 test, 12 SENS, 6 PI-3), none excluded | [M6](docs/PHASE_1C_M6_COLLECTION.md) |
| 1C M7: Calibration, ML, lock | COMPLETE: contract v0.6.0-draft; train-only calibration; ML (random forest) used although it missed G-Q2 on validation; artefacts locked at `afdde9a` | [objectives](docs/PHASE_1C_M7_CALIBRATION_OBJECTIVES.md), [contract revision](docs/PHASE_1C_M7_CONTRACT_REVISION.md), [report](docs/PHASE_1C_M7_CALIBRATION_REPORT.md) |
| 1C M8: Held-out evaluation | EVALUATED ONCE: rules alone **G-Q1 FAIL** (0.765), **G-Q2 FAIL**; G-Q3, G-Q4 pass; ML gated G-Q1 pass, G-Q2 fail | [protocol](docs/PHASE_1C_M8_EVALUATION_PROTOCOL.md), [report](docs/PHASE_1C_M8_REPORT.md) |
| 2A: Runtime design | GO (review session; summarised in the 2A report) | [PHASE_2A_RUNTIME_REPORT.md](docs/PHASE_2A_RUNTIME_REPORT.md) |
| 2A.1–2A.4: Runtime implementation | PASS (per closeout) | [PHASE_2A_RUNTIME_REPORT.md](docs/PHASE_2A_RUNTIME_REPORT.md) |
| 2A.5: First live acquisition | PASS (bounded gate: M3A-only, idle target) | [report §6](docs/PHASE_2A_RUNTIME_REPORT.md), [provenance](results/phase2a_live/first-live-cron/PROVENANCE.json) |
| 2A.6: Runtime closeout | CLOSED: `d119618` (runtime source and tests, the exact live-run source) and `d6b9333` (evidence, provenance, documentation), both on `origin/main`. At closeout: runtime tests 153/153; regression 1,026/1,028 (2 known environmental failures). Live-run BPF state unverified | [report §8](docs/PHASE_2A_RUNTIME_REPORT.md) |

Machine-readable status: [`docs/PROJECT_STATUS.json`](docs/PROJECT_STATUS.json).

Naming: "Phase 2A" is the runtime integration above. An earlier README roadmap (commit `6d404c8`) used "Phase 2" for an
eBPF telemetry collector, which was built as Phase 1C M3B; the two are different milestones. No Phase 2B–2F is
defined. R2-A to R2-F are Phase 1C FaultLab tracks, not Phase 2 subphases. How that earlier roadmap's Phase 1C exit
gate and its LLM-agent Phase 3 relate to the current plan is unresolved and left for a separate design decision.

## Roadmap

| Step | Goal | Gate |
|---|---|---|
| Next (undecided, pending an explicit decision) | Address the M8 findings, each as a new, separately evaluated version (the M8 result stays as recorded): network evaluability in AB.R3 (TCP below `SEG_MIN`), the per-thread run-delay excess (D-6), memory pressure without latency impact; regeneration check G-P1; out-of-distribution evaluation | Each needs its own design, approval and a fresh held-out evaluation |
| Alternative next steps | Live eBPF acquisition mode, live interface/qdisc collection | Each needs its own design, privilege gate and approval |
| Future | Optional LLM/agent layer for explanation or orchestration; it must not bypass M2 or evidence validation | To be designed and gated |
| Future | Mitigation and verification loop | To be designed and gated; not started |

## Hardware and safety constraints (verified)

| Resource | Value | Design consequence |
|---|---|---|
| CPU | i7-13700, 16C/24T. P-cores = CPUs 0–15, E-cores = CPUs 16–23 | FaultLab targets an isolated E-core (CPU 18); tooling stays on 0–15 |
| RAM | 15.3 GiB, 2 GiB swap | FaultLab lab cgroups run with `memory.swap.max = 0` |
| GPU | Intel UHD 770, no compute runtime | CPU-only inference for any local model |
| Disk | NVMe; 141 GiB free at the Phase 0 audit | Comfortable |
| Kernel | 6.8.0 with BTF; eBPF requires root | Privileged eBPF loader behind a narrow interface; runtime live acquisition uses M3A only |
| Network | `enp0s31f6` (physical) and `docker0` are protected | Faults only inside lab netns/veth; collectors refuse protected interfaces |

## Repository layout

```
src/sentinelai/
  diagnostic/contract/   M1 evidence contract, models, IDs, canonical serialisation (+ data/labels.json, parameters.json)
  diagnostic/rules/      M2 deterministic rule engine
  collectors/            M3A read-only collectors, parsers, normalisation, snapshot builder
  ebpf/                  M3B loader process boundary
  runtime/               Phase 2A runtime: context, registry, ticks, store, events, report, pipeline, replay, live
  __main__.py            CLI: python -m sentinelai diagnose | verify | replay
ebpf/                    BPF programs, loader, replay harness, Makefile (build output ebpf/build/ is not committed)
scripts/                 safety gate, smoke tests, M3B validation, FaultLab R2-A–R2-F drivers and validators
tests/                   collectors, ebpf, evidence, rules, faultlab, runtime (+ test_phase1a.py, host-mutating; see below)
docs/                    phase reports, evidence contract, PROJECT_STATUS.json
results/                 committed evidence from validation runs (phase2a_live/: first live run + provenance)
experiments/llm_benchmark/  Phase 1B benchmark and confirmatory test
experiments/faultlab/    FaultLab lab, preflight, pilot, matrix generator (matrix.py), M6 runner (m6.py),
                         M7 calibration/ML/lock (m7.py), M8 evaluation (m8.py)
datasets/faultlab/v1/    raw dataset (append-only, SHA-256 manifest), matrix.json, m7/ locked artefacts,
                         m8/evaluation.json
configs/                 (placeholder; .gitkeep only)
requirements.in / requirements.lock
```

Not in the committed repository: `.venv/`, `logs/*`, `ebpf/build/`, the M6 staging directory `results/phase1c_m6/`,
and owner working files (for example `experiments/faultlab/docker/Dockerfile`).

## Usage

```bash
# Recreate the environment
python3 -m venv .venv && .venv/bin/pip install -r requirements.lock

# Safety gate (fails closed; run before any experiment)
scripts/safety_check.sh

# Verification test suite: every test package except the host-mutating tests/test_phase1a.py.
# Expect 1,552 tests. tests/ebpf runs `make -C ebpf all` (it needs the BPF toolchain and rewrites
# ebpf/build/min_core.btf with identical content); tests/collectors includes a short read-only live read of
# its own cgroup.
(cd tests && rc=0 && for p in collectors ebpf evidence rules faultlab runtime; do
   PYTHONNOUSERSITE=1 ../.venv/bin/python -m unittest discover -s "$p" -t . || rc=1
 done; exit $rc)
```

`tests/test_phase1a.py` is a Phase 1A environment acceptance test. It runs Docker containers and changes host
state (root cgroup controllers, a `docker0` address), so it is **not** part of routine verification. Run it only
deliberately.

**Environment-dependent tests:** `faultlab.test_r2c.TestDryRun.test_dry_run_mutates_nothing` and
`faultlab.test_r2d.TestMatrixAndStatic.test_dry_run_mutates_nothing`. R2-C's preflight requires the exact root cgroup
controller set that exists after Docker has run, so these two tests can fail after a reboot until Docker has started
a container. They are kept unchanged rather than weakened. At the M8 checkpoint (`2db8ec4`) all 1,552 tests pass on
the reference host.

Several integrity tests require a clean working tree; run the suite with no uncommitted tracked changes.

FaultLab validation runs (`sudo bash scripts/r2*_validate.sh`) and the M3B privileged validation change lab
state as root. Each requires its own reviewed, authorised gate. They are not part of routine usage.

Runtime CLI (needs `PYTHONPATH=src`; stdout is one canonical JSON object; exit codes are documented in
`src/sentinelai/__main__.py`):

```bash
PYTHONNOUSERSITE=1 PYTHONPATH=src .venv/bin/python -m sentinelai verify --run-dir ABSOLUTE_RUN_DIR
PYTHONNOUSERSITE=1 PYTHONPATH=src .venv/bin/python -m sentinelai replay --run-dir ABSOLUTE_RUN_DIR --source ticks
PYTHONNOUSERSITE=1 PYTHONPATH=src .venv/bin/python -m sentinelai replay --run-dir ABSOLUTE_RUN_DIR --source snapshot
```

FaultLab M7/M8 (offline, read-only on the committed dataset; outputs are add-only and the tools refuse to overwrite):

```bash
.venv/bin/python experiments/faultlab/m7.py calibrate --out SCRATCH_DIR        # train split only
.venv/bin/python experiments/faultlab/m8.py evaluate --rehearsal-train --out SCRATCH_DIR   # train-only rehearsal
```

The one-time test evaluation (`m8.py evaluate` without options) has been run and refuses to run again.

`verify` and `replay` are offline and read-only. `diagnose` performs a live read-only M3A acquisition of a target
cgroup; it requires `--ebpf disabled` (eBPF and `--iface` are refused) and an explicit `--code-commit`. Under this
project's gate discipline, each live run needs its own preflight and authorisation.
