# SentinelAI

> **Status: In progress (October 2026).** Phases 0–1B done (infrastructure audit, safety gate, local LLM benchmark + confirmatory test). Next: fix the gaps Phase 1B exposed, then build the eBPF telemetry collector and diagnosis agent. No application code yet; this repo currently holds the foundation and the evaluation evidence.

An agentic AI system for autonomous diagnosis and mitigation of distributed-system performance incidents.

## Why this exists

When p99 latency spikes in a containerised service, most of the time goes into working out *which layer* is at fault: the kernel, the network or the application. LLM agents could speed that up, but:

- **Production telemetry often can't leave the machine.** So SentinelAI runs fully locally on open-weight models, with no cloud APIs.
- **A confident wrong diagnosis is worse than none.** So every claim must be backed by measured evidence, and the agent must answer "insufficient evidence" instead of guessing.

**Who it's for:** on-call / SRE engineers who need a trustworthy first diagnosis without sending sensitive data to a third party.

## Key finding so far

A pre-registered confirmatory test (48 scenarios, fixed 70% adequacy bar) overturned my first benchmark's winner. The best local 8–9B models scored **37.5% and 43.8%**. They caught only **1 of 6** TCP-retransmission incidents and guessed a fault in **9 of 13** ambiguous cases, with ~0.93 self-reported confidence whether right or wrong. I declared the phase **NO-GO** rather than build on them. Details: [Phase 1B confirmatory report](docs/PHASE_1B_CONFIRMATORY_EVALUATION.md).

## Objective

SentinelAI will detect, diagnose, mitigate and verify performance incidents (CPU contention, scheduler latency, softirq/network pressure, TCP retransmits, memory and I/O stalls) in containerised services. It combines kernel-level eBPF telemetry, classical ML, retrieval over operational knowledge, and a locally hosted LLM agent. Every claim the system makes must be backed by measured evidence, and every phase ends at an explicit GO/NO-GO gate.

## Current phase

**Phase 1B (local LLM selection, including confirmatory test) is complete: FAIL / NO-GO. Next phase being planned.** Phase 1A built the foundation; Phase 1B benchmarked local models (`experiments/llm_benchmark/`). No SentinelAI application code exists yet.

| Phase | Status | Report |
|---|---|---|
| 0: Infrastructure audit | Done (GO) | [docs/PHASE_0_EVALUATION.md](docs/PHASE_0_EVALUATION.md) |
| 1A: Foundation | GO WITH CONDITIONS | [docs/PHASE_1A_EVALUATION.md](docs/PHASE_1A_EVALUATION.md) |
| 1B: Local LLM selection | **FAIL / NO-GO**: confirmatory test found no model adequate as autonomous diagnostician; no final primary | [docs/PHASE_1B_EVALUATION.md](docs/PHASE_1B_EVALUATION.md), [docs/PHASE_1B_CONFIRMATORY_EVALUATION.md](docs/PHASE_1B_CONFIRMATORY_EVALUATION.md) |

## Roadmap

| Phase | Goal | Exit gate (GO/NO-GO) |
|---|---|---|
| 1C | Fix what Phase 1B exposed: the TCP retransmission vs packet-loss boundary, and abstention on ambiguous evidence (e.g. a rule/ML pre-classifier before the LLM, stricter evidence requirements per label) | Re-run the 48-scenario confirmatory suite: ≥ 70% correct, and correct abstention on ambiguous cases |
| 2 | eBPF telemetry collector (scheduler latency, softirq, TCP retransmits, drops, memory/I/O stalls) behind a narrow privileged interface | Collector detects each injected fault in the netns/veth test bed |
| 3 | Diagnosis agent: telemetry + retrieval over runbooks + local LLM, with evidence-cited output | End-to-end diagnosis accuracy on injected incidents |
| 4 | Mitigation + verification loop (apply fix, confirm metrics recover) | Verified recovery without unsafe actions |

## Hardware constraints (verified)

| Resource | Value | Design consequence |
|---|---|---|
| CPU | i7-13700, 16C/24T. P-cores = CPUs 0–15, E-cores = CPUs 16–23 | Agent and workload get separate cpusets |
| RAM | 15.3 GiB, 2 GiB swap | One resident LLM, embedded stores, heavy components run one at a time |
| GPU | Intel UHD 770, no compute runtime | CPU-only inference (AVX2/AVX-VNNI) |
| Disk | NVMe, about 140 GiB free | Comfortable |
| Kernel | 6.8.0 with BTF; eBPF requires root | Privileged collector behind a narrow interface |
| Access | Remote SSH only | `enp0s31f6` is read-only; faults go into netns/veth only |

## Local-first principle

SentinelAI runs entirely on this machine with open-weight models (served by Ollama). It needs no cloud LLM APIs, no API keys and no paid infrastructure. Cloud models may later be used only as optional, clearly labelled external benchmarks.

## Layout (Phase 1A minimum)

```
.venv/              isolated Python env (not committed)
configs/            configuration (empty for now)
docs/               phase evaluations and design notes
experiments/        llm_benchmark/ (Phase 1B benchmark + confirmatory test)
scripts/            safety_check.sh, privileged_smoke.sh
tests/              acceptance tests (stdlib unittest)
results/            evidence produced by scripts/tests
logs/               runtime logs (not committed)
requirements.in     direct Python dependencies
requirements.lock   exact pinned environment
```

## Usage

```bash
# Recreate the environment
python3 -m venv .venv && .venv/bin/pip install -r requirements.lock

# Safety gate (fails closed; run before any experiment)
scripts/safety_check.sh

# Privileged eBPF/perf smoke tests (read-only, auto-exit)
sudo bash scripts/privileged_smoke.sh

# Acceptance tests
PYTHONNOUSERSITE=1 .venv/bin/python -m unittest discover -s tests -v
```
