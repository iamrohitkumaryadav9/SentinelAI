# SentinelAI

An agentic AI system for autonomous diagnosis and mitigation of distributed-system performance incidents.

## Objective

SentinelAI will detect, diagnose, mitigate and verify performance incidents (CPU contention, scheduler latency, softirq/network pressure, TCP retransmits, memory and I/O stalls) in containerised services. It combines kernel-level eBPF telemetry, classical ML, retrieval over operational knowledge, and a locally hosted LLM agent. Every claim the system makes must be backed by measured evidence, and every phase ends at an explicit GO/NO-GO gate.

## Current phase

**Phase 1A: reproducible development foundation.** This phase covers Docker access, an isolated Python environment, the compiler and eBPF toolchain, safety checks and baseline validation. No SentinelAI application code exists yet.

| Phase | Status | Report |
|---|---|---|
| 0: Infrastructure audit | Done (GO) | [docs/PHASE_0_EVALUATION.md](docs/PHASE_0_EVALUATION.md) |
| 1A: Foundation | See report | [docs/PHASE_1A_EVALUATION.md](docs/PHASE_1A_EVALUATION.md) |

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
