# SentinelAI — Phase 0 Evaluation

**Infrastructure audit, capability discovery and project-readiness assessment**

| Field | Value |
|---|---|
| Audit date | 2026-10-02 |
| Host | `iiitd-Precision-3660` (Dell Precision 3660), user `iiitd` |
| Access | SSH from `192.168.52.107` → `192.168.192.151:22` |
| Method | Read-only commands run as the unprivileged user. Nothing was installed, configured, restarted or downloaded. `sudo` needs a password and was **not** used, so a few root-only facts are marked *unverified*. |
| Only active test | One 128-token inference against the **already-present** Ollama model `gemma3:1b`, used as a CPU throughput baseline. |

Legend: ✅ verified working · ⚠️ present with caveats · ❌ missing or not working · ❔ not verifiable without root

---

## A. Hardware (verified)

| Item | Verified value | Evidence |
|---|---|---|
| CPU | 13th Gen Intel Core i7-13700 (family 6, model 183, stepping 1) | `lscpu` |
| Cores / threads | 16 cores (8 P + 8 E; L2 shows 10 instances = 8 P-core L2 + 2 E-core clusters), 24 threads, 1 socket, 1 NUMA node | `lscpu`, `nproc` = 24 |
| Frequency | 800 MHz – 5200 MHz; `intel_pstate` driver, `powersave` governor (HWP) | `lscpu`, sysfs cpufreq |
| Cache | L1d 640 KiB, L1i 768 KiB, L2 24 MiB, L3 30 MiB | `lscpu` |
| SIMD useful for LLM/ML | AVX, AVX2, **AVX-VNNI**, FMA, F16C, SSE4.2. **No AVX-512, no AMX.** | `/proc/cpuinfo` flags |
| Virtualisation | VT-x (`vmx`), EPT; `kvm_intel` loaded; `/dev/kvm` exists (ACL'd) | `lscpu`, `lsmod`, `ls -l /dev/kvm` |
| RAM | 16,054,116 kB = **15.3 GiB** usable | `/proc/meminfo` |
| RAM available at audit time | **9.5 GiB** available (4.5 GiB used, 9.9 GiB cache). The GNOME desktop session plus Chrome, snap-store and others hold about 4–4.5 GiB. | `free -h`, `ps` |
| RAM type/speed | ❔ needs `dmidecode` (root) | — |
| Swap | 2 GiB swap **file** (`/swapfile`), no zswap, swappiness 60 | `swapon --show` |
| GPU | Intel Raptor Lake-S UHD Graphics 770 `[8086:a780]`, driver `i915` (`xe` module also loaded); `/dev/dri/renderD128` present | `lspci -nnk`, `lsmod` |
| GPU compute | ❌ **Not available.** No OpenCL ICD, no Level Zero, `clinfo` and `glxinfo` absent, `torch.xpu.is_available() == False`, `torch.cuda.is_available() == False`, Ollama reports `size_vram: 0` (pure CPU). | see §G |
| NPU | ❌ None (`/dev/accel` absent; device `8086:a71d` is the DTT thermal controller, not an NPU) | `lspci`, `ls /dev/accel` |
| Disk | SK hynix PC801 NVMe 1 TB (non-rotational), dual-boot with NTFS (Windows) partitions | `lsblk` |
| Linux root FS | `/dev/nvme0n1p7` ext4, 298 GiB, **141 GiB free** (51 % used) | `df -hT` |
| `/boot` | 431 MiB, 188 MiB free; `/boot/efi` 96 MiB, 19 MiB free (81 %) | `df -hT` |
| NIC | `enp0s31f6`, Intel `e1000e`, 1000 Mb/s full duplex, `192.168.192.151/20`, default gateway `192.168.192.11` (DHCP) | `ip`, sysfs |
| Other links | `docker0` 172.17.0.1/16 (no carrier, no containers) | `ip -br addr` |
| OS | Ubuntu 22.04.5 LTS (jammy) | `/etc/os-release` |
| Kernel | `6.8.0-138-generic` (HWE), PREEMPT_DYNAMIC | `uname -a` |
| Boot / security | Secure Boot **disabled**; lockdown `none`; cmdline `quiet splash` | `mokutil`, `/sys/kernel/security/lockdown` |
| Uptime / load | 3 days, load average about 0.4–0.7 (idle) | `uptime` |
| Default target | `graphical.target`, with a local GNOME session on seat0 | `systemctl`, `loginctl` |

## B. Software (installed, verified versions)

### Development

| Tool | Version |
|---|---|
| git | 2.34.1 |
| gcc / g++ | 11.4.0 |
| make | GNU Make 4.3 |
| pkg-config | 0.29.2 |
| curl | 7.81.0 |
| wget | 1.21.2 |
| jq | 1.6 |
| linux-headers | 6.8.0-138-generic ✅ (matches running kernel) |

### Python

| Item | Status |
|---|---|
| python3 | 3.10.12 (`/usr/bin/python3`) |
| pip | 22.0.2 (apt `python3-pip`) |
| venv | ❌ **broken**: `python3 -m venv` fails because `ensurepip` is missing (`python3.10-venv` not installed) |
| conda / pyenv / uv | ❌ none |
| numpy | 1.25.2 (in `~/.local`) |
| pandas | 2.2.3 (in `~/.local`) |
| scipy | 1.8.0 (apt). ⚠️ **Version conflict**: it warns that it needs numpy < 1.25 |
| scikit-learn | ❌ missing |
| matplotlib | 3.9.4 (in `~/.local`) |
| PyTorch | 2.8.0**+cu128** (in `~/.local`). It works on CPU (16 threads; 10 × 2048² fp32 matmul in 0.23 s), but it is a CUDA build that can never use a GPU here. |
| networkx | 3.4.2 |
| prometheus_client | present (apt) |
| transformers, sentence-transformers, langchain, llama-cpp-python, openvino, faiss, chromadb, qdrant-client, psutil, bcc (python), fastapi, pydantic | ❌ all missing |

`~/.local/lib/python3.10/site-packages` is **6.9 GiB** (much of it CUDA wheels) and `~/.cache/pip` is **5.3 GiB**. These user-site packages leak into every `python3` process, which is a reproducibility hazard (§J).

### LLM runtime

| Item | Status |
|---|---|
| Ollama | ✅ 0.35.0, systemd service `active` + `enabled`, runs as user `ollama`, listens on **127.0.0.1:11434 only** |
| Models present | `gemma3:1b` (815 MB) only. Model store is under `/usr/share/ollama` (mode 0750, size ❔ needs root) |
| llama.cpp (`llama-cli`/`llama-server`) | ❌ not installed |
| Hugging Face cache | ❌ none (`~/.cache/huggingface` absent) |
| GGUF / safetensors files | none found in `~`, `/opt`, `/srv` (max depth 6) |

### Observability / performance tools

| Tool | Status |
|---|---|
| perf | ✅ 6.8.12 (`linux-tools-6.8.0-138-generic`). Unprivileged use is effectively blocked (`perf_event_paranoid = 4`). |
| vmstat | ✅ (procps) |
| ss, ip, tc | ✅ (iproute2) |
| tcpdump | ✅ (user is in the `wireshark` group) |
| bpftool | ✅ v7.4.0 (bundled libbpf 1.4) |
| pidstat, iostat, mpstat, sar | ❌ (`sysstat` not installed) |
| ethtool | ❌ |
| bpftrace | ❌ |
| BCC (`bpfcc-tools`, python3-bpfcc) | ❌ |
| iperf3, stress-ng, htop, numactl, lm-sensors | ❌ |
| Prometheus / node_exporter / Grafana | ❌ none installed or listening |

## C. Missing dependencies (separated)

Nothing below was installed in this phase.

| Category | Missing | Blocking for |
|---|---|---|
| **Access / permissions** | User `iiitd` **not in `docker` group**; **no passwordless sudo** | All container work; all eBPF/perf work |
| Python tooling | `python3.10-venv` (and therefore working venvs) | Reproducible Python environments |
| Python libraries | scikit-learn, psutil, pydantic, fastapi, transformers / sentence-transformers (or an alternative embedder), vector-store client, BCC python bindings | ML, RAG, agent services |
| Build | `cmake`, `clang`/`llvm` (needed for CO-RE BPF programs and for building llama.cpp) | eBPF C programs, llama.cpp |
| eBPF | `bpftrace`, `bpfcc-tools`/`python3-bpfcc`, `libbpf-dev` (only the old `libbpf0` 0.5 runtime library is present) | eBPF instrumentation |
| Perf tools | `sysstat` (pidstat/iostat/mpstat/sar), `ethtool`, `stress-ng`, `iperf3` | Baselines, fault injection |
| Kubernetes | `kubectl`, `kind`/`k3d`, `helm` | K8s-based scenarios |
| Observability | Prometheus, node_exporter (cAdvisor optional) | Metrics pipeline |
| Local LLM | A 4B–8B instruct model with tool calling; an embedding model | Agent reasoning, RAG |
| GPU compute | Intel OpenCL / Level Zero runtime (not recommended to pursue, see §G) | — |

## D. eBPF readiness

| Check | Result |
|---|---|
| Kernel | 6.8.0 ✅. This is recent enough for CO-RE, ring buffers, BTF-typed tracepoints (`tp_btf`), fentry/fexit, `bpf_loop`, and cgroup and LSM BPF. sched_ext is **not** available (`CONFIG_SCHED_CLASS_EXT` absent; it arrived in 6.12), but SentinelAI does not need it. |
| Kernel config | `BPF_SYSCALL=y`, `BPF_JIT=y`, `BPF_JIT_ALWAYS_ON=y`, `BPF_EVENTS=y`, `KPROBES=y`, `KPROBE_EVENTS=y`, `UPROBES=y`, `UPROBE_EVENTS=y`, `TRACEPOINTS=y`, `FTRACE=y`, `FUNCTION_TRACER=y`, `CGROUP_BPF=y`, `BPF_LSM=y`, `XDP_SOCKETS=y`, `NET_CLS_BPF=m`, `NET_ACT_BPF=m`, `NET_SCH_NETEM=m`, `IKHEADERS=m` ✅ |
| BTF | ✅ `/sys/kernel/btf/vmlinux` present (`DEBUG_INFO_BTF=y`, `_MODULES=y`), so CO-RE works without kernel headers at runtime |
| JIT | ✅ `bpf_jit_enable = 1` |
| bpffs | ✅ mounted at `/sys/fs/bpf` (mode 700) |
| tracefs / debugfs | ✅ mounted at `/sys/kernel/tracing` and `/sys/kernel/debug`, but **root-only** (mode 700) |
| cgroup v2 | ✅ unified hierarchy; controllers `cpuset cpu io memory hugetlb pids rdma misc` |
| PSI | ✅ `/proc/pressure/{cpu,memory,io}` readable (useful low-cost signal) |
| Unprivileged BPF | ❌ `kernel.unprivileged_bpf_disabled = 2`, and bpftool confirms "bpf() syscall restricted to privileged users" |
| perf events | ❌ for the user: `perf_event_paranoid = 4` (Ubuntu's restrictive setting); `kptr_restrict = 1` (`/proc/kallsyms` addresses hidden) |
| Lockdown / Secure Boot | ✅ lockdown `none`, Secure Boot disabled, so kprobes/BPF are not blocked by lockdown |
| bpftool | ✅ v7.4.0 |
| bpftrace / BCC / libbpf-dev / clang | ❌ all missing |

**Tracepoint availability.** tracefs is root-only, so I verified the tracepoints through the world-readable vmlinux BTF (`trace_event_raw_*` types, 1,204 found):

| Target | Tracepoint (event class in BTF) | Present |
|---|---|---|
| sched_switch | `sched:sched_switch` | ✅ |
| sched_wakeup / wakeup_new | `sched_wakeup_template` | ✅ |
| migration / exec / runtime | `sched_migrate_task`, `sched_process_exec`, `sched_stat_runtime` | ✅ |
| softirq | `irq:softirq_{entry,exit,raise}` (class `softirq`) | ✅ |
| hard IRQ | `irq_handler_entry` | ✅ |
| Net device TX/RX | `net_dev_template` (covers `netif_receive_skb`, `net_dev_queue`), `net_dev_xmit`, `napi_poll` | ✅ |
| TCP | `tcp_event_sk_skb` (`tcp_retransmit_skb`, `tcp_send_reset`), `tcp_probe`, `tcp_retransmit_synack`, `sock:inet_sock_set_state` | ✅ |
| Drops / qdisc | `skb:kfree_skb`, `qdisc_dequeue` | ✅ |
| Block I/O | `block_rq`, `block_rq_completion` | ✅ |
| Syscalls | `raw_syscalls:sys_enter/sys_exit` | ✅ |
| Memory reclaim | `mm_vmscan_direct_reclaim_*` | ✅ |

Note: `netif_receive_skb` has no raw type of its own because it is an instance of the `net_dev_template` class. That is expected and not a gap.

**Verdict.** The kernel can instrument everything SentinelAI needs (scheduler latency, softirq, NAPI, TCP retransmits and state, drops, block I/O, reclaim). **Every eBPF and perf experiment will need root** (or CAP_BPF + CAP_PERFMON granted to specific binaries). I loaded no BPF programs, because doing so requires root, and this phase forbids it anyway.

## E. Container readiness

| Check | Result |
|---|---|
| Docker Engine (client) | ✅ 29.8.0 (Docker CE repo), API 1.56 |
| Docker Compose | ✅ plugin v5.5.1 (the legacy `docker-compose` binary is absent; not needed) |
| Buildx | ✅ v0.37.0 |
| containerd / runc | ✅ binaries present; `docker` and `containerd` services `active` |
| Daemon reachable by user | ❌ **`permission denied` on `/var/run/docker.sock`** (`root:docker 660`; user not in `docker` group) |
| Docker storage / resources | ❔ `docker info` and `/var/lib/docker` need root. The underlying FS has 141 GiB free. |
| Existing containers | None apparent (`docker0` has no carrier) |
| Podman / nerdctl | ❌ not installed (not needed) |
| cgroup v2 + KVM | ✅ (good for kind/k3d; KVM is only needed if a VM-based driver is ever used) |
| User namespaces | ✅ `max_user_namespaces = 61821`; `unshare -rn` works for the user |

**Verdict.** The engine is healthy, but the user cannot use it until the `docker` group is granted (one `sudo` action plus a fresh login). Membership in `docker` is root-equivalent; that is acceptable on a single-user research box but should be a conscious decision.

## F. Kubernetes readiness

Nothing is installed: no kubectl, kind, minikube, k3d, k3s or helm.

**Recommendation for 16 GB RAM:**

1. **Default substrate: Docker Compose.** Most SentinelAI fault scenarios (CPU contention, noisy neighbours, netem latency/loss, softirq pressure, memory pressure, I/O stalls) are reproducible with Compose and cgroups at a fraction of the RAM, and are easier to instrument from the host with eBPF.
2. **When K8s is needed: `kind`, single node** (control plane only, about 0.7–1.0 GiB idle plus workloads). It is the best fit because it:
   - runs inside Docker, so it never touches host iptables or kubelet config outside the container. That matters on a remote SSH box with `ufw` active.
   - is fully disposable (`kind delete cluster`) and declaratively reproducible (config YAML pins the node image and K8s version), which suits a research artifact.
   - runs workloads as host processes in host cgroups, so host-side eBPF sees pod tasks directly.
3. `k3d` is an acceptable lighter alternative (about 0.4–0.6 GiB). It runs k3s, which is less "vanilla" for reproducibility claims.
4. **Avoid native `k3s`.** It installs a system service and rewrites host iptables/networking, which is a disconnection risk over SSH. **Avoid `minikube`:** its default 2 CPU / about 2 GiB+ allocation adds overhead with no benefit here.
5. Never run more than one cluster and never use multi-node kind on this machine. Bring the cluster up only for K8s-specific experiments.

Note: `fs.inotify.max_user_instances = 128` is low for kind with many pods (kind docs suggest 512). Raising it is a sysctl change, so it is deferred to Phase 1 for explicit approval.

## G. Local LLM readiness

### Measured baseline (existing model, no download)

```
model gemma3:1b (≈1B params, Q4, 815 MB) via Ollama 0.35.0, CPU only (size_vram = 0)
load 1.31 s | prompt eval 205 tok/s (22-token prompt) | generation 57.8 tok/s
```

Token generation on CPU is memory-bandwidth-bound. 815 MB × 58 tok/s ≈ 47 GB/s of effective weight-read bandwidth. **Extrapolated** (not measured) generation speeds:

| Class | Q4_K_M size (approx.) | RAM incl. 8k ctx | Est. gen tok/s | Fit on this box |
|---|---|---|---|---|
| 1B–3B | 0.8–2.0 GB | 1.5–3 GB | 25–58 | ✅ fast; good for routing, classification, summarising tool output |
| **4B** | ≈2.5 GB | 3–4 GB | ≈15–20 | ✅ good "worker" model |
| **7B–8B** | 4.5–5 GB | 5.5–7 GB | ≈8–10 | ✅ **primary reasoning model**, usable but slow on long RAG prompts |
| 12B–14B | 7.5–9 GB | 9–11 GB | ≈4–6 | ⚠️ fits only with nothing else heavy running; too slow for multi-step agent loops |
| ≥ 24B / 30B-MoE at Q4 | 14–19 GB | > 16 GB | — | ❌ does not fit (MoE 30B-A3B is fast per token but its weights alone exceed RAM) |

Prompt processing (prefill) dominates RAG latency. Expect roughly 30–80 tok/s prefill for an 8B model on this CPU, so a **4k-token RAG context costs about 1–2 minutes before the first output token**. This is an estimate to be measured in Phase 1. It is the single most important design constraint (§K).

### iGPU

The UHD 770 (32 EU) shares system RAM and memory bandwidth, so for decode-bound LLM inference it offers no bandwidth advantage over the CPU. Enabling it would require the Intel compute runtime (OpenCL/Level Zero) plus a SYCL/Vulkan/OpenVINO backend, which is new system packages with uncertain gains. **Treat GPU acceleration as unavailable.** Benchmarking it can be an optional experiment later, never a dependency.

### Conservative model recommendation (to be benchmarked in Phase 1, not yet downloaded)

| Role | Size class | Candidates (check that current releases are open-weight with permissive licences) |
|---|---|---|
| Primary agent (reasoning + tool calling) | 7B–8B, Q4_K_M | Qwen3-8B (Apache-2.0, native tool calling, 32k ctx), Llama-3.1-8B-Instruct (Llama Community Licence), Granite 3.x 8B (Apache-2.0) |
| Fast worker / router / judge-lite | 3B–4B | Qwen3-4B, Phi-4-mini (MIT), Gemma 3 4B (Gemma terms) |
| Embeddings | ≤ 0.6B | nomic-embed-text, bge-small/bge-base, or bge-m3 (multilingual, larger) |
| Optional reranker | ≤ 0.6B | bge-reranker-base / -v2-m3 |

Rules:

- **One generative model resident at a time.** Multiple agent "roles" must share one model with different system prompts and tool sets, not separate models. Set `OLLAMA_MAX_LOADED_MODELS=1`, `OLLAMA_NUM_PARALLEL=1`, and keep the embedding model small.
- Default context to 8k. Use 16k only when measured to fit.
- Use Ollama (already installed) as the primary runtime. A `llama.cpp` build is optional for GBNF-constrained decoding and finer control.

## H. Storage budget

Current state: 141 GiB free on `/` (ext4, NVMe). Reclaimable: `~/.cache/pip` 5.3 GiB; the CUDA PyTorch wheels inside `~/.local` (several GiB) are unused because there is no NVIDIA GPU. I deleted nothing.

| Item | Projected size |
|---|---|
| LLMs (one 8B + one 4B + one 1B, Q4) | 8–10 GB |
| Embedding + reranker | 1–2 GB |
| Python venv(s) with CPU-only torch, sentence-transformers, ML stack | 4–6 GB |
| Docker images (app services, Prometheus, workloads, kind node image about 1 GB) | 10–20 GB |
| Prometheus TSDB (15 s scrape, 15-day retention, small target set) | 1–5 GB |
| eBPF traces, experiment raw data, results | 10–30 GB (must be rotated and compressed) |
| RAG corpus + vector index (+ graph) | 1–5 GB |
| Toolchain (clang/llvm, bpftrace, bcc, sysstat, kind, kubectl) | 1–2 GB |
| **Total projected** | **≈ 40–80 GB** |

**Verdict.** It fits, with 60+ GiB headroom. `/boot/efi` (81 % full, 19 MiB free) is unrelated to the project but is a reason **not** to install additional kernels.

## I. RAM budget

Usable RAM is 15.3 GiB. The desktop session and browsers currently take about 4–4.5 GiB, leaving about 9.5 GiB available. If the GUI apps (Chrome, snap-store) are closed while experiments run, about 12–13 GiB is available. Swap is only 2 GiB.

| Component | Steady RSS estimate |
|---|---|
| OS + sshd + system services (headless share) | 1.0–1.5 GiB |
| GNOME desktop + browser (as currently running) | 3–4.5 GiB |
| LLM 8B Q4 + 8k KV cache (Ollama) | 5.5–7 GiB |
| LLM 4B Q4 (alternative to 8B, not in addition) | 3–4 GiB |
| Embedding model (loaded on demand) | 0.3–1.2 GiB |
| SentinelAI Python app (agents, orchestrator, API) | 0.3–0.8 GiB |
| Vector store, embedded (FAISS/LanceDB/Chroma) or Qdrant container | 0.2–0.6 GiB |
| Graph store: embedded (networkx / Kùzu / SQLite) | 0.1–0.5 GiB |
| Graph store: Neo4j (JVM) | 1.5–3 GiB ❌ avoid |
| PostgreSQL (small) | 0.2–0.5 GiB; prefer SQLite unless concurrency is needed |
| Prometheus + node_exporter (+ cAdvisor) | 0.3–0.8 GiB |
| Docker engine + containerd (idle) | 0.1–0.3 GiB |
| Target microservice workload (Compose, 4–8 small services) | 1–2 GiB |
| kind single node (idle) + workload | 1–1.5 GiB + workload |
| ML training (scikit-learn / small torch on tabular features) | 0.5–2 GiB, transient |
| eBPF collectors (bpftrace/BCC/libbpf) | 0.05–0.3 GiB (BCC compiles with clang at load time: transient spike of about 0.3 GiB) |

**Can run simultaneously** (headless-ish, about 12 GiB budget): OS + Ollama 8B (≈ 6.5) + embedder (0.5) + app (0.6) + embedded vector/graph store (0.5) + Prometheus/node_exporter (0.6) + Compose workload (1.5) + eBPF collectors (0.3) ≈ **11.5 GiB**. That is tight but feasible.

**Must run sequentially or in exclusive windows:**
- kind cluster **or** the Compose workload, never both.
- Any ML training/feature-extraction job runs **while the LLM is unloaded** (`keep_alive=0`).
- 12B–14B experiments (if ever) run with no cluster and no workload.
- Embedding/index build happens offline, before the agent runs.

**Avoid:** Neo4j, Elasticsearch/OpenSearch, Grafana Loki + Tempo + full LGTM stack, multi-node K8s, minikube, Kafka, multiple concurrent LLMs, and the CUDA PyTorch wheels.

**Lightweight alternatives:** embedded vector store over Qdrant/Milvus; networkx/Kùzu over Neo4j; SQLite/DuckDB over PostgreSQL for results; plain Prometheus (Grafana optional and only on demand); BM25 via `rank_bm25`/`tantivy` for hybrid retrieval.

**A safety caveat:** measuring under deliberate memory-pressure faults on a box whose own LLM needs about 6.5 GiB can trigger the OOM killer against the *observer* (Ollama/agent) rather than the target. Fault-injected workloads must run in cgroups with hard `memory.max` limits.

## J. Risks

| # | Risk | Severity | Note / mitigation |
|---|---|---|---|
| R1 | **No passwordless sudo**; eBPF and perf need root | High | Phase 1 needs the user to run privileged steps interactively. Later, use targeted file capabilities (`cap_bpf,cap_perfmon` on collector binaries) or a small root-run collector service, not blanket NOPASSWD. |
| R2 | **User not in `docker` group** | High (blocking) | One `usermod`, then a new SSH login. Accept docker = root-equivalent. |
| R3 | CPU-only LLM, slow prefill: long RAG contexts add latency of minutes | High | Short, structured contexts; aggressive retrieval top-k; summarise tool output with a small model; cache; measure in Phase 1. |
| R4 | 16 GiB RAM with about 4.5 GiB taken by the GUI session | High | Close browsers during runs, or treat the desktop as a fixed overhead in the budget. Do **not** switch the default target to multi-user without explicit approval. |
| R5 | Only 2 GiB swap, so OOM risk during memory-pressure experiments | Medium | cgroup `memory.max` on all workloads; optionally (with approval) add zram or enlarge the swapfile in Phase 1. |
| R6 | Observer effect: LLM inference saturates P-cores and memory bandwidth, distorting the very latencies being diagnosed | High (scientific validity) | Pin Ollama and agents to a CPU set (for example E-cores 16–23) and the workload to P-cores via cgroup `cpuset`. Record a baseline with the agent idle. Do not run the LLM during the measurement window, only after it. |
| R7 | Hybrid P/E-core CPU plus `powersave` governor: frequency and core-type variability adds noise | Medium | Fix CPU affinity per experiment, repeat runs (≥ 5), report variance. Do not change the governor without approval. |
| R8 | User-site Python pollution (`~/.local`, numpy/scipy mismatch, CUDA torch) | Medium | Project venv **without** `--system-site-packages`; use `PYTHONNOUSERSITE=1`; CPU-only torch wheel. |
| R9 | Ubuntu 22.04 apt versions of bpftrace/BCC are old | Medium | Prefer libbpf + CO-RE (bpftool 7.4 / libbpf 1.4 already available) for production collectors; use a newer upstream bpftrace static binary for ad-hoc work if apt's is insufficient. Verify versions in Phase 1. |
| R10 | Remote SSH session: netem or tc on the **physical** NIC `enp0s31f6` could cut the connection | High | **Never** apply qdiscs to `enp0s31f6`. Fault-inject only on veth/bridge interfaces inside network namespaces or containers. Every tc change gets a timed auto-revert. |
| R11 | `ufw` active and Docker bypasses ufw for published ports | Low–Med | Bind published ports to `127.0.0.1`; use SSH port forwarding to view UIs from Windows. |
| R12 | Ollama bound to `127.0.0.1` only; containers cannot reach it by default | Low | Run the agent on the host (venv), or expose it deliberately to the Docker bridge only. |
| R13 | `inotify.max_user_instances=128` | Low | Raise only if kind fails (Phase 1, with approval). |
| R14 | Dual-boot machine with Windows partitions | Low | Never touch partitions; keep all data under `$HOME`. |
| R15 | Shared/institutional machine: the directory "MT25037 (Don't Delete)" and other users' tools (Metasploit, IDEs) suggest prior use | Low | Keep the project self-contained in one directory; no global config changes. |

## K. Recommended architecture constraints

1. **Single resident LLM, multiple roles.** Planner, diagnoser, verifier and reporter are prompts and tool scopes over one 7B–8B model (fallback 4B). No per-role models.
2. **Agents must be token-frugal.** Tools return compact, pre-aggregated JSON (percentiles, top-N, deltas), never raw traces. eBPF aggregation happens in-kernel (maps/histograms), not in the LLM.
3. **Deterministic first, LLM second.** Anomaly detection and candidate ranking use classical ML and rules over metrics and eBPF features. The LLM reasons over the shortlist, picks tools, explains, and proposes mitigations. This is cheaper and evaluable.
4. **Embedded data stores.** Vector index plus BM25 (hybrid) in-process; "GraphRAG" over a lightweight in-process graph (networkx/Kùzu) of services, hosts, cgroups and runbooks. No JVM databases.
5. **Compose-first fault lab; kind only for K8s-specific scenarios**, run one at a time.
6. **Privilege separation.** A small privileged collector (eBPF loaders, tc/netem in namespaces) exposed to the unprivileged agent through a narrow, allow-listed tool interface (MCP-style). The LLM never gets a shell or root.
7. **Safe mitigation actions.** Allow-list only (cgroup limits, CPU pinning, tc on lab veths, container restart). Every action carries a timeout and an automatic rollback, and is verified by re-measurement.
8. **Isolation for measurement validity.** Use cpusets for agent vs. workload, a defined experiment protocol (baseline → inject → detect → mitigate → verify), and record LLM-on/LLM-off baselines.
9. **Local-first.** No cloud APIs or keys. An OpenAI-compatible endpoint abstraction (Ollama exposes one) allows cloud models later as optional benchmarks only.
10. **Reproducibility.** Pinned venv (lockfile), pinned container images and model digests, kind config in-repo, every experiment emitting a manifest (git SHA, model digest, kernel, config).

### Recommended project layout (not yet created)

```
sentinelai/
├── README.md, pyproject.toml, uv.lock|requirements.lock, Makefile, .env.example (no secrets)
├── docs/                 # design, ADRs (docs/adr/), phase reports (PHASE_*.md), runbooks
├── src/sentinelai/
│   ├── agents/           # planner, diagnoser, verifier, reporter (prompts + policies)
│   ├── orchestration/    # agent graph/state machine, memory, retries, recovery
│   ├── llm/              # model client (OpenAI-compatible), prompt templates, guards
│   ├── tools/            # MCP-style tool servers: metrics, ebpf, procfs, docker, k8s, tc
│   ├── rag/              # ingestion, chunking, embeddings, hybrid retrieval, graph RAG
│   ├── detection/        # ML/rules anomaly detection, feature extraction
│   ├── mitigation/       # allow-listed actions + rollback + verification
│   ├── telemetry/        # Prometheus queries, PSI, collectors' clients
│   └── common/           # config, schemas (pydantic), logging
├── collectors/
│   ├── ebpf/             # libbpf CO-RE C sources, bpftrace scripts, build files
│   └── privileged/       # root-side daemon exposing narrow API
├── infra/
│   ├── compose/          # fault lab services, Prometheus config
│   ├── kind/             # cluster config, manifests
│   └── scripts/          # setup/teardown, safety guards (tc auto-revert)
├── faults/               # fault injection scenarios (declarative YAML + drivers)
├── knowledge/            # RAG corpus: runbooks, kernel docs excerpts, postmortems
├── experiments/          # experiment definitions (configs), one dir per study
├── evaluation/           # metrics, scorers, benchmark harness, LLM-judge (optional)
├── datasets/             # raw/ processed/ (gitignored large files; DVC or manifests)
├── models/               # model manifests/digests only (weights stay in Ollama store)
├── results/              # run outputs (gitignored), summarized tables/figures
├── logs/                 # runtime logs (gitignored, rotated)
├── notebooks/            # analysis only, never source of truth
└── tests/                # unit, integration (tools), scenario smoke tests
```

## L. Phase 1 recommendation (do not execute yet)

Phase 1 is **"Minimal, reproducible foundation"**. Steps marked 🔑 need the user's sudo password.

1. 🔑 `sudo usermod -aG docker iiitd`, then start a **new** SSH session and verify `docker run --rm hello-world`. Record `docker info` (storage driver, cgroup driver, data root).
2. 🔑 apt install (jammy repos, no upgrades of existing packages): `python3.10-venv cmake clang llvm libbpf-dev libelf-dev zlib1g-dev sysstat ethtool stress-ng iperf3 bpfcc-tools python3-bpfcc bpftrace htop`. Then **record installed versions** and verify that `bpftrace -l 'tracepoint:sched:*'` and `sudo bpftrace -e 'tracepoint:sched:sched_switch { @[comm]=count(); } interval:s:3 { exit(); }'` work. If apt's bpftrace is too old, evaluate the upstream static binary.
3. eBPF smoke test (root, read-only probes, auto-exit ≤ 5 s): one each for `sched_switch`/`sched_wakeup` run-queue latency, `softirq_entry/exit`, `tcp_retransmit_skb`, `inet_sock_set_state`, `kfree_skb`. Plus one minimal libbpf CO-RE program built with clang to prove the toolchain.
4. Python: create `sentinelai/.venv` (no system site packages, `PYTHONNOUSERSITE=1`), and install **CPU-only** torch plus the minimal stack (numpy, scipy, pandas, scikit-learn, psutil, pydantic, httpx, prometheus-client). Pin it in a lockfile. Do not touch `~/.local`.
5. LLM: pull **one** 7B–8B tool-calling model and **one** 4B model (Q4_K_M) plus one small embedding model through the existing Ollama. Benchmark prefill and decode tok/s at 2k/4k/8k context, peak RSS, and tool-call JSON validity on 20–50 test prompts. Select the primary model by evidence. Configure `OLLAMA_MAX_LOADED_MODELS=1` (🔑 systemd override) only if needed.
6. Observability: Prometheus + node_exporter via Docker Compose, ports bound to 127.0.0.1, 15 s scrape, size-capped retention. Verify scraping and RSS.
7. Install `kubectl` + `kind` (user-local binaries in `~/.local/bin` or the project `bin/`, pinned versions). Create **one** single-node cluster, measure idle RSS, then **delete it**. 🔑 Raise `fs.inotify.max_user_instances` only if kind requires it, with approval.
8. Safety guards: a script for tc/netem **only on veth inside a netns**, with mandatory auto-revert, plus a check that refuses `enp0s31f6`. Define cpusets for observer (E-cores) vs. workload (P-cores) and verify them.
9. Create the repository skeleton (§K), `git init`, and record a machine manifest (kernel, versions, model digests).
10. Produce `PHASE_1_EVALUATION.md` with measured numbers that replace this report's estimates (LLM prefill speed, kind RSS, Prometheus RSS, the concurrent RAM peak).

Optional and needing approval: close the GUI apps during experiments; enlarge swap or enable zram; clean `~/.cache/pip`.

---

## 15. Objective evaluation

**Objective: "Can this machine realistically host the complete SentinelAI development environment?"**

### Result: **PASS WITH CONSTRAINTS**

The kernel, BTF, CPU instruction set, disk and container engine are all adequate, and a local LLM is already serving on CPU at a measured 58 tok/s for 1B. It is not a plain PASS for four reasons: (1) there is no GPU compute, so LLM throughput caps at about 8–10 tok/s for 8B models with slow prefill; (2) 16 GiB RAM forces sequential operation of the heavy components; (3) eBPF and perf require root that is password-gated; (4) Docker is currently unusable by the user.

| Capability | Status | Evidence | Limitation | Mitigation |
|---|---|---|---|---|
| **Local LLM** | PASS WITH CONSTRAINTS | Ollama 0.35.0 active; gemma3:1b 57.8 tok/s decode, 205 tok/s prefill, `size_vram 0`; AVX2/AVX-VNNI present; 9.5–13 GiB RAM free | CPU-only; 8B ≈ 8–10 tok/s (est.); ≥ 14B impractical; long prompts slow | 8B primary / 4B worker, Q4_K_M, 8k ctx, single resident model, compact tool outputs; measure in Phase 1 |
| **ML** | PASS | Torch 2.8 CPU works (16 threads); numpy/pandas/matplotlib present; 24 threads | sklearn missing; user-site version conflicts; CUDA wheels wasted | Clean venv with CPU-only torch; classical/tabular ML, small models; run training with the LLM unloaded |
| **RAG** | PASS WITH CONSTRAINTS | Disk 141 GiB free; RAM headroom for embedded indices; networkx present | No vector DB/embedder installed; prefill cost limits context size | Small embedder, embedded hybrid (BM25 + vector) index, reranker, tight top-k; lightweight graph instead of Neo4j |
| **Agentic AI** | PASS WITH CONSTRAINTS | Local OpenAI-compatible endpoint (Ollama) is up; tool-calling-capable 8B models fit in RAM | Multi-step loops × slow inference = minutes per incident; small models make tool-call errors | Deterministic pre-analysis, schema-validated tool calls with retries, step budgets, shared single model for all roles |
| **eBPF** | PASS WITH CONSTRAINTS | Kernel 6.8, BTF, JIT, kprobes/uprobes/tracepoints; sched/softirq/net/TCP/skb/block tracepoints confirmed via BTF; lockdown none; bpftool 7.4 | Unprivileged BPF disabled (=2), perf_event_paranoid=4, tracefs root-only; bpftrace/BCC/clang/libbpf-dev missing; nothing has been loaded yet | Phase 1: install toolchain (🔑), run root smoke tests; privileged collector with narrow API |
| **Docker** | PASS WITH CONSTRAINTS | Engine 29.8.0, Compose v5.5.1, Buildx, daemon active, cgroup v2 | **User cannot access the socket** (not in `docker` group) | 🔑 `usermod -aG docker` plus re-login; bind ports to localhost |
| **Kubernetes** | PASS WITH CONSTRAINTS (not installed) | cgroup v2, Docker, user namespaces and KVM available; RAM allows one small cluster | No tooling; RAM forbids running K8s alongside the full stack; inotify limit low | kind single-node, on demand, torn down after use; Compose as the default lab |
| **Single machine** | PASS WITH CONSTRAINTS | All of the above on one host; 141 GiB disk; 24 threads | Observer and target share CPU, memory bandwidth and RAM, which threatens measurement validity; GUI session consumes about 4.5 GiB; remote-only access | cpuset isolation (E-cores for agent, P-cores for workload), LLM-off measurement windows, cgroup memory limits, no tc on the physical NIC |

---

## PHASE 0 GATE

### Overall status: **GO**

There is no hard blocker. Two items are **preconditions for starting Phase 1**, and both require the account owner's sudo password:

1. Add `iiitd` to the `docker` group (then a new SSH login).
2. Install the missing toolchain packages (venv, clang/llvm/libbpf-dev/cmake, bpftrace/BCC, sysstat, ethtool, stress-ng, iperf3).

### Exact actions for Phase 1 (not executed)

1. Docker group access, then verify with `hello-world` and record `docker info`.
2. apt toolchain install (list in §L.2), then version inventory.
3. Root eBPF smoke tests: sched_switch/wakeup, softirq, TCP retransmit/state, kfree_skb, and one libbpf CO-RE program.
4. Isolated project venv with CPU-only PyTorch and a pinned minimal stack.
5. Pull one 8B and one 4B tool-calling model plus an embedder; benchmark prefill/decode/RSS/tool-call validity; choose the primary model by evidence.
6. Prometheus + node_exporter via Compose (localhost-bound); measure RSS.
7. kubectl + kind (user-local, pinned); create, measure and delete a single-node cluster.
8. Safety tooling: netns-only tc/netem with auto-revert and a physical-NIC denylist; cpuset partition for observer vs. workload.
9. Repository skeleton + `git init` + machine manifest.
10. `PHASE_1_EVALUATION.md` with measured replacements for every estimate in this report.

*Phase 0 ends here. Phase 1 has not been started.*
