# Phase 1A Evaluation

| Field | Value |
|---|---|
| Date | 2026-10-02 (13:36–13:50 IST) |
| Host | iiitd-Precision-3660, kernel 6.8.0-138-generic, Ubuntu 22.04.5 LTS |
| Repository | `~/sentinelai`, initial commit `1198040` |
| Evidence | `results/phase1a/` (committed), `logs/` (local only) |

## Objective

Build a reproducible and safe development foundation: Docker access, an isolated Python environment, the compiler/eBPF toolchain, basic performance and network tools, a safety gate and baseline validation. SentinelAI itself is out of scope.

### Phase 0 re-verification (before any change)

| Check | Result | Matches Phase 0 |
|---|---|---|
| `uname -r` | 6.8.0-138-generic | ✅ |
| `lsb_release -a` / `/etc/os-release` | Ubuntu 22.04.5 LTS (jammy) | ✅ |
| `nproc` | 24 | ✅ |
| `free -h` | 15 Gi total, 9 Gi available, swap 2.0 Gi unused | ✅ |
| `df -h /` | 298G, 141G available | ✅ |
| `id` / `groups` | no `docker` group | ✅ (still blocked) |
| `docker --version` | 29.8.0, build 88096ef; `docker ps` → permission denied | ✅ |
| `ollama --version` | 0.35.0 | ✅ |
| `sudo -n true` | password required | ✅ |

---

## 1. Docker

| | |
|---|---|
| **Before** | Socket `/var/run/docker.sock` is `root:docker 0660`; `iiitd` is not in the `docker` group; every API call returns `permission denied`. |
| **Action** | The user ran `sudo usermod -aG docker iiitd`. |
| **After** | `getent group docker` → `docker:x:998:OS_2026,iiitd` |
| **Status** | ✅ **PASS**, with one caveat (below) |

**Evidence.** The current process predates the group change, so I verified access with `sg docker -c …`. That command applies the group from `/etc/group` and needs no password and no sudo.

```
uid=1000(iiitd) gid=998(docker) groups=998(docker),...
server=29.8.0 api=1.56 minapi=1.40
storage=overlayfs cgroupdriver=systemd cgroupver=2 root=/var/lib/docker
ncpu=24 mem=16439414784 containers=0 images=1 runtime=runc warnings=[]
docker run --rm hello-world → "Hello from Docker!"  (image 25.9 kB, container auto-removed)
```

| Property | Value |
|---|---|
| Docker Engine | 29.8.0 (client and server) |
| API version | 1.56 (min 1.40) |
| Storage driver | overlayfs (containerd snapshotter) |
| Cgroup driver / version | systemd / v2 |
| Docker root | `/var/lib/docker` (on `/`, 140 GiB free) |
| Resources visible | 24 CPUs, 15.3 GiB RAM, no resource limits configured |
| Daemon warnings | none |
| Compose / Buildx | v5.5.1 / v0.37.0 |

**Caveat.** The terminal output the user pasted after `usermod` still showed no `docker` group and `permission denied`. That output came from a session opened **before** `usermod`, which is expected behaviour. A **brand-new SSH login** still has to confirm `id` shows `998(docker)` and that plain `docker run --rm hello-world` works without `sg`. The VS Code / Claude Code server process also keeps the old group list until it restarts, which is why the test suite falls back to `sg docker`.

## 2. Python

| | |
|---|---|
| **Environment** | `~/sentinelai/.venv`, created with `python3 -m venv` (stdlib venv, after installing `python3.10-venv`). Python 3.10.12, pip 22.0.2 (venv-local). |
| **Isolation** | `pyvenv.cfg: include-system-site-packages = false`; `site.ENABLE_USER_SITE = False`; `sys.path` = stdlib + `.venv/lib/python3.10/site-packages` only, with no `~/.local` and no `dist-packages`. This holds both with and without `PYTHONNOUSERSITE=1`. Before any install, `import numpy` raised `ModuleNotFoundError`, which shows that the `~/.local` numpy is invisible. |
| **Dependencies** | Direct: `requirements.in` (8 packages). Resolved: `requirements.lock` (`pip freeze --local`, 25 pins). `pip check` → *No broken requirements found*. |
| **Reproducibility** | I recreated a fresh venv from the lock in a scratch directory: the `pip freeze` diff against the lock was identical and all imports worked, then I deleted it. |
| **PyTorch** | Not installed (intentional). The CUDA torch in `~/.local` is untouched and invisible to the venv. |
| **Status** | ✅ **PASS** |

| Package | Version | Loaded from |
|---|---|---|
| numpy | 2.2.6 | `.venv` |
| pandas | 2.3.3 | `.venv` |
| scipy | 1.15.3 | `.venv` |
| scikit-learn | 1.7.2 | `.venv` |
| psutil | 7.2.2 | `.venv` |
| pydantic | 2.13.5 (core 2.46.5) | `.venv` |
| httpx | 0.28.1 | `.venv` |
| prometheus-client | 0.26.0 | `.venv` |

The Phase 0 numpy/scipy conflict is gone **inside the venv**: scipy 1.15.3 matches numpy 2.2.6. The conflict still exists in system python3 + `~/.local`, which this phase deliberately left alone.

## 3. eBPF

| Item | Result |
|---|---|
| **Kernel** | 6.8.0-138-generic; BPF_SYSCALL, JIT (always on), BPF_EVENTS, KPROBES and UPROBES all enabled |
| **BTF** | `/sys/kernel/btf/vmlinux` 5.9 MiB; `sudo bpftool btf dump … format raw` → `[1] INT 'long unsigned int' size=8 …` ✅ |
| **bpftool** | v7.4.0 (libbpf 1.4). `sudo bpftool feature probe` → rc 0, 2,243 lines. JIT enabled, hardening disabled. Program types kprobe, tracepoint, perf_event, tracing and sched_cls available; ringbuf and user_ringbuf available. |
| **bpftrace** | v0.14.0 (Ubuntu jammy; links LLVM 11) |
| **BCC** | bpfcc-tools / python3-bpfcc 0.18.0. ⚠️ Installed, but the bundled `runqlat` **fails to compile** (see §9). |
| **libbpf-dev** | 0.5.0 (old; see §9) |
| **clang / llvm** | 14.0.0 |
| **Unprivileged BPF** | Disabled (`unprivileged_bpf_disabled=2`). Every attach below ran as root via `sudo bash scripts/privileged_smoke.sh`. |
| **Sysctls modified** | None |

### Event tests

Each test attached a bpftrace probe that counted events for 3 s and exited by itself under a hard `timeout 15`. All 7 tracepoints also exist in tracefs (`tracefs_presence.txt`).

| Event | Status | Error | Evidence (`results/phase1a/privileged/`) |
|---|---|---|---|
| `sched:sched_switch` | ✅ PASS | — | attached=yes, **2,650 events**, 3.66 s |
| `sched:sched_wakeup` | ✅ PASS | — | attached=yes, **1,874 events**, 3.64 s |
| `irq:softirq_entry` | ✅ PASS | — | attached=yes, **2,437 events**, 3.64 s |
| `irq:softirq_exit` | ✅ PASS | — | attached=yes, **2,037 events**, 3.66 s |
| `tcp:tcp_retransmit_skb` | ✅ PASS (attach) | — | attached=yes, **0 events**, 3.64 s. No retransmits occurred on an idle LAN. The probe attaches, but observing real retransmits remains **unproven** until a fault is injected in a netns (Phase 1B+). |
| `sock:inet_sock_set_state` | ✅ PASS | — | attached=yes, **10 events**, 3.66 s (triggered by one loopback `curl` to 127.0.0.1:11434) |
| `skb:kfree_skb` | ✅ PASS | — | attached=yes, **91 events**, 3.63 s |
| BCC `runqlat-bpfcc 1 1` | ❌ FAIL | `no member named 'state' in 'struct task_struct'` | `bcc_runqlat.txt` |
| BPF program leak check | ✅ PASS | — | loaded programs before=23, after=22. Nothing was left behind; the −1 is unrelated system churn. |

**Status:** ✅ **PASS WITH CONSTRAINTS.** bpftrace and tracepoints work for every required event class. The apt version of BCC is partly broken on this kernel, and a CO-RE C build with libbpf was **not** attempted in this phase.

## 4. Performance tools

| Tool | Version | Status |
|---|---|---|
| perf | 6.8.12 | ⚠️ Unprivileged: **blocked** (`perf_event_paranoid=4`; `perf stat … sleep 1` → "Access to performance monitoring … is limited", rc 255). As root: ✅ `context-switches 1, cpu-migrations 0, 1.001 s elapsed`. Paranoid was **not** changed. |
| pidstat / iostat / mpstat / sar | sysstat 12.5.2 | ✅ installed. The collector stays **disabled** (`ENABLED="false"`, `sysstat.service` disabled/inactive). |
| vmstat | procps | ✅ |
| stress-ng | 0.13.12 | ✅ functional (`--cpu 1 --timeout 1s` in the test suite) |
| iperf3 | 3.9 | ✅ functional (1 s loopback test bound to 127.0.0.1:5299) |
| cmake | 3.22.1 | ✅ |
| clang / llvm-config | 14.0.0 / 14.0.0 | ✅ |

## 5. Network tools

| Tool | Status | Evidence |
|---|---|---|
| `ip -br addr` / `ip link` | ✅ | lo, `enp0s31f6` UP 192.168.192.151/20, `docker0` DOWN 172.17.0.1/16 |
| `ss -s` | ✅ | 1,133 sockets; TCP 47 (estab 19) |
| `tc qdisc show` | ✅ | `enp0s31f6`: `fq_codel` root (distribution default); lo/docker0: `noqueue`. No netem anywhere. |
| ethtool | ✅ | 5.16 |

No qdisc, link, route or firewall rule was modified. `enp0s31f6` was only read. Raw output: `results/phase1a/network_tools.txt`.

## 6. Repository

| Item | Status |
|---|---|
| Location | `~/sentinelai` |
| Structure | `.venv/ docs/ scripts/ tests/ results/ logs/ configs/ requirements.in requirements.lock README.md .gitignore`. This is the minimum only; no application architecture. |
| Git | Initialised on `main`. Identity set **repo-local** (`user.name=iiitd`, `user.email` = the account email); global git config untouched. |
| Initial commit | `1198040` (33 files; `.venv/` and `logs/*` excluded by `.gitignore`) |
| Secrets | None. `.env` is git-ignored; no keys were created. |
| Status | ✅ **PASS** |

### Acceptance tests

`PYTHONNOUSERSITE=1 .venv/bin/python -m unittest discover -s tests -v` → **Ran 24 tests: OK (23 passed, 1 skipped)**. Output is in `results/phase1a/test_run_user.txt`.

| Group | Tests |
|---|---|
| Python (6) | Interpreter is the venv; user site is disabled; `sys.path` is clean; all imports resolve from `.venv`; freeze equals the lock; `pip check` passes |
| Docker (3) | User is in the docker group; `docker info` reports cgroup v2; `hello-world` runs (via the `sg docker` fallback in this stale-group process) |
| eBPF (5) | bpftool runs; BTF exists; bpftrace installed; recorded privileged smoke evidence validated. **Skipped:** live bpftrace attach (needs root; runs live with `sudo .venv/bin/python -m unittest …`). |
| System tools (7) | Versions of perf/ip/tc/ss/ethtool/stress-ng/iperf3/pidstat/clang/cmake; perf restriction behaves as documented; stress-ng functional; iperf3 loopback; physical NIC has no netem; safety gate passes; safety gate fails closed |
| Git (3) | Repo exists; initial commit contains the required files and no `.venv`; a clean commit can be created in a throwaway clone |

## 7. Safety

`scripts/safety_check.sh` is read-only and fails closed: exit 0 only when every check positively passes, exit 1 otherwise. It checks:
- the project root is `~/sentinelai` and is a git repo
- the kernel version is recorded
- `ssh.service` is active and `:22` is listening
- `SSH_CONNECTION` is set and the SSH client's route goes via `enp0s31f6` (or an explicit `SENTINEL_LOCAL_CONSOLE=1`)
- the NIC is UP
- the default route goes via the NIC
- the NIC's qdiscs are on a benign allow-list (`fq_codel|mq|fq|pfifo_fast|noqueue`)
- there are no ingress/egress tc filters on the NIC, and no netem on any interface
- at least 20 GiB disk is free and at least 4 GiB RAM is available
- all 13 required tools are present

Each run is logged to `logs/safety_check_<ts>_<pid>.log`.

| Case | Expected | Result |
|---|---|---|
| Baseline (real SSH session) | SAFE | ✅ exit 0, 0 failures |
| `SENTINEL_PHYS_NIC=eth9` (unknown NIC) | REFUSE | ✅ exit 1, 6 failures |
| No `SSH_CONNECTION` | REFUSE | ✅ exit 1 (`ssh_session`) |
| `SENTINEL_MIN_MEM_GB=64` | REFUSE | ✅ exit 1 (`memory`) |
| `SENTINEL_MIN_DISK_GB=999` | REFUSE | ✅ exit 1 (`disk`) |
| `SENTINEL_ROOT=/tmp` | REFUSE | ✅ exit 1 (`project_root`) |

Two defects that I found in my own first version during this testing and **fixed** are listed in §9.

`scripts/privileged_smoke.sh` refuses to run without root. It wraps every command in `timeout`, writes only to `results/phase1a/privileged/`, never modifies sysctls/qdiscs/links/services, and verifies that no BPF programs remain loaded afterwards.

## 8. Resource baseline

Measured at 13:48 IST, idle apart from the desktop session.

| Metric | Value |
|---|---|
| RAM total / used / available | 15.3 GiB / 4.8 GiB / **9.6 GiB** |
| Swap | 2.0 GiB, 0 used |
| Load average | 0.17 / 0.25 / 0.38 |
| Disk free `/` | **140 GiB** (51 % used) |
| Top memory consumers | Chrome (≈ 10 processes, ≈ 3.1 GiB RSS combined), snap-store 545 MiB, Electron/VS Code `MainThread` processes ≈ 1.2 GiB, gnome-shell 310 MiB, claude 2 × (200–290 MiB), fwupd 170 MiB |
| CPU topology | **P-cores = CPUs 0–15** (8 cores × 2 HT, max 5.1–5.2 GHz). **E-cores = CPUs 16–23** (2 clusters of 4 sharing L2 #8 and #9, max 4.1 GHz). Source: `/sys/devices/cpu_core/cpus` and `cpu_atom/cpus`, consistent with `lscpu -e`. |

Phase 1A footprint: venv 357 MiB, apt packages ≈ 1 GiB (disk free 141 → 140 GiB), Docker image 26 kB. No resident services were added, so idle RAM use is unchanged.

Raw output: `results/phase1a/resource_baseline.txt`, `cpu_topology.txt`.

## 9. Problems encountered

| # | Problem | Diagnosis | Status / proposed resolution |
|---|---|---|---|
| P1 | The user's post-`usermod` terminal still showed `permission denied` | Supplementary groups are fixed at login; that shell predates `usermod`. `/etc/group` is correct. | Verified through `sg docker`. **Open:** confirm in a brand-new SSH login. |
| P2 | **BCC 0.18 `runqlat-bpfcc` fails to compile** on kernel 6.8: `no member named 'state' in 'struct task_struct'` | Since kernel 5.14, `task_struct.state` is named `__state`; jammy's BCC 0.18 predates that. Other BCC tools that touch renamed fields will fail the same way. | **Open.** Do not depend on apt BCC tools. Use bpftrace (works) and libbpf CO-RE. If BCC is needed, build a current BCC release later (a decision for a future phase). |
| P3 | bpftrace is v0.14.0 (2021) and pulls in a second LLVM (11) | It is the only jammy package. Tracepoints work, but newer language features and fixes are missing. | Accepted for smoke tests. Production collectors will be libbpf CO-RE; re-evaluate upgrading bpftrace if it blocks something. |
| P4 | `libbpf-dev` is 0.5.0 (2021) | Old; lacks libbpf ≥ 1.0 APIs used by modern CO-RE skeletons. bpftool 7.4 bundles libbpf 1.4 internally, but no 1.x headers or library are installed. | **Open.** No CO-RE C program was built in Phase 1A. Before writing collectors, vendor libbpf ≥ 1.x as a git submodule and build one minimal CO-RE program. |
| P5 | Unprivileged perf is blocked (`perf_event_paranoid=4`) | Ubuntu's restrictive default. | Accepted. perf works as root. Paranoid was not changed; any change needs explicit approval. |
| P6 | `tcp_retransmit_skb` observed 0 events | No retransmits on an idle LAN. | Attach proven; observation not yet proven. Validate with netem loss inside a netns later. |
| P7 | Safety script v1 defect: logs from runs in the same second collided | Log name used second resolution | **Fixed:** PID added to the log name. |
| P8 | Safety script v1 defect: `nic_filter_*` printed PASS on a nonexistent NIC (fail-open sub-check) | `tc filter show` on a missing device produced empty output, which was treated as "no filters" | **Fixed:** checks `rc` and fails if it cannot read. Re-verified (6 failures for an unknown NIC). The overall verdict had already been REFUSE in that case. |
| P9 | Initial `sg docker` quoting bug in the test helper | `" ".join` broke `--format "{{…}} {{…}}"` | **Fixed** with `shlex.join` before the suite ran. |
| P10 | Observations not caused by Phase 1A | (a) `apt install -y nodejs npm` was run by `iiitd` at 13:25, before this phase. (b) unattended-upgrades is active (it upgraded gstreamer and libxpm at 06:12 today). (c) The `docker` group already contained user `OS_2026`. (d) `iiitd` is also in group `ollama`. | Recorded only. (b) is a reproducibility risk: system packages can change underneath experiments. Record `dpkg -l` per experiment; consider pinning later (needs approval). |

## 10. Changes made

**System-level changes (all run by the user with sudo):**
1. `apt-get install --no-install-recommends -y python3.10-venv cmake clang llvm libbpf-dev libelf-dev zlib1g-dev sysstat ethtool stress-ng iperf3 bpfcc-tools python3-bpfcc bpftrace` → **40 packages newly installed, 0 upgraded, 0 removed** (apt history, `results/phase1a/apt_installed_packages.txt`). `libelf-dev` and `zlib1g-dev` were already installed.
2. `usermod -aG docker iiitd`.
3. `scripts/privileged_smoke.sh`: transient probes only, auto-detached, no persistent state.

**Docker state:** pulled `hello-world:latest` (25.9 kB). Containers were run with `--rm`, so none remain.

**User-space changes (as `iiitd`):**
- Created `~/sentinelai/` (venv, scripts, tests, docs, evidence) and a git repo with a repo-local identity.
- Copied the Phase 0 report into `docs/`; the original in `~/Documents/MT25037(Don't Delete)/` is unchanged.
- pip downloads reused or added to `~/.cache/pip`.

**Not changed:** sysctls (BPF, perf, inotify), kernel, boot, SSH, firewall, NIC/qdiscs/routes, CPU governor/affinity, `~/.local`, the CUDA PyTorch install, `~/.cache/pip` contents, Ollama models, running applications.

## 11. Objective evaluation

**Did Phase 1A achieve its objective?** → **PASS WITH CONSTRAINTS**

- **Achieved:**
  - Docker access works for `iiitd` (overlayfs, systemd cgroup driver, cgroup v2, hello-world).
  - The Python environment is isolated, pinned, and proven reproducible by a rebuild from the lock.
  - The toolchain is installed with versions recorded.
  - All 7 required kernel event classes attach under bpftrace with real event counts. `tcp_retransmit_skb` attaches but saw 0 events.
  - The safety gate exists and is proven to fail closed in 5 negative cases.
  - The repository and initial commit exist.
  - 23/23 runnable acceptance tests pass.
- **Constraints:**
  - The apt BCC is partly broken on kernel 6.8 (P2).
  - The libbpf headers are too old for modern CO-RE, and no CO-RE build was attempted (P4).
  - eBPF and perf require root on every use (P5).
  - Docker access still needs confirming in a fresh login (P1).

None of these blocks the next phase, but P2 and P4 constrain how eBPF collectors will be built.

---

## PHASE 1A GATE

### **GO WITH CONDITIONS**

Unresolved issues, which must be closed or explicitly accepted before or at the start of Phase 1B:

1. **Fresh-login Docker confirmation (P1).** In a new SSH session, `id` must list `998(docker)` and `docker run --rm hello-world` must succeed without `sg`/sudo.
2. **BCC decision (P2).** Accept "bpftrace + libbpf CO-RE only, no apt BCC tools", or schedule a source build of a current BCC.
3. **CO-RE toolchain proof (P4).** Before any collector work, vendor libbpf ≥ 1.x and compile and load one minimal CO-RE tracepoint program.
4. **Root model for eBPF/perf (P5).** Every eBPF run currently needs an interactive sudo. A future phase must choose between a dedicated privileged collector (recommended) and per-binary capabilities (`cap_bpf,cap_perfmon`). This needs explicit approval and no blanket NOPASSWD.
5. **Reproducibility of system packages (P10b).** Decide whether to accept unattended-upgrades, with a `dpkg -l` snapshot per experiment, or to hold the toolchain packages.

Phase 1B has **not** been started.
