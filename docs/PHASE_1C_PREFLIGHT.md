# Phase 1C FaultLab Pilot Preflight (Gate 1.2)

**Read-only and fail-closed.** The preflight reports whether the prerequisites of the future privileged pilot are
met. It never authorises a run. `READY` means every mandatory check is `PASS` and every required Freeze-1 decision
is formally approved. The privileged pilot still needs a separate owner authorisation (Gate 2).

Implementation: [`experiments/faultlab/preflight.py`](../experiments/faultlab/preflight.py). Tests:
[`tests/faultlab/test_preflight.py`](../tests/faultlab/test_preflight.py). Decision source:
[`PHASE_1C_FREEZE1_DECISION_REGISTER.md`](PHASE_1C_FREEZE1_DECISION_REGISTER.md) (PROPOSED / PENDING OWNER APPROVAL).

## 1. Invocation

```
.venv/bin/python experiments/faultlab/preflight.py [--decisions PATH] [--summary]
```

- The report (JSON, format `sentinelai.faultlab.preflight.v1`) goes to stdout. `--summary` adds one line per check
  on stderr. The preflight writes no file.
- Exit status: 0 `READY`, 1 `NOT_READY`, 2 usage error.
- `--decisions` names a committed Freeze-1 decisions record (§5). Without it, every decision is `BLOCKED`.
- Run it as the invoking user. Run unprivileged, it is `NOT_READY` by construction: `ENV-PRIVILEGE` and
  `LAB-NO-SENTINEL-BPF` cannot be established without root, and the preflight never invokes `sudo`.

## 2. Status model

| Status | Meaning |
|---|---|
| `PASS` | Verified, and meets an approved requirement |
| `FAIL` | Verified, and violates it |
| `UNVERIFIED` | Cannot be established by a permitted read-only check |
| `BLOCKED` | A required approval, frozen value or prerequisite is missing |

Overall `READY` only if every mandatory check is `PASS`. Otherwise `NOT_READY`.

**Fail-closed rules:**
- A check whose requirement depends on an unapproved decision is `BLOCKED` whatever the host shows. Its
  `evaluation` field records the result against the proposed requirement, and `blocked_by` names the decisions.
- An exception inside a check gives `UNVERIFIED`. An operation outside the read-only allowlist is refused before
  execution and gives `FAIL`.
- A missing, duplicated, mis-flagged or invalid-status mandatory check adds `PF-COMPLETENESS` = `FAIL`.
- `report.blockers` separates three kinds: `owner_approval` (decisions and checks blocked by them), `environment`
  (host `FAIL`/`UNVERIFIED`, including blocked checks whose evaluation failed) and `technical` (integrity and
  provenance).

**Every check records:** `id`, `title`, `category`, `mandatory`, `status`, `observed`, `required`, `provenance`,
`explanation`, `next_action` (non-`PASS` only), `depends_on`, `blocked_by` and `evaluation`.

## 3. Checks

**Approvals (all mandatory, `BLOCKED` unless approved in the record).** `PROV-DECISIONS-RECORD` plus one
`APPR-<id>` per decision:

| Decision | Register item | Frozen value required |
|---|---|---|
| `FZ-WORKLOAD` | 1 | keys `rate_per_s, jitter, pool, pool_shrink, queue, cpu_us, lock_hold_us, dependency_delay_ms, poll_s, timeout_s, connection_model, publish_s` (numbers; `connection_model` text) |
| `FZ-INTENSITY` | 2 | any value |
| `FZ-PI5`, `FZ-PI7`, `FZ-PI8` | 3, 3b | any value |
| `FZ-TTRANS` | 4 | keys `T_TRANS_rule, T_cap, T_fb` |
| `FZ-DATA-QUALITY` | 5 | keys `U-2, COV_MIN, N_BASE_MIN, SEG_MIN` |
| `FZ-CB-B` | 6 | keys `c_B, b` |
| `FZ-STAGING` | 7 | key `path` (absolute) |
| `FZ-AMD-01` … `FZ-AMD-17` | 8 | approval of the design text |
| `FZ-MANIFEST`, `FZ-ROOT-OF-TRUST`, `FZ-EXCLUSIONS`, `FZ-R2CD-ENV` | 9–12 | approval only |
| `FZ-LAB-SPEC` | draft §5.1 | approval only |
| `FZ-SAFETY-CHECKLIST` | draft §9 | approval only |
| `FZ-M4-BASELINE` | draft §9 | key `commit` (40-hex) |

The preflight interprets none of these values: no unit, range or threshold is assumed. Decisions that no host check
consumes are still mandatory, because the registered pilot procedure cannot run without them. Each check's
`explanation` says so.

**Environment (mandatory):**
- `ENV-KERNEL`, `ENV-KERNEL-TOOLING` (release matches the committed bpftool path), `ENV-BTF`, `ENV-CGROUP2`;
- `TOOL-*`: unshare, setpriv, timeout, taskset, python3, bpftool, sentinel_loader, ip, tc, findmnt, git, systemctl;
- `ENV-PRIVILEGE`.

**Lab prerequisites (mandatory, inspection only):**
- `LAB-NETNS-SUPPORT`, `LAB-VETH-AVAILABLE`, `LAB-NETEM-AVAILABLE`;
- `LAB-ROOT-SUBTREE` (R2-F required-subset rule; depends on `FZ-R2CD-ENV`), `LAB-ROOT-CPUSET`;
- `LAB-CPUS-ONLINE`, `LAB-CPU18-NO-SMT`, `LAB-NIC-IRQ`, `LAB-IP-FORWARD` (all depend on `FZ-LAB-SPEC`);
- `LAB-PROTECTED-IFACES`, `LAB-DEFAULT-ROUTE`, `LAB-NO-NETEM`;
- no leftover state: `LAB-NO-SENTINEL-NETNS`, `LAB-NO-LAB-INTERFACES`, `LAB-NO-SENTINEL-CGROUP`, `LAB-NO-LAB-PROCESS`,
  `LAB-RUN-DIR-ABSENT`, `LAB-NO-SENTINEL-BPF`;
- `LAB-LAB-UID`, `LAB-OPENVPN-DISABLED`.

**Resources (mandatory):**
- `RES-MEM-AVAILABLE` ≥ 4 GiB (`scripts/safety_check.sh:17`, R2-F). Design §9's 2 GiB is the stale value (register §2
  item 1); the stricter committed floor is used.
- `RES-DISK-REPO` ≥ 20 GiB (`scripts/safety_check.sh:16`).

**Staging (mandatory; depends on `FZ-STAGING`; never created or changed):** `STG-EXISTS` (no symlink component,
directory), `STG-PERSISTENT` (not tmpfs/ramfs/devtmpfs), `STG-PERMISSIONS` (owned by the invoking uid or uid 1000, not
world-writable), `STG-FREE-SPACE` (≥ 20 GiB, draft §9; also depends on `FZ-SAFETY-CHECKLIST`).

**Integrity (mandatory):** `INT-REPO-CLEAN`, `INT-INTEGRITY-POLICY` (the live AMD-18 policy), `INT-M4-BASELINE`
(depends on `FZ-M4-BASELINE`).

**Recorded only (not mandatory):** `ENV-OS-RELEASE`, `ENV-TOOL-VERSIONS`, `LAB-ROOT-SUBTREE-R2C` (shows why the two
accepted R2-C/R2-D failures occur), `INT-HEAD`. No approved requirement exists for these.

## 4. What the preflight cannot verify read-only

| Item | Why | Where it must be established |
|---|---|---|
| Privileges for netns/veth, lab cgroup, `tc`, loader | needs `sudo`; never invoked | Gate 2, re-run with the approved privileges |
| BPF programs, links, maps | `bpftool` needs root | Gate 2 |
| `scripts/safety_check.sh` (incl. SSH recovery path) | writes `logs/` (not read-only) | immediately before the authorised run |
| Lab connectivity (A↔R↔B) | needs the lab, i.e. mutation | the authorised run's per-run lab checks (draft §5.1) |
| Authenticity of approvals | the record is trusted only as a committed, unmodified Git file | decision `FZ-ROOT-OF-TRUST` |

## 5. Decisions record (format PROPOSED by this preflight, not approved)

```json
{"format": "sentinelai.faultlab.freeze1-decisions.v0",
 "decisions": {"FZ-PI7": {"status": "approved", "approved_by": "Rohit Kumar", "date": "YYYY-MM-DD",
                          "reference": "<where the approval is recorded>", "value": "<frozen value>"}}}
```

- Parsing is strict. Duplicate keys, NaN, unknown decision ids, unknown entry keys, a wrong format string or an
  approved entry without approver, date or reference make the whole record `FAIL`. Every decision is then treated as
  unapproved.
- Status must be one of `approved`, `proposed`, `pending` or `rejected`; only `approved` with a complete value counts.
- The record must be a regular file in this repository, tracked by Git and identical to HEAD.
- No record exists yet. Committing one needs an owner decision and an exact-path integrity amendment.

## 6. Host-state invariants of the future run

`report.invariants` lists four categories:
1. **Observed by the preflight now:** root cgroup files, cgroup directories, named netns, interfaces, addresses,
   routes, qdiscs, the R2 sysctl set, IRQ affinities, mounts, `/run/sentinelai-lab` absence, memory and disk.
2. **Captured immediately before an authorised run:** the full R2-C `host_snapshot` with BPF (root),
   `safety_check.sh`, a re-run of every `LAB-*` check, and the `oom_kill` baseline.
3. **Checked after the run:** `compare_host(..., require_bpf=True)` with its full `must` list, cleanup verification
   (draft §5.9), an `oom_kill` delta of 0, and the R2-C abort criteria.
4. **Not guaranteed unchanged:**
   - kernel module state: `veth` and `sch_netem` load on first use and stay loaded, and `compare_host` does not
     capture them;
   - dynamic counters;
   - page cache and slab;
   - kernel log and journal;
   - BPF JIT memory;
   - CPU frequency and thermal state.

`report.host_state.observed_now` is current state only. A read-only preflight implies nothing about the state during
or after the future run.
