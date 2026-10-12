# Phase 1C M5 pilot report

Status: **in progress.** PI-0 and the CTRL runs are complete. The PI-1 unprivileged, PI-6 collectors-off and workload
instrumentation on/off runs are being built (Step 2). No fault class has been run.

What this report shows: the A–R–B lab, the collection pipeline and the CTRL-stage pilot criteria work on this host. It
does **not** validate any fault class, and it does not support any diagnostic claim. M2 was never run on pilot data
(pilot design §7).

## 1. Campaigns

Evidence lives in `results/phase1c_m5_pilot/<campaign>/<run>/` and is committed under AMD-27 (§5). The runner
(`experiments/faultlab/pilot.py`) allows CTRL only after 5/5 PI-0 cycles at the same commit in the same campaign
(`require_pi0`).

| Campaign (UTC) | Commit | Runs | Outcome |
|---|---|---|---|
| `20261011T175343Z` | `cab7b59` | PI0-1 | **FAILED.** Lab checks failed `a_ip_forward`, `b_ip_forward`. The host comparison failed `mounts_identical` (the first `ip netns add` mounted `/run/netns`, and that mount stayed). Fixed in `6c0030d` and `7f6eac7`. |
| `20261012T030504Z` | `7f6eac7` | PI0-1…5, CTRL-900001 | PI-0 5/5 passed. CTRL-900001 **FAILED** (`app_features`, §3). |
| `20261012T040045Z` | `af2a4e7` | PI0-1…5, CTRL-900002…900005 | PI-0 5/5 passed. CTRL 4/4 passed. |

Every privileged invocation ran its own privileged preflight (`preflight.json` in each run directory). Each preflight
was READY and recorded the run's commit.

## 2. PI-0: lab lifecycle (design §6.1)

Criterion: 5/5 cycles with all lab checks passing, cleanup verified, and the host comparison `ok: true`, BPF compared.

| Campaign | Cycles | Lab checks (incl. ip_forward A 0, R 1, B 0) | Ping A↔B, TCP echo A→B | Cleanup | Host comparison | Owned `/run/netns` mount removed |
|---|---|---|---|---|---|---|
| `20261012T030504Z` | 5/5 | pass | pass | verified | ok | yes |
| `20261012T040045Z` | 5/5 | pass | pass | verified | ok | yes |

Lab setup plus teardown (op-log span): 1.3–1.4 s per cycle.

## 3. CTRL (design §6.2 timeline; FZ-WORKLOAD)

Setup:

- Workload `lock_hold_us 0`, 100 req/s, jitter 0.5, pool 4, queue 32, `cpu_us 2000`, dependency delay 2 ms.
- Timeline: warm-up 15 s, B 45 s, W 90 s, cool-down 20 s.
- Collection: M3A + M3B + app at 1 Hz, run by the root driver.

| Run | Commit | Pipeline (9 checks) | Requests (200 / scheduled) | PI-1 min coverage | PI-6 collector CPU (budget 0.02 core) | PI-7 valid app ticks | Client latency p50 / p99 |
|---|---|---|---|---|---|---|---|
| CTRL-900001 | `7f6eac7` | **FAILED** (`app_features`) | 17000 / 17000 | 1.0 | 0.0020 | 136/136 | 4.41 / 4.59 ms |
| CTRL-900002 | `af2a4e7` | pass | 17000 / 17000 | 1.0 | 0.0020 | 136/136 | 4.43 / 4.62 ms |
| CTRL-900003 | `af2a4e7` | pass | 17000 / 17000 | 1.0 | 0.0019 | 136/136 | 4.42 / 4.62 ms |
| CTRL-900004 | `af2a4e7` | pass | 17000 / 17000 | 1.0 | 0.0020 | 136/136 | 4.38 / 4.61 ms |
| CTRL-900005 | `af2a4e7` | pass | 17000 / 17000 | 1.0 | 0.0019 | 136/136 | 4.38 / 4.58 ms |

The nine pipeline checks: run completed, cleanup, host comparison, BPF released, manifest, byte-identical replay,
app features, client/server reconciliation and across-R reconciliation. In every passing run the server's
completed/rejected/failed deltas equal the client outcomes exactly, and R dropped nothing.

**CTRL-900001 stays a failed evaluation.** Its only failing check was `app_features`: `app.lock_wait_ms` P99 was
MISSING.

- The cause is a mismatch between the evaluator and the approved workload, not between the workload and the evidence.
  FZ-WORKLOAD sets `lock_hold_us 0` ("no lock contention in CTRL"), and the workload records lock waits only while it
  holds the lock.
- `af2a4e7` exempts this single measurement, and only when the run's manifest-verified evidence proves
  `lock_hold_us == 0`. The proof covers `run.json`, the workload's config echo and its hash, both bracketing metrics
  documents, and zero lock-wait observations.
- Every other app feature, quality and scope check is unchanged.
- An offline re-evaluation of CTRL-900001 under `af2a4e7` passes. It does not count: the run was evaluated at
  `7f6eac7`, and its `report.json` is unchanged and pinned (§5).

The exemption is recorded in every report under `checks.app_features.structurally_unavailable`.

## 4. PI verdicts so far

| PI | Status | Basis |
|---|---|---|
| PI-0 | **pass** (5/5 at `af2a4e7`) | §2 |
| PI-1 | driver-root mode: coverage 1.0 in every CTRL run. **Unprivileged mode not yet run.** | Design: 2 runs per mode |
| PI-6 | CTRL part: collector CPU ≈ 0.002 core, coverage ≥ 0.99 in every run. **Collectors-off pairs not yet run.** | Design §6.7 |
| PI-7 | CTRL part: 136/136 valid app ticks, `app.latency_ms` P99 measured, in every run. The fault part needs FZ-INTENSITY and FZ-PI7 (§6). | FZ-PI7 `ctrl` |
| PI-2, PI-3, PI-5, PI-8, OV-4 | not run | §6 |

## 5. Evidence and integrity (AMD-27)

- **Committed:** every file under `results/phase1c_m5_pilot/<campaign>/<run>/`, for PI-0 cycles and CTRL runs,
  passing and failed: 175 files, about 45 MB.
- **Excluded:** `<run>/lg/client.jsonl` (transport copy) and `<run>/collector/` (the unprivileged collector's
  output, copied into `evidence/`). These are ignored by `.gitignore`. Each `lg/client.jsonl` was verified
  byte-identical to the manifest-covered `evidence/client.jsonl` before it was excluded.
- `tests/faultlab/test_integrity.py` enforces the following on the committed tree:
  - allowed names only: `<UTC campaign>/<PI0-k | CTRL|PI1U|PI6OFF|INSTOFF-9xxxxx>/[evidence/|logs/]<name>.(json|jsonl|stderr)`;
  - regular files only;
  - append-only history (no edit, delete or retype after commit);
  - every run manifest lists exactly the run's committed `evidence/` files, with matching SHA-256.
- Pinned by SHA-256, so they can never be relabelled: `20261011T175343Z/PI0-1/run.json` (ok false) and
  `20261012T030504Z/CTRL-900001/report.json` (`pipeline_ok` false).
- Committed snapshots are classified `PILOT_RUN` in `tests/runtime/test_corpus.py`. Their parameter set must stay
  unregistered, so M2 cannot evaluate them, and their manifest must verify.
- `tests/runtime/test_raw_replay.py` rebuilds each committed pilot snapshot byte-identically from its committed
  `ticks.jsonl` with `pilot.replay`.

Re-check from a clean checkout:

    .venv/bin/python experiments/faultlab/pilot.py evaluate results/phase1c_m5_pilot/<campaign>/CTRL-<seed>

## 6. Blockers (owner decisions)

- **FZ-INTENSITY (pending).** Ceilings for application (P′, lock hold, dependency delay), congestion, police, memory,
  OV-4 and OV-5 have no evidence, so those classes cannot run.
- **FZ-PI5 (pending).** The workload has no memory working set, so PI-5 cannot run.
- **AMD-13 / AMD-15.** Approved as unresolved, so OV-4 and OV-5 cannot run.
- **FZ-PI7, lock-hold comparison undefined.** The fault criterion requires "the injected mechanism's wait metric (W
  value) above the maximum of the same metric over the CTRL runs". For a lock-hold fault that metric is
  `app.lock_wait_ms`, which is structurally MISSING in every CTRL run (`lock_hold_us 0`), so no CTRL maximum exists.
  Until the owner resolves this explicitly, no lock-hold fault result can be evaluated or claimed.
