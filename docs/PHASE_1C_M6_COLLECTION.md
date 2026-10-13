# Phase 1C M6 collection

Status: **collecting.** The matrix is committed (`9918b83`, the code pin). Batch 1 of 6 collected and packed.

This document records how the M6 matrix is collected and what each batch produced. It is a runbook and a ledger; it
validates nothing. M2 is never run on M6 data before M7 locks the parameters and the model (design §6.6).

## 1. Basis

- **Plan:** `FZ-M6-PLAN` (owner reply "all A", 2026-10-13; register §5 P-1 … P-8), the frozen levels in
  `FZ-INTENSITY` (R-8), `FZ-OV`, `FZ-Q5`, `FZ-TTRANS` (T_TRANS 16 s, W 24 s), `FZ-Q2` (driver-root collection in A's
  network namespace, P-7).
- **Code:** `experiments/faultlab/matrix.py` (generator), `experiments/faultlab/m6.py` (runner and dataset writer),
  `experiments/faultlab/pilot.py` (variant `m6`), admitted by AMD-29.

## 2. Matrix

`datasets/faultlab/v1/matrix.json`, SHA-256 `5e4df932cd79c17754e7539cf5c7f45faf89a33b3714f6bff5512dabe785b560`,
master seed 20261013. It regenerates byte-identically from the approved record
(`python experiments/faultlab/matrix.py check datasets/faultlab/v1/matrix.json`). The file is add-only (AMD-29).

| Set | Runs |
|---|---|
| single-fault train: 6 classes × {I1, I3} × 4 seeds | 48 |
| single-fault test: 6 classes × 12 (I1 4 / I2 4 / I3 4; 10 required, 2 provisioned, Q-5) | 72 |
| overlap and distractor OV-1 … OV-10, 2 train / 2 test each | 40 |
| CTRL, 10 train / 14 test | 24 |
| SENS at I0 = half the strength of I1, 2 per class (not gated) | 12 |
| PI-3 quota runs at I1/I2/I3 × 2, first in batch 1 (U-4; never scored) | 6 |
| **Total** | **202** |

- Packet loss uses netem on A only (P-8); application seeds rotate over dependency delay, lock hold and pool shrink;
  retransmission seeds over path loss and congestion (P-1).
- Memory (768 MiB) and pool (P′ = 1) run at their single level (P-2, R-3, R-6).
- OOD is deferred (P-4).
- Engineering values recorded in the matrix file: 5 distractor lines/s (OV-6, OV-10), a 40 Mbit/s iperf3 TCP flow
  A → B (OV-1), stress loops pinned to CPUs 19 and 20 (OV-3).
- Seeds 100001 … 100202 (disjoint from the pilot's 900000 … and the smoke seeds 800001 …). Run order is shuffled by
  the master seed; batches 1–5 hold 34 runs, batch 6 holds 32.

## 3. Smoke (before the pin)

One run per family through the M6 runner, with smoke seeds that are never packed into the dataset.

| Campaign | Commit | Runs | Result |
|---|---|---|---|
| `20261013T081416Z` | `6fabebf` | PI0-1…5; CTRL, SENS, OV-1, OV-2, OV-3 | PI-0 5/5; CTRL, SENS, OV-1 passed. **OV-2 failed** the host comparison only: a login session scope ended during the run (external; the owner keeps sessions stable during batches). **OV-3 failed** injection verification: the stress read-back looked for `taskset`, which execs the busy loop; fixed in `458cf2c`. |
| `20261013T092340Z` | `458cf2c` | PI0-1…5; OV-2, OV-3, OV-6, OV-7, OV-8, OV-9, OV-10 | All passed their pipeline checks. OV-3: quota and both stress loops read back (on CPUs 19, 20). OV-7: both faults issued in order and read back. OV-8: no eBPF, no interfaces. OV-9: app metrics off, so PI-6 and PI-7 miss on the app features by design. OV-6, OV-10: the distractor rate echoed. |

Smoke directories stay in the git-ignored staging (`results/phase1c_m6/`).

## 4. Collection procedure (per batch)

1. The owner pushes, then runs the batch command: 5 PI-0 cycles in a new campaign, then the batch's runs in matrix
   order. The chain stops at the first PI-0 failure or the first run that fails its pipeline checks.
2. Every run passes a full-stage privileged preflight; it needs the committed matrix to regenerate byte-identically and
   no change since this commit other than `datasets/faultlab/v1/raw/…`, the manifest and `docs/PHASE_1C_M6_*.md`
   (`m6.py` refuses otherwise). Nothing else is committed until M6 ends.
3. After the batch: `python experiments/faultlab/m6.py pack --campaign <C>` writes each finished run (and each PI-0
   cycle) to `datasets/faultlab/v1/raw/<run id>/*.jsonl.gz` with an append-only manifest; the pack and this ledger are
   committed together.
4. Stopped batches resume in a new campaign with the runs not yet run; a run directory and a seed are never reused.

**Failure rules (FZ-M6-PLAN):** a failed injection is excluded and counted, never retried (AMD-10); any other failed
run is kept as failed and its seed is not reused; the provisioned test seeds absorb exclusions. Sessions on the host
stay stable while a batch runs (a login session appearing or ending fails the host comparison).

## 5. Ledger

| Batch | Campaign | Commit | Runs | Passed | Failed (kept) | Packed in |
|---|---|---|---|---|---|---|
| 1 | `20261013T094920Z` | `9918b83` | 34 (+ PI0-1…5) | 34 pipeline; 32 every PI | 0 | this commit |
| 2 | — | — | 34 | — | — | — |
| 3 | — | — | 34 | — | — | — |
| 4 | — | — | 34 | — | — | — |
| 5 | — | — | 34 | — | — | — |
| 6 | — | — | 32 | — | — | — |

## 6. Notes per batch

**Batch 1.** PI-0 5/5; all 34 runs passed their pipeline checks; nothing excluded. Two training runs at the strongest
quota (I3, 0.075 core: M6-s100026, M6-s100032) missed PI-6 coverage on `psi.cpu.some.target` (0.989 and 0.978). The
target is CPU-stalled almost all of the time there, and in 1–2 of the 90 W ticks the PSI `some` delta came out a hair
longer than the tick (fractions 1.000048, 1.000133, 1.000021), which the frozen normaliser rejects as a fraction above 1.
Same class as M-4 (`mem.util.target`); report-only, the raw ticks are kept, and it is listed for M7. Packed: 34 runs and
5 PI-0 cycles, 44 MB; every packed run unpacks with every SHA-256 intact and its snapshot replays byte-identically.
