#!/usr/bin/env bash
# SentinelAI R2-D — controlled CPU-throttling validation (RUNTIME; requires explicit R2-D runtime authorisation).
#
# Run:   sudo bash scripts/r2d_validate.sh
#
# Refuses unless: root via sudo from uid 1000; HEAD is 7354f40 (or adds only R2-C/R2-D tooling) with a clean tracked
# tree; the read-only preflight passes. Then: host baseline snapshot -> calibration = runtime step 0 (R2-C target alone
# on CPU 18, no quota, no contender; provenance only) -> for each run of r2d_cpu.MATRIX: the driver (taskset -c 0-15)
# creates sentinel-r2c, applies the approved quota schedule to sentinel-r2c/target/cpu.max ONLY (Q_B before tick 0,
# Q_W in the window callback, MAX after the last W tick), runs target / contender / collection / ground truth / M2,
# restores and removes everything; the host is compared with the baseline after every run. Stops at the first failure.
# Cleanup is registered before anything is created: trap on EXIT, INT and TERM runs the op-log cleanup, which restores
# 'max 100000' (read-back verified) before killing and removing the lab cgroup.
# Never: any other cpu.max, sysctls, affinity of non-lab processes, IRQ affinity, enp0s31f6, docker0, netem/qdiscs,
# stress tools, memory limits.
# Evidence: results/phase1c_r2d/<UTC timestamp>/ (owned by the invoking user).
set -euo pipefail

if [[ $EUID -ne 0 || -z "${SUDO_USER:-}" || "${SUDO_UID:-}" != "1000" ]]; then
  echo "REFUSING: run as: sudo bash $0 (from uid 1000)" >&2; exit 2
fi
REPO=$(cd "$(dirname "$0")/.." && pwd)
BASE=7354f40
PY=$REPO/.venv/bin/python
R2D=$REPO/scripts/r2d_cpu.py
DRIVER=$REPO/scripts/r2d_driver.py
LOADER=$REPO/ebpf/build/sentinel_loader
MATRIX=(E0-open Q0-1 Q0-2 C1-1 C1-2 T1-1 T1-2 T1-3 T2-1 T2-2 T2-3 TC-1 TC-2 TC-3 E0-close)
export PYTHONNOUSERSITE=1

HEAD=$(sudo -u "$SUDO_USER" python3 "$R2D" candidate "$REPO" "$BASE") || { echo "REFUSING: $HEAD" >&2; exit 3; }
[[ -x "$PY" && -x "$LOADER" ]] || { echo "REFUSING: venv/loader missing" >&2; exit 3; }
"$LOADER" --version | grep -q '"libbpf_linked":"1.4"' || { echo "REFUSING: loader not linked to libbpf 1.4" >&2; exit 3; }
"$PY" "$R2D" preflight > /dev/null || { echo "REFUSING: preflight failed" >&2; "$PY" "$R2D" preflight >&2; exit 4; }

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$REPO/results/phase1c_r2d/$TS
mkdir -p "$OUT"
OPS=$OUT/ops.log
FINISHED=0
STATUS=0

finish() {   # idempotent: quota restored first, then every run's op log is cleaned; results chowned
  if (( FINISHED )); then return; fi
  FINISHED=1
  "$PY" "$R2D" cleanup "$OUT" > "$OUT/final_cleanup.json" 2>&1 || STATUS=1
  chown -R "$SUDO_USER": "$REPO/results/phase1c_r2d"
}
trap finish EXIT
trap 'finish; exit 130' INT TERM

{
  echo "commit=$HEAD"; echo "base=$BASE"; uname -a; echo "user=$SUDO_USER"; date -u
  "$LOADER" --version
  "$PY" "$R2D" criteria
  printf 'matrix: %s\n' "${MATRIX[@]}"
} > "$OUT/environment.txt"

"$PY" "$R2D" host-snapshot "$OUT/host_baseline"

echo "[calibration]" | tee -a "$OPS"
taskset -c 0-15 timeout 180 "$PY" "$DRIVER" --calibrate --out "$OUT/calibration" --commit "$HEAD" --execute \
    > "$OUT/calibration.out" 2> "$OUT/calibration.err" || STATUS=1
ITERS=$("$PY" -c 'import json,sys; r=json.load(open(sys.argv[1])); print(r["iters"] if r["driver_ok"] else "")' \
        "$OUT/calibration/run.json" 2>/dev/null || true)
"$PY" "$R2D" host-snapshot "$OUT/calibration/host_wrapper_after"
"$PY" "$R2D" compare "$OUT/host_baseline" "$OUT/calibration/host_wrapper_after" > "$OUT/calibration/host_compare.json" \
    || STATUS=1
if (( STATUS )) || [[ -z "$ITERS" ]]; then echo "[calibration] failed: stopping" | tee -a "$OPS"; STATUS=1; fi

if (( ! STATUS )); then
  for label in "${MATRIX[@]}"; do
    R=$OUT/$label
    echo "[$label] iters=$ITERS driver" | tee -a "$OPS"
    taskset -c 0-15 timeout 180 "$PY" "$DRIVER" --run "$label" --iters "$ITERS" --out "$R" --commit "$HEAD" --execute \
        > "$R.out" 2> "$R.err" || STATUS=1
    "$PY" "$R2D" host-snapshot "$R/host_wrapper_after"
    "$PY" "$R2D" compare "$OUT/host_baseline" "$R/host_wrapper_after" > "$R/host_compare.json" || STATUS=1
    tee -a "$OPS" < "$R.out"
    if (( STATUS )); then echo "[$label] a check failed: stopping" | tee -a "$OPS"; break; fi
  done
fi

finish
"$PY" "$R2D" host-snapshot "$OUT/host_final"
"$PY" "$R2D" compare "$OUT/host_baseline" "$OUT/host_final" > "$OUT/host_final_compare.json" || STATUS=1

"$PY" - "$OUT" "$STATUS" <<'EOF' | tee "$OUT/summary.json"
import json, sys
from pathlib import Path
out, status = Path(sys.argv[1]), int(sys.argv[2])
res = {"status_ok": status == 0, "runs": {}}
for r in sorted(p for p in out.iterdir() if p.is_dir() and p.name[:2] in ("E0", "Q0", "C1", "T1", "T2", "TC")):
    j = json.loads((r / "run.json").read_text()) if (r / "run.json").exists() else {}
    hc = json.loads((r / "host_compare.json").read_text()) if (r / "host_compare.json").exists() else {}
    g = j.get("ground_truth", {})
    res["runs"][r.name] = {"verdict": j.get("verdict"), "aborts": j.get("aborts"),
                           "throttling_established": g.get("throttling_established"),
                           "throttling_absent_confirmed": g.get("throttling_absent_confirmed"),
                           "m2": j.get("m2", {}).get("decision"), "GR": j.get("GR", {}).get("ok"),
                           "host_ok": hc.get("ok")}
res["host_final_ok"] = json.loads((out / "host_final_compare.json").read_text())["ok"]
print(json.dumps(res, indent=1))
EOF
echo "evidence: $OUT"
exit "$STATUS"
