#!/usr/bin/env bash
# SentinelAI R2-F — controlled memory-pressure validation (RUNTIME; requires explicit R2-F runtime authorisation).
#
# Run:   sudo bash scripts/r2f_validate.sh
#
# Refuses unless: root via sudo from uid 1000; HEAD descends from 4aa23b8 and differs from it only by R2-F tooling,
# with a clean tracked tree; the loader is linked to libbpf 1.4; the read-only preflight passes (no sentinel cgroup,
# no R2-F scratch directory, /var/tmp on ext4, host MemAvailable >= 4 GiB, NIC IRQ off CPU 18).
# Then: host baseline -> step 0 calibration (E0 configuration, provenance only; NOT FEASIBLE stops here) -> each run of
# r2f_memory.MATRIX through r2f_driver.py (taskset -c 0-15): lab cgroup, memory controls written and verified before
# the target starts (memory.swap.max 0 everywhere), target, collection, ground truth, M2, cleanup (kill -> verify
# termination -> verify controls -> loader -> BPF release -> scratch file -> cgroups); the host is compared with the
# baseline after every run. Stops at the first failure (a host OOM always stops the campaign).
# Never: swapoff/swapon, drop_caches, any sysctl (vm.* included), any non-lab cgroup, cpu.max, tc, IRQ affinity,
# enp0s31f6, docker0, OpenVPN or other services.
# Evidence: results/phase1c_r2f/<UTC timestamp>/ (owned by the invoking user).
set -euo pipefail

if [[ $EUID -ne 0 || -z "${SUDO_USER:-}" || "${SUDO_UID:-}" != "1000" ]]; then
  echo "REFUSING: run as: sudo bash $0 (from uid 1000)" >&2; exit 2
fi
REPO=$(cd "$(dirname "$0")/.." && pwd)
BASE=4aa23b8
PY=$REPO/.venv/bin/python
R2F=$REPO/scripts/r2f_memory.py
DRIVER=$REPO/scripts/r2f_driver.py
LOADER=$REPO/ebpf/build/sentinel_loader
MATRIX=(E0-open M1-1 M1-2 M1-3 M2-1 M2-2 M2-3 N1-1 N1-2 N2-1 N2-2 E0-close)
export PYTHONNOUSERSITE=1

HEAD=$(sudo -u "$SUDO_USER" "$PY" "$R2F" candidate "$REPO" "$BASE") || { echo "REFUSING: $HEAD" >&2; exit 3; }
[[ -x "$PY" && -x "$LOADER" ]] || { echo "REFUSING: venv/loader missing" >&2; exit 3; }
"$LOADER" --version | grep -q '"libbpf_linked":"1.4"' || { echo "REFUSING: loader not linked to libbpf 1.4" >&2; exit 3; }
"$PY" "$R2F" preflight > /dev/null || { echo "REFUSING: preflight failed" >&2; "$PY" "$R2F" preflight >&2; exit 4; }

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$REPO/results/phase1c_r2f/$TS
mkdir -p "$OUT"
OPS=$OUT/ops.log
FINISHED=0
STATUS=0

finish() {   # idempotent: every run's op log is cleaned (kill, verify, scratch file, cgroups); results chowned
  if (( FINISHED )); then return; fi
  FINISHED=1
  "$PY" "$R2F" cleanup "$OUT" > "$OUT/final_cleanup.json" 2>&1 || STATUS=1
  chown -R "$SUDO_USER": "$REPO/results/phase1c_r2f"
}
trap finish EXIT
trap 'finish; exit 130' INT TERM

{
  echo "commit=$HEAD"; echo "base=$BASE"; uname -a; echo "user=$SUDO_USER"; date -u
  "$LOADER" --version
  "$PY" "$R2F" criteria
  printf 'matrix: %s\n' "${MATRIX[@]}"
  free -b; cat /proc/swaps
} > "$OUT/environment.txt" 2>&1

"$PY" "$R2F" host-snapshot "$OUT/host_baseline"

step() {   # $1 name, rest: driver args; then the wrapper-level host comparison
  local name=$1; shift
  taskset -c 0-15 timeout 300 "$PY" "$DRIVER" --out "$OUT/$name" --ts "$TS" --commit "$HEAD" --execute "$@" \
      > "$OUT/$name.out" 2> "$OUT/$name.err" || STATUS=1
  "$PY" "$R2F" host-snapshot "$OUT/$name/host_wrapper_after"
  "$PY" "$R2F" compare "$OUT/host_baseline" "$OUT/$name/host_wrapper_after" > "$OUT/$name/host_compare.json" \
      || STATUS=1
  tee -a "$OPS" < "$OUT/$name.out"
}

echo "[calibration]" | tee -a "$OPS"
step calibration --calibrate
FEASIBLE=$("$PY" -c 'import json,sys; r=json.load(open(sys.argv[1])); c=r.get("calibration") or {}
print("yes" if r["driver_ok"] and c.get("feasible") else (c.get("reason") or "calibration failed"))' \
           "$OUT/calibration/run.json" 2>/dev/null || echo "calibration unavailable")
if (( STATUS )); then echo "[calibration] failed: stopping" | tee -a "$OPS"
elif [[ "$FEASIBLE" != "yes" ]]; then echo "[calibration] $FEASIBLE: stopping (R2-F NOT FEASIBLE)" | tee -a "$OPS"; STATUS=1
fi

if (( ! STATUS )); then
  for label in "${MATRIX[@]}"; do
    echo "[$label]" | tee -a "$OPS"
    step "$label" --run "$label"
    if (( STATUS )); then echo "[$label] a check failed: stopping" | tee -a "$OPS"; break; fi
  done
fi

finish
"$PY" "$R2F" host-snapshot "$OUT/host_final"
"$PY" "$R2F" compare "$OUT/host_baseline" "$OUT/host_final" > "$OUT/host_final_compare.json" || STATUS=1

"$PY" - "$OUT" "$STATUS" <<'EOF' | tee "$OUT/summary.json"
import json, sys
from pathlib import Path
out, status = Path(sys.argv[1]), int(sys.argv[2])
res = {"status_ok": status == 0, "runs": {}}
cal = out / "calibration" / "run.json"
res["calibration"] = json.loads(cal.read_text()).get("calibration") if cal.exists() else None
for r in sorted(p for p in out.iterdir() if p.is_dir() and p.name[:2] in ("E0", "M1", "M2", "N1", "N2")):
    j = json.loads((r / "run.json").read_text()) if (r / "run.json").exists() else {}
    hc = json.loads((r / "host_compare.json").read_text()) if (r / "host_compare.json").exists() else {}
    g = j.get("ground_truth", {})
    res["runs"][r.name] = {"verdict": j.get("verdict"), "aborts": j.get("aborts"), "established": g.get("established"),
                           "m2": j.get("m2", {}).get("decision"), "GR": j.get("GR", {}).get("ok"),
                           "host_oom": j.get("host_oom"), "host_ok": hc.get("ok")}
res["host_final_ok"] = json.loads((out / "host_final_compare.json").read_text())["ok"]
print(json.dumps(res, indent=1))
EOF
echo "evidence: $OUT"
exit "$STATUS"
