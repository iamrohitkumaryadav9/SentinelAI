#!/usr/bin/env bash
# SentinelAI R2-E — controlled softirq-overload validation (RUNTIME; requires explicit R2-E runtime authorisation).
#
# Run:   sudo bash scripts/r2e_validate.sh
#
# Refuses unless: root via sudo from uid 1000; HEAD descends from d11e755 and differs from it only by R2-E tooling,
# with a clean tracked tree; the loader is linked to libbpf 1.4; iperf3 is present; the read-only preflight passes
# (no sentinel cgroup, no lab namespace or interface, every host RPS map 0, NIC IRQ off the experiment CPUs).
# Then: host baseline -> step 0a (R2-C target calibration on CPU 18; provenance only) -> step 0b (UDP rate ladder:
# fixes delta, S1, S2, S3; provenance only; NOT FEASIBLE stops here) -> each run of r2e_softirq.MATRIX through
# r2e_driver.py (taskset -c 0-15): lab + single-queue veth, RPS on sentlab-b0 rx-0 (40000 | N2 80000), target, traffic,
# collection, ground truth, M2, cleanup (traffic -> RPS 0 verified -> loader -> cgroups -> lab namespaces); the host is
# compared with the baseline after every run. Stops at the first failure. An unsafe/incomplete cleanup (RPS not
# verified 0) stops everything: manual cleanup and verification are required before any further run.
# Cleanup is registered before anything is created: the trap on EXIT, INT and TERM runs the op-log cleanup.
# Never: enp0s31f6, docker0, any host RPS map, host routes/firewall/sysctls, IRQ affinity, tc, ethtool -K, modprobe,
# cpu.max, OpenVPN or other services.
# Evidence: results/phase1c_r2e/<UTC timestamp>/ (owned by the invoking user).
set -euo pipefail

if [[ $EUID -ne 0 || -z "${SUDO_USER:-}" || "${SUDO_UID:-}" != "1000" ]]; then
  echo "REFUSING: run as: sudo bash $0 (from uid 1000)" >&2; exit 2
fi
REPO=$(cd "$(dirname "$0")/.." && pwd)
BASE=d11e755
PY=$REPO/.venv/bin/python
R2E=$REPO/scripts/r2e_softirq.py
DRIVER=$REPO/scripts/r2e_driver.py
LOADER=$REPO/ebpf/build/sentinel_loader
MATRIX=(E0-open S1-1 S1-2 S2-1 S2-2 S2-3 S3-1 S3-2 S3-3 N1-1 N1-2 N2-1 N2-2 E0-close)
export PYTHONNOUSERSITE=1

HEAD=$(sudo -u "$SUDO_USER" "$PY" "$R2E" candidate "$REPO" "$BASE") || { echo "REFUSING: $HEAD" >&2; exit 3; }
[[ -x "$PY" && -x "$LOADER" && -x /usr/bin/iperf3 ]] || { echo "REFUSING: venv/loader/iperf3 missing" >&2; exit 3; }
"$LOADER" --version | grep -q '"libbpf_linked":"1.4"' || { echo "REFUSING: loader not linked to libbpf 1.4" >&2; exit 3; }
"$PY" "$R2E" preflight > /dev/null || { echo "REFUSING: preflight failed" >&2; "$PY" "$R2E" preflight >&2; exit 4; }

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$REPO/results/phase1c_r2e/$TS
mkdir -p "$OUT"
OPS=$OUT/ops.log
FINISHED=0
STATUS=0

finish() {   # idempotent: every run's op log is cleaned (traffic, RPS 0 verified, cgroups, lab); results chowned
  if (( FINISHED )); then return; fi
  FINISHED=1
  if ! "$PY" "$R2E" cleanup "$OUT" > "$OUT/final_cleanup.json" 2>&1; then
    STATUS=1
    echo "CLEANUP NOT COMPLETE: see $OUT/final_cleanup.json; if unsafe_incomplete is listed, RPS was not verified 0:" \
         "no further run may start until manual cleanup and verification" | tee -a "$OPS" >&2
  fi
  chown -R "$SUDO_USER": "$REPO/results/phase1c_r2e"
}
trap finish EXIT
trap 'finish; exit 130' INT TERM

{
  echo "commit=$HEAD"; echo "base=$BASE"; uname -a; echo "user=$SUDO_USER"; date -u
  "$LOADER" --version; /usr/bin/iperf3 --version | head -1
  "$PY" "$R2E" criteria
  printf 'matrix: %s\n' "${MATRIX[@]}"
} > "$OUT/environment.txt"

"$PY" "$R2E" host-snapshot "$OUT/host_baseline"

step() {   # $1 name, rest: driver args; then wrapper-level host comparison
  local name=$1; shift
  taskset -c 0-15 timeout 300 "$PY" "$DRIVER" --out "$OUT/$name" --commit "$HEAD" --execute "$@" \
      > "$OUT/$name.out" 2> "$OUT/$name.err" || STATUS=1
  "$PY" "$R2E" host-snapshot "$OUT/$name/host_wrapper_after"
  "$PY" "$R2E" compare "$OUT/host_baseline" "$OUT/$name/host_wrapper_after" > "$OUT/$name/host_compare.json" \
      || STATUS=1
  tee -a "$OPS" < "$OUT/$name.out"
}

echo "[calibration]" | tee -a "$OPS"
step calibration --calibrate
ITERS=$("$PY" -c 'import json,sys; r=json.load(open(sys.argv[1])); print(r["iters"] if r["driver_ok"] else "")' \
        "$OUT/calibration/run.json" 2>/dev/null || true)
if (( STATUS )) || [[ -z "$ITERS" ]]; then echo "[calibration] failed: stopping" | tee -a "$OPS"; STATUS=1; fi

if (( ! STATUS )); then
  echo "[ladder]" | tee -a "$OPS"
  step ladder --ladder
  FEASIBLE=$("$PY" -c 'import json,sys; r=json.load(open(sys.argv[1])); print("yes" if r["feasible"] else r["reason"])' \
             "$OUT/ladder/ladder.json" 2>/dev/null || echo "ladder unavailable")
  if (( STATUS )); then echo "[ladder] failed: stopping" | tee -a "$OPS"
  elif [[ "$FEASIBLE" != "yes" ]]; then echo "[ladder] $FEASIBLE: stopping (R2-E NOT FEASIBLE)" | tee -a "$OPS"; STATUS=1
  fi
fi

if (( ! STATUS )); then
  for label in "${MATRIX[@]}"; do
    echo "[$label] iters=$ITERS" | tee -a "$OPS"
    step "$label" --run "$label" --iters "$ITERS" --ladder-file "$OUT/ladder/ladder.json"
    if (( STATUS )); then echo "[$label] a check failed: stopping" | tee -a "$OPS"; break; fi
  done
fi

finish
"$PY" "$R2E" host-snapshot "$OUT/host_final"
"$PY" "$R2E" compare "$OUT/host_baseline" "$OUT/host_final" > "$OUT/host_final_compare.json" || STATUS=1

"$PY" - "$OUT" "$STATUS" <<'EOF' | tee "$OUT/summary.json"
import json, sys
from pathlib import Path
out, status = Path(sys.argv[1]), int(sys.argv[2])
res = {"status_ok": status == 0, "runs": {}}
lad = out / "ladder" / "ladder.json"
res["ladder"] = {k: v for k, v in json.loads(lad.read_text()).items() if k != "steps"} if lad.exists() else None
for r in sorted(p for p in out.iterdir() if p.is_dir() and p.name[:2] in ("E0", "S1", "S2", "S3", "N1", "N2")):
    j = json.loads((r / "run.json").read_text()) if (r / "run.json").exists() else {}
    hc = json.loads((r / "host_compare.json").read_text()) if (r / "host_compare.json").exists() else {}
    g = j.get("ground_truth", {})
    res["runs"][r.name] = {"verdict": j.get("verdict"), "aborts": j.get("aborts"), "established": g.get("established"),
                           "m2": j.get("m2", {}).get("decision"), "GR": j.get("GR", {}).get("ok"),
                           "rps_restored": j.get("rps_restored"), "unsafe_incomplete": j.get("unsafe_incomplete"),
                           "host_ok": hc.get("ok")}
res["host_final_ok"] = json.loads((out / "host_final_compare.json").read_text())["ok"]
print(json.dumps(res, indent=1))
EOF
echo "evidence: $OUT"
exit "$STATUS"
