#!/usr/bin/env bash
# SentinelAI M3B R1 — privileged runtime validation of the committed eBPF observation layer.
#
# Run:   sudo bash scripts/m3b_r1_validate.sh
#
# What it does:  loads/attaches the committed loader (ebpf/build/sentinel_loader, no rebuild), records
#                bpftool program/link/map state, collects snapshots through the production process
#                boundary under harmless local activity (sleep/wake threads, /bin/true, TCP on 127.0.0.1),
#                kills/restarts the loader to check cleanup, and measures overhead. About 6-7 minutes.
# What it never does: tc/netem, ip link/addr/route changes, namespaces or veth, sysctl writes, cgroup
#                writes, traffic on enp0s31f6 or docker0, rebuilding as root, pinning BPF objects.
# Evidence:      results/phase1c_m3b_r1/<UTC timestamp>/ (owned by the invoking user).
set -euo pipefail

if [[ $EUID -ne 0 || -z "${SUDO_USER:-}" ]]; then
  echo "REFUSING: run as: sudo bash $0" >&2; exit 2
fi
REPO=$(cd "$(dirname "$0")/.." && pwd)
# M3B runtime candidate: HEAD must be this commit or a descendant adding only R1 tooling (m3b_r1_candidate.py)
CANDIDATE=f18e9fc1f44ad4966f731dcc45adc16b15f3d72a
BPFTOOL=/usr/lib/linux-hwe-6.8-tools-6.8.0-138/bpftool
LOADER=$REPO/ebpf/build/sentinel_loader
PY=$REPO/.venv/bin/python

HEAD=$(sudo -u "$SUDO_USER" python3 "$REPO/scripts/m3b_r1_candidate.py" "$REPO" "$CANDIDATE") \
  || { echo "REFUSING: $HEAD" >&2; exit 3; }
[[ -x "$LOADER" && -x "$BPFTOOL" && -x "$PY" ]] || { echo "REFUSING: loader/bpftool/venv missing" >&2; exit 3; }
"$LOADER" --version | grep -q '"libbpf_linked":"1.4"' || { echo "REFUSING: loader not linked to libbpf 1.4" >&2; exit 3; }

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$REPO/results/phase1c_m3b_r1/$TS
mkdir -p "$OUT"
finish() { chown -R "$SUDO_USER": "$REPO/results/phase1c_m3b_r1"; }
trap finish EXIT

snapshot() {   # read-only host state
  local d=$OUT/host_$1; mkdir -p "$d"
  ip -j -d link show > "$d/links.json"
  ip -j addr show > "$d/addrs.json"
  ip -j route show > "$d/routes4.json"
  ip -j -6 route show > "$d/routes6.json"
  ls -1 /run/netns 2>/dev/null > "$d/netns.txt" || true
  for s in kernel/unprivileged_bpf_disabled kernel/perf_event_paranoid kernel/bpf_stats_enabled \
           net/core/bpf_jit_enable net/ipv4/ip_forward; do
    echo "$s=$(cat /proc/sys/$s)"; done > "$d/sysctls.txt"
  cat /sys/kernel/security/lockdown > "$d/lockdown.txt"
  "$BPFTOOL" -j prog show > "$d/bpf_progs.json"
  "$BPFTOOL" -j link show > "$d/bpf_links.json"
  "$BPFTOOL" -j map show > "$d/bpf_maps.json"
}

{
  echo "commit=$HEAD"; echo "m3b_candidate=$CANDIDATE"; uname -a; echo "user=$SUDO_USER"; date -u
  "$LOADER" --version
  sha256sum "$LOADER" "$REPO/ebpf/build/sentinel.bpf.o" "$REPO/ebpf/build/sentinel.skel.h"
} > "$OUT/environment.txt"
snapshot before

set +e
PYTHONNOUSERSITE=1 timeout 1500 "$PY" "$REPO/scripts/m3b_r1_validate.py" "$OUT" 2>&1 | tee "$OUT/driver.log"
RC=${PIPESTATUS[0]}
set -e
sleep 1
snapshot after

PYTHONNOUSERSITE=1 "$PY" "$REPO/scripts/m3b_r1_compare.py" "$OUT" | tee "$OUT/host_compare.txt"
echo "driver exit code: $RC"
echo "evidence: $OUT"
exit "$RC"
