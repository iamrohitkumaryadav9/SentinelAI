#!/usr/bin/env bash
# SentinelAI R2-B — controlled network packet-loss validation in the isolated R2-A lab.
#
# Run:   sudo bash scripts/r2b_validate.sh
#
# For each run of the matrix (E0 baseline 0 %; E1 1 %; E2 1 % x2; E3 5 % x2):
#   create the R2-A lab -> validate it (lab-local connectivity) -> capture the clean lab -> run the driver INSIDE
#   sentinel-lab-a (workload, M3A+M3B collection, netem loss on sentlab-a0 during W only, ground truth, M2) ->
#   capture the lab and compare with the clean lab -> destroy the lab -> compare the host with the baseline.
# Stops at the first failed check. The only fault is netem loss on sentlab-a0 (built and checked by
# scripts/r2b_fault.py); this script itself only creates/destroys the lab and reads state.
# Never: anything on enp0s31f6 or docker0, host routes/addresses/qdiscs/sysctls/firewall/Docker, delay/reorder/
# corruption/duplication, CPU or memory stress.
# Evidence: results/phase1c_r2b/<UTC timestamp>/ (owned by the invoking user).
set -euo pipefail

if [[ $EUID -ne 0 || -z "${SUDO_USER:-}" ]]; then
  echo "REFUSING: run as: sudo bash $0" >&2; exit 2
fi
REPO=$(cd "$(dirname "$0")/.." && pwd)
BASE=683d87af0f60d803f01c393b479b4b0b111029e2
PY=$REPO/.venv/bin/python
R2A=$REPO/scripts/r2a_lab.py
R2B=$REPO/scripts/r2b_fault.py
BPFTOOL=/usr/lib/linux-hwe-6.8-tools-6.8.0-138/bpftool
LOADER=$REPO/ebpf/build/sentinel_loader

NS_A=sentinel-lab-a
NS_B=sentinel-lab-b
IF_A=sentlab-a0
IF_B=sentlab-b0
IP_A=10.199.0.1
IP_B=10.199.0.2
PREFIX=24
MATRIX=("E0-baseline 0" "E1-loss1 1" "E2-loss1-rep2 1" "E2-loss1-rep3 1" "E3-loss5 5" "E3-loss5-rep2 5")

HEAD=$(sudo -u "$SUDO_USER" python3 "$R2B" candidate "$REPO" "$BASE") || { echo "REFUSING: $HEAD" >&2; exit 3; }
[[ -x "$PY" && -x "$LOADER" && -x "$BPFTOOL" ]] || { echo "REFUSING: venv/loader/bpftool missing" >&2; exit 3; }
"$LOADER" --version | grep -q '"libbpf_linked":"1.4"' || { echo "REFUSING: loader not linked to libbpf 1.4" >&2; exit 3; }

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$REPO/results/phase1c_r2b/$TS
mkdir -p "$OUT"
OPS=$OUT/ops.log
CREATED_A=0
CREATED_B=0

run() {   # every host-mutating command of this script goes through here and is logged with its exit code
  local rc=0
  "$@" || rc=$?
  printf '%s rc=%d  %s\n' "$(date -u +%H:%M:%S.%3N)" "$rc" "$*" >> "$OPS"
  return "$rc"
}

destroy_lab() {   # removes only the namespaces this run created (veth pair and any lab qdisc go with them)
  if (( CREATED_A )); then run ip netns del "$NS_A" && CREATED_A=0; fi
  if (( CREATED_B )); then run ip netns del "$NS_B" && CREATED_B=0; fi
}

finish() {
  destroy_lab || true
  chown -R "$SUDO_USER": "$REPO/results/phase1c_r2b"
}
trap finish EXIT

refuse_if_exists() {
  local n
  for n in "$NS_A" "$NS_B"; do
    if ip netns list | awk '{print $1}' | grep -qx "$n" || [[ -e /run/netns/$n ]]; then
      echo "REFUSING: namespace $n already exists" >&2; exit 4
    fi
  done
  for n in "$IF_A" "$IF_B"; do
    if ip link show "$n" >/dev/null 2>&1; then echo "REFUSING: interface $n exists in the host" >&2; exit 4; fi
  done
}

snapshot() {   # read-only host state (same content as R2-A)
  local d=$1; mkdir -p "$d"
  ip -j -d link show > "$d/links.json"
  ip -j addr show > "$d/addrs.json"
  ip -j route show > "$d/routes4.json"
  ip -j -6 route show > "$d/routes6.json"
  tc -j qdisc show > "$d/qdiscs.json"
  ip -j netns list > "$d/netns.json"
  ls -1 /run/netns > "$d/run_netns.txt" 2>/dev/null || true
  local s
  for s in kernel/unprivileged_bpf_disabled kernel/perf_event_paranoid kernel/bpf_stats_enabled \
           net/core/bpf_jit_enable net/core/default_qdisc net/ipv4/ip_forward net/ipv4/conf/all/forwarding \
           net/ipv4/conf/all/rp_filter net/ipv6/conf/all/forwarding net/ipv6/conf/all/disable_ipv6; do
    echo "$s=$(cat /proc/sys/$s)"; done > "$d/sysctls.txt"
  "$BPFTOOL" -j prog show > "$d/bpf_progs.json"
  "$BPFTOOL" -j link show > "$d/bpf_links.json"
  "$BPFTOOL" -j map show > "$d/bpf_maps.json"
  findmnt -rn -o TARGET,FSTYPE | sort > "$d/mounts.txt"
}

create_lab() {   # identical to R2-A
  refuse_if_exists
  run ip netns add "$NS_A"; CREATED_A=1
  run ip netns add "$NS_B"; CREATED_B=1
  run ip link add "$IF_A" netns "$NS_A" type veth peer name "$IF_B" netns "$NS_B"
  run ip -n "$NS_A" addr add "$IP_A/$PREFIX" dev "$IF_A"
  run ip -n "$NS_B" addr add "$IP_B/$PREFIX" dev "$IF_B"
  run ip -n "$NS_A" link set lo up
  run ip -n "$NS_B" link set lo up
  run ip -n "$NS_A" link set "$IF_A" up
  run ip -n "$NS_B" link set "$IF_B" up
  sleep 2
}

lab_state() {   # read-only lab state
  local d=$1 side ns; mkdir -p "$d"
  ip -j netns list > "$d/netns.json"
  ip -j link show > "$d/host_links.json"
  for side in a b; do
    if [[ $side == a ]]; then ns=$NS_A; else ns=$NS_B; fi
    ip -n "$ns" -j -d link show > "$d/${side}_links.json"
    ip -n "$ns" -j addr show > "$d/${side}_addrs.json"
    ip -n "$ns" -j route show > "$d/${side}_routes4.json"
    ip -n "$ns" -j -6 route show > "$d/${side}_routes6.json"
    tc -n "$ns" -s -j qdisc show > "$d/${side}_qdiscs.json"
  done
}

lab_probe() {   # lab-local connectivity (R2-A checks): every probe inside a lab namespace towards a lab address
  local d=$1 side ns ifn peer
  lab_state "$d"
  for side in a b; do
    if [[ $side == a ]]; then ns=$NS_A; ifn=$IF_A; peer=$IP_B; else ns=$NS_B; ifn=$IF_B; peer=$IP_A; fi
    ip -n "$ns" route get 8.8.8.8 > "$d/${side}_route_get_external.txt" 2>&1 || true   # lookup only, no packet
    ip netns exec "$ns" ping -n -c 2 -W 1 127.0.0.1 > "$d/${side}_ping_lo.txt" 2>&1 || true
    ip netns exec "$ns" ping -n -c 3 -W 1 -I "$ifn" "$peer" > "$d/${side}_ping_peer.txt" 2>&1 || true
  done
  ip netns exec "$NS_B" timeout 10 python3 -c "
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('$IP_B', 5001)); s.listen(1); s.settimeout(8)
c, _ = s.accept(); c.sendall(c.recv(64)); c.close(); s.close()" &
  local srv=$!
  ip netns exec "$NS_A" timeout 8 python3 -c "
import socket, time
for _ in range(25):
    try:
        c = socket.create_connection(('$IP_B', 5001), timeout=2); break
    except OSError:
        time.sleep(0.2)
c.sendall(b'sentinel-r2b'); print('ECHO-OK' if c.recv(64) == b'sentinel-r2b' else 'ECHO-BAD')" \
    > "$d/tcp_result.txt" 2>&1 || true
  wait "$srv" || true
}

{
  echo "commit=$HEAD"; echo "base=$BASE"; uname -a; echo "user=$SUDO_USER"; date -u
  ip -V; tc -V; "$LOADER" --version
  echo "lab: $NS_A/$IF_A $IP_A/$PREFIX <-> $NS_B/$IF_B $IP_B/$PREFIX"
  printf 'matrix: %s\n' "${MATRIX[@]}"
} > "$OUT/environment.txt"

snapshot "$OUT/host_baseline"
STATUS=0
for entry in "${MATRIX[@]}"; do
  read -r label loss <<< "$entry"
  R=$OUT/$label
  mkdir -p "$R"
  echo "[$label] loss=$loss% create lab" | tee -a "$OPS"
  create_lab
  lab_probe "$R/lab_clean"
  python3 "$R2A" validate-lab "$R/lab_clean" > "$R/lab_clean_checks.json" || { STATUS=1; echo "[$label] lab invalid" | tee -a "$OPS"; break; }
  echo "[$label] driver" | tee -a "$OPS"
  # ip netns exec gives the driver a private (slave) mount namespace with the lab's sysfs, where the cgroup v2
  # hierarchy is not mounted: mount it read-only there (cannot propagate to the host; gone when the driver exits).
  ip netns exec "$NS_A" /bin/sh -c 'mount -t cgroup2 -o ro,nosuid,nodev,noexec cgroup2 /sys/fs/cgroup && exec "$@"' \
      sh env PYTHONNOUSERSITE=1 timeout 240 "$PY" "$REPO/scripts/r2b_driver.py" \
      --out "$R/run" --loss "$loss" --label "$label" --commit "$HEAD" > "$R/driver.out" 2> "$R/driver.err" || STATUS=1
  printf '%s rc=%d  driver %s loss=%s\n' "$(date -u +%H:%M:%S.%3N)" "$STATUS" "$label" "$loss" >> "$OPS"
  lab_state "$R/lab_after"
  python3 "$R2B" lab-compare "$R/lab_clean" "$R/lab_after" > "$R/lab_restore_compare.json" || STATUS=1
  echo "[$label] destroy lab" | tee -a "$OPS"
  destroy_lab
  sleep 2
  snapshot "$R/host_after"
  python3 "$R2A" compare "$OUT/host_baseline" "$R/host_after" > "$R/host_compare.json" || STATUS=1
  diff "$OUT/host_baseline/mounts.txt" "$R/host_after/mounts.txt" > "$R/host_mounts.diff" || STATUS=1
  cat "$R/driver.out" | tee -a "$OPS"
  if (( STATUS )); then echo "[$label] a check failed: stopping" | tee -a "$OPS"; break; fi
done
snapshot "$OUT/host_final"
python3 "$R2A" compare "$OUT/host_baseline" "$OUT/host_final" > "$OUT/host_final_compare.json" || STATUS=1
diff "$OUT/host_baseline/mounts.txt" "$OUT/host_final/mounts.txt" > "$OUT/host_final_mounts.diff" || STATUS=1

python3 - "$OUT" "$STATUS" <<'EOF' | tee "$OUT/summary.json"
import json, sys
from pathlib import Path
out, status = Path(sys.argv[1]), int(sys.argv[2])
res = {"status_ok": status == 0, "runs": {}}
for r in sorted(p for p in out.iterdir() if p.is_dir() and p.name.startswith("E")):
    run = r / "run" / "run.json"
    j = json.loads(run.read_text()) if run.exists() else {}
    ok = lambda f: json.loads((r / f).read_text())["ok"] if (r / f).exists() else None
    res["runs"][r.name] = {"lab_clean_ok": ok("lab_clean_checks.json"), "driver_ok": j.get("driver_ok"),
                           "qdisc_drops_w": j.get("attribution", {}).get("qdisc_drops"),
                           "prediction": j.get("prediction", {}).get("decision"), "m2": j.get("m2", {}).get("decision"),
                           "lab_restored": ok("lab_restore_compare.json"), "host_ok": ok("host_compare.json")}
res["host_final_ok"] = json.loads((out / "host_final_compare.json").read_text())["ok"]
print(json.dumps(res, indent=1))
EOF
echo "evidence: $OUT"
exit "$STATUS"
