#!/usr/bin/env bash
# SentinelAI R2-A — FaultLab infrastructure-only validation.
#
# Run:   sudo bash scripts/r2a_lab_validate.sh
#
# Topology (host netns untouched: the veth is created directly inside the lab namespaces):
#     netns sentinel-lab-a  [lo, sentlab-a0 10.199.0.1/24] <==veth==> [sentlab-b0 10.199.0.2/24, lo]  netns sentinel-lab-b
#     no default route in either namespace: the lab has no path out.
# What it does:  host baseline snapshot (read-only) -> 2 cycles of {create lab, validate lab-local connectivity
#                (ping, TCP echo), compare host, destroy lab, compare host} -> final comparison.
# What it never does: fault injection (no netem, no qdisc changes at all), sysctl writes, route/address changes in
#                the host netns, anything on enp0s31f6 or docker0, firewall changes, Docker changes, BPF.
# Evidence:      results/phase1c_r2a/<UTC timestamp>/ (owned by the invoking user).
set -euo pipefail

if [[ $EUID -ne 0 || -z "${SUDO_USER:-}" ]]; then
  echo "REFUSING: run as: sudo bash $0" >&2; exit 2
fi
REPO=$(cd "$(dirname "$0")/.." && pwd)
BASE=3f1eb40190e5c9e3e373f6242691b560be4f4248
HELPER=$REPO/scripts/r2a_lab.py
BPFTOOL=/usr/lib/linux-hwe-6.8-tools-6.8.0-138/bpftool

NS_A=sentinel-lab-a
NS_B=sentinel-lab-b
IF_A=sentlab-a0
IF_B=sentlab-b0
IP_A=10.199.0.1
IP_B=10.199.0.2
PREFIX=24

HEAD=$(sudo -u "$SUDO_USER" python3 "$HELPER" candidate "$REPO" "$BASE") \
  || { echo "REFUSING: $HEAD" >&2; exit 3; }

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$REPO/results/phase1c_r2a/$TS
mkdir -p "$OUT"
OPS=$OUT/ops.log
CREATED_A=0
CREATED_B=0

run() {   # every host-mutating command goes through here and is logged with its exit code
  local rc=0
  "$@" || rc=$?
  printf '%s rc=%d  %s\n' "$(date -u +%H:%M:%S.%3N)" "$rc" "$*" >> "$OPS"
  return "$rc"
}

destroy_lab() {   # removes only the namespaces this run created (the veth pair goes with them)
  if (( CREATED_A )); then run ip netns del "$NS_A" && CREATED_A=0; fi
  if (( CREATED_B )); then run ip netns del "$NS_B" && CREATED_B=0; fi
}

finish() {
  destroy_lab || true
  chown -R "$SUDO_USER": "$REPO/results/phase1c_r2a"
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

snapshot() {   # read-only host state
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
}

create_lab() {
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

capture_lab() {   # lab-local only: every probe runs inside a lab namespace towards a lab address
  local d=$1 side ns ifn peer; mkdir -p "$d"
  ip -j netns list > "$d/netns.json"
  ip -j link show > "$d/host_links.json"
  for side in a b; do
    if [[ $side == a ]]; then ns=$NS_A; ifn=$IF_A; peer=$IP_B; else ns=$NS_B; ifn=$IF_B; peer=$IP_A; fi
    ip -n "$ns" -j -d link show > "$d/${side}_links.json"
    ip -n "$ns" -j addr show > "$d/${side}_addrs.json"
    ip -n "$ns" -j route show > "$d/${side}_routes4.json"
    ip -n "$ns" -j -6 route show > "$d/${side}_routes6.json"
    tc -n "$ns" -j qdisc show > "$d/${side}_qdiscs.json"
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
c.sendall(b'sentinel-r2a'); print('ECHO-OK' if c.recv(64) == b'sentinel-r2a' else 'ECHO-BAD')" \
    > "$d/tcp_result.txt" 2>&1 || true
  wait "$srv" || true
}

{
  echo "commit=$HEAD"; echo "base=$BASE"; uname -a; echo "user=$SUDO_USER"; date -u
  ip -V; tc -V
  echo "lab: $NS_A/$IF_A $IP_A/$PREFIX <-> $NS_B/$IF_B $IP_B/$PREFIX"
} > "$OUT/environment.txt"

snapshot "$OUT/baseline"
STATUS=0
for cycle in 1 2; do
  C=$OUT/cycle$cycle
  echo "[cycle $cycle] create" | tee -a "$OPS"
  create_lab
  capture_lab "$C/lab"
  snapshot "$C/with_lab"
  python3 "$HELPER" validate-lab "$C/lab" > "$C/lab_checks.json" || STATUS=1
  python3 "$HELPER" compare "$OUT/baseline" "$C/with_lab" "$NS_A" "$NS_B" > "$C/with_lab_compare.json" || STATUS=1
  echo "[cycle $cycle] destroy" | tee -a "$OPS"
  destroy_lab
  sleep 1
  snapshot "$C/after"
  python3 "$HELPER" compare "$OUT/baseline" "$C/after" > "$C/after_compare.json" || STATUS=1
  if (( STATUS )); then echo "[cycle $cycle] a check failed: stopping" | tee -a "$OPS"; break; fi
done
snapshot "$OUT/final"
python3 "$HELPER" compare "$OUT/baseline" "$OUT/final" > "$OUT/final_compare.json" || STATUS=1

python3 - "$OUT" "$STATUS" <<'EOF' | tee "$OUT/summary.json"
import json, sys
from pathlib import Path
out, status = Path(sys.argv[1]), int(sys.argv[2])
res = {"status_ok": status == 0, "cycles": {}}
for c in sorted(out.glob("cycle*")):
    res["cycles"][c.name] = {f: json.loads((c / f"{f}.json").read_text())["ok"]
                             for f in ("lab_checks", "with_lab_compare", "after_compare") if (c / f"{f}.json").exists()}
res["final_compare_ok"] = json.loads((out / "final_compare.json").read_text())["ok"]
print(json.dumps(res, indent=1))
EOF
echo "evidence: $OUT"
exit "$STATUS"
