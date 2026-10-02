#!/usr/bin/env bash
# SentinelAI — pre-experiment safety gate (FAIL CLOSED).
#
# Exit 0 only if every check positively proves the system is in a known-safe
# state. Any failed, missing or indeterminate check => exit 1 ("REFUSE").
# Read-only: this script never modifies the system.
#
# Usage: scripts/safety_check.sh [--quiet]
# Tunables (env): SENTINEL_MIN_DISK_GB (20), SENTINEL_MIN_MEM_GB (4),
#                 SENTINEL_PHYS_NIC (enp0s31f6),
#                 SENTINEL_LOCAL_CONSOLE=1 to accept a non-SSH local console.
set -u
set -o pipefail

PHYS_NIC="${SENTINEL_PHYS_NIC:-enp0s31f6}"
MIN_DISK_GB="${SENTINEL_MIN_DISK_GB:-20}"
MIN_MEM_GB="${SENTINEL_MIN_MEM_GB:-4}"
EXPECTED_ROOT="${SENTINEL_ROOT:-$HOME/sentinelai}"
# Root qdiscs considered benign on the physical NIC (distribution defaults).
SAFE_QDISCS="fq_codel|mq|fq|pfifo_fast|noqueue"
REQUIRED_TOOLS="ip tc ss ethtool perf bpftool bpftrace stress-ng iperf3 pidstat docker git python3"
QUIET="${1:-}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
mkdir -p "$ROOT/logs"
LOG="$ROOT/logs/safety_check_$(date +%Y%m%dT%H%M%S)_$$.log"
FAILS=0

say()  { echo "$*" >> "$LOG"; [[ "$QUIET" == "--quiet" ]] || echo "$*"; }
pass() { say "PASS  $1 :: $2"; }
fail() { say "FAIL  $1 :: $2"; FAILS=$((FAILS+1)); }

say "# safety_check $(date -Is) host=$(hostname) user=$(id -un)"

# 1. Project location -------------------------------------------------------
exp_real="$(cd "$EXPECTED_ROOT" 2>/dev/null && pwd -P || echo MISSING)"
if [[ "$ROOT" == "$exp_real" && -d "$ROOT/.git" ]]; then
  pass project_root "$ROOT (git repo)"
else
  fail project_root "script root=$ROOT expected=$exp_real git=$([[ -d $ROOT/.git ]] && echo yes || echo no)"
fi

# 2. Kernel recorded ---------------------------------------------------------
kver="$(uname -r 2>/dev/null)"
if [[ -n "$kver" ]]; then pass kernel "$kver"; else fail kernel "uname -r failed"; fi

# 3. SSH environment ---------------------------------------------------------
if systemctl is-active --quiet ssh 2>/dev/null && ss -Htln 2>/dev/null | grep -qE '[:.]22\s'; then
  pass sshd "ssh.service active, listening on :22"
else
  fail sshd "ssh.service not active or not listening on :22 — remote recovery path unproven"
fi
if [[ -n "${SSH_CONNECTION:-}" ]]; then
  read -r cli_ip _ srv_ip srv_port <<< "$SSH_CONNECTION"
  route_dev="$(ip -o route get "$cli_ip" 2>/dev/null | grep -oP 'dev \K\S+')"
  if [[ "$route_dev" == "$PHYS_NIC" ]]; then
    pass ssh_session "client $cli_ip -> $srv_ip:$srv_port via $route_dev (protected NIC)"
  else
    fail ssh_session "client $cli_ip routes via '${route_dev:-?}', expected $PHYS_NIC — protection target uncertain"
  fi
elif [[ "${SENTINEL_LOCAL_CONSOLE:-0}" == "1" ]]; then
  pass ssh_session "no SSH_CONNECTION; SENTINEL_LOCAL_CONSOLE=1 explicitly asserted"
else
  fail ssh_session "SSH_CONNECTION not set and no explicit local-console assertion — cannot determine session path"
fi

# 4. Physical NIC integrity -------------------------------------------------
if ip -br link show dev "$PHYS_NIC" 2>/dev/null | grep -qw UP; then
  pass nic_up "$PHYS_NIC is UP"
else
  fail nic_up "$PHYS_NIC missing or not UP"
fi
def_dev="$(ip -o route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -1)"
if [[ "$def_dev" == "$PHYS_NIC" ]]; then
  pass default_route "$(ip -o route show default | head -1)"
else
  fail default_route "default route dev='${def_dev:-none}', expected $PHYS_NIC"
fi

qd="$(tc qdisc show dev "$PHYS_NIC" 2>&1)"; rc=$?
if [[ $rc -ne 0 || -z "$qd" ]]; then
  fail nic_qdisc "cannot read qdisc on $PHYS_NIC (rc=$rc)"
else
  # Every qdisc line on the physical NIC must be a benign default type.
  bad="$(echo "$qd" | awk '{print $2}' | grep -vxE "$SAFE_QDISCS" || true)"
  if [[ -z "$bad" ]]; then
    pass nic_qdisc "$(echo "$qd" | awk '{print $2}' | sort -u | tr '\n' ' ')"
  else
    fail nic_qdisc "non-default qdisc(s) on $PHYS_NIC: $(echo "$bad" | tr '\n' ' ')"
  fi
fi
for dir in ingress egress; do
  f="$(tc filter show dev "$PHYS_NIC" "$dir" 2>&1)"; rc=$?
  if [[ $rc -ne 0 ]]; then fail "nic_filter_$dir" "cannot read filters on $PHYS_NIC (rc=$rc)"
  elif [[ -z "$f" ]]; then pass "nic_filter_$dir" "none"
  else fail "nic_filter_$dir" "filters present on $PHYS_NIC $dir"; fi
done
if tc qdisc show 2>/dev/null | grep -q netem; then
  fail netem_global "netem qdisc present somewhere: $(tc qdisc show | grep netem | head -1)"
else
  pass netem_global "no netem qdisc on any interface"
fi

# 5. Resources ---------------------------------------------------------------
avail_gb="$(df -BG --output=avail "$ROOT" 2>/dev/null | tail -1 | tr -dc '0-9')"
if [[ -n "$avail_gb" && "$avail_gb" -ge "$MIN_DISK_GB" ]]; then
  pass disk "${avail_gb} GiB free (min $MIN_DISK_GB)"
else
  fail disk "${avail_gb:-?} GiB free < $MIN_DISK_GB"
fi
mem_kb="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null)"
if [[ -n "$mem_kb" ]] && (( mem_kb >= MIN_MEM_GB*1024*1024 )); then
  pass memory "$((mem_kb/1024)) MiB available (min ${MIN_MEM_GB} GiB)"
else
  fail memory "${mem_kb:-?} kB available < ${MIN_MEM_GB} GiB"
fi
swap_free_kb="$(awk '/^SwapFree:/{print $2}' /proc/meminfo)"
say "INFO  swap_free :: $((swap_free_kb/1024)) MiB; load=$(cut -d' ' -f1-3 /proc/loadavg)"

# 6. Required tools ----------------------------------------------------------
missing=""
for t in $REQUIRED_TOOLS; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
if [[ -z "$missing" ]]; then pass tools "all present: $REQUIRED_TOOLS"; else fail tools "missing:$missing"; fi

# Verdict --------------------------------------------------------------------
if (( FAILS == 0 )); then
  say "VERDICT SAFE (0 failures) log=$LOG"; exit 0
else
  say "VERDICT REFUSE ($FAILS failure(s)) log=$LOG"; exit 1
fi
