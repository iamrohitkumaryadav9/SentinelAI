#!/usr/bin/env bash
# SentinelAI Phase 1A — privileged, read-only eBPF/perf smoke tests.
#
# Run as:  sudo bash ~/sentinelai/scripts/privileged_smoke.sh
#
# What it does:  attaches short-lived (≈3 s) bpftrace probes, runs bpftool
#                feature/BTF queries and one perf stat. Every command has a
#                hard timeout. Nothing is persisted in the kernel.
# What it never does: change sysctls, load persistent/pinned BPF programs,
#                touch qdiscs, interfaces, routes, firewall or services.
set -u

if [[ $EUID -ne 0 ]]; then
  echo "REFUSING: must be run with sudo (needed for bpf()/tracefs)." >&2
  exit 2
fi

OWNER="${SUDO_USER:-iiitd}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/results/phase1a/privileged"
mkdir -p "$OUT"
SUMMARY="$OUT/summary.tsv"
: > "$SUMMARY"
LOG="$OUT/run.log"
exec > >(tee "$LOG") 2>&1

echo "# privileged_smoke start $(date -Is) kernel=$(uname -r) user=$OWNER"

record() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$SUMMARY"; }

# --- 0. Snapshot of loaded BPF programs before tests (leak check) ---------
PROGS_BEFORE=$(bpftool prog list 2>/dev/null | grep -c '^[0-9]\+:' || true)
echo "bpf programs loaded before tests: $PROGS_BEFORE"

# --- 1. bpftool feature probe (full, privileged) ---------------------------
timeout 60 bpftool feature probe > "$OUT/bpftool_feature_probe.txt" 2>&1
rc=$?
record bpftool_feature_probe "$([[ $rc -eq 0 ]] && echo PASS || echo FAIL)" "rc=$rc" "bpftool_feature_probe.txt ($(wc -l < "$OUT/bpftool_feature_probe.txt") lines)"

# --- 2. BTF dump ------------------------------------------------------------
ls -lh /sys/kernel/btf/vmlinux > "$OUT/btf.txt" 2>&1
timeout 60 bpftool btf dump file /sys/kernel/btf/vmlinux format raw 2>&1 | head -20 >> "$OUT/btf.txt"
if grep -q "STRUCT\|INT\|PTR" "$OUT/btf.txt"; then
  record btf_dump PASS "-" "btf.txt"
else
  record btf_dump FAIL "no BTF types in output" "btf.txt"
fi

# --- 3. Tracepoint presence in tracefs --------------------------------------
TP_DIR=/sys/kernel/tracing/events
for tp in sched/sched_switch sched/sched_wakeup irq/softirq_entry irq/softirq_exit \
          tcp/tcp_retransmit_skb sock/inet_sock_set_state skb/kfree_skb; do
  if [[ -f "$TP_DIR/$tp/format" ]]; then echo "tracefs has $tp"; else echo "tracefs MISSING $tp"; fi
done | tee "$OUT/tracefs_presence.txt"

# --- 4. bpftrace attach tests ----------------------------------------------
# Each probe: count events for ~3 s, then exit. Hard timeout 15 s.
# A probe "attaches" iff bpftrace reports "Attaching N probes" and exits 0.
bpftrace --version > "$OUT/bpftrace_version.txt" 2>&1

run_bt() {
  local name="$1" probe="$2" trigger="${3:-}"
  local f="$OUT/bt_${name}.txt"
  local t0 t1 rc
  t0=$(date +%s.%N)
  local tpid=""
  if [[ -n "$trigger" ]]; then
    ( sleep 1; eval "$trigger" ) >/dev/null 2>&1 &
    tpid=$!
  fi
  timeout 15 bpftrace -e "$probe { @events = count(); } interval:s:3 { exit(); }" > "$f" 2>&1
  rc=$?
  [[ -n "$tpid" ]] && wait "$tpid" 2>/dev/null
  t1=$(date +%s.%N)
  local dur; dur=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')
  local attached=no count=0
  grep -q "Attaching" "$f" && attached=yes
  count=$(awk -F': ' '/^@events:/{print $2}' "$f"); count=${count:-0}
  local status
  if [[ $rc -eq 0 && $attached == yes ]]; then status=PASS; else status=FAIL; fi
  local err="-"; [[ $status == FAIL ]] && err="rc=$rc $(grep -iE 'error|ERROR|fail' "$f" | head -1)"
  record "bpftrace:$name" "$status" "$err" "attached=$attached events=$count duration_s=$dur"
  echo "[$status] $name attached=$attached events=$count duration=${dur}s rc=$rc"
}

# Scheduler warm-up first (the canonical smoke test from the phase spec).
run_bt sched_switch        "tracepoint:sched:sched_switch"
run_bt sched_wakeup        "tracepoint:sched:sched_wakeup"
run_bt softirq_entry       "tracepoint:irq:softirq_entry"
run_bt softirq_exit        "tracepoint:irq:softirq_exit"
# Retransmits are rare on an idle LAN; a zero count with a successful attach is expected.
run_bt tcp_retransmit_skb  "tracepoint:tcp:tcp_retransmit_skb"
# Trigger: one loopback HTTP request to the local Ollama API (TCP state changes on lo only).
run_bt inet_sock_set_state "tracepoint:sock:inet_sock_set_state" "curl -s -m 2 http://127.0.0.1:11434/api/version"
run_bt kfree_skb           "tracepoint:skb:kfree_skb"

# --- 5. BCC sanity (one bundled tool, 1 interval of 1 s) --------------------
f="$OUT/bcc_runqlat.txt"
if command -v runqlat-bpfcc >/dev/null; then
  timeout 60 runqlat-bpfcc 1 1 > "$f" 2>&1; rc=$?
  if [[ $rc -eq 0 ]] && grep -q "usecs" "$f"; then record bcc_runqlat PASS "-" "bcc_runqlat.txt"
  else record bcc_runqlat FAIL "rc=$rc $(grep -iE 'error' "$f" | head -1)" "bcc_runqlat.txt"; fi
else
  record bcc_runqlat FAIL "runqlat-bpfcc not installed" "-"
fi

# --- 6. perf (privileged diagnostic only; paranoid is NOT changed) ---------
cat /proc/sys/kernel/perf_event_paranoid > "$OUT/perf_paranoid.txt"
timeout 10 perf stat -e context-switches,cpu-migrations sleep 1 > "$OUT/perf_stat_root.txt" 2>&1; rc=$?
if [[ $rc -eq 0 ]] && grep -q "context-switches" "$OUT/perf_stat_root.txt"; then
  record perf_stat_root PASS "-" "perf_stat_root.txt"
else
  record perf_stat_root FAIL "rc=$rc" "perf_stat_root.txt"
fi

# --- 7. Leak check ------------------------------------------------------------
sleep 1
PROGS_AFTER=$(bpftool prog list 2>/dev/null | grep -c '^[0-9]\+:' || true)
echo "bpf programs loaded after tests: $PROGS_AFTER"
if [[ "$PROGS_AFTER" -le "$PROGS_BEFORE" ]]; then
  record bpf_leak_check PASS "-" "before=$PROGS_BEFORE after=$PROGS_AFTER"
else
  record bpf_leak_check FAIL "programs remain loaded" "before=$PROGS_BEFORE after=$PROGS_AFTER"
fi

echo "# privileged_smoke end $(date -Is)"
echo
column -t -s $'\t' "$SUMMARY"
chown -R "$OWNER:$OWNER" "$OUT"
