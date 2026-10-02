#!/usr/bin/env python3
"""Generate the 48 confirmatory agent scenarios (deterministic) and validate gold labels.

Every gold label must satisfy the published labelling rule (LABEL_DEFINITIONS in
PROTOCOL.md / the agent system prompt). validate() checks each scenario's telemetry
against machine-checkable versions of those rules and refuses to write the dataset
if any scenario is inconsistent.
"""

import json
from pathlib import Path

from simulator import Simulator, baseline_state, deep_merge

HERE = Path(__file__).resolve().parent
NET, CPU, SCH, LOG = "get_network_metrics", "get_cpu_metrics", "get_scheduler_latency", "get_recent_logs"
INS = "INSUFFICIENT_EVIDENCE"
SC = []


def S(id, cat, sub, gold, required, host, service, incident, state, terms, distractors=(), why=""):
    SC.append({"id": id, "category": cat, "subcase": sub, "gold": gold, "required_any": list(required),
               "host": host, "service": service, "incident": incident, "state": state,
               "diagnostic_terms": list(terms), "distractors": list(distractors), "rationale": why})


def iface(**kw):
    base = baseline_state("x")["net"]["interfaces"]["eth0"]
    return {**base, **kw}


def logs(svc, *lines):
    return {"logs": {svc: [list(l) for l in lines]}}


def M(*dicts):
    out = {}
    for d in dicts:
        out = deep_merge(out, d)
    return out


# ============ A. TCP retransmission vs packet loss (18) ==========================
S("A01", "A_tcp_vs_loss", "1_retx_high_no_drops", "tcp_retransmissions", [NET], "db-2", "sync",
  "Service 'sync' on host db-2: replication to the remote replica slowed; p99 write latency rose from 12 ms to 310 ms. Investigate.",
  {"net": {"tcp": {"retrans_segs_per_s": 640, "baseline_retrans_segs_per_s": 2, "rto_timeouts_per_s": 18, "rtt_ms_p50": 140,
                   "baseline_rtt_ms_p50": 2.1, "cwnd_reductions_per_s": 120, "goodput_mbps": 90, "baseline_goodput_mbps": 410}}},
  ["retrans", "rtt", "640", "140"], [], "Retransmissions 320x baseline and RTT up; every local drop counter is zero.")
S("A02", "A_tcp_vs_loss", "1_retx_high_no_drops", "tcp_retransmissions", [NET], "api-3", "orders",
  "Service 'orders' on host api-3: calls to the payments cluster (10.4.0.0/24) show p99 latency of 2.4 s (baseline 180 ms). CPU on api-3 is 78%, which is normal for this host. Investigate.",
  M({"cpu": {"util_pct": 78.0, "user_pct": 66.0, "run_queue_len": 14}},
    {"net": {"tcp": {"retrans_segs_per_s": 310, "baseline_retrans_segs_per_s": 3, "rto_timeouts_per_s": 41, "rtt_ms_p50": 95,
                     "baseline_rtt_ms_p50": 1.0, "cwnd_reductions_per_s": 60}}}),
  ["retrans", "rto", "rtt", "310"], ["cpu_util 78% (normal)"], "Retransmissions/RTOs to one peer group; no local drops; CPU is a distractor.")
S("A03", "A_tcp_vs_loss", "1_retx_high_no_drops", "tcp_retransmissions", [NET], "cdn-4", "media",
  "Service 'media' on host cdn-4: download p99 rose 6x for clients in one region. Investigate.",
  M({"cpu": {"util_pct": 85.0, "user_pct": 70.0}},
    {"net": {"tcp": {"retrans_segs_per_s": 2100, "baseline_retrans_segs_per_s": 25, "rtt_ms_p50": 88, "baseline_rtt_ms_p50": 14,
                     "cwnd_reductions_per_s": 400}}}),
  ["retrans", "2100", "rtt"], ["cpu 85% (normal for host)"], "Remote-path retransmissions, no local drops.")
S("A04", "A_tcp_vs_loss", "6_congestion", "tcp_retransmissions", [NET], "lb-2", "gateway",
  "Service 'gateway' on host lb-2: p99 latency rises every afternoon peak, from 40 ms to 600 ms. Investigate.",
  {"net": {"interfaces": {"eth0": iface(tx_mbps=9450, rx_mbps=2100, tx_pps=820000)},
           "tcp": {"retrans_segs_per_s": 420, "baseline_retrans_segs_per_s": 4, "rtt_ms_p50": 65, "baseline_rtt_ms_p50": 1.0,
                   "cwnd_reductions_per_s": 900, "goodput_mbps": 9300, "baseline_goodput_mbps": 9300}}},
  ["retrans", "cwnd", "rtt", "9450", "link"], [], "Egress near 10G link capacity, RTT growth and cwnd reductions: congestion; no local drops.")
S("A05", "A_tcp_vs_loss", "6_congestion", "tcp_retransmissions", [NET], "agg-1", "search-aggregator",
  "Service 'search-aggregator' on host agg-1: fan-in queries to 200 shards have p99 of 1.9 s (baseline 90 ms) during bursts. Investigate.",
  {"net": {"tcp": {"retrans_segs_per_s": 880, "baseline_retrans_segs_per_s": 5, "rto_timeouts_per_s": 95, "rtt_ms_p50": 1.1,
                   "baseline_rtt_ms_p50": 0.9, "cwnd_reductions_per_s": 300, "syn_retrans_per_s": 0}}},
  ["rto", "retrans", "880", "95"], [], "Incast-style RTO bursts at fan-in; local drop counters zero.")
S("A06", "A_tcp_vs_loss", "6_congestion", "tcp_retransmissions", [NET], "vpn-1", "replicator",
  "Service 'replicator' on host vpn-1: cross-site replication over the WAN lags by 40 s; p99 RPC latency 3.1 s. Investigate.",
  {"net": {"interfaces": {"eth0": iface(tx_mbps=940, link_mbps=1000)},
           "tcp": {"retrans_segs_per_s": 260, "baseline_retrans_segs_per_s": 2, "rtt_ms_p50": 410, "baseline_rtt_ms_p50": 32,
                   "cwnd_reductions_per_s": 70, "goodput_mbps": 610, "baseline_goodput_mbps": 900}}},
  ["rtt", "retrans", "410", "260"], [], "Bufferbloat/WAN congestion: RTT 13x, retransmissions, no local drops.")
S("A07", "A_tcp_vs_loss", "2_drops_high_retx_low", "network_packet_loss", [NET], "dns-1", "resolver",
  "Service 'resolver' (UDP DNS) on host dns-1: clients see query timeouts; p99 resolution 1.1 s. Investigate.",
  {"net": {"interfaces": {"eth0": iface(rx_pps=1400000, rx_dropped_per_s=9100, rx_missed_per_s=9050, ring_rx="256/4096")},
           "tcp": {"retrans_segs_per_s": 3.0, "baseline_retrans_segs_per_s": 2.5}}},
  ["rx_missed", "rx_dropped", "ring", "9050", "9100"], [], "NIC ring overruns drop UDP packets; TCP retransmissions irrelevant/low.")
S("A08", "A_tcp_vs_loss", "2_drops_high_retx_low", "network_packet_loss", [NET], "edge-3", "ingest",
  "Service 'ingest' on host edge-3: telemetry ingestion loses events; p99 ack latency 700 ms. Investigate.",
  {"net": {"interfaces": {"eth0": iface(tx_dropped_per_s=5200)},
           "kfree_skb": {"drops_per_s": 5300, "top_reasons": {"QDISC_DROP": 5200, "NOT_SPECIFIED": 100}},
           "tcp": {"retrans_segs_per_s": 4.0, "baseline_retrans_segs_per_s": 2.0}}},
  ["qdisc_drop", "tx_dropped", "kfree_skb", "5200"], [], "Egress qdisc drops proven by kfree_skb; retransmissions low.")
S("A09", "A_tcp_vs_loss", "3_both_high", "network_packet_loss", [NET], "lb-1", "gateway",
  "Service 'gateway' on host lb-1: intermittent client timeouts; p99 rose 5x. Investigate.",
  {"net": {"interfaces": {"eth0": iface(rx_pps=900000, rx_dropped_per_s=7200, rx_missed_per_s=7150, ring_rx="256/4096")},
           "tcp": {"retrans_segs_per_s": 900, "baseline_retrans_segs_per_s": 6, "rtt_ms_p50": 1.3, "baseline_rtt_ms_p50": 0.9}}},
  ["rx_dropped", "rx_missed", "ring", "7200", "7150"], [], "Local RX drops proven; retransmissions are the consequence.")
S("A10", "A_tcp_vs_loss", "3_both_high", "network_packet_loss", [NET], "app-12", "checkout",
  "Service 'checkout' on host app-12: p99 latency rose from 90 ms to 1.3 s; error rate 3%. Investigate.",
  {"cpu": {"softirq_pct": 12.0, "softirq_by_type_pct": {"NET_RX": 11.0}},
   "net": {"softnet": {"dropped_per_s": 4100, "time_squeeze_per_s": 1900},
           "kfree_skb": {"drops_per_s": 4150, "top_reasons": {"CPU_BACKLOG": 4100, "NOT_SPECIFIED": 50}},
           "tcp": {"retrans_segs_per_s": 520, "baseline_retrans_segs_per_s": 3}}},
  ["softnet", "cpu_backlog", "4100", "dropped"], ["softirq 12% (moderate)"], "Backlog (softnet) drops proven by kfree_skb CPU_BACKLOG; retransmissions follow.")
S("A11", "A_tcp_vs_loss", "7_kernel_proven_loss", "network_packet_loss", [NET], "fw-2", "edge",
  "Service 'edge' on host fw-2: new connections intermittently fail; p99 connect time 3 s. Investigate.",
  {"net": {"conntrack": {"count": 262144, "max": 262144, "drops_per_s": 2500},
           "kfree_skb": {"drops_per_s": 2520, "top_reasons": {"NETFILTER_DROP": 2500, "NOT_SPECIFIED": 20}},
           "tcp": {"retrans_segs_per_s": 60, "baseline_retrans_segs_per_s": 3, "syn_retrans_per_s": 55}}},
  ["conntrack", "netfilter_drop", "2500", "262144"], [], "Conntrack table full; kernel drops proven.")
S("A12", "A_tcp_vs_loss", "7_kernel_proven_loss", "network_packet_loss", [NET], "store-5", "blob",
  "Service 'blob' on host store-5: reads from the storage network (interface eth1) have p99 of 2.2 s (baseline 40 ms). Investigate.",
  {"net": {"interfaces": {"eth0": iface(), "eth1": iface(rx_errors_per_s=3100, rx_dropped_per_s=3100, rx_mbps=4200)},
           "tcp": {"retrans_segs_per_s": 250, "baseline_retrans_segs_per_s": 2}}},
  ["eth1", "rx_errors", "3100"], [], "CRC/rx errors on eth1 (storage NIC); drops proven on that interface only.")
S("A13", "A_tcp_vs_loss", "4_neither_high", "application_bottleneck", [LOG], "web-7", "catalog",
  "Service 'catalog' on host web-7: p99 latency rose from 150 ms to 1.6 s. Network is suspected. Investigate.",
  M(logs("catalog", ("warn", "slow query 1480ms: SELECT * FROM products WHERE ... (missing index idx_products_category)"),
         ("warn", "slow query 1510ms: SELECT * FROM products WHERE ..."), ("info", "request completed status=200"))),
  ["slow query", "index", "1480"], ["network suspected by reporter"], "All kernel/network counters normal; logs show slow queries.")
S("A14", "A_tcp_vs_loss", "4_neither_high", INS, [], "web-9", "profile",
  "Service 'profile' on host web-9: p99 latency rose from 120 ms to 380 ms. Network is suspected. Investigate.",
  {}, [], ["network suspected by reporter"], "Everything normal including logs: no identifiable cause.")
S("A15", "A_tcp_vs_loss", "5_insufficient", INS, [], "app-20", "billing",
  "Service 'billing' on host app-20: clients report timeouts; p99 6x yesterday. Investigate.",
  M({"unavailable": {NET: "metrics unavailable: node exporter on app-20 is down"}},
    logs("billing", ("warn", "upstream connection reset by peer"), ("info", "request completed status=200"))),
  [], ["connection reset warnings"], "Network data missing; CPU normal; resets alone do not identify a cause.")
S("A16", "A_tcp_vs_loss", "5_insufficient", INS, [], "vm-14", "notifications",
  "Service 'notifications' on host vm-14: delivery latency doubled. Investigate.",
  {"net": {"interfaces": {"=eth0": {"error": "interface statistics not supported by virtio driver build"}},
           "tcp": {"retrans_segs_per_s": 8.0, "baseline_retrans_segs_per_s": 2.0},
           "softnet": {"error": "softnet_stat unavailable in this container"},
           "kfree_skb": {"error": "kfree_skb tracer not deployed"}}},
  ["retrans", "unavailable"], [], "Retransmissions mildly elevated; drop counters unavailable; latency impact unexplained.")
S("A17", "A_tcp_vs_loss", "8_cannot_distinguish", INS, [], "vm-22", "ledger",
  "Service 'ledger' on host vm-22: p99 commit latency rose from 30 ms to 900 ms. Investigate.",
  {"net": {"interfaces": {"=eth0": {"error": "interface statistics not supported in this VM"}},
           "tcp": {"retrans_segs_per_s": 700, "baseline_retrans_segs_per_s": 3, "rtt_ms_p50": 22, "baseline_rtt_ms_p50": 1.0},
           "softnet": {"error": "softnet_stat unavailable"}, "kfree_skb": {"error": "kfree_skb tracer not deployed"}}},
  ["retrans", "unavailable", "cannot"], [], "Retransmissions high but every drop counter unavailable: loss vs congestion undecidable.")
S("A18", "A_tcp_vs_loss", "8_cannot_distinguish", INS, [], "db-9", "orders-db",
  "Service 'orders-db' on host db-9 (traffic on bonded interface bond0): p99 query latency rose 8x. Investigate.",
  {"net": {"interfaces": {"eth0": iface(rx_pps=1200, tx_pps=1100), "=bond0": {"error": "statistics for bond0 unavailable (bonding driver)"}},
           "tcp": {"retrans_segs_per_s": 480, "baseline_retrans_segs_per_s": 2},
           "softnet": {"error": "softnet_stat unavailable"}, "kfree_skb": {"error": "kfree_skb tracer not deployed"}}},
  ["bond0", "unavailable", "retrans"], ["eth0 counters clean (idle interface)"], "Retransmissions high; the data interface's drop counters are unavailable; eth0 is idle.")

# ============ B. CPU scheduling / throttling (7) ================================
S("B01", "B_cpu", "runqueue_contention", "cpu_contention", [CPU, SCH], "web-1", "search",
  "Service 'search' on host web-1: p99 latency rose from 80 ms to 1.4 s over 10 minutes. Investigate.",
  {"cpu": {"util_pct": 99.0, "user_pct": 88.0, "run_queue_len": 44, "load_avg_1m": 43.0,
           "top_processes": [{"name": "search-worker", "cpu_pct": 1190}, {"name": "batch-reindex", "cpu_pct": 1050}]},
   "sched": {"p99_ms_default": 38.0}},
  ["run_queue", "99", "44", "38", "batch-reindex"], [], "Saturated CPUs, run queue 44 on 24 cores, run-queue delay 38 ms.")
S("B02", "B_cpu", "affinity_hotspot", "cpu_contention", [CPU, SCH], "web-3", "api",
  "Service 'api' (cpuset 0-3) on host web-3: p99 doubled. Host CPU utilization is only 30%. Investigate.",
  {"cpu": {"util_pct": 30.0, "per_cpu_hotspots": [{"cpus": "0-3", "util_pct": 100.0}],
           "top_processes": [{"name": "api (cpuset 0-3)", "cpu_pct": 395}, {"name": "log-shipper (cpuset 0-3)", "cpu_pct": 180}]},
   "sched": {"p99_ms_by_cpu": {"0": 25.0, "1": 26.0, "2": 24.5, "3": 25.5}}},
  ["0-3", "100", "25", "cpuset"], ["host util 30%"], "Pinned CPUs saturated by a co-pinned process; only those CPUs show run-queue delay.")
S("B03", "B_cpu", "context_switch_storm", "cpu_contention", [CPU, SCH], "mq-2", "broker",
  "Service 'broker' on host mq-2: p99 publish latency rose from 5 ms to 140 ms. Investigate.",
  {"cpu": {"util_pct": 97.0, "system_pct": 31.0, "run_queue_len": 31, "context_switches_per_s": 480000, "migrations_per_s": 61000},
   "sched": {"p99_ms_default": 12.0}},
  ["context_switches", "480000", "run_queue", "12"], [], "Saturated CPUs with switch/migration storm and 12 ms run-queue delay.")
S("B04", "B_cpu", "hypervisor_steal", "cpu_contention", [CPU, SCH], "vm-31", "render",
  "Service 'render' on host vm-31: job latency p99 tripled. Investigate.",
  {"cpu": {"util_pct": 64.0, "steal_pct": 36.0, "run_queue_len": 30, "cores": 24}, "sched": {"p99_ms_default": 15.0}},
  ["steal", "36", "run_queue", "15"], [], "Hypervisor steal 36%: runnable tasks wait for CPU.")
S("B05", "B_cpu", "cgroup_throttling", "cpu_throttling", [CPU], "k8s-3", "pricing",
  "Service 'pricing' (container) on host k8s-3: p99 rose from 30 ms to 700 ms after a deploy; p50 unchanged. Investigate.",
  {"cpu": {"util_pct": 28.0, "cgroups": [{"name": "pricing", "cpu_max": "50000 100000", "nr_periods_delta": 6000,
                                          "nr_throttled_delta": 4100, "throttled_usec_delta": 212000000}]}},
  ["throttl", "nr_throttled", "4100", "cpu_max", "50000"], [], "Quota throttling 68% of periods; host not saturated.")
S("B06", "B_cpu", "cgroup_throttling", "cpu_throttling", [CPU], "k8s-7", "auth",
  "Service 'auth' on host k8s-7: logins time out at peak. Host CPU is 88%, which is normal for this host at peak. Investigate.",
  {"cpu": {"util_pct": 88.0, "user_pct": 76.0, "run_queue_len": 18,
           "cgroups": [{"name": "auth", "cpu_max": "100000 100000", "nr_periods_delta": 6000, "nr_throttled_delta": 5400,
                        "throttled_usec_delta": 390000000}]}},
  ["throttl", "5400", "nr_throttled", "cpu_max"], ["host util 88% (normal at peak)"], "Throttled 90% of periods; run queue below core count and run-queue delay normal.")
S("B07", "B_cpu", "cgroup_throttling", "cpu_throttling", [CPU], "k8s-9", "thumbnailer",
  "Service 'thumbnailer' on host k8s-9: p99 rose 12x while p50 stayed flat. Investigate.",
  {"cpu": {"util_pct": 22.0, "cgroups": [{"name": "thumbnailer", "cpu_max": "30000 100000", "nr_periods_delta": 6000,
                                          "nr_throttled_delta": 3300, "throttled_usec_delta": 140000000}]}},
  ["throttl", "3300", "30000"], [], "300m CPU limit throttled 55% of periods.")

# ============ C. Network / softirq overload (6) =================================
S("C01", "C_softirq", "single_queue_net_rx", "softirq_overload", [CPU, SCH], "ing-2", "ingest",
  "Service 'ingest' on host ing-2: requests handled on CPU 3 have 20x higher p99 than other CPUs. Investigate.",
  {"cpu": {"util_pct": 38.0, "softirq_by_type_pct": {"NET_RX": 9.0},
           "per_cpu_hotspots": [{"cpu": 3, "util_pct": 100.0, "softirq_pct": 93.0}],
           "top_processes": [{"name": "ksoftirqd/3", "cpu_pct": 64}]},
   "net": {"interfaces": {"eth0": iface(rx_pps=1250000, rx_queues=1)}, "softnet": {"dropped_per_s": 0, "time_squeeze_per_s": 900}},
   "sched": {"p99_ms_by_cpu": {"3": 40.0}}},
  ["softirq", "93", "cpu 3", "net_rx", "ksoftirqd"], [], "NET_RX softirq saturates CPU 3; no drops.")
S("C02", "C_softirq", "irq_affinity", "softirq_overload", [CPU, SCH], "cache-1", "kv",
  "Service 'kv' on host cache-1: p999 latency spikes to 300 ms on a subset of requests. Investigate.",
  {"cpu": {"util_pct": 31.0, "per_cpu_hotspots": [{"cpu": 0, "util_pct": 99.0, "softirq_pct": 89.0}],
           "top_processes": [{"name": "ksoftirqd/0", "cpu_pct": 71}]},
   "net": {"softnet": {"time_squeeze_per_s": 650}}, "sched": {"p99_ms_by_cpu": {"0": 33.0}}},
  ["softirq", "89", "cpu 0", "ksoftirqd"], [], "All NIC IRQs on CPU 0: softirq saturation; no drops.")
S("C03", "C_softirq", "napi_busy", "softirq_overload", [CPU, SCH], "lb-5", "proxy",
  "Service 'proxy' on host lb-5: p99 rose from 3 ms to 45 ms at 2M packets/s. Investigate.",
  {"cpu": {"util_pct": 47.0, "softirq_pct": 34.0, "softirq_by_type_pct": {"NET_RX": 33.0},
           "per_cpu_hotspots": [{"cpus": "0-7", "util_pct": 98.0, "softirq_pct": 82.0}]},
   "memory": {"available_mib": 5200},
   "net": {"interfaces": {"eth0": iface(rx_pps=2100000)}, "softnet": {"time_squeeze_per_s": 1400}},
   "sched": {"p99_ms_by_cpu": {str(c): 18.0 for c in range(8)}}},
  ["softirq", "82", "0-7", "net_rx"], ["available memory 5.2 GiB (PSI zero)"], "NET_RX/NAPI load saturates CPUs 0-7; memory is a distractor.")
S("C04", "C_softirq", "small_packet_flood", "softirq_overload", [CPU, SCH], "dns-4", "resolver",
  "Service 'resolver' on host dns-4: query p99 rose 9x during a traffic surge of small packets. Investigate.",
  {"cpu": {"util_pct": 29.0, "per_cpu_hotspots": [{"cpus": "5-6", "util_pct": 100.0, "softirq_pct": 88.0}]},
   "net": {"interfaces": {"eth0": iface(rx_pps=1900000)}, "softnet": {"time_squeeze_per_s": 2200}},
   "sched": {"p99_ms_by_cpu": {"5": 28.0, "6": 29.0}}},
  ["softirq", "88", "5-6", "time_squeeze"], [], "Small-packet flood saturates CPUs 5-6 in softirq; no drops.")
S("C05", "C_softirq", "softirq_with_drops", "network_packet_loss", [NET], "ing-6", "ingest",
  "Service 'ingest' on host ing-6: p99 rose 15x and some client batches are lost. Investigate.",
  {"cpu": {"per_cpu_hotspots": [{"cpu": 2, "util_pct": 100.0, "softirq_pct": 95.0}]},
   "net": {"softnet": {"dropped_per_s": 6000, "time_squeeze_per_s": 3100},
           "kfree_skb": {"drops_per_s": 6040, "top_reasons": {"CPU_BACKLOG": 6000, "NOT_SPECIFIED": 40}}},
   "sched": {"p99_ms_by_cpu": {"2": 37.0}}},
  ["softnet", "dropped", "6000", "cpu_backlog"], ["softirq 95% on CPU 2"], "Softirq saturation AND proven backlog drops: rule says drops proven -> network_packet_loss.")
S("C06", "C_softirq", "weak_softirq_signal", INS, [], "web-12", "frontend",
  "Service 'frontend' on host web-12: one p999 spike to 250 ms was seen in the last hour. Investigate.",
  {"cpu": {"softirq_pct": 9.0, "softirq_by_type_pct": {"NET_RX": 8.0}}},
  [], ["softirq 9% (baseline 5%)"], "Slightly elevated softirq without hotspot, drops or scheduling delay: inconclusive.")

# ============ D. Memory pressure (5) ============================================
S("D01", "D_memory", "reclaim", "memory_pressure", [CPU, LOG], "app-4", "reports",
  "Service 'reports' on host app-4: requests stall for seconds. Investigate.",
  {"cpu": {"system_pct": 27.0, "psi": {"memory_some_avg10": 52.0, "memory_full_avg10": 24.0},
           "top_processes": [{"name": "kswapd0", "cpu_pct": 97}]},
   "memory": {"available_mib": 600, "pgscan_direct_per_s": 180000, "kswapd_cpu_pct": 97}},
  ["psi", "52", "kswapd", "pgscan", "600"], [], "Memory PSI 52/24, direct reclaim, kswapd saturated.")
S("D02", "D_memory", "swapping", "memory_pressure", [CPU, LOG], "db-3", "warehouse",
  "Service 'warehouse' on host db-3: query latency rose 10x. Investigate.",
  {"cpu": {"iowait_pct": 14.0, "psi": {"memory_some_avg10": 38.0, "memory_full_avg10": 15.0}},
   "memory": {"available_mib": 1200, "swap_used_mib": 30000, "swap_in_mib_per_s": 150.0, "major_faults_per_s": 9000}},
  ["swap", "150", "major_faults", "psi"], [], "Heavy swap-in and major faults.")
S("D03", "D_memory", "oom_kills", "memory_pressure", [CPU, LOG], "k8s-4", "analytics",
  "Service 'analytics' on host k8s-4: the service restarted 4 times in 10 minutes. Investigate.",
  M({"memory": {"oom_kills_last_10m": 4}},
    logs("analytics", ("error", "kernel: Memory cgroup out of memory: Killed process 4321 (analytics-jvm)"),
         ("info", "service restarted"), ("error", "kernel: Memory cgroup out of memory: Killed process 4410 (analytics-jvm)"))),
  ["oom", "out of memory", "killed"], [], "Cgroup OOM kills.")
S("D04", "D_memory", "allocation_stalls", "memory_pressure", [CPU, LOG], "cache-3", "session",
  "Service 'session' on host cache-3: p99 rose 20x. CPU system time is high. Investigate.",
  M({"cpu": {"system_pct": 30.0, "util_pct": 62.0, "psi": {"memory_some_avg10": 31.0, "memory_full_avg10": 9.0}},
     "memory": {"available_mib": 900, "pgscan_direct_per_s": 95000}},
    logs("session", ("warn", "kernel: page allocation stall for 3120ms, order:2"), ("info", "request completed status=200"))),
  ["allocation stall", "psi", "31", "pgscan"], ["system cpu 30% (caused by reclaim)"], "Allocation stalls with memory PSI 31.")
S("D05", "D_memory", "page_cache_distractor", "cpu_contention", [CPU, SCH], "batch-2", "etl",
  "Service 'etl' on host batch-2: job p99 runtime doubled. Free memory looks very low. Investigate.",
  {"cpu": {"util_pct": 99.0, "run_queue_len": 52, "top_processes": [{"name": "etl-worker", "cpu_pct": 1300}, {"name": "backup-compress", "cpu_pct": 980}]},
   "memory": {"available_mib": 41000, "total_mib": 64000}, "sched": {"p99_ms_default": 41.0}},
  ["run_queue", "52", "41", "99"], ["'free' memory low but available 41 GiB, PSI ~0"], "Memory is page cache (available high, PSI 0); CPUs saturated.")

# ============ E. Application bottleneck (5) =====================================
S("E01", "E_application", "db_pool", "application_bottleneck", [LOG], "app-7", "orders",
  "Service 'orders' on host app-7: p99 rose from 200 ms to 4 s. Investigate.",
  logs("orders", ("error", "db pool exhausted: 50/50 connections in use, waited 3800ms"), ("error", "db pool exhausted: 50/50 connections in use"),
       ("info", "request completed status=200")),
  ["pool exhausted", "50/50"], [], "Connection-pool exhaustion; kernel metrics normal.")
S("E02", "E_application", "lock_contention", "application_bottleneck", [LOG], "app-9", "inventory",
  "Service 'inventory' on host app-9: p99 rose 9x; CPU is low. Investigate.",
  M({"cpu": {"util_pct": 12.0}},
    logs("inventory", ("warn", "lock wait on stock_mutex 850ms (holder: reconcile-job)"), ("warn", "lock wait on stock_mutex 910ms"))),
  ["lock", "stock_mutex", "850"], [], "Application lock contention.")
S("E03", "E_application", "slow_dependency", "application_bottleneck", [LOG], "api-8", "checkout",
  "Service 'checkout' on host api-8: p99 rose to 2.5 s. Network is suspected. Investigate.",
  logs("checkout", ("error", "call to fraud-check took 2300ms (timeout 2000ms)"), ("error", "call to fraud-check took 2410ms"),
       ("info", "request completed status=200")),
  ["fraud-check", "2300", "timeout"], ["network suspected by reporter"], "Slow downstream dependency; network/TCP normal.")
S("E04", "E_application", "thread_pool", "application_bottleneck", [LOG], "web-11", "search-api",
  "Service 'search-api' on host web-11: p99 rose 7x. CPU utilization is 92%. Investigate.",
  M({"cpu": {"util_pct": 92.0, "user_pct": 84.0, "run_queue_len": 8}},
    logs("search-api", ("error", "request rejected: worker pool saturated (64/64 busy, queue 500/500)"),
         ("warn", "worker pool saturated (64/64 busy)"))),
  ["worker pool", "64/64", "saturated"], ["cpu 92% but run queue 8 and run-queue delay normal"], "Worker-pool saturation; CPUs busy but not contended.")
S("E05", "E_application", "request_queue", "application_bottleneck", [LOG], "app-15", "uploads",
  "Service 'uploads' on host app-15: p99 upload latency rose 6x. Investigate.",
  M({"net": {"tcp": {"retrans_segs_per_s": 5.0, "baseline_retrans_segs_per_s": 3.0}}},
    logs("uploads", ("error", "virus-scan queue full (1000/1000); upload waited 4100ms"), ("warn", "virus-scan queue depth 990"))),
  ["virus-scan", "queue full", "4100"], ["retrans 5/s vs 3/s baseline"], "Application work queue full; minor retransmissions are a distractor.")

# ============ F. Insufficient / ambiguous (7) ===================================
S("F01", "F_insufficient", "all_normal", INS, [], "web-5", "profile",
  "Service 'profile' on host web-5: p99 increased from 120 ms to 400 ms. Investigate.", {}, [], [], "All normal, logs clean.")
S("F02", "F_insufficient", "data_missing", INS, [], "app-9b", "billing",
  "Service 'billing' on host app-9b: p99 is 6x higher than yesterday. Investigate.",
  {"unavailable": {CPU: "metrics unavailable: node exporter down", NET: "metrics unavailable: node exporter down",
                   SCH: "tracer not deployed on this host"}}, [], [], "Only logs available, and they are normal.")
S("F03", "F_insufficient", "weak_conflicting", INS, [], "web-8", "catalog",
  "Service 'catalog' on host web-8: a single customer reported slowness yesterday; dashboards show p99 in the normal range today. Investigate.",
  M({"cpu": {"util_pct": 58.0, "psi": {"memory_some_avg10": 0.4}}, "net": {"tcp": {"retrans_segs_per_s": 3.0, "baseline_retrans_segs_per_s": 2.5}}},
    logs("catalog", ("warn", "slow request 1200ms at 03:12 (single occurrence)"), ("info", "request completed status=200"))),
  [], ["single slow request log"], "Weak, conflicting, non-recurring evidence.")
S("F04", "F_insufficient", "outside_retention", INS, [], "web-14", "maps",
  "Service 'maps' on host web-14: a latency spike was reported 3 days ago; metrics retention is 24 hours. Investigate.",
  {}, [], [], "Current metrics normal; the incident window is not observable.")
S("F05", "F_insufficient", "logs_only_generic", INS, [], "app-30", "reports",
  "Service 'reports' on host app-30: p99 doubled. Investigate.",
  M({"unavailable": {CPU: "metrics unavailable", NET: "metrics unavailable", SCH: "tracer not deployed"}},
    logs("reports", ("warn", "request slow: 2100ms"), ("warn", "request slow: 1900ms"))),
  [], ["generic slow-request logs"], "Logs restate the symptom; no causal data.")
S("F06", "F_insufficient", "multiple_moderate", INS, [], "app-33", "pricing-api",
  "Service 'pricing-api' on host app-33: p99 rose 2x. Investigate.",
  {"cpu": {"util_pct": 61.0, "softirq_pct": 7.0,
           "cgroups": [{"name": "pricing-api", "cpu_max": "200000 100000", "nr_periods_delta": 6000, "nr_throttled_delta": 120,
                        "throttled_usec_delta": 900000}]},
   "net": {"tcp": {"retrans_segs_per_s": 9.0, "baseline_retrans_segs_per_s": 3.0}}, "sched": {"p99_ms_default": 1.1}},
  [], ["2% throttled periods", "retrans 3x of a low baseline", "softirq 7%"], "Several minor deviations; none sufficient.")
S("F07", "F_insufficient", "irrelevant_interface_drops", INS, [], "app-40", "api",
  "Service 'api' on host app-40 (service traffic uses interface eth1): p99 rose 3x. Investigate.",
  {"net": {"interfaces": {"eth0": iface(rx_pps=900, tx_pps=850, rx_dropped_per_s=150, rx_mbps=2), "eth1": iface()}}},
  [], ["drops on eth0 (management interface, idle)"], "Drops only on the unused management interface; service interface clean.")


# ============ validation =========================================================
def _num(x):
    return x if isinstance(x, (int, float)) else 0


def facts(sc):
    s = Simulator(sc).s
    c, m, n = s["cpu"], s["memory"], s["net"]
    ifs = [v for v in n["interfaces"].values() if isinstance(v, dict) and "error" not in v]
    drops = max([0] + [_num(i.get(k)) for i in ifs for k in ("rx_dropped_per_s", "tx_dropped_per_s", "rx_missed_per_s", "rx_errors_per_s")])
    kf = n["kfree_skb"]
    kdrops = _num(kf.get("drops_per_s")) if "error" not in kf else 0
    sn = _num(n["softnet"].get("dropped_per_s")) if "error" not in n["softnet"] else 0
    ct = _num(n["conntrack"].get("drops_per_s"))
    tcp = n["tcp"]
    retx_ratio = tcp["retrans_segs_per_s"] / max(tcp["baseline_retrans_segs_per_s"], 0.1)
    sched_max = max([s["sched"]["p99_ms_default"]] + list(s["sched"]["p99_ms_by_cpu"].values()))
    hot_soft = max([0] + [_num(h.get("softirq_pct")) for h in c["per_cpu_hotspots"]])
    hot_util = max([0] + [_num(h.get("util_pct")) for h in c["per_cpu_hotspots"]])
    thr = max([0] + [g["nr_throttled_delta"] / g["nr_periods_delta"] for g in c["cgroups"]])
    app_err = any(lv in ("warn", "error") for lines in s["logs"].values() for lv, _ in lines)
    drop_counters_complete = ("error" not in kf) and ("error" not in n["softnet"]) and all(
        "error" not in i for i in n["interfaces"].values())
    return dict(drops=max(drops, kdrops if kdrops > 50 else 0, sn, ct), retx_ratio=retx_ratio, sched=sched_max,
                hot_soft=hot_soft, hot_util=hot_util, throttle=thr, util=c["util_pct"], steal=c["steal_pct"],
                runq_over=c["run_queue_len"] / s["cores"], psi_mem=c["psi"]["memory_some_avg10"],
                oom=m["oom_kills_last_10m"], swap_in=m["swap_in_mib_per_s"], pgscan=m["pgscan_direct_per_s"],
                app_err=app_err, unavailable=set(s["unavailable"]), drop_counters_complete=drop_counters_complete)


def rule_labels(f):
    """Labels whose machine-checkable rule is satisfied by the telemetry."""
    L = set()
    if f["drops"] >= 1000:
        L.add("network_packet_loss")
    if f["retx_ratio"] >= 10 and f["drops"] < 100:
        L.add("tcp_retransmissions")
    if f["hot_soft"] >= 80 and f["drops"] < 100:
        L.add("softirq_overload")
    if f["throttle"] >= 0.3 and f["util"] < 90 and f["sched"] < 2:
        L.add("cpu_throttling")
    if f["sched"] >= 10 and (f["runq_over"] > 1 or f["hot_util"] >= 95 or f["steal"] >= 20) and f["hot_soft"] < 50:
        L.add("cpu_contention")
    if f["psi_mem"] >= 20 or f["oom"] > 0 or f["swap_in"] >= 50 or f["pgscan"] >= 50000:
        L.add("memory_pressure")
    kernel_normal = (f["drops"] < 100 and f["retx_ratio"] < 4 and f["sched"] < 2 and f["psi_mem"] < 5 and f["throttle"] < 0.1
                     and f["hot_soft"] < 50 and f["oom"] == 0)
    if kernel_normal and f["app_err"] and not f["unavailable"]:
        L.add("application_bottleneck")
    return L


def validate():
    errs = []
    ids = [s["id"] for s in SC]
    assert len(ids) == len(set(ids)), "duplicate ids"
    for sc in SC:
        f = facts(sc)
        L = rule_labels(f)
        g = sc["gold"]
        sc_logs = Simulator(sc).s["logs"]
        if g == INS:
            # insufficient: no fault rule may fire cleanly, OR the deciding data is unavailable
            if L - {"application_bottleneck"} and not (f["unavailable"] or not f["drop_counters_complete"]):
                errs.append(f"{sc['id']}: gold INSUFFICIENT but rules fire {L}")
            if "application_bottleneck" in L and any("slow" not in m and "single" not in m for lines in sc_logs.values()
                                                     for lv, m in lines if lv != "info"):
                errs.append(f"{sc['id']}: gold INSUFFICIENT but logs look causal")
        else:
            if g not in L:
                errs.append(f"{sc['id']}: gold {g} not supported by rules {L} facts={f}")
            if g == "tcp_retransmissions" and not f["drop_counters_complete"]:
                errs.append(f"{sc['id']}: tcp_retransmissions requires all drop counters to be readable")
            if len(L) > 1 and not (g == "network_packet_loss" and L <= {"network_packet_loss", "softirq_overload", "cpu_contention"}):
                errs.append(f"{sc['id']}: ambiguous, rules fire {L}")
    return errs


def main():
    errs = validate()
    if errs:
        raise SystemExit("DATASET INVALID:\n" + "\n".join(errs))
    from collections import Counter
    out = {"version": 1, "n": len(SC), "label_counts": dict(Counter(s["gold"] for s in SC)),
           "category_counts": dict(Counter(s["category"] for s in SC)), "scenarios": SC}
    (HERE / "scenarios.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: out[k] for k in ("n", "label_counts", "category_counts")}, indent=1))
    print("insufficient share:", round(out["label_counts"][INS] / out["n"], 3))


if __name__ == "__main__":
    main()
