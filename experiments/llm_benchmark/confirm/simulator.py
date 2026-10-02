"""Argument-respecting synthetic telemetry for the Phase 1B confirmatory experiment.

Each scenario defines a single host's state (overrides deep-merged onto a normal
baseline). Tools answer ONLY what was requested:
  * unknown host / interface / service / cpu -> explicit error, no data
  * get_network_metrics(interface=X)        -> only interface X (+ host TCP/kernel counters)
  * get_scheduler_latency(cpu, percentile)  -> that cpu / that percentile only
  * get_recent_logs(service, level, limit)  -> filtered by service, min level, limit
  * a tool marked unavailable                -> {"error": ...}
"""

import copy
import json

LEVELS = {"info": 0, "warn": 1, "error": 2}


def baseline_state(host):
    return {
        "host": host,
        "cores": 24,
        "cpu": {
            "util_pct": 35.0, "user_pct": 27.0, "system_pct": 5.0, "softirq_pct": 2.0, "iowait_pct": 0.5,
            "steal_pct": 0.0, "run_queue_len": 3, "load_avg_1m": 6.0,
            "context_switches_per_s": 22000, "migrations_per_s": 900,
            "softirq_by_type_pct": {"NET_RX": 1.2, "NET_TX": 0.2, "TIMER": 0.4, "RCU": 0.2},
            "per_cpu_hotspots": [],
            "top_processes": [{"name": "app-worker", "cpu_pct": 520}],
            "cgroups": [],
            "psi": {"cpu_some_avg10": 1.0, "memory_some_avg10": 0.1, "memory_full_avg10": 0.0, "io_some_avg10": 0.4},
        },
        "memory": {"total_mib": 64000, "available_mib": 38000, "swap_used_mib": 0, "swap_in_mib_per_s": 0.0,
                   "swap_out_mib_per_s": 0.0, "pgscan_direct_per_s": 0, "kswapd_cpu_pct": 0.1,
                   "major_faults_per_s": 2, "oom_kills_last_10m": 0},
        "net": {
            "interfaces": {"eth0": {"rx_pps": 45000, "tx_pps": 43000, "rx_mbps": 380, "tx_mbps": 350, "link_mbps": 10000,
                                    "rx_dropped_per_s": 0, "tx_dropped_per_s": 0, "rx_missed_per_s": 0,
                                    "rx_errors_per_s": 0, "ring_rx": "1024/4096", "rx_queues": 8}},
            "tcp": {"retrans_segs_per_s": 1.5, "baseline_retrans_segs_per_s": 1.5, "rto_timeouts_per_s": 0.0,
                    "rtt_ms_p50": 0.8, "baseline_rtt_ms_p50": 0.8, "cwnd_reductions_per_s": 0.2,
                    "established": 1800, "time_wait": 2400, "syn_retrans_per_s": 0.0,
                    "goodput_mbps": 360, "baseline_goodput_mbps": 360},
            "softnet": {"dropped_per_s": 0, "time_squeeze_per_s": 2},
            "kfree_skb": {"drops_per_s": 3, "top_reasons": {"NOT_SPECIFIED": 3}},
            "conntrack": {"count": 21000, "max": 262144, "drops_per_s": 0},
        },
        "sched": {"p99_ms_default": 0.4, "p99_ms_by_cpu": {}},
        "logs": {},
        "unavailable": {},
    }


def deep_merge(base, over):
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict) and not k.startswith("="):
            out[k] = deep_merge(out[k], v)
        else:
            out[k.lstrip("=")] = copy.deepcopy(v)   # "=key" replaces instead of merging
    return out


class Simulator:
    def __init__(self, scenario):
        self.s = deep_merge(baseline_state(scenario["host"]), scenario.get("state", {}))
        self.services = set(self.s["logs"]) | {scenario["service"]}

    # -- helpers -------------------------------------------------------------
    def _host_ok(self, host):
        if host is None or host == self.s["host"]:
            return None
        return {"error": f"unknown host '{host}'", "known_hosts": [self.s["host"]]}

    def _window(self, w):
        return {"window_seconds": w if isinstance(w, int) else 300}

    def _p99(self, cpu):
        return self.s["sched"]["p99_ms_by_cpu"].get(str(cpu), self.s["sched"]["p99_ms_default"])

    # -- tools ---------------------------------------------------------------
    def get_cpu_metrics(self, host=None, window_seconds=None):
        if "get_cpu_metrics" in self.s["unavailable"]:
            return {"error": self.s["unavailable"]["get_cpu_metrics"]}
        if (e := self._host_ok(host)):
            return e
        c = self.s["cpu"]
        return {"host": self.s["host"], **self._window(window_seconds), "cores": self.s["cores"], **c,
                "memory": self.s["memory"]}

    def get_network_metrics(self, host=None, interface=None, window_seconds=None):
        if "get_network_metrics" in self.s["unavailable"]:
            return {"error": self.s["unavailable"]["get_network_metrics"]}
        if (e := self._host_ok(host)):
            return e
        n = self.s["net"]
        ifaces = n["interfaces"]
        if interface is not None:
            if interface not in ifaces:
                return {"error": f"unknown interface '{interface}'", "known_interfaces": sorted(ifaces)}
            ifaces = {interface: ifaces[interface]}
        out = {"host": self.s["host"], **self._window(window_seconds), "interfaces": ifaces}
        for k in ("tcp", "softnet", "kfree_skb", "conntrack"):
            out[k] = n[k]
        return out

    def get_scheduler_latency(self, cpu=None, percentile=None):
        if "get_scheduler_latency" in self.s["unavailable"]:
            return {"error": self.s["unavailable"]["get_scheduler_latency"]}
        pct = percentile if percentile in (50, 90, 99) else 99
        scale = {50: 0.15, 90: 0.5, 99: 1.0}[pct]
        if cpu is not None:
            if not isinstance(cpu, int) or not 0 <= cpu < self.s["cores"]:
                return {"error": f"cpu {cpu} out of range 0-{self.s['cores'] - 1}"}
            return {"cpu": cpu, "percentile": pct, "run_queue_delay_ms": round(self._p99(cpu) * scale, 2)}
        vals = {c: round(self._p99(c) * scale, 2) for c in range(self.s["cores"])}
        worst = sorted(vals.items(), key=lambda kv: -kv[1])[:4]
        srt = sorted(vals.values())
        return {"percentile": pct, "all_cpus_median_ms": srt[len(srt) // 2],
                "worst_cpus": [{"cpu": c, "run_queue_delay_ms": v} for c, v in worst],
                "baseline_ms": round(0.4 * scale, 2)}

    def get_recent_logs(self, service=None, level=None, limit=None):
        if "get_recent_logs" in self.s["unavailable"]:
            return {"error": self.s["unavailable"]["get_recent_logs"]}
        if service not in self.services:
            return {"error": f"unknown service '{service}'", "known_services": sorted(self.services)}
        lines = self.s["logs"].get(service, [["info", "request completed status=200"]] * 3)
        lo = LEVELS.get(level, 0)
        sel = [f"{lv.upper()} {msg}" for lv, msg in lines if LEVELS[lv] >= lo]
        n = limit if isinstance(limit, int) and limit > 0 else 20
        return {"service": service, "level": level or "info", "lines": sel[:n]}

    def run_experiment(self, experiment=None, duration_seconds=None):
        return {"status": "refused", "reason": "production incident in progress; lab experiments are not available"}

    def call(self, name, args):
        fn = getattr(self, name, None) if name in TOOL_NAMES else None
        if fn is None:
            return {"error": f"unknown tool '{name}'"}
        try:
            return fn(**(args or {}))
        except TypeError as e:  # unexpected argument names
            return {"error": f"bad arguments for {name}: {e}"}


TOOL_NAMES = ("get_cpu_metrics", "get_network_metrics", "get_scheduler_latency", "get_recent_logs", "run_experiment")


def render(result):
    return json.dumps(result, separators=(",", ":"))
