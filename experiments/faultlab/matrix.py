"""Phase 1C M6 matrix generator (design §6.4, §6.6, §6.7; pilot design §5.3, §8; FZ-M6-PLAN; AMD-29).

    python experiments/faultlab/matrix.py generate [--out datasets/faultlab/v1/matrix.json]
    python experiments/faultlab/matrix.py check datasets/faultlab/v1/matrix.json

Deterministic: the master seed and the approved decisions (FZ-INTENSITY levels, FZ-M6-PLAN, FZ-OV, FZ-Q5) give a
byte-identical matrix. Its SHA-256 is committed before any collection, and the file is add-only (AMD-29).

- The run is the unit of independence: every run has one split (train, test, sens, pi3).
- I2 of every graded single-fault mechanism is test-only (design §6.6); single-level mechanisms (memory, pool) run at
  their single level in both splits (P-2).
- A class's seeds are spread evenly over its mechanisms (P-1, P-8: packet loss = netem on A only).
- SENS runs at I0 = half the strength of I1 (P-3): x 0.5 where higher is stronger, x 2 where lower is stronger.
- OOD is deferred (P-4). PI-3 (U-4) adds 6 quota runs in batch 1.
- Seeds 100001.. are disjoint from the pilot's 900000..999999. Run order is shuffled by the master seed, so no batch
  holds one family; batches are contiguous slices of that order.
"""
import argparse
import hashlib
import json
import random
import sys
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[2]
DECISIONS = ROOT / "docs" / "PHASE_1C_FREEZE1_DECISIONS.json"
DEFAULT_OUT = ROOT / "datasets" / "faultlab" / "v1" / "matrix.json"
FORMAT = "sentinelai.faultlab.m6.matrix.v1"
MASTER_SEED = 20261013
SEED_BASE = 100001                       # disjoint from the pilot seeds (900000..999999)
BATCHES = 6
MIN_TEST_PER_CLASS = 10                  # design §7.5 G-Q2 (Q-5 provisions 12)

# class -> mechanisms (P-1; P-8: police is not used in M6)
CLASSES = {
    "cpu_contention": ["cpu_contender"],
    "cpu_throttling": ["cpu_quota"],
    "network_packet_loss": ["netem_loss_a_egress"],
    "tcp_retransmissions": ["netem_loss_r_egress", "netem_rate_r"],
    "memory_pressure": ["memory_max"],
    "application_bottleneck": ["app_dependency_delay", "app_lock", "app_pool"],
}
# fault -> (FZ-INTENSITY level key, stronger direction)
LEVEL_KEY = {
    "cpu_contender": ("cpu_contender_weight", "higher"), "cpu_quota": ("cpu_quota_us", "lower"),
    "netem_loss_a_egress": ("netem_loss_a_egress_pct", "higher"), "police_a_ingress": ("police_a_ingress_kbit", "lower"),
    "netem_loss_r_egress": ("netem_loss_r_egress_pct", "higher"), "netem_rate_r": ("netem_rate_r_kbit", "lower"),
    "memory_max": ("memory_max_mib", "lower"), "app_dependency_delay": ("app_dependency_delay_ms", "higher"),
    "app_lock": ("app_lock_hold_us", "higher"), "app_pool": ("app_pool_size", "lower"),
    "ov4_udp_flood": ("ov4_udp_flood_pps", "higher"), "ov5_page_cache_fill": ("ov5_page_cache_fill_mib", "higher"),
}
FLOAT_UNITS = {"netem_loss_a_egress", "netem_loss_r_egress"}
TRAIN_GROUPS = (("I1", "I3"), 4)                                # 8 per class (design §6.7)
TEST_GROUPS = (("I1", "I2", "I3"), 4)                           # 12 per class: 3/4/3 + 2 provisioned (Q-5)
SENS_GROUPS = (("I0",), 2)
DISTRACTOR_LINES_PER_S = 5                                      # OV-6, OV-10 (ENG)
BULK_MBIT = 40                                                  # OV-1 iperf3 TCP A -> B (ENG; OV-4 ran 41 Mbit/s)
STRESS_CPUS = [19, 20]                                          # OV-3: other lab CPUs, never the target's 18 (ENG)
COLLECT = {"ifaces": ["sentlab-a0"], "ebpf": True, "app_metrics": True}


def expected(primary, contributing=(), acceptable=None):
    e = {"primary": primary, "contributing": sorted(contributing)}
    if acceptable is not None:
        e["acceptable"] = acceptable
    return e


INS = "INSUFFICIENT_EVIDENCE"


def load(path=DECISIONS) -> Dict:
    rec = json.loads(Path(path).read_text())["decisions"]
    for d in ("FZ-INTENSITY", "FZ-M6-PLAN", "FZ-OV", "FZ-Q5"):
        if rec.get(d, {}).get("status") != "approved":
            raise SystemExit(f"{d} is not approved; no matrix")
    return rec


def levels(rec) -> Dict[str, Dict]:
    lv = rec["FZ-INTENSITY"]["value"]["levels"]
    out = {}
    for fault, (key, stronger) in LEVEL_KEY.items():
        x = dict(lv[key])
        if "single" not in x:
            x["single"] = None
        out[fault] = {"stronger": stronger, **x}
    return out


def magnitude(lv: Dict, fault: str, intensity: str):
    x = lv[fault]
    if x["single"] is not None:                                  # P-2: single-level mechanisms
        return x["single"] if intensity != "I0" else i0(fault, x["single"], x["stronger"])
    if intensity == "I0":
        return i0(fault, x["I1"], x["stronger"])
    return x[intensity]


def i0(fault, i1, stronger):
    """P-3: half the strength of I1 in injection units."""
    v = i1 * 0.5 if stronger == "higher" else i1 * 2
    return float(v) if fault in FLOAT_UNITS else int(round(v))


def spread(mechanisms: List[str], groups) -> List[tuple]:
    """(mechanism, intensity) slots: group t, position j goes to mechanism (j + t) mod m, so each mechanism gets an
    even share of the runs and of each intensity (P-1)."""
    group, n = groups
    m = len(mechanisms)
    return [(mechanisms[(j + t) % m], it) for t in range(n) for j, it in enumerate(group)]


def overlap_families(lv) -> Dict[str, Dict]:
    f = lambda t, m: {"type": t, "magnitude": m}
    i2 = lambda t: lv[t]["I2"]
    return {
        "OV-1": {"faults": [f("cpu_contender", i2("cpu_contender"))], "bulk_flow_mbit": BULK_MBIT,
                 "expected": expected("cpu_contention")},
        "OV-2": {"faults": [f("netem_loss_a_egress", i2("netem_loss_a_egress"))],
                 "expected": expected("network_packet_loss", ["tcp_retransmissions"])},
        "OV-3": {"faults": [f("cpu_quota", i2("cpu_quota"))], "stress_cpus": STRESS_CPUS,
                 "expected": expected("cpu_throttling")},
        "OV-4": {"faults": [f("ov4_udp_flood", lv["ov4_udp_flood"]["single"])], "expected": expected(INS)},
        "OV-5": {"faults": [f("ov5_page_cache_fill", lv["ov5_page_cache_fill"]["single"])], "expected": expected(INS)},
        "OV-6": {"faults": [f("cpu_contender", i2("cpu_contender"))],
                 "distractor": {"kind": "slow_request", "lines_per_s": DISTRACTOR_LINES_PER_S},
                 "expected": expected("cpu_contention")},
        "OV-7": {"faults": [f("cpu_quota", i2("cpu_quota")), f("cpu_contender", i2("cpu_contender"))],
                 "expected": expected(INS, acceptable=[
                     {"primary": INS, "contributing": []},
                     {"primary": "cpu_throttling", "contributing": ["cpu_contention"]},
                     {"primary": "cpu_contention", "contributing": ["cpu_throttling"]}])},
        "OV-8": {"faults": [f("netem_loss_r_egress", i2("netem_loss_r_egress"))],
                 "collectors": {"ifaces": [], "ebpf": False, "app_metrics": True},     # drop collectors disabled
                 "expected": expected(INS)},
        "OV-9": {"faults": [f("app_pool", lv["app_pool"]["single"])],
                 "collectors": {"ifaces": ["sentlab-a0"], "ebpf": True, "app_metrics": False},
                 "expected": expected(INS)},
        "OV-10": {"faults": [], "distractor": {"kind": "generic", "lines_per_s": DISTRACTOR_LINES_PER_S},
                  "expected": expected(INS)},
    }


def generate(rec, master_seed: int = MASTER_SEED) -> Dict:
    lv = levels(rec)
    ctrl_test = rec["FZ-Q5"]["value"]["ctrl_test_runs"]
    runs = []

    def add(family, split, faults, exp, cls=None, mechanism=None, intensity=None, **extra):
        r = {"family": family, "split": split, "class": cls, "mechanism": mechanism, "intensity": intensity,
             "faults": faults, "expected": exp, "collectors": dict(COLLECT), "distractor": None,
             "bulk_flow_mbit": None, "stress_cpus": None}
        r.update(extra)
        runs.append(r)

    for cls, mechs in CLASSES.items():
        for split, groups in (("train", TRAIN_GROUPS), ("test", TEST_GROUPS)):
            for mech, it in spread(mechs, groups):
                label = "single" if lv[mech]["single"] is not None else it
                add("SF", split, [{"type": mech, "magnitude": magnitude(lv, mech, it)}], expected(cls), cls, mech, label)
        for mech, it in spread(mechs, SENS_GROUPS):
            add("SENS", "sens", [{"type": mech, "magnitude": magnitude(lv, mech, "I0")}], expected(cls), cls, mech, "I0")
    for fam, spec in overlap_families(lv).items():
        for split in ("train", "train", "test", "test"):
            x = dict(spec)
            add(fam, split, x.pop("faults"), x.pop("expected"), **x)
    for split, n in (("train", 10), ("test", ctrl_test)):
        for _ in range(n):
            add("CTRL", split, [], expected(INS))
    rng = random.Random(master_seed)
    rng.shuffle(runs)
    shuffled, runs[:] = list(runs), []
    for it in ("I1", "I2", "I3", "I1", "I2", "I3"):                 # U-4: PI-3, opens batch 1, never scored
        add("PI3", "pi3", [{"type": "cpu_quota", "magnitude": lv["cpu_quota"][it]}], expected("cpu_throttling"),
            "cpu_throttling", "cpu_quota", it)
    ordered = runs + shuffled
    size = -(-len(ordered) // BATCHES)
    for k, r in enumerate(ordered):
        seed = SEED_BASE + k
        r.update(seed=seed, run_id=f"M6-s{seed}", batch=1 + k // size)
    m = {"format": FORMAT, "master_seed": master_seed, "seed_base": SEED_BASE, "batches": BATCHES,
         "levels": lv, "classes": CLASSES,
         "engineering_values": {"distractor_lines_per_s": DISTRACTOR_LINES_PER_S, "bulk_flow_mbit": BULK_MBIT,
                                "stress_cpus": STRESS_CPUS},
         "basis": "FZ-INTENSITY (R-8), FZ-M6-PLAN (P-1..P-8), FZ-OV, FZ-Q5; design §6.4, §6.6, §6.7",
         "runs": ordered}
    m["counts"] = counts(m)
    check(m)
    return m


def counts(m) -> Dict:
    c: Dict = {"total": len(m["runs"]), "by_split": {}, "by_family": {}, "test_by_class": {}, "train_by_class": {}}
    for r in m["runs"]:
        c["by_split"][r["split"]] = c["by_split"].get(r["split"], 0) + 1
        c["by_family"][r["family"]] = c["by_family"].get(r["family"], 0) + 1
        if r["family"] == "SF":
            k = f"{r['split']}_by_class"
            c[k][r["class"]] = c[k].get(r["class"], 0) + 1
    return {k: dict(sorted(v.items())) if isinstance(v, dict) else v for k, v in c.items()}


def check(m) -> None:
    """Refuses a matrix that breaks the design's split rules or minimum counts."""
    runs, problems = m["runs"], []
    ids = [r["run_id"] for r in runs]
    if len(set(ids)) != len(ids) or len({r["seed"] for r in runs}) != len(runs):
        problems.append("run ids or seeds repeat")
    if any(not (100000 <= r["seed"] < 900000) for r in runs):
        problems.append("a seed overlaps the pilot range")
    if any(r["split"] == "train" and r["intensity"] == "I2" for r in runs):
        problems.append("I2 in train (design §6.6: test-only)")
    for cls in CLASSES:
        n = sum(1 for r in runs if r["family"] == "SF" and r["split"] == "test" and r["class"] == cls)
        if n < MIN_TEST_PER_CLASS:
            problems.append(f"{cls}: {n} test runs < {MIN_TEST_PER_CLASS}")
    if any(f["type"] == "police_a_ingress" for r in runs for f in r["faults"]):
        problems.append("police is not used in M6 (P-8)")
    if [r["family"] for r in runs if r["batch"] == 1][:6] != ["PI3"] * 6 or \
            sum(1 for r in runs if r["family"] == "PI3") != 6:
        problems.append("PI-3 must be the first 6 runs of batch 1 (U-4)")
    if problems:
        raise SystemExit("matrix refused: " + "; ".join(problems))


def dump(m) -> bytes:
    return (json.dumps(m, indent=1, sort_keys=True) + "\n").encode()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--out", default=str(DEFAULT_OUT))
    c = sub.add_parser("check")
    c.add_argument("path")
    a = ap.parse_args(argv)
    data = dump(generate(load()))
    if a.cmd == "check":
        same = Path(a.path).read_bytes() == data
        print(json.dumps({"identical_to_regeneration": same, "sha256": hashlib.sha256(data).hexdigest()}))
        return 0 if same else 1
    out = Path(a.out)
    if out.exists():
        raise SystemExit(f"{out} exists; the matrix is add-only (AMD-29)")
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "xb") as fh:
        fh.write(data)
    print(json.dumps({"written": str(out), "sha256": hashlib.sha256(data).hexdigest(), "counts": json.loads(data)["counts"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
