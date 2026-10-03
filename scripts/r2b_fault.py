#!/usr/bin/env python3
"""SentinelAI R2-B: controlled network packet-loss fault, guards and analysis (pure except execute()).

The only fault this phase may create is `netem loss <p>%` as the root qdisc of sentlab-a0 inside netns
sentinel-lab-a (egress of the lab sender), at an approved loss level. Every tc command is built here and
re-validated by check_argv() immediately before its single execution site, execute().
"""

import json
import math
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from r2a_lab import LAB, PROTECTED  # noqa: E402  (the R2-A topology, validated at R2-A)

NS_A, NS_B, IF_A, IF_B = LAB["ns_a"], LAB["ns_b"], LAB["if_a"], LAB["if_b"]
APPROVED_LOSS_PCT = (1.0, 5.0)
APPROVED_FAULTS = ("loss",)
REFUSED_FAULTS = ("delay", "reorder", "corrupt", "duplicate", "rate", "slot", "gap", "jitter", "distribution")
TOOLING = ("scripts/r2b_fault.py", "scripts/r2b_driver.py", "scripts/r2b_validate.sh",
           "tests/faultlab/test_r2b.py")


class FaultRefused(ValueError):
    """A command or parameter outside the R2-B authorisation."""


# ------------------------------------------------------------------------------------------ commands
def _loss_token(loss_pct) -> str:
    if isinstance(loss_pct, bool) or not isinstance(loss_pct, (int, float)) or float(loss_pct) not in APPROVED_LOSS_PCT:
        raise FaultRefused(f"loss {loss_pct!r} is not an approved level {APPROVED_LOSS_PCT}")
    return f"{float(loss_pct):g}%"


def netem_add(loss_pct, fault="loss"):
    if fault != "loss":
        raise FaultRefused(f"fault type {fault!r} is not authorised in R2-B (only {APPROVED_FAULTS})")
    return ["tc", "-n", NS_A, "qdisc", "add", "dev", IF_A, "root", "netem", "loss", _loss_token(loss_pct)]


def netem_del():
    return ["tc", "-n", NS_A, "qdisc", "del", "dev", IF_A, "root"]


def qdisc_show():
    return ["tc", "-n", NS_A, "-s", "-j", "qdisc", "show", "dev", IF_A]


def qdisc_show_text():
    return ["tc", "-n", NS_A, "qdisc", "show", "dev", IF_A]


def check_argv(argv):
    """Exactly one of the three built shapes, with an approved loss level; nothing else is executable."""
    if not (isinstance(argv, list) and all(isinstance(a, str) for a in argv)):
        raise FaultRefused("argv must be a list of strings")
    joined = " ".join(argv)
    for p in PROTECTED:
        if p in joined:
            raise FaultRefused(f"protected interface {p} in command")
    if any(f in argv for f in REFUSED_FAULTS):
        raise FaultRefused(f"unapproved netem parameter in {argv}")
    allowed = [netem_del(), qdisc_show(), qdisc_show_text()] + [netem_add(p) for p in APPROVED_LOSS_PCT]
    if argv not in allowed:
        raise FaultRefused(f"command not in the R2-B allowlist: {argv}")
    return argv


def execute(argv, runner=subprocess.run):
    """The single execution site for tc in R2-B (list argv, shell=False, re-validated first)."""
    check_argv(argv)
    p = runner(argv, capture_output=True, text=True, timeout=10, shell=False)
    return p.returncode, p.stdout, p.stderr


# ------------------------------------------------------------------------------------------ parsing
def parse_qdiscs(text):
    """tc -s -j qdisc show output -> [{kind, handle, root, packets, bytes, drops, overlimits, requeues, options}]."""
    data = json.loads(text or "[]")
    if not isinstance(data, list):
        raise ValueError("qdisc JSON is not a list")
    out = []
    for q in data:
        out.append({"kind": q.get("kind"), "handle": q.get("handle"), "root": bool(q.get("root", False)),
                    "packets": int(q.get("packets", 0)), "bytes": int(q.get("bytes", 0)),
                    "drops": int(q.get("drops", 0)), "overlimits": int(q.get("overlimits", 0)),
                    "requeues": int(q.get("requeues", 0)), "options": q.get("options", {})})
    return out


def is_clean(qdiscs):
    """The R2-A clean state of the lab veth: a single root noqueue qdisc."""
    return len(qdiscs) == 1 and qdiscs[0]["kind"] == "noqueue" and qdiscs[0]["root"]


_NETEM_TEXT = re.compile(r"^qdisc netem \S+ root .*\bloss (\d+(?:\.\d+)?)%", re.M)
_OTHER_IMPAIRMENT = re.compile(r"\b(delay|reorder|corrupt|duplicate|rate|slot)\b")


def netem_ground_truth(qdiscs, text, loss_pct):
    """The installed fault, read back from the kernel: counters from the JSON show, and the configured loss
    parameter from tc's text rendering ('... netem ... loss 1%'), whose units do not depend on the JSON format."""
    if len(qdiscs) != 1 or qdiscs[0]["kind"] != "netem" or not qdiscs[0]["root"]:
        raise ValueError(f"expected one root netem qdisc, found {[q['kind'] for q in qdiscs]}")
    m = _NETEM_TEXT.search(text or "")
    if not m:
        raise ValueError(f"netem loss not found in: {text!r}")
    if _OTHER_IMPAIRMENT.search(text.split("loss", 1)[0] + text.split("%", 1)[-1]):
        raise ValueError(f"netem reports an impairment other than loss: {text!r}")
    if not math.isclose(float(m.group(1)), float(loss_pct), rel_tol=1e-9):
        raise ValueError(f"netem loss {m.group(1)}% does not match configured {loss_pct}%")
    q = qdiscs[0]
    return {"kind": "netem", "loss_pct": float(m.group(1)), "packets": q["packets"], "bytes": q["bytes"],
            "drops": q["drops"], "text": text.strip()}


# ------------------------------------------------------------------------------------------ analysis
def w_delta(a, b):
    """Delta of two parsed loader samples (collectors.ebpf.Sample) over the window."""
    return {"retrans": b.retrans - a.retrans,
            "kfree": {s: b.kfree.get(s, 0) - a.kfree.get(s, 0) for s in set(a.kfree) | set(b.kfree)
                      if b.kfree.get(s, 0) - a.kfree.get(s, 0)},
            "stats": {k: b.stats[k] - a.stats[k] for k in b.stats if b.stats[k] - a.stats[k]}}


def attribution_checks(loss_pct, qdisc_drops_w, a, b, qdisc_slot):
    """Netns attribution over W. a/b: w_delta of the loader targeting netns A (sender, faulted) and B (receiver).
    qdisc_drops_w: drops counted by the qdisc over the same ticks (M3A tc source). qdisc_slot: kfree slot of
    QDISC_DROP in this kernel."""
    a_q = a["kfree"].get(qdisc_slot, 0)
    tol = max(2, math.ceil(0.02 * qdisc_drops_w))
    c = {
        "a_qdisc_drop_kfree_matches_qdisc_counter": abs(a_q - qdisc_drops_w) <= tol,
        "b_has_no_qdisc_drop_kfree": b["kfree"].get(qdisc_slot, 0) == 0,
        "b_has_no_target_retransmissions": b["retrans"] == 0,
        "a_events_seen_as_other_netns_by_b": b["stats"].get("retrans_other_netns", 0) >= a["retrans"],
    }
    if loss_pct > 0:
        c["a_retransmissions_observed"] = a["retrans"] > 0
        c["a_qdisc_drops_observed"] = qdisc_drops_w > 0
    else:
        c["a_no_retransmissions_at_baseline"] = a["retrans"] == 0
        c["a_no_qdisc_drops_at_baseline"] = qdisc_drops_w == 0 and a_q == 0
    return {"ok": all(c.values()), "checks": c, "a_qdisc_drop_kfree": a_q, "qdisc_drops": qdisc_drops_w,
            "tolerance": tol}


def predict_m2(loss_pct, drops_per_s, pkts_per_s, numbers):
    """What the unchanged M2 rules should decide, stated before looking at M2's output."""
    if loss_pct == 0:
        return {"decision": "INSUFFICIENT_EVIDENCE", "basis": "no fault in W"}
    frac = drops_per_s / (pkts_per_s + drops_per_s) if pkts_per_s + drops_per_s > 0 else 0.0
    if drops_per_s >= numbers["DROP_ABS_MIN"] and frac >= numbers["DROP_FRAC_MIN"]:
        return {"decision": "network_packet_loss", "basis": f"qdisc drops {drops_per_s:.2f}/s >= DROP_ABS_MIN and "
                f"fraction {frac:.4f} >= DROP_FRAC_MIN (baseline median 0)"}
    return {"decision": "INSUFFICIENT_EVIDENCE", "basis": f"qdisc drops {drops_per_s:.2f}/s or fraction {frac:.4f} "
            "below the validation thresholds"}


# ------------------------------------------------------------------------------------------ lab restoration
def _lab_state(d, side):
    import m3b_r1_compare as hostcmp
    d = Path(d)
    j = lambda n: json.loads((d / f"{side}_{n}.json").read_text() or "[]")
    return {"links": {l["ifname"]: hostcmp.link_config(l) for l in j("links")},
            "addrs": sorted((a["ifname"], i["family"], i["local"], i["prefixlen"]) for a in j("addrs")
                            for i in a.get("addr_info", [])),
            "routes4": j("routes4"), "routes6": j("routes6"),
            "qdiscs": sorted((q.get("dev"), q.get("kind"), q.get("handle"), bool(q.get("root"))) for q in j("qdiscs"))}


def lab_compare(before, after):
    """The lab after a run equals the clean lab before it: links (configuration), addresses, routes, qdiscs."""
    res = {}
    for side in ("a", "b"):
        b, a = _lab_state(before, side), _lab_state(after, side)
        for k in b:
            res[f"{side}_{k}_identical"] = b[k] == a[k]
        res[f"{side}_no_netem"] = not any(q[1] == "netem" for q in a["qdiscs"])
    res["ok"] = all(res.values())
    return res


# ------------------------------------------------------------------------------------------ candidate
def candidate(repo, base):
    g = lambda *a: subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)
    head, b = g("rev-parse", "HEAD"), g("rev-parse", "--verify", f"{base}^{{commit}}")
    if head.returncode or b.returncode:
        return {"ok": False, "reason": "HEAD or base not resolvable"}
    head, b = head.stdout.strip(), b.stdout.strip()
    if g("merge-base", "--is-ancestor", b, head).returncode:
        return {"ok": False, "reason": f"HEAD {head} does not descend from {b}"}
    changed = [p for p in g("diff", "--name-only", b, head).stdout.split() if p not in TOOLING]
    if changed:
        return {"ok": False, "reason": f"changed since {b[:7]} beyond R2-B tooling: {sorted(changed)}"}
    if g("status", "--porcelain", "--untracked-files=no").stdout.strip():
        return {"ok": False, "reason": "tracked files modified"}
    return {"ok": True, "head": head, "base": b}


if __name__ == "__main__":
    if sys.argv[1] == "lab-compare":
        r = lab_compare(sys.argv[2], sys.argv[3])
        print(json.dumps(r, indent=1, sort_keys=True))
        sys.exit(0 if r["ok"] else 3)
    if sys.argv[1] == "candidate":
        r = candidate(sys.argv[2], sys.argv[3])
        print(r["head"] if r["ok"] else r["reason"])
        sys.exit(0 if r["ok"] else 3)
    raise SystemExit("usage: r2b_fault.py candidate REPO BASE | lab-compare BEFORE AFTER")
