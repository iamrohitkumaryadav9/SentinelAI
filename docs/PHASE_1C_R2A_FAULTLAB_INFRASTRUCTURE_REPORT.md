# Phase 1C — R2-A FaultLab Infrastructure-Only Validation Report

| | |
|---|---|
| Phase boundary (base) | `3f1eb40` docs(ebpf): record M3B R1 runtime validation |
| Checkout under test | `683d87af0f60d803f01c393b479b4b0b111029e2` test(faultlab): add R2-A infrastructure-only lab validation tooling (parent `3f1eb40`; R2-A tooling only) |
| Run | `results/phase1c_r2a/20261003T093604Z/` (2026-10-03 09:36:04 UTC), executed by the user: `cd /home/iiitd/sentinelai && sudo bash scripts/r2a_lab_validate.sh`; exit status 0 |
| Gate | **R2-A FAULTLAB INFRASTRUCTURE GATE: GO** |

## 1. Commit

- **Preflight:** HEAD `3f1eb40`; `git status --short` showed only `?? experiments/faultlab/` (untouched); previous M3B/R1 commits unmodified.
- **Full suite before any change:** 574 run, 573 passed, 0 failed, 1 skipped (pre-existing root-only bpftrace test).
- **Tooling commit:** `683d87a`, directly on `3f1eb40`. Four files:
  - `scripts/r2a_lab_validate.sh` (root-only runner);
  - `scripts/r2a_lab.py` (candidate check, host comparison, lab validation; pure, no mutation);
  - `tests/faultlab/__init__.py`;
  - `tests/faultlab/test_r2a_lab.py` (12 tests).
- **Suite after the tooling commit:** 586 run, 585 passed, 0 failed, 1 skipped.
- The runner verified that HEAD descends from `3f1eb40` with only R2-A tooling changed and no modified tracked file. Its record: `{"base": "3f1eb40…", "head": "683d87a…", "ok": true}`.

## 2. Authorisation boundary

**Authorised:** dedicated network namespaces, a dedicated veth pair, lab loopback, lab-side addresses and lab-only routes.

**Not done**, and pinned by the static tests in `test_r2a_lab.py`:
- any qdisc change (no netem, no tc mutation: `tc` is used only as `tc -j qdisc show`);
- any sysctl write;
- any firewall, Docker, route or address change in the host netns;
- anything involving `enp0s31f6` or `docker0`;
- external traffic, BPF, CPU, memory or cgroup activity.

**Guards:**
- every host-mutating command goes through a logged wrapper and must target one of the four lab names;
- the runner refuses to start if any lab name already exists;
- a trap removes only the objects this run created.

## 3. Host baseline (before any lab object; read-only)

| Item | Baseline |
|---|---|
| Interfaces | `lo` UNKNOWN mtu 65536 `noqueue`; `enp0s31f6` UP mtu 1500 `fq_codel` 4c:d7:17:87:53:ae; `docker0` DOWN mtu 1500 `noqueue` 3e:21:b8:b7:ee:35 (bridge) |
| Addresses | `lo` 127.0.0.1/8, ::1/128; `enp0s31f6` 192.168.192.151/20, fe80::ee1d:b010:7719:8efc/64; `docker0` 172.17.0.1/16, fe80::3c21:b8ff:feb7:ee35/64 |
| IPv4 routes | default via 192.168.192.11 dev `enp0s31f6`; 169.254.0.0/16 dev `enp0s31f6`; 172.17.0.0/16 dev `docker0`; 192.168.192.0/20 dev `enp0s31f6` |
| Qdiscs (`tc -j qdisc show`) | `lo` noqueue; `enp0s31f6` fq_codel (limit 10240, flows 1024, …); `docker0` noqueue |
| Namespaces | `ip netns list`: none; `/run/netns`: empty |
| Sysctls | `unprivileged_bpf_disabled=2`, `perf_event_paranoid=4`, `bpf_stats_enabled=0`, `bpf_jit_enable=1`, `default_qdisc=fq_codel`, `ip_forward=1`, `conf/all/forwarding=1`, `conf/all/rp_filter=2`, `ipv6 conf/all/forwarding=0`, `ipv6 conf/all/disable_ipv6=0` |
| BPF | 22 programs (pre-existing), plus links and maps recorded |
| Tools | iproute2-5.15.0 (`ip`, `tc`) |

## 4. Lab topology

```text
host netns (untouched: no lab interface, address or route)

netns sentinel-lab-a                                   netns sentinel-lab-b
  lo          127.0.0.1/8 (UP)                           lo          127.0.0.1/8 (UP)
  sentlab-a0  10.199.0.1/24  <======== veth ========>    sentlab-b0  10.199.0.2/24
  routes: 10.199.0.0/24 dev sentlab-a0 only               routes: 10.199.0.0/24 dev sentlab-b0 only
  no default route (IPv4 or IPv6)                         no default route (IPv4 or IPv6)
```

- **Why this shape:** the veth pair is created directly inside the two lab namespaces, so it never exists in the host netns. A second namespace (rather than a host-side peer) keeps the host completely outside the lab and gives future phases a separate netns for filter validation.
- **Addressing:** 10.199.0.0/24 is not used by any host route. Lab routing tables are separate from the host's in any case.
- **External connectivity:** none.

## 5. Creation commands (from `ops.log`, cycle 1; cycle 2 identical)

```text
09:36:04.958 rc=0  ip netns add sentinel-lab-a
09:36:04.959 rc=0  ip netns add sentinel-lab-b
09:36:04.962 rc=0  ip link add sentlab-a0 netns sentinel-lab-a type veth peer name sentlab-b0 netns sentinel-lab-b
09:36:04.964 rc=0  ip -n sentinel-lab-a addr add 10.199.0.1/24 dev sentlab-a0
09:36:04.965 rc=0  ip -n sentinel-lab-b addr add 10.199.0.2/24 dev sentlab-b0
09:36:04.967 rc=0  ip -n sentinel-lab-a link set lo up
09:36:04.969 rc=0  ip -n sentinel-lab-b link set lo up
09:36:04.970 rc=0  ip -n sentinel-lab-a link set sentlab-a0 up
09:36:04.972 rc=0  ip -n sentinel-lab-b link set sentlab-b0 up
```

Each name was checked as absent (`ip netns list`, `/run/netns/<name>`, `ip link show <ifname>`) before creation. These nine commands plus the two `ip netns del` are the only host-mutating operations of the run, and every one returned 0.

## 6. Resources created

| Resource | Location | Observed state (both cycles) |
|---|---|---|
| `sentinel-lab-a` | network namespace (`/run/netns/sentinel-lab-a`) | present while the lab existed |
| `sentinel-lab-b` | network namespace | present while the lab existed |
| `sentlab-a0` | in `sentinel-lab-a` | `veth`, UP, LOWER_UP, mtu 1500, qdisc `noqueue`, peer in another netns (`link_netnsid 0`); 10.199.0.1/24 + kernel link-local fe80::/64 |
| `sentlab-b0` | in `sentinel-lab-b` | `veth`, UP, LOWER_UP, mtu 1500, qdisc `noqueue`, peer in another netns; 10.199.0.2/24 + kernel link-local |
| Lab routes | inside each namespace | IPv4 `10.199.0.0/24 dev sentlab-x0 proto kernel scope link` only; IPv6 `fe80::/64` only |

The kernel added only the defaults: IPv6 link-local addresses, the connected routes and `noqueue` qdiscs. No qdisc was configured; none was required for this phase.

## 7. Connectivity validation (lab-local only; 27 checks per cycle, all pass)

| Check | Cycle 1 | Cycle 2 |
|---|---|---|
| Both namespaces exist | yes | yes |
| Each namespace contains exactly `lo` + its veth end | yes | yes |
| veth type, UP, peer in the other namespace | yes | yes |
| Addresses exactly 10.199.0.1/24 and 10.199.0.2/24 | yes | yes |
| Routes: lab subnet only, no default route (IPv4 and IPv6) | yes | yes |
| External route lookup `ip -n <ns> route get 8.8.8.8` (lookup only, no packet) | `RTNETLINK answers: Network is unreachable` (both) | same |
| Loopback ping 127.0.0.1 in each namespace | 2/2, 0 % loss (both) | 2/2, 0 % loss |
| Peer ping a→b and b→a (`-I sentlab-x0`) | 3/3, 0 % loss; rtt avg 0.041 / 0.038 ms | 3/3, 0 % loss |
| TCP echo (server in b on 10.199.0.2:5001, client in a) | `ECHO-OK` | `ECHO-OK` |
| No netem qdisc in the lab | yes | yes |
| No lab interface in the host netns while the lab existed | yes (host links: `lo`, `enp0s31f6`, `docker0`) | yes |

Every probe ran inside a lab namespace towards a lab or loopback address. No probe used the physical NIC or an external host.

## 8. Protected-interface comparison

`scripts/r2a_lab.py compare` checks, against the baseline:
- interfaces (configuration fields; only the four documented bridge countdown timers ignored, on bridge links);
- addresses, IPv4/IPv6 routes;
- the full qdisc list, and `enp0s31f6`/`docker0` qdiscs separately;
- namespaces (`ip netns list` and `/run/netns`), sysctls, BPF programs/links/maps;
- no `sentlab*` interface in the host.

| Comparison | Result |
|---|---|
| Baseline vs **lab present**, cycle 1 and cycle 2 | `ok: true`. Everything identical; `netns_added = [sentinel-lab-a, sentinel-lab-b]` (exactly the expected set); `netns_removed = []`; `no_lab_interface_in_host: true` |
| Of which: `enp0s31f6_identical`, `docker0_identical`, `interfaces_identical`, `addresses_identical`, `routes_identical`, `qdiscs_identical`, `protected_qdiscs_identical`, `sysctls_identical`, BPF ids identical | all `true` (both cycles) |

The only host-visible change while the lab existed was the two dedicated namespace entries in `/run/netns`.

## 9. Cleanup

```text
09:36:13.416 rc=0  ip netns del sentinel-lab-a      (cycle 1; cycle 2: 09:36:22.698)
09:36:13.418 rc=0  ip netns del sentinel-lab-b      (cycle 2: 09:36:22.699)
```

Deleting a namespace destroys its veth end, and with it the pair.

| Comparison | Result |
|---|---|
| Baseline vs after cleanup, cycle 1 | `ok: true`, everything identical, `netns_added = []`, `netns_removed = []` |
| Baseline vs after cleanup, cycle 2 | `ok: true`, everything identical |
| Baseline vs final (end of run) | `ok: true`: interfaces, `enp0s31f6`, `docker0`, addresses, routes, qdiscs, protected qdiscs, namespaces, sysctls and BPF progs/links/maps (22 programs before and after) all identical; `interfaces_differing: []` |
| After the run (unprivileged re-check) | `/run/netns` empty; host interfaces `lo`, `enp0s31f6`, `docker0` |

No stale namespace, veth, route, address or qdisc remains.

## 10. Repeatability

The identical topology was created and destroyed twice in one run, with the same names:
- the cycle-2 `ip netns add` and `ip link add` succeeded, so the names were reusable and no stale object blocked them;
- all 27 lab checks passed again;
- the host comparisons with the lab present and after cleanup were again `ok: true`.

The only differences between cycles are kernel-generated veth MAC addresses and the IPv6 link-local addresses derived from them, as expected.

## 11. Unexpected changes and anomalies

- **None in host state.**
- The kernel auto-configured IPv6 link-local addresses and `fe80::/64` routes on the lab veths. They exist only inside the lab namespaces, and there is no IPv6 default route.
- **Cosmetic tooling issue:** `environment.txt` records the candidate-check JSON on its `commit=` line instead of a bare SHA. The head (`683d87a`) and base are in that JSON, so no information is lost.

## 12. Evidence artifacts (`results/phase1c_r2a/20261003T093604Z/`)

| Artifact | Content |
|---|---|
| `environment.txt` | Candidate check (head/base), kernel, user, time, iproute2 versions, lab specification |
| `ops.log` | Every host-mutating command with timestamp and exit code |
| `baseline/`, `final/` | Read-only host snapshots: `links.json`, `addrs.json`, `routes4.json`, `routes6.json`, `qdiscs.json`, `netns.json`, `run_netns.txt`, `sysctls.txt`, `bpf_progs.json`, `bpf_links.json`, `bpf_maps.json` |
| `cycle{1,2}/lab/` | Lab-internal state: `{a,b}_links/addrs/routes4/routes6/qdiscs.json`, `{a,b}_ping_lo.txt`, `{a,b}_ping_peer.txt`, `{a,b}_route_get_external.txt`, `tcp_result.txt`, `netns.json`, `host_links.json` |
| `cycle{1,2}/with_lab/`, `cycle{1,2}/after/` | Host snapshots with the lab present and after cleanup |
| `cycle{1,2}/lab_checks.json`, `with_lab_compare.json`, `after_compare.json`; `final_compare.json`; `summary.json` | Machine-checked results (`status_ok: true`; every `ok: true`) |

## 13. Gate

| Criterion | Status |
|---|---|
| Isolated lab creation succeeds | yes: 2/2 cycles, every operation rc=0 |
| Lab connectivity succeeds | yes: loopback, peer ping both ways, TCP echo; no external path |
| No protected host state changes | yes: `enp0s31f6`, `docker0`, addresses, routes, qdiscs, sysctls and BPF identical; only the two lab namespaces appeared, temporarily |
| Cleanup succeeds; no stale lab resources | yes: after each cycle and at the end the host is identical to the baseline |
| No fault injection | yes: no netem or qdisc change, no loss, delay, CPU, memory or cgroup activity |
| M3B / M2 unchanged | yes: the tooling commit touches only `scripts/r2a_lab*` and `tests/faultlab/`; no diff under `src/` or `ebpf/` |

```text
R2-A FAULTLAB INFRASTRUCTURE GATE: GO
```

R2-A shows that the lab itself is safe and isolated. It does **not** show that any fault model works.

**STOP.** Packet loss, delay, deliberate retransmissions, CPU contention or throttling, memory pressure, K1–K4, M2 changes and mitigation experiments require separate authorisation.
