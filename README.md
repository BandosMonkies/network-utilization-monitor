# SDN Network Utilization Monitor (Core Version)

This version implements the core requirements end-to-end:

- Mininet topology: 1 switch + 4 hosts
- POX controller (OpenFlow 1.0):
  - `ConnectionUp` handling
  - `PacketIn` handling
  - L2 learning switch (`MAC -> port`)
  - Flow installation via `ofp_flow_mod`
  - Custom policy: block `h1 <-> h3` (both directions)
- Periodic flow statistics polling
- Utilization calculation (`bytes/sec`) and total data tracking
- Simple web dashboard + API for live visualization

## Files

- [simple_sdn_topology.py](simple_sdn_topology.py) — Mininet topology runner
- [pox/ext/sdn_utilization_monitor.py](pox/ext/sdn_utilization_monitor.py) — POX controller + monitoring + web UI/API

---

## How to run

Open **two terminals**.

### 1) Start POX controller

From [pox](pox):

```bash
cd /home/nagaraj/Computer-Networks/network-Utilization-monitor/pox
./pox.py log.level --INFO openflow.of_01 sdn_utilization_monitor --poll_period=2.0 --web_port=8000 --block_pair=h1-h3
```

If `./pox.py` is not executable, use:

```bash
python3 /home/nagaraj/Computer-Networks/network-Utilization-monitor/pox/pox.py log.level --INFO openflow.of_01 sdn_utilization_monitor --poll_period=2.0 --web_port=8000 --block_pair=h1-h3
```

### Block/unblock policy before running

Set this with `--block_pair` in POX command:

- Block `h1 <-> h2`:

```bash
./pox.py log.level --INFO openflow.of_01 sdn_utilization_monitor --poll_period=2.0 --web_port=8000 --block_pair=h1-h2
```

- Block `h1 <-> h3` (default):

```bash
./pox.py log.level --INFO openflow.of_01 sdn_utilization_monitor --poll_period=2.0 --web_port=8000 --block_pair=h1-h3
```

- Disable host-pair blocking:

```bash
./pox.py log.level --INFO openflow.of_01 sdn_utilization_monitor --poll_period=2.0 --web_port=8000 --block_pair=none
```

### 2) Start Mininet topology

From project root:

```bash
cd /home/nagaraj/Computer-Networks/network-Utilization-monitor
sudo python3 simple_sdn_topology.py
```

---

## How to test

Inside Mininet CLI:

### A) Verify baseline connectivity

```bash
pingall
```

Expected:
- Most pairs should communicate.
- `h1 <-> h3` should be blocked by controller policy.

### B) Generate traffic (allowed pair)

Use `iperf` between `h1` and `h2`:

```bash
h2 iperf -s &
h1 iperf -c h2 -t 15
```

Expected:
- Throughput appears on dashboard/API.
- POX installs forwarding flows, reducing repeated `PacketIn`.

### E) Increase congestion / make graph go high

Use multiple simultaneous traffic streams.

1) Start iperf servers:

```bash
h2 iperf -s -p 5001 &
h3 iperf -s -p 5002 &
h4 iperf -s -p 5003 &
```

2) Start parallel clients from h1:

```bash
h1 iperf -c h2 -p 5001 -t 60 -P 8 &
h1 iperf -c h3 -p 5002 -t 60 -P 8 &
h1 iperf -c h4 -p 5003 -t 60 -P 8 &
```

3) Optional: add UDP high-rate traffic too:

```bash
h1 iperf -u -c h2 -p 5001 -t 60 -b 200M &
```

This increases aggregate bytes/sec, so the dashboard graph rises strongly.

### C) Validate blocked traffic

Try traffic between blocked pair:

```bash
h3 iperf -s &
h1 iperf -c h3 -t 10
```

Expected:
- Connection should fail or show no meaningful throughput.
- Block policy `h1 -> h3` and `h3 -> h1` is enforced.

### D) Open web dashboard

In browser:

- http://127.0.0.1:8000/

API endpoint:

- http://127.0.0.1:8000/api/metrics

You should see:
- Aggregate bandwidth (bytes/sec)
- Total data transferred
- Per-host upload/download rates
- Top flows table (live updates)

---

## Notes

- Block matching is based on Mininet default MACs with `autoSetMacs=True`:
  - `h1 = 00:00:00:00:00:01`
  - `h3 = 00:00:00:00:00:03`
- This is the **core feature** build. Advanced polishing (persistent storage, richer charts, multi-switch analytics) can be added later.
