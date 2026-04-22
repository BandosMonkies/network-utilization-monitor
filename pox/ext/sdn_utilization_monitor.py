"""
SDN Utilization Monitor (POX + OpenFlow 1.0)

Core features implemented:
1) L2 learning switch (MAC -> port)
2) Flow installation using ofp_flow_mod (match + action)
3) Custom security rule: block selected host pair (both directions)
4) Periodic flow stats polling (byte counters)
5) Real-time utilization estimation (bytes/sec)
6) Lightweight web UI + JSON API for live monitoring

Run:
  ./pox.py log.level --INFO openflow.of_01 sdn_utilization_monitor

Optional args:
  --poll_period=2.0 --web_host=0.0.0.0 --web_port=8000 --block_pair=h1-h3
"""

import json
import threading
import time

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.recoco import Timer
from pox.lib.util import dpid_to_str

log = core.getLogger()


# -----------------------------------------------------------------------------
# Simple in-process web server
# -----------------------------------------------------------------------------

INDEX_HTML = """<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>SDN Utilization Monitor</title>
  <script src=\"https://cdn.jsdelivr.net/npm/chart.js\"></script>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #f6f8fa; color: #111; }
    h1 { margin: 0 0 12px; }
    .row { display: flex; gap: 16px; flex-wrap: wrap; }
    .card { background: #fff; border: 1px solid #ddd; border-radius: 10px; padding: 14px; min-width: 220px; }
    .value { font-size: 1.3rem; font-weight: 700; }
    table { border-collapse: collapse; width: 100%; margin-top: 12px; background: #fff; }
    th, td { border: 1px solid #e3e3e3; padding: 8px; text-align: left; font-size: 0.92rem; }
    th { background: #f3f4f6; }
    .muted { color: #666; font-size: .9rem; }
  </style>
</head>
<body>
  <h1>SDN Network Utilization Monitor</h1>
  <div class=\"muted\">Live OpenFlow stats from POX controller</div>

  <div class=\"row\" style=\"margin-top:12px\">
    <div class=\"card\"><div>Total Throughput</div><div class=\"value\" id=\"totalBps\">0 B/s</div></div>
    <div class=\"card\"><div>Total Data</div><div class=\"value\" id=\"totalBytes\">0 B</div></div>
    <div class=\"card\"><div>Connected Switches</div><div class=\"value\" id=\"switches\">0</div></div>
  </div>

  <div class=\"card\" style=\"margin-top:16px\">
    <canvas id=\"throughputChart\" height=\"80\"></canvas>
  </div>

  <h3>Per-host Utilization</h3>
  <table>
    <thead>
      <tr>
        <th>Host</th><th>MAC</th><th>Upload</th><th>Download</th><th>Total Data</th>
      </tr>
    </thead>
    <tbody id=\"hostBody\"></tbody>
  </table>

  <h3>Top Flows (by current bytes/sec)</h3>
  <table>
    <thead>
      <tr>
        <th>DPID</th><th>Src MAC</th><th>Dst MAC</th><th>Src IP</th><th>Dst IP</th><th>Bytes</th><th>Rate</th>
      </tr>
    </thead>
    <tbody id=\"flowBody\"></tbody>
  </table>

<script>
const MAX_POINTS = 30;
const labels = [];
const points = [];

const ctx = document.getElementById('throughputChart').getContext('2d');
const chart = new Chart(ctx, {
  type: 'line',
  data: {
    labels,
    datasets: [{ label: 'Aggregate Throughput (B/s)', data: points, tension: 0.2 }]
  },
  options: {
    responsive: true,
    scales: {
      y: { beginAtZero: true }
    }
  }
});

function humanBytes(v) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let x = Number(v || 0);
  let i = 0;
  while (x >= 1024 && i < units.length - 1) { x /= 1024; i++; }
  return x.toFixed(i === 0 ? 0 : 2) + ' ' + units[i];
}

function updateHostTable(hosts) {
  const body = document.getElementById('hostBody');
  body.innerHTML = '';
  const names = Object.keys(hosts || {}).sort();
  for (const name of names) {
    const h = hosts[name];
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${name}</td>
      <td>${h.mac || '-'}</td>
      <td>${humanBytes(h.upload_bps)}/s</td>
      <td>${humanBytes(h.download_bps)}/s</td>
      <td>${humanBytes(h.total_bytes)}</td>
    `;
    body.appendChild(tr);
  }
}

function updateFlowTable(flows) {
  const body = document.getElementById('flowBody');
  body.innerHTML = '';
  (flows || []).slice(0, 12).forEach(f => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${f.dpid}</td>
      <td>${f.src_mac || '-'}</td>
      <td>${f.dst_mac || '-'}</td>
      <td>${f.src_ip || '-'}</td>
      <td>${f.dst_ip || '-'}</td>
      <td>${humanBytes(f.byte_count)}</td>
      <td>${humanBytes(f.bps)}/s</td>
    `;
    body.appendChild(tr);
  });
}

async function refresh() {
  try {
    const res = await fetch('/api/metrics');
    const data = await res.json();

    document.getElementById('totalBps').textContent = humanBytes(data.aggregate_bps) + '/s';
    document.getElementById('totalBytes').textContent = humanBytes(data.total_data_bytes);
    document.getElementById('switches').textContent = String(data.connected_switches || 0);

    const t = new Date().toLocaleTimeString();
    labels.push(t);
    points.push(Number(data.aggregate_bps || 0));
    while (labels.length > MAX_POINTS) { labels.shift(); points.shift(); }
    chart.update();

    updateHostTable(data.hosts || {});
    updateFlowTable(data.flows || []);
  } catch (e) {
    console.error('refresh error', e);
  }
}

refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""


class _MonitorHttpHandler(BaseHTTPRequestHandler):
  monitor = None

  def _send_json(self, payload, code=200):
    body = json.dumps(payload).encode("utf-8")
    self.send_response(code)
    self.send_header("Content-Type", "application/json; charset=utf-8")
    self.send_header("Content-Length", str(len(body)))
    self.send_header("Cache-Control", "no-store")
    self.send_header("Access-Control-Allow-Origin", "*")
    self.end_headers()
    self.wfile.write(body)

  def _send_html(self, html, code=200):
    body = html.encode("utf-8")
    self.send_response(code)
    self.send_header("Content-Type", "text/html; charset=utf-8")
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)

  def log_message(self, fmt, *args):
    # Keep HTTP logs quiet; POX logs are already verbose enough.
    return

  def do_GET(self):
    if self.path == "/" or self.path.startswith("/index.html"):
      self._send_html(INDEX_HTML)
      return

    if self.path.startswith("/api/metrics"):
      if self.monitor is None:
        self._send_json({"error": "monitor not ready"}, code=503)
      else:
        self._send_json(self.monitor.snapshot_metrics())
      return

    self._send_json({"error": "not found"}, code=404)


class _WebServerThread(threading.Thread):
  def __init__(self, monitor, host, port):
    super(_WebServerThread, self).__init__(daemon=True)
    self.monitor = monitor
    self.host = host
    self.port = int(port)
    self.httpd = None

  def run(self):
    _MonitorHttpHandler.monitor = self.monitor
    self.httpd = ThreadingHTTPServer((self.host, self.port), _MonitorHttpHandler)
    log.info("Web dashboard at http://%s:%s", self.host, self.port)
    self.httpd.serve_forever()


# -----------------------------------------------------------------------------
# OpenFlow logic
# -----------------------------------------------------------------------------

class LearningSwitchWithPolicy(object):
  """
  Per-switch learning switch with explicit block policy.
  """

  def __init__(self, connection, blocked_mac_pair=None):
    self.connection = connection
    self.mac_to_port = {}
    self.blocked_mac_pair = blocked_mac_pair
    connection.addListeners(self)

  def install_block_rules(self):
    """
    Install static high-priority DROP rules for the selected host pair
    in both directions.

    Match-Action logic:
      match: dl_src + dl_dst
      action: none => drop
    """
    if self.blocked_mac_pair is None:
      log.info("No host-pair blocking configured")
      return

    a_mac, b_mac = self.blocked_mac_pair
    for src, dst in ((a_mac, b_mac), (b_mac, a_mac)):
      fm = of.ofp_flow_mod()
      fm.priority = 50000
      fm.match.dl_src = src
      fm.match.dl_dst = dst
      fm.idle_timeout = 0
      fm.hard_timeout = 0
      # No actions = DROP
      self.connection.send(fm)
      log.info("Installed block rule %s -> %s", src, dst)

  def _is_blocked_pair(self, packet):
    if self.blocked_mac_pair is None:
      return False
    a_mac, b_mac = self.blocked_mac_pair
    src = packet.src
    dst = packet.dst
    return ((src == a_mac and dst == b_mac) or
            (src == b_mac and dst == a_mac))

  def _drop_packet(self, event):
    if event.ofp.buffer_id is not None:
      po = of.ofp_packet_out()
      po.buffer_id = event.ofp.buffer_id
      po.in_port = event.port
      self.connection.send(po)

  def _flood(self, event):
    po = of.ofp_packet_out()
    po.in_port = event.port
    po.data = event.ofp
    po.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    self.connection.send(po)

  def _install_forward_flow(self, event, packet, out_port):
    """
    Install forwarding rule to avoid repeated PacketIn events.

    Match-Action logic:
      match = parsed packet fields (from_packet)
      action = output to learned port
    """
    fm = of.ofp_flow_mod()
    fm.priority = 1000
    fm.match = of.ofp_match.from_packet(packet, event.port)
    fm.idle_timeout = 30
    fm.hard_timeout = 120
    fm.actions.append(of.ofp_action_output(port=out_port))

    # Include triggering packet so switch forwards immediately.
    fm.data = event.ofp
    self.connection.send(fm)

  def _handle_PacketIn(self, event):
    packet = event.parsed
    if not packet.parsed:
      return

    # Packet parsing from pox.lib.packet
    ip_pkt = packet.find(ipv4)
    if ip_pkt is not None:
      log.debug("PacketIn IPv4 %s -> %s (%s -> %s)",
                packet.src, packet.dst, ip_pkt.srcip, ip_pkt.dstip)
    elif isinstance(packet, ethernet):
      log.debug("PacketIn Ethernet %s -> %s type=0x%04x",
                packet.src, packet.dst, packet.type)

    # Learn source MAC location.
    self.mac_to_port[packet.src] = event.port

    # Enforce custom block policy for configured host pair.
    if self._is_blocked_pair(packet):
      # Install exact temporary drop to suppress repeated PacketIn.
      fm = of.ofp_flow_mod()
      fm.priority = 50001
      fm.match = of.ofp_match.from_packet(packet, event.port)
      fm.idle_timeout = 60
      fm.hard_timeout = 0
      fm.buffer_id = event.ofp.buffer_id
      self.connection.send(fm)
      return

    if packet.dst.is_multicast:
      self._flood(event)
      return

    out_port = self.mac_to_port.get(packet.dst)
    if out_port is None:
      self._flood(event)
      return

    if out_port == event.port:
      self._drop_packet(event)
      return

    self._install_forward_flow(event, packet, out_port)


class SDNUtilizationMonitor(object):
  """
  Global controller component:
  - tracks switch connections
  - polls flow stats periodically
  - computes per-flow and per-host utilization
  - serves metrics to web dashboard
  """

  HOST_MAP = {
    "00:00:00:00:00:01": "h1",
    "00:00:00:00:00:02": "h2",
    "00:00:00:00:00:03": "h3",
    "00:00:00:00:00:04": "h4",
  }

  MAC_BY_HOST = {
    "h1": EthAddr("00:00:00:00:00:01"),
    "h2": EthAddr("00:00:00:00:00:02"),
    "h3": EthAddr("00:00:00:00:00:03"),
    "h4": EthAddr("00:00:00:00:00:04"),
  }

  def __init__(self, poll_period=2.0, web_host="0.0.0.0", web_port=8000,
               block_pair="h1-h3"):
    self.poll_period = float(poll_period)
    self.web_host = str(web_host)
    self.web_port = int(web_port)
    self.block_pair = str(block_pair)
    self.blocked_mac_pair = self._parse_block_pair(self.block_pair)

    self.switches = {}             # dpid -> LearningSwitchWithPolicy
    self.flow_prev = {}            # flow_key -> (last_bytes, last_time)
    self.latest_flows = {}         # dpid -> [flow dict]

    self.lock = threading.Lock()
    self.host_stats = self._empty_host_stats()

    core.openflow.addListeners(self)

    self.web_thread = _WebServerThread(self, self.web_host, self.web_port)
    self.web_thread.start()

    self._stats_timer = Timer(self.poll_period, self._poll_flow_stats, recurring=True)
    log.info("SDN monitor started: poll_period=%ss block_pair=%s",
             self.poll_period, self.describe_block_policy())

  def _parse_block_pair(self, block_pair):
    """
    Parse launch arg `block_pair`.

    Supported values:
      - h1-h3 (default)
      - h1-h2
      - none / off / disable
    """
    bp = (block_pair or "").strip().lower().replace("_", "-")
    if bp in ("", "h1-h3"):
      return (self.MAC_BY_HOST["h1"], self.MAC_BY_HOST["h3"])
    if bp == "h1-h2":
      return (self.MAC_BY_HOST["h1"], self.MAC_BY_HOST["h2"])
    if bp in ("none", "off", "disable", "disabled"):
      return None

    log.warning("Unknown block_pair='%s'. Falling back to h1-h3", block_pair)
    return (self.MAC_BY_HOST["h1"], self.MAC_BY_HOST["h3"])

  def describe_block_policy(self):
    if self.blocked_mac_pair is None:
      return "none"
    a, b = self.blocked_mac_pair
    inv_host_map = {str(v): k for k, v in self.MAC_BY_HOST.items()}
    a_name = inv_host_map.get(str(a), str(a))
    b_name = inv_host_map.get(str(b), str(b))
    return "%s<->%s" % (a_name, b_name)

  def _empty_host_stats(self):
    hosts = {}
    for mac, name in self.HOST_MAP.items():
      hosts[name] = {
        "mac": mac,
        "upload_bps": 0.0,
        "download_bps": 0.0,
        "total_bytes": 0,
      }
    return hosts

  def _handle_ConnectionUp(self, event):
    log.info("Switch connected: %s", dpid_to_str(event.dpid))
    ls = LearningSwitchWithPolicy(event.connection,
                                  blocked_mac_pair=self.blocked_mac_pair)
    self.switches[event.dpid] = ls
    ls.install_block_rules()

  def _handle_ConnectionDown(self, event):
    dpid = event.dpid
    if dpid in self.switches:
      del self.switches[dpid]
    with self.lock:
      self.latest_flows.pop(dpid, None)
    log.info("Switch disconnected: %s", dpid_to_str(dpid))

  def _poll_flow_stats(self):
    # Ask each connected switch for flow counters.
    for dpid, ls in list(self.switches.items()):
      try:
        req = of.ofp_stats_request(body=of.ofp_flow_stats_request())
        ls.connection.send(req)
      except Exception:
        log.exception("Flow stats poll failed for %s", dpid_to_str(dpid))

  def _flow_key(self, dpid, stat):
    m = stat.match
    return (
      dpid,
      str(getattr(m, "dl_src", None)),
      str(getattr(m, "dl_dst", None)),
      str(getattr(m, "nw_src", None)),
      str(getattr(m, "nw_dst", None)),
      getattr(m, "nw_proto", None),
      getattr(m, "tp_src", None),
      getattr(m, "tp_dst", None),
      getattr(m, "in_port", None),
    )

  def _is_drop_rule(self, stat):
    actions = getattr(stat, "actions", None)
    return actions is None or len(actions) == 0

  def _safe_str(self, v):
    if v is None:
      return None
    s = str(v)
    if s in ("0.0.0.0", "00:00:00:00:00:00", "None"):
      return None
    return s

  def _handle_FlowStatsReceived(self, event):
    now = time.time()
    dpid_str = dpid_to_str(event.dpid)

    flows = []
    host_bps = self._empty_host_stats()

    for stat in event.stats:
      # Skip pure drop rules (block policies) for utilization reporting.
      if self._is_drop_rule(stat):
        continue

      key = self._flow_key(event.dpid, stat)
      byte_count = int(getattr(stat, "byte_count", 0) or 0)
      prev = self.flow_prev.get(key)

      delta_bytes = 0
      bps = 0.0
      if prev is not None:
        prev_bytes, prev_ts = prev
        dt = now - prev_ts
        if dt > 0 and byte_count >= prev_bytes:
          delta_bytes = byte_count - prev_bytes
          bps = float(delta_bytes) / dt

      self.flow_prev[key] = (byte_count, now)

      m = stat.match
      src_mac = self._safe_str(getattr(m, "dl_src", None))
      dst_mac = self._safe_str(getattr(m, "dl_dst", None))
      src_ip = self._safe_str(getattr(m, "nw_src", None))
      dst_ip = self._safe_str(getattr(m, "nw_dst", None))

      flow_item = {
        "dpid": dpid_str,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "byte_count": byte_count,
        "bps": round(bps, 2),
      }
      flows.append(flow_item)

      # Aggregate host metrics by MAC.
      if src_mac in self.HOST_MAP:
        h = host_bps[self.HOST_MAP[src_mac]]
        h["upload_bps"] += bps
        h["total_bytes"] += delta_bytes

      if dst_mac in self.HOST_MAP:
        h = host_bps[self.HOST_MAP[dst_mac]]
        h["download_bps"] += bps
        h["total_bytes"] += delta_bytes

    # Highest utilization flows first (for dashboard readability).
    flows.sort(key=lambda x: x["bps"], reverse=True)

    with self.lock:
      # Merge host cumulative totals (do not reset total_bytes each poll).
      for name, h in host_bps.items():
        old = self.host_stats[name]
        old["upload_bps"] = round(h["upload_bps"], 2)
        old["download_bps"] = round(h["download_bps"], 2)
        old["total_bytes"] += int(h["total_bytes"])

      self.latest_flows[event.dpid] = flows

  def snapshot_metrics(self):
    with self.lock:
      all_flows = []
      for dpid, items in self.latest_flows.items():
        all_flows.extend(items)

      # Keep top flows globally for compact UI.
      all_flows.sort(key=lambda x: x["bps"], reverse=True)
      top_flows = all_flows[:30]

      aggregate_bps = sum(float(f.get("bps", 0.0) or 0.0) for f in all_flows)
      total_data = 0
      for h in self.host_stats.values():
        total_data += int(h["total_bytes"])

      payload = {
        "timestamp": time.time(),
        "connected_switches": len(self.switches),
        "aggregate_bps": round(aggregate_bps, 2),
        "total_data_bytes": int(total_data),
        "blocked_policy": {
          "pair": self.describe_block_policy(),
        },
        "hosts": self.host_stats,
        "flows": top_flows,
      }
      return payload


def launch(poll_period=2.0, web_host="0.0.0.0", web_port=8000,
           block_pair="h1-h3"):
  """
  Starts the SDN utilization monitor.

  Args:
    poll_period: stats polling interval in seconds
    web_host: HTTP listen host (default 0.0.0.0)
    web_port: HTTP listen port (default 8000)
    block_pair: host-pair blocking policy (h1-h3 | h1-h2 | none)
  """
  core.registerNew(SDNUtilizationMonitor,
                   poll_period=float(poll_period),
                   web_host=web_host,
                   web_port=int(web_port),
                   block_pair=block_pair)
