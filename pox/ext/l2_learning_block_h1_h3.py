"""
POX OpenFlow 1.0 learning switch with a custom host-to-host block rule.

Features:
- Handles ConnectionUp and PacketIn events
- Learns MAC -> switch port mappings (L2 learning switch)
- Installs flow rules (match + action) to reduce repeated PacketIn events
- Blocks traffic between h1 and h3 in both directions

Run example:
  ./pox.py log.level --DEBUG openflow.of_01 l2_learning_block_h1_h3
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

# Packet parsing helpers from pox.lib.packet (requested)
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4

from pox.lib.addresses import EthAddr

log = core.getLogger()


class LearningSwitchWithBlock(object):
  """
  Per-switch learning switch logic + explicit blocking policy.
  """

  # Mininet default MACs with autoSetMacs=True:
  # h1 -> 00:00:00:00:00:01
  # h3 -> 00:00:00:00:00:03
  H1_MAC = EthAddr("00:00:00:00:00:01")
  H3_MAC = EthAddr("00:00:00:00:00:03")

  def __init__(self, connection):
    self.connection = connection
    self.mac_to_port = {}

    # Listen for PacketIn events from this switch connection.
    connection.addListeners(self)

  def _install_bidirectional_block_rules(self):
    """
    Install high-priority DROP rules for h1<->h3 in both directions.

    Match-Action logic:
      match: dl_src=<h1>, dl_dst=<h3>  -> action: drop (no actions)
      match: dl_src=<h3>, dl_dst=<h1>  -> action: drop (no actions)

    In OpenFlow 1.0, an ofp_flow_mod with no actions behaves as drop.
    """
    blocked_pairs = [
      (self.H1_MAC, self.H3_MAC),
      (self.H3_MAC, self.H1_MAC),
    ]

    for src_mac, dst_mac in blocked_pairs:
      fm = of.ofp_flow_mod()
      fm.priority = 50000  # Higher priority than learned forwarding rules
      fm.match.dl_src = src_mac
      fm.match.dl_dst = dst_mac
      fm.idle_timeout = 0
      fm.hard_timeout = 0
      # No action => DROP
      self.connection.send(fm)
      log.info("Installed BLOCK rule: %s -> %s", src_mac, dst_mac)

  def _packet_is_blocked(self, packet):
    """
    Checks whether current packet matches our custom blocked host pair.
    """
    src = packet.src
    dst = packet.dst

    return ((src == self.H1_MAC and dst == self.H3_MAC) or
            (src == self.H3_MAC and dst == self.H1_MAC))

  def _drop_packet(self, event):
    """
    Drops current packet by consuming switch buffer (if present).
    """
    if event.ofp.buffer_id is not None:
      po = of.ofp_packet_out()
      po.buffer_id = event.ofp.buffer_id
      po.in_port = event.port
      self.connection.send(po)

  def _flood_packet(self, event):
    """
    Flood packet when destination is unknown/multicast.
    """
    po = of.ofp_packet_out()
    po.in_port = event.port
    po.data = event.ofp
    po.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    self.connection.send(po)

  def _install_forwarding_flow(self, event, packet, out_port):
    """
    Install learned forwarding flow to reduce repeated PacketIn events.

    Match-Action logic:
      match: packet 5-tuple/L2 fields from incoming packet (via from_packet)
      action: output to learned destination port
    """
    fm = of.ofp_flow_mod()
    fm.match = of.ofp_match.from_packet(packet, event.port)
    fm.idle_timeout = 30
    fm.hard_timeout = 120
    fm.actions.append(of.ofp_action_output(port=out_port))

    # Include the triggering packet so switch forwards it immediately,
    # avoiding a separate packet_out.
    fm.data = event.ofp
    self.connection.send(fm)

  def _handle_PacketIn(self, event):
    packet = event.parsed
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    # Parse upper-layer payload using pox.lib.packet.
    # (Used for visibility/debug and to satisfy packet parsing requirement.)
    ip_pkt = packet.find(ipv4)
    if ip_pkt is not None:
      log.debug("IPv4 PacketIn %s -> %s (%s -> %s)",
                packet.src, packet.dst, ip_pkt.srcip, ip_pkt.dstip)
    elif isinstance(packet, ethernet):
      log.debug("Ethernet PacketIn %s -> %s type=0x%04x",
                packet.src, packet.dst, packet.type)

    # L2 learning step: source MAC is reachable through ingress port.
    self.mac_to_port[packet.src] = event.port

    # Enforce custom policy: block h1 <-> h3 traffic.
    if self._packet_is_blocked(packet):
      log.info("Blocked packet %s -> %s on port %s",
               packet.src, packet.dst, event.port)

      # Install an exact drop rule from this packet as additional protection
      # against repeated PacketIn (in case packet reached controller before
      # static block rules were fully applied).
      fm = of.ofp_flow_mod()
      fm.priority = 50001
      fm.match = of.ofp_match.from_packet(packet, event.port)
      fm.idle_timeout = 60
      fm.hard_timeout = 0
      # No action => DROP
      fm.buffer_id = event.ofp.buffer_id
      self.connection.send(fm)
      return

    # Multicast destination: flood.
    if packet.dst.is_multicast:
      self._flood_packet(event)
      return

    # Unknown destination: flood, and learn when response comes back.
    out_port = self.mac_to_port.get(packet.dst)
    if out_port is None:
      self._flood_packet(event)
      return

    # Same ingress/egress port means likely loop or stale entry; drop.
    if out_port == event.port:
      log.warning("Ingress and egress are same port (%s), dropping %s -> %s",
                  out_port, packet.src, packet.dst)
      self._drop_packet(event)
      return

    # Install forwarding rule for known destination.
    self._install_forwarding_flow(event, packet, out_port)


class L2LearningBlockController(object):
  """
  Component entry class: listens on core.openflow for switch connections.
  """

  def __init__(self):
    core.openflow.addListeners(self)
    self.switches = {}

  def _handle_ConnectionUp(self, event):
    log.info("Switch connected: %s", event.connection)

    sw = LearningSwitchWithBlock(event.connection)
    self.switches[event.dpid] = sw

    # Install static bidirectional block rules immediately at connection time.
    sw._install_bidirectional_block_rules()


def launch():
  """
  Launches the custom POX module.
  """
  core.registerNew(L2LearningBlockController)
  log.info("l2_learning_block_h1_h3 module loaded")
