#!/usr/bin/env python3
"""Minimal Mininet topology for SDN experiments (POX/Ryu remote controller)."""

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo


class SimpleSDNTopo(Topo):
    """1 switch + 4 hosts."""

    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow10")

        # IPs are assigned automatically by Mininet.
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")
        h4 = self.addHost("h4")

        for host in (h1, h2, h3, h4):
            self.addLink(host, s1)


def run(controller_ip="127.0.0.1", controller_port=6633):
    topo = SimpleSDNTopo()

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True,
    )

    info(f"*** Adding remote controller c0 at {controller_ip}:{controller_port}\n")
    net.addController(
        "c0",
        controller=RemoteController,
        ip=controller_ip,
        port=controller_port,
    )

    info("*** Starting network\n")
    net.start()

    info("*** Basic connectivity test (pingAll)\n")
    net.pingAll()

    info("*** Dropping into Mininet CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
