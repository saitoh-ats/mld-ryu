"""
Custom topology for DPI

                     s2                   w1
 (1)---(1)  (3)---(1)  (2)---(1)  (3)---(1)
d1          s4                    s1
 (1)---(2)  (4)---(1)  (2)---(2)  (4)---(1)
                     s3                   w2

d1(1)=d1-eth0: 10.0.0.1 / fe80::200:ff:fe00:1
               2001:db8:2000::11
               2001:db8:2000::111
w1(1)=w2-eth0: 10.0.0.2 / fe80::200:ff:fe00:2
               2001:db8:2000::13
w2(1)=w2-eth0: 10.0.0.3 / fe80::200:ff:fe00:3
               2001:db8:2000::14

sudo mn --mac --custom topo-dpi.py --topo dpi
sudo mn --mac --controller remote --custom topo-dpi.py --topo dpi --pre mn-pre

"""

from mininet.topo import Topo


class MyTopo(Topo):

    def __init__(self):
        "Create custom topo."

        # Initialize topology
        Topo.__init__(self)

        # Switch Parameters
        opts = {"protocols": ["OpenFlow13"]}

        # Add hosts and switches
        DPI1 = self.addHost('d1')
        Edge4 = self.addSwitch('s4')
        Bridge2 = self.addSwitch('s2')
        Bridge3 = self.addSwitch('s3')
        Edge1 = self.addSwitch('s1')
        Web1 = self.addHost('w1')
        Web2 = self.addHost('w2')

        # Add links
        self.addLink(Edge4, DPI1)
        self.addLink(Edge4, Bridge2)
        self.addLink(Edge4, Bridge3)
        self.addLink(Edge1, Bridge2)
        self.addLink(Edge1, Bridge3)
        self.addLink(Edge1, Web1)
        self.addLink(Edge1, Web2)


topos = {'dpi': (lambda: MyTopo())}
