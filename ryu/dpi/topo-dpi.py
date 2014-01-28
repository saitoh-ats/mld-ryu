"""
Custom topology for DPI

 startup
 =======
 $ sudo mn --controller remote --custom topo-dpi.py --pre mn-pre \
     --topo [dpi|dpi-w1]


 topo=dpi: DPI and WebServer-2
 =============================

              (2)---(1)s2(2)---(1)  (3)---(1)w1
 d1(1)---(1)s4                    s1
              (3)---(1)s3(2)---(2)  (4)---(1)w2


 topo=dpi-w1: DPI and WebServer-1
 ================================

              (2)---(1)s2(2)---(1)
 d1(1)---(1)s4                    s1(3)---(1)w1
              (3)---(1)s3(2)---(2)


 host interfaces
 ===============
 d1(1)=d1-eth0: 10.0.0.1
                fe80::200:ff:fe00:1
                2001:db8:2000::11
                2001:db8:2000::111
 w1(1)=w1-eth0: 10.0.0.2
                fe80::200:ff:fe00:2
                2001:db8:2000::13
 w2(1)=w2-eth0: 10.0.0.3
                fe80::200:ff:fe00:3
                2001:db8:2000::14

"""

from mininet.topo import Topo


class DpiTopoWeb1(Topo):
    def __init__(self):
        # Initialize topology
        Topo.__init__(self)

        # Switch Parameters
        opts = {"protocols": ["OpenFlow13"]}

        # Add hosts and switches
        self.DPI1 = self.addHost('d1')
        self.Edge4 = self.addSwitch('s4')
        self.Bridge2 = self.addSwitch('s2')
        self.Bridge3 = self.addSwitch('s3')
        self.Edge1 = self.addSwitch('s1')
        self.Web1 = self.addHost('w1')

        # Add links
        self.addLink(self.Edge4, self.DPI1)
        self.addLink(self.Edge4, self.Bridge2)
        self.addLink(self.Edge4, self.Bridge3)
        self.addLink(self.Edge1, self.Bridge2)
        self.addLink(self.Edge1, self.Bridge3)
        self.addLink(self.Edge1, self.Web1)


class DpiTopoWeb2(DpiTopoWeb1):
    def __init__(self):
        DpiTopoWeb1.__init__(self)

        # Add hosts and switches
        self.Web2 = self.addHost('w2')

        # Add links
        self.addLink(self.Edge1, self.Web2)


topos = {'dpi': (lambda: DpiTopoWeb2()), 'dpi-w1': (lambda: DpiTopoWeb1())}
