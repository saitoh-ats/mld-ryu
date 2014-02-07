"""
Custom topology for DPI

 startup
 =======
 $ sudo mn --controller remote --custom topo-dpi.py --pre mn-pre \
     --topo [dpi|dpi-w1|dpi-r3]

 or

 $ sudo python ./topo-dpi.py


 topo=dpi: DPI and WebServer-2
 =============================

                /---(1)s2(2)---\
              (2)              (1)  (3)---(1)w1
 d1(1)---(1)s4                    s1
              (3)              (2)  (4)---(1)w2
                \---(1)s3(2)---/


 topo=dpi-w1: DPI and WebServer-1
 ================================

                /---(1)s2(2)---\
              (2)              (1)
 d1(1)---(1)s4                    s1(3)---(1)w1
              (3)              (2)
                \---(1)s3(2)---/


 topo=dpi-r3: DPI and WebServer-1 by 3-routes
 ============================================

                /---(1)s2(2)---\
              (2)              (1)
 d1(1)---(1)s4(4)--------------(4)s1(3)---(1)w1
              (3)              (2)
                \---(1)s3(2)---/


 host interfaces
 ===============
 d1(1)=d1-eth0: 10.0.0.1
                fe80::200:ff:fe00:1
                2001:db8:2000::11
                2001:db8:2000::111
                2001:db8:2000::1111
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


class DpiTopoWeb1Route3(DpiTopoWeb1):
    def __init__(self):
        DpiTopoWeb1.__init__(self)

        # Add links
        self.addLink(self.Edge1, self.Edge4)


topos = {'dpi': (lambda: DpiTopoWeb2()),
         'dpi-w1': (lambda: DpiTopoWeb1()),
         'dpi-r3': (lambda: DpiTopoWeb1Route3())}


from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI


def set_ofp_version(switch, protocols):
    protocols_str = ','.join(protocols)
    command = 'ovs-vsctl set Bridge %s protocols=%s' % (switch, protocols_str)
    switch.cmd(command.split(' '))


def add_ipv6address(host, inf, ipv6s):
    print '*** %s setup IPv6 addresses' % host
    for ipv6 in ipv6s:
        host.cmd('ifconfig', inf, 'inet add', ipv6)
    print host.cmd('ifconfig', inf)


def set_normalsw(switch):
    print '*** %s is Bridge:' % switch
    switch.cmd('ovs-ofctl add-flow', switch, 'actions=normal')
    print switch.cmd('ovs-ofctl dump-flows', switch)

ipv6_list = {'d1': {'d1-eth0': ['2001:db8:2000::11',
                                '2001:db8:2000::111',
                                '2001:db8:2000::1111']},
             'w1': {'w1-eth0': ['2001:db8:2000::13']},
             'w2': {'w2-eth0': ['2001:db8:2000::13']}}
bridge_list = ['s2', 's3']

if '__main__' == __name__:
    setLogLevel('info')
    net = Mininet(topo=DpiTopoWeb1Route3())
    net.start()

    # set ofp version
    for sw in net.switches:
        set_ofp_version(sw, ['OpenFlow10', 'OpenFlow13'])
        # setup normal SW
        if sw.name in bridge_list:
            set_normalsw(sw)

    # add IPv6 addresses
    for host in net.hosts:
        for inf, ipv6s in ipv6_list[host.name].iteritems():
            add_ipv6address(host, inf, ipv6s)

    CLI(net)
    net.stop()
