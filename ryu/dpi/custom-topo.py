"""
Custom topology for general purpose using definition file

 Usage of this class is similar to topo-dpi.py

 startup
 =======
 $ sudo mn --controller remote --custom custom-topo.py --pre mn-pre \
     --topo [dpi|dpi-w1|dpi-r3]

 or

 $ sudo python ./custom-topo.py -f definition_file_path


"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import RemoteController
import json
import sys
import argparse

topos = {'dpi': (lambda: CustomTopo("./dpi_to_web2.json")),
         'simple': (lambda: CustomTopo("./simple_topo.json"))}

class CustomTopo(Topo):
    def __init__(self, topoDefFile):
        # Call same function on super class
        Topo.__init__(self)

        # Switch Parameters
        opts = {"protocols": ["OpenFlow13"]}

        # create topology
        self.create_topology(topoDefFile)

    def create_topology(self, fileName):
        #
        # read and parse definition file
        #
        try:
            fh = open(fileName)
            self.jsonData = json.load(fh)
        except IOError:
            print >> sys.stderr, 'Failed to open %s.' % fileName
            return False
        except:
            print >> sys.stderr, 'Failed to parse definition file: ', sys.exc_info()[0]
            return False
        finally:
            fh.close()

        # create topology
        self.hostList = {}
        self.switchList = {}
        self.add_hosts()
        self.add_switches()
        if False == self.add_links():
            return False

        return True

    def start_networking(self):
        setLogLevel("info")
        net = Mininet(topo=self, controller=lambda name: RemoteController(name))
        net.start()

        # setup each switch
        for sw in net.switches:
            # set ofp version
            self.set_ofp_version(sw, ['OpenFlow10', 'OpenFlow13'])
            # if sw is bridge, set it up for normal SW
            swEntry = self.switchList[sw.name][1]
            isBridge = swEntry["bridge"]
            if isBridge:
                self.set_normalsw(sw)
            self.switchList[sw.name].append(sw)

        # setup each host
        for host in net.hosts:
            self.add_ipv6address(host)
            self.hostList[host.name].append(host)

        # execute pre_command
        if self.jsonData.has_key("pre_cmd_file"):
            cmd_file = self.jsonData["pre_cmd_file"]
            self.exec_usercmd(cmd_file)

        CLI(net)

        # execute post_command
        if self.jsonData.has_key("post_cmd_file"):
            cmd_file = self.jsonData["post_cmd_file"]
            self.exec_usercmd(cmd_file)

        net.stop()

    def add_hosts(self):
        hosts = self.jsonData["hosts"]
        if False == isinstance(hosts, list):
            print >> sys.stderr, "ERROR: hosts must be list."
            return False
        for hostEntry in hosts:
            if False == isinstance(hostEntry, dict):
                print >> sys.stderr, "ERROR: hostEntry must be dict."
                return False
            hostName = hostEntry["host_name"].encode("ascii")
            host = self.addHost(hostName)
            self.hostList[hostName] = [host, hostEntry]

    def add_switches(self):
        switches = self.jsonData["switches"]
        if False == isinstance(switches, list):
            print >> sys.stderr, "ERROR: switches must be list."
            return False
        for swEntry in switches:
            if False == isinstance(swEntry, dict):
                print >> sys.stderr, "ERROR: swEntry must be dict."
                return False
            swName = swEntry["switch_name"].encode("ascii")
            sw = self.addSwitch(swName)
            self.switchList[swName] = [sw, swEntry]

    def add_links(self):
        links = self.jsonData["links"]
        if False == isinstance(links, list):
            print >> sys.stderr, "ERROR: links must be list."
            return False
        for linkEntry in links:
            if False == isinstance(linkEntry, list):
                print >> sys.stderr, "ERROR: linkEntry must be list."
                return False
            n1entry = linkEntry[0]
            n2entry = linkEntry[1]
            (n1,p1) = self.find_node(n1entry)
            (n2,p2) = self.find_node(n2entry)
            if None != n1 and None != n2:
                self.addLink(n1, n2, p1, p2)
            else:
                return False

    def find_node(self, entry):
        # find entry in hostList
        port = None
        if ":" in entry:
            entry, port = entry.split(":")
        if self.hostList.has_key(entry):
            hostEntry = self.hostList[entry][1]
            idx = 0
            for infEntry in hostEntry["inf_list"]:
                if infEntry["inf_name"] == port:
                    port = idx
                    break
                idx += 1
            return (self.hostList[entry][0].encode("ascii"), port)
        # find entry in switchlist
        elif self.switchList.has_key(entry):
            return (self.switchList[entry][0].encode("ascii"), port)
        else:
            # if not found, return None
            print >> sys.stderr, "ERROR: %s is not exist." % entry
            return None, None

    def set_ofp_version(self, switch, protocols):
        protocols_str = ','.join(protocols)
        command = 'ovs-vsctl set Bridge %s protocols=%s' % (switch, protocols_str)
        switch.cmd(command.split(' '))

    def add_ipv6address(self, host):
        hostEntry = self.hostList[host.name][1]
        for infEntry in hostEntry["inf_list"]:
            inf = infEntry["inf_name"].encode("ascii")
            addrList = infEntry["addr_list"]
            addrList = map(lambda x: x.encode("ascii"), addrList)
            print '*** %s setup IPv6 addresses' % host
            for ipv6 in addrList:
                host.cmd('ifconfig', inf, 'inet add', ipv6.encode("ascii"))
                print host.cmd('ifconfig', inf)
    
    def set_normalsw(self, switch):
        print '*** %s is Bridge:' % switch
        switch.cmd('ovs-ofctl add-flow', switch, 'actions=normal')
        print switch.cmd('ovs-ofctl dump-flows', switch)

    def exec_usercmd(self, cmd_file):
        # open file
        fh = open(cmd_file, "r")
        print "*** Execute user command in %s." % (cmd_file)
        for line in fh:
            line = line.rstrip()
            dmy = line.split(":", 1)
            if len(dmy) != 2: continue
            (host_name, cmd) = dmy
            host = None
            if self.switchList.has_key(host_name):
                host = self.switchList[host_name][2]
            elif self.hostList.has_key(host_name):
                host = self.hostList[host_name][2]
            else: continue
            # execute each line
            print "executing on %s :%s" % (host_name, cmd)
            print host.cmd(cmd)
        fh.close()

#
#
#

if '__main__' == __name__:
    setLogLevel('debug')

    # parse options
    argParser = argparse.ArgumentParser(description='test');
    argParser.add_argument('-f', '--file', required = True, help = 'definition file')
    args = argParser.parse_args()
    
    defFile = args.file
    
    topo = CustomTopo(defFile)

    if False == topo.start_networking() :
        print >> sys.stderr, "ERROR: Failed to set network parameter for %s." % defFile
        exit
