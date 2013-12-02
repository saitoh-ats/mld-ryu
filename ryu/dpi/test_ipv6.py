# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging
import itertools
from nose.tools import *

from ryu.lib import ofctl_v1_3
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.dpi import ipv6sw

LOG = logging.getLogger(__name__)


class _Datapath(object):
    ofproto = ofproto_v1_3
    ofproto_parser = ofproto_v1_3_parser

    def __init__(self):
        self.msgs = []

    def send_msg(self, msg):
        self.msgs.append(msg)


class Test_ipv6sw(unittest.TestCase):

    """ Test case for ipv6sw functions
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _get_to_match(self, attrs):
        dp = _Datapath()
        return ipv6sw.to_match(dp, attrs)

    def test_to_match_ok(self):
        attrs = {}
        attrs['in_port'] = 1
        attrs['eth_type'] = 0x86dd
        attrs['ipv6_src'] = '2001:db8:bd05:1d2:288a:1fc0:1:10ee'
        attrs['ipv6_dst'] = '2001:db8:bd05:1d2:288a:1fc0:1:10ef'
        
        match = self._get_to_match(attrs)

        for key in attrs.keys():
            eq_(match[key], attrs[key])

    def test_to_match_unmatched(self):
        attrs = {'dummy': 1}
        match = self._get_to_match(attrs)
        ok_('dummy' not in match)

    def test_add_flows(self):
        dp = _Datapath()
        flows = [ipv6sw.FLOW_PKT_IN]
        ipv6sw.add_flows(dp, flows)

        for msg in dp.msgs:
            ok_(isinstance(msg, dp.ofproto_parser.OFPFlowMod))
            eq_(msg.command, dp.ofproto.OFPFC_ADD)

    def test_del_flows(self):
        dp = _Datapath()
        flows = [ipv6sw.FLOW_PKT_IN]
        ipv6sw.del_flows(dp, flows)

        for msg in dp.msgs:
            ok_(isinstance(msg, dp.ofproto_parser.OFPFlowMod))
            eq_(msg.command, dp.ofproto.OFPFC_DELETE)

    def test_del_cookies(self):
        dp = _Datapath()
        cookies = [1, 2, 3]
        ipv6sw.del_cookies(dp, cookies)

        for i, msg in enumerate(dp.msgs):
            ok_(isinstance(msg, dp.ofproto_parser.OFPFlowMod))
            eq_(msg.command, dp.ofproto.OFPFC_DELETE)
            eq_(msg.cookie, cookies[i])
