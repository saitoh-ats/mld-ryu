# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging
import itertools
from nose.tools import *

from ryu.lib import ofctl_v1_3
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob.response import Response
from webob.request import Request
from ryu.dpi import ipv6sw
from ryu.controller.dpset import EventDP

LOG = logging.getLogger(__name__)


class _Datapath(object):
    ofproto = ofproto_v1_3
    ofproto_parser = ofproto_v1_3_parser

    def __init__(self, id=1):
        self.msgs = []
        self.id = id

    def send_msg(self, msg):
        self.msgs.append(msg)


class _DPSet(object):
    def __init__(self):
        self.dps = {}

    def register(self, dp):
         self.dps[dp.id] = dp
         self.ev = EventDP(dp, True)

    def get(self, dp_id):
        return self.dps.get(dp_id)

    def get_all(self):
        return self.dps.items()


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

class TestDpiStatsController(unittest.TestCase):

    """ Test case for StatsController
    """

    def setUp(self):
        dp = _Datapath()
        dpset = _DPSet()
        dpset.register(dp)

        self.dpset = dpset
        self.waiters = {}
        self.data = {
            'waiters': self.waiters,
            'dpset': self.dpset,
            'DpiRestApi': None,
            'flow_list': ipv6sw.IPV6DPI
        }
        self.wsgi = WSGIApplication()
        self.wsgi.register(ipv6sw.DpiStatsController, self.data)
        #LOG.debug((self.data.keys()))
        #LOG.debug((self.wsgi))

    def tearDown(self):
        pass

    def _request_dpi(self, uri, code=200, method='GET', body=''):
        # Todo: status Http library to use
        status = { 200: '200 OK',
                   400: '400 Bad Request',
                   404: '404 Not Found',
                   500: '500'}

        req = Request.blank(uri)
        req.method = method
        req.body = body
        return  self.wsgi(req.environ, lambda s, _: eq_(s, status[code]))

    def test_dpi_received_404_unreserved_uri(self):
        res = self._request_dpi('/dpi', 404)

    def test_dpi_received_404_unreserved_method(self):
        res = self._request_dpi('/dpi/flow', 404)

    def test_dpi_received_400_body_is_none(self):
        res = self._request_dpi('/dpi/flow', 400, 'PUT')
        LOG.debug(("return", res[0], type(res[0])))

        # Todo:
        # res = ["{'body': '', 'err_msg': 'invalid syntax at body'}"]
        #eq_(res[0].body, '')

    def test_dpi_received_400_body_has_not_dpi(self):
        body = "{'test': 0}"
        res = self._request_dpi('/dpi/flow', 400, 'PUT', body)
        LOG.debug(("return", res[0]))

    def test_dpi_received_400_dpi_value_is_fail(self):
        body = "{'dpi': 0}"
        res = self._request_dpi('/dpi/flow', 400, 'PUT', body)
        LOG.debug(("return", res[0]))
