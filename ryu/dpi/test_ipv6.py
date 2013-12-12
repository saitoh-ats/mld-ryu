# vim: tabstop=4 shiftwidth=4 softtabstop=4

import os
import unittest
import logging
import itertools
import webob
import json
from nose.tools import *
from mock import patch

from ryu.lib import hub, ofctl_v1_3
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.dpi import ipv6sw
from ryu.controller.dpset import EventDP
from ryu.controller import ofp_event

LOG = logging.getLogger(__name__)

TEST_FLOW_STD = {"actions": [{"type": "OUTPUT", "port": 1}]}
TEST_FLOW_PRI = {"actions": [{"type": "OUTPUT", "port": 2}]}


class _Datapath(object):
    ofproto = ofproto_v1_3
    ofproto_parser = ofproto_v1_3_parser

    def __init__(self, id=1):
        self.msgs = []
        self.id = id
        self.xid = 1

    def set_xid(self, msg):
        self.xid += 1
        self.xid &= self.ofproto.MAX_XID
        msg.set_xid(self.xid)
        return self.xid

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
        reload(ipv6sw)

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

    def test_to_match_invalid(self):
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

    @patch('ryu.lib.hub.Event.wait', return_value=False)
    def test_wait_barrier_ng(self, m):
        ipv6sw.BARRIER_REPLY_TIMER = 0
        ok_(not ipv6sw.wait_barrier(_Datapath(), {}))

    @patch('ryu.lib.hub.Event.wait', return_value=True)
    def test_wait_barrier_ok(self, m):
        ipv6sw.BARRIER_REPLY_TIMER = 0
        ok_(ipv6sw.wait_barrier(_Datapath(), {}))


class TestFlowdict(unittest.TestCase):
    """ Test case for Flowdict
    """

    def setUp(self):
        self.flow = TEST_FLOW_STD
        self.dict = {"1": [self.flow]}
        self.json = json.dumps(self.dict)
        self.flowdict = ipv6sw.Flowdict()
        self.flowdict["1"] = [self.flow]

    def tearDown(self):
        pass

    def test_from_file(self):
        flowdict = ipv6sw.Flowdict()
        file = "/tmp/_test_json"
        with open(file, 'w') as f:
            json.dump(self.dict, f)
        flowdict.from_file(file)
        eq_(json.dumps(flowdict), self.json)
        os.remove(file)

    def test_from_json(self):
        flowdict = ipv6sw.Flowdict()
        dict = {"1": [self.flow, self.flow], "2": [self.flow], "3": []}
        j = json.dumps(dict)
        flowdict.from_json(j)
        eq_(json.dumps(flowdict), j)

    def test_to_json_indentFalse(self):
        eq_(self.flowdict.to_json(), self.json)

    def test_to_json_indentTrue(self):
        eq_(self.flowdict.to_json(True),
            json.dumps(self.dict, sort_keys=True, indent=4))

    def test_get_dpids(self):
        eq_(self.flowdict.get_dpids(), [1])

    def test_get_items(self):
        eq_(self.flowdict.get_items(), [(1, [self.flow])])

    def test_get_flows_dpid_in_dict(self):
        eq_(self.flowdict.get_flows(1), [self.flow])

    def test_get_flows_dpid_not_in_dict(self):
        eq_(self.flowdict.get_flows(2), [])

    def test_check_dp_dpid_in_dpset(self):
        dpset = _DPSet()
        dpset.register(_Datapath())
        ok_(self.flowdict.check_dp(dpset) is None)

    def test_check_dp_dpid_not_in_dpset(self):
        dpset = _DPSet()
        eq_(self.flowdict.check_dp(dpset), 1)


class TestDpiStatsController(unittest.TestCase):
    """ Test case for StatsController
    """

    def setUp(self):
        self.dpiflow = {"standard": ipv6sw.Flowdict(),
                        "primary": ipv6sw.Flowdict()}
        self.dpiflow["standard"]["1"] = [TEST_FLOW_STD]
        self.dpiflow["primary"]["1"] = [TEST_FLOW_PRI]
        self.data = {
            'waiters': {},
            'dpset': _DPSet(),
            'dpiflow': self.dpiflow
        }
        self.wsgi = WSGIApplication()
        self.wsgi.register(ipv6sw.DpiStatsController, self.data)

    def tearDown(self):
        pass

    def _test_request_dpi(self, wsgi, uri, code=200, method='GET', body=''):
        req = webob.Request.blank(uri)
        req.method = method
        req.body = body

        res = req.get_response(wsgi)
        eq_(res.charset, 'UTF-8')
        eq_(res.status_code, code)

        return res

    @patch('ryu.dpi.ipv6sw.wait_barrier', return_value=True)
    def _test_dpi_received_200(self, body, m):
        dp = _Datapath()
        data = self.data
        self.data["dpset"].register(dp)
        _cmddict = {"on": dp.ofproto.OFPFC_ADD,
                    "off": dp.ofproto.OFPFC_DELETE}
        cmd = _cmddict[json.loads(body)["dpi"]]

        wsgi = WSGIApplication()
        wsgi.register(ipv6sw.DpiStatsController, self.data)

        res = self._test_request_dpi(wsgi, '/dpi/flow', 200, 'PUT', body)
        msgs = self.data["dpset"].dps[1].msgs

        eq_(res.json, body)
        eq_(len(msgs), 1)
        ok_(isinstance(msgs[0], dp.ofproto_parser.OFPFlowMod))
        eq_(msgs[0].command, cmd)

    def test_dpi_received_200_dpi_on(self):
        body = '{"dpi": "on"}'
        self._test_dpi_received_200(body)

    def test_dpi_received_200_dpi_off(self):
        body = '{"dpi": "off"}'
        self._test_dpi_received_200(body)

    def test_dpi_received_404_notfound_uri(self):
        self._test_request_dpi(self.wsgi, '/dpi', 404)

    def test_dpi_received_404_unreserved_method(self):
        self._test_request_dpi(self.wsgi, '/dpi/flow', 404)

    def test_dpi_received_400_body_is_none(self):
        res = self._test_request_dpi(self.wsgi, '/dpi/flow', 400, 'PUT')

        ok_('body' in res.json)
        ok_('err_msg' in res.json)
        eq_(res.json['body'], '')

    def test_dpi_received_400_body_is_not_json(self):
        body = 'test'
        res = self._test_request_dpi(self.wsgi, '/dpi/flow', 400, 'PUT', body)

        ok_('body' in res.json)
        ok_('err_msg' in res.json)
        eq_(res.json['body'], body)

    def test_dpi_received_400_body_has_not_dpi(self):
        body = '{"test": 0}'
        res = self._test_request_dpi(self.wsgi, '/dpi/flow', 400, 'PUT', body)

        ok_('body' in res.json)
        ok_('err_msg' in res.json)
        eq_(res.json['body'], body)

    def test_dpi_received_400_dpi_value_is_invalid(self):
        body = '{"dpi": 0}'
        res = self._test_request_dpi(self.wsgi, '/dpi/flow', 400, 'PUT', body)

        ok_('body' in res.json)
        ok_('err_msg' in res.json)
        eq_(res.json['body'], body)

    def test_dpi_received_500_dpid_not_in_dpset(self):
        body = '{"dpi": "on"}'
        res = self._test_request_dpi(self.wsgi, '/dpi/flow', 500, 'PUT', body)

        ok_('body' in res.json)
        ok_('err_msg' in res.json)
        eq_(res.json['body'], body)

    @patch('ryu.dpi.ipv6sw.wait_barrier', return_value=False)
    def test_dpi_received_500_BarrierRequest_timeout(self, m):
        data = self.data
        self.data["dpset"].register(_Datapath())
        wsgi = WSGIApplication()
        wsgi.register(ipv6sw.DpiStatsController, self.data)

        body = '{"dpi": "on"}'
        res = self._test_request_dpi(wsgi, '/dpi/flow', 500, 'PUT', body)

        ok_('body' in res.json)
        ok_('err_msg' in res.json)
        eq_(res.json['body'], body)


class TestDpiRestApi(unittest.TestCase):
    """ Test case for DpiRestApi
    """

    def setUp(self):
        reload(ipv6sw)
        self.dpset = _DPSet()
        self.wsgi = WSGIApplication()
        self.kwargs = {'dpset': self.dpset, 'wsgi': self.wsgi}
        self.app = ipv6sw.DpiRestApi(**self.kwargs)

    def tearDown(self):
        pass

    def test_init(self):
        eq_(self.app.dpset, self.dpset)
        ok_("primary" in self.app.data["dpiflow"])
        ok_("standard" in self.app.data["dpiflow"])
        eq_(self.app.data["dpset"], self.dpset)
        eq_(self.app.data["waiters"], {})

    @raises(SystemExit)
    def test_init_jsonfile_not_exist(self):
        ipv6sw.JSONFILE = ["test_not_exist"]
        ipv6sw.DpiRestApi(**self.kwargs)

    def test_switch_features_handler_set_packetin(self):
        dp = _Datapath()
        msg = dp.ofproto_parser.OFPSwitchFeatures(dp, 1, 0, 0)
        ev = ofp_event.EventOFPMsgBase(msg)
        self.app._switch_features_handler(ev)
        msg = dp.msgs[0]
        ok_(isinstance(msg, dp.ofproto_parser.OFPFlowMod))
        eq_(msg.command, dp.ofproto.OFPFC_ADD)

    def test_handler_datapath_dp_enter_True(self):
        dp = _Datapath()
        ev = EventDP(dp, True)
        self.app._handler_datapath(ev)
        msg = dp.msgs[0]
        ok_(isinstance(msg, dp.ofproto_parser.OFPFlowMod))
        eq_(msg.command, dp.ofproto.OFPFC_ADD)

    def test_handler_datapath_dp_enter_False(self):
        dp = _Datapath()
        ev = EventDP(dp, False)
        self.app._handler_datapath(ev)
        eq_(dp.msgs, [])

    def _get_ev_barrier_reply(self):
        xid = 1
        dp = _Datapath()
        msg = dp.ofproto_parser.OFPBarrierReply(dp)
        msg.set_xid(xid)
        msg.serialize()
        ev = ofp_event.EventOFPMsgBase(msg)

        return ev, dp, xid

    def test_barrier_reply_handler_event_wait(self):
        ev, dp, xid = self._get_ev_barrier_reply()
        event = hub.Event()
        waiter = self.app.waiters.setdefault(dp.id, {})
        waiter[xid] = event

        self.app._barrier_reply_handler(ev)

        eq_(self.app.waiters[dp.id], {})

    def test_barrier_reply_handler_xid_not_in_waiters(self):
        ev, dp, xid = self._get_ev_barrier_reply()
        self.app.waiters.setdefault(dp.id, {})
        self.app._barrier_reply_handler(ev)
        eq_(self.app.waiters[dp.id], {})

    def test_barrier_reply_handler_xid_not_in_waiters(self):
        ev, dp, xid = self._get_ev_barrier_reply()
        LOG.debug(self.app.waiters)
        self.app.waiters = {}
        self.app._barrier_reply_handler(ev)
        eq_(self.app.waiters, {})

    def test_packet_in_handler(self):
        pkt = packet.Packet()
        dp = _Datapath()
        match = dp.ofproto_parser.OFPMatch(in_port=1)
        msg = dp.ofproto_parser.OFPPacketIn(dp, 0, 0, 0, 0, 0, match, pkt)
        ev = ofp_event.EventOFPMsgBase(msg)
        self.app._packet_in_handler(ev)
