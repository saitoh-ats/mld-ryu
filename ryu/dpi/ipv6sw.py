# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import struct
from webob import Response

from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import ofctl_v1_3
from ryu.lib.packet import packet
from ryu.app.ofctl_rest import StatsController, RestStatsApi
from ryu.app.wsgi import route
from ryu.ofproto.ofproto_parser import StringifyMixin


LOG = logging.getLogger(__name__)
FLOW_PKT_IN = {
    'actions': [{'type': 'OUTPUT', 'port': 0xfffffffd, 'max_len': 65535}]}

FLOW_1 = {
    'cookie': 1,
    'priority': 100,
    'match': {'eth_type': 0x0800, 'inport': 1},
    'actions': [{'type': 'OUTPUT', 'port': 2}]
    }
FLOW_2 = {
    'cookie': 1,
    'priority': 100,
    'match': {'eth_type': 0x0800, 'in_port': 2},
    'actions': [{'type': 'OUTPUT', 'port': 1}]
    }
FLOW_3 = {
    'cookie': 1,
    'priority': 100,
    'match': {'eth_type': 0x0806, 'in_port': 2},
    'actions': [{'type': 'OUTPUT', 'port': 0xfffffffb}]
    }
FLIST = {1: [FLOW_1, FLOW_2, FLOW_3]}
FLIST[2] = [FLOW_1, FLOW_2, FLOW_3]
IPV6FLOW = {
    'cookie': 2,
    'priority': 200,
    'match': {'eth_type': 0x86dd, 'ipv6_dst': ['ff02::','ffff:ffff:ffff:ffff::']},
    'actions': [{'type': 'OUTPUT', 'port': 0xfffffffb}]
    }
IPV6FLOW2 = {
    'cookie': 2,
    'priority': 200,
    'match': {'in_port': 1, 'eth_type': 0x86dd, 'ipv6_dst': 'fe80::200:ff:fe00:2'},
    'actions': [{'type': 'OUTPUT', 'port': 2}]
    }
IPV6FLOW3 = {
    'cookie': 2,
    'priority': 200,
    'match': {'in_port': 2, 'eth_type': 0x86dd, 'ipv6_dst': 'fe80::200:ff:fe00:1'},
    'actions': [{'type': 'OUTPUT', 'port': 1}]
    }
IPV6LIST = {1: [IPV6FLOW, IPV6FLOW2, IPV6FLOW3]}
IPV6LIST[2] = [IPV6FLOW, IPV6FLOW2, IPV6FLOW3]
IPV6DPI = {'on': IPV6LIST, 'off': FLIST}


def to_match(dp, attrs):
    try:
        match = dp.ofproto_parser.OFPMatch(**attrs)
    except Exception as e:
        match = dp.ofproto_parser.OFPMatch()
        LOG.error("Match-ERR: %s", e)
        LOG.debug("  --> attrs=%s", attrs)
        LOG.debug("  --> match=%s", match.to_jsondict())

    return match

def mod_flow_entry(dp, flow, cmd):
    cookie = int(flow.get('cookie', 0))
    cookie_mask = int(flow.get('cookie_mask', 0))
    table_id = int(flow.get('table_id', 0))
    idle_timeout = int(flow.get('idle_timeout', 0))
    hard_timeout = int(flow.get('hard_timeout', 0))
    priority = int(flow.get('priority', 0))
    buffer_id = int(flow.get('buffer_id', dp.ofproto.OFP_NO_BUFFER))
    out_port = int(flow.get('out_port', dp.ofproto.OFPP_ANY))
    out_group = int(flow.get('out_group', dp.ofproto.OFPG_ANY))
    flags = int(flow.get('flags', 0))
    match = to_match(dp, flow.get('match', {}))
    inst = ofctl_v1_3.to_actions(dp, flow.get('actions', []))

    flow_mod = dp.ofproto_parser.OFPFlowMod(
        dp, cookie, cookie_mask, table_id, cmd, idle_timeout,
        hard_timeout, priority, buffer_id, out_port, out_group,
        flags, match, inst)

    dp.send_msg(flow_mod)

def add_flows(dp, flows):
    cmd = dp.ofproto.OFPFC_ADD
    for flow in flows:
         mod_flow_entry(dp, flow, cmd)

def del_flows(dp, flows):
    cmd = dp.ofproto.OFPFC_DELETE
    for flow in flows:
         mod_flow_entry(dp, flow, cmd)


class StringifyFlow(StringifyMixin):
    """
    """
    def __init__(self, cookie=0, priority=0, idle_timeout=0, hard_timeout=0,
                 match=None, actions=[]):
        super(StringifyFlow, self).__init__()
        self.cookie = cookie
        self.priority = priority
        self.idle_timeout = idle_timeout
        self.hard_timeout = hard_timeout
        self.match = match
        self.actions = actions


class Flow(dict):
    """
    flow = {'cookie': cookie,
            'priority': priority,
            'flags': 0,
            'idle_timeout': 0,
            'hard_timeout': 0,
            'match': match,
            'actions': actions}
    """

    def __init__(self):
        super(Flow, self).__init__()

        match = {"in_port": 1}
        actions = [{"output": 2}]
        instructions = [{"output": 2}]

        self.__setitem__('cookie', 0)
        self.__setitem__('priority', 0)
        self.__setitem__('match', match)
        self.__setitem__('actions', actions)
        self.__setitem__('instructions', instructions)

class FlowList(object):
    """
    flowlist = {'<dpid>': [flow, ...], ...}
    flow = {'cookie': cookie,
            'priority': priority,
            'flags': 0,
            'idle_timeout': 0,
            'hard_timeout': 0,
            'match': match,
            'actions': actions}
    """

    def __init__(self, filename=None):
        self.flowlist = {}

    def get_switches(self):
        return self.flowlist.keys()

    def get_flows(self, dpid):
        try:
            return self.flowlist[dpid]
        except:
            return []

    def set_flows(self, dpid, flows):
        self.flowlist[dpid] = flows

    def add_flows(self, dpid, flows):
        if dpid in self.flowlist:
            self.flowlist[dpid].append(flows)
        else:
            self.set_flows(dpid, flows)

    def __str__(self):
        return str(self.flowlist)



class DpiStatsController(StatsController):
    DPI_REST_LIST = {'dpi': ['on', 'off']}

    def __init__(self, req, link, data, **config):
        super(DpiStatsController, self).__init__(req, link, data, **config)
        self.flowlist = data['flow_list']
        self.dpirestapi = data['DpiRestApi']

    def _dpi_res(self, status, body, err_msg=None):
        if err_msg:
            _dpi_body = {'err_msg': err_msg, 'body': body}
            LOG.info('REST-ERR: %s: %s', err_msg, str(body))
        else:
            _dpi_body = body
        return Response(content_type='application/json', status=status,
            body=str(_dpi_body))

    @route('dpi', '/dpi/flow', methods=['PUT'])
    def dpi_received(self, req, **_kwargs):
        body = req.body
        LOG.debug("================ Received REST DPI")
        LOG.debug("  body=%s", body)
        LOG.debug("  dpset=%s", self.dpset)
        LOG.debug("  waiters=%s", self.waiters)
        LOG.debug("  flowlist=%s", self.flowlist)
        LOG.debug("  RyuApp=%s", self.dpirestapi)

        # REST Parameter check
        try:
            dpi_cmd = eval(body)['dpi']
        except:
            err_msg = "invalid syntax at body"
            return self._dpi_res(400, body, err_msg)

        if dpi_cmd not in self.DPI_REST_LIST['dpi']:
            err_msg = "invalid value at dpi"
            return self._dpi_res(400, body, err_msg)

        # Datapath check
        dpi_flow = IPV6DPI
        flow_list = dpi_flow['on']
        for dpid, flows in flow_list.items():
            dp = self.dpset.get(dpid)
            if dp is None:
                err_msg = "Datapath[dpid=%s] is None" % dpid
                return self._dpi_res(500, body, err_msg)

            LOG.debug("  --> mod flows [%s] dpid=%s", dpi_cmd, dpid)
            LOG.debug("      flows=%s", flows)
            if dpi_cmd == 'on':
                add_flows(dp, flows)
            elif dpi_cmd == 'off':
                del_flows(dp, flows)

            dp.send_barrier()

        LOG.debug("==================================")
        return self._dpi_res(200, body)


class DpiRestApi(RestStatsApi):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DpiRestApi, self).__init__(*args, **kwargs)

        #flow = Flow()
        #sflow = StringifyFlow.from_jsondict(JSON)
        flowlist = FlowList()
        #flowlist.add_flows(1,[sflow,flow])
        #print flow
        #print sflow
        #print sflow.to_jsondict()['StringifyFlow']
        #print str(flowlist)
        #print flowlist.get_switches()
        #print flowlist.get_flows(1)
        #print flowlist.get_flows(2)
        #exit()

        LOG.debug("=================== REST-API(init)")
        LOG.debug("  args=%s, kwargs=%s", args, kwargs)

        wsgi = kwargs['wsgi']
        self.data['flow_list'] = flowlist
        self.data['DpiRestApi'] = self
        wsgi.register(DpiStatsController, self.data)

        LOG.debug("  CONTEXTS=%s", self._CONTEXTS)
        LOG.debug("  dpset=%s", self.dpset)
        LOG.debug("  data=%s", self.data)
        LOG.debug("==================================")

    def _del_flow(self, flow_stats):
        match = flow_stats.match
        cookie = flow_stats.cookie
        cmd = self.dp.ofproto.OFPFC_DELETE_STRICT
        priority = flow_stats.priority
        actions = []

        flow_mod = self.dp.ofproto_parser.OFPFlowMod(
            self.dp, match, cookie, cmd, priority=priority, actions=actions)
        self.dp.send_msg(flow_mod)
        self.logger.info('Delete flow [cookie=0x%x]', cookie, extra=self.sw_id)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        dp = ev.msg.datapath
        dpid = dp.id
        LOG.debug("=================== SwitchFeatures")
        LOG.debug("  dpid=%s, dpset=%s", dpid, self.dpset.get_all())

        if dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            flows = [FLOW_PKT_IN]
            LOG.debug("  --> add flows dpid=%s", dpid)
            LOG.debug("      flows=%s", flows)
            add_flows(dp, flows)

        LOG.debug("==================================")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        LOG.debug("======================== Packet-in")
        LOG.debug("  -->dpid=%s, in_port=%s", dpid, in_port)
        LOG.debug("     packet=%s", str(pkt))
        LOG.debug("==================================")

    @set_ev_cls(dpset.EventDP)
    def _handler_datapath(self, ev):
        if ev.enter:
            dp = ev.dp
            dpid = dp.id
            LOG.debug("==================== dpset EventDP")
            LOG.debug("  dpid=%s, xid=%s, dpset=%s",
                dpid, dp.xid, self.dpset.get_all())

            flow_list = IPV6DPI['off']
            flows = flow_list[dp.id]
            LOG.debug("  --> add flows dpid=%s", dpid)
            LOG.debug("      flows=%s", flows)
            add_flows(dp, flows)
            LOG.debug("==================================")
