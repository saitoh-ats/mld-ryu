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
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.app.ofctl_rest import StatsController, RestStatsApi
from ryu.app.wsgi import ControllerBase, route
from ryu.ofproto.ofproto_parser import StringifyMixin


LOG = logging.getLogger(__name__)
JSON = {'cookie': 1, 'priority': 99,
    'match': [{'in_port': 1}],
    'instructions': [{'output': 2}]
    }

class StringifyFlow(StringifyMixin):
    """
    """
    def __init__(self, cookie=0, priority=0, idle_timeout=0, hard_timeout=0,
                 match=None, instructions=[]):
        super(StringifyFlow, self).__init__()
        self.cookie = cookie
        self.priority = priority
        self.idle_timeout = idle_timeout
        self.hard_timeout = hard_timeout
        self.match = match
        self.instructions = instructions


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
        #self.__setitem__('actions', actions)
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



class StatsController(ControllerBase):
    DPI_REST_LIST = {'dpi': ['on', 'off']}

    def _dpi_res(self, status, body, err_msg=None):
        if err_msg:
            _dpi_body = {'err_msg': err_msg, 'body': body}
            LOG.debug('REST-ERR: %s: %s', err_msg, str(body))
        else:
            _dpi_body = body
        return Response(content_type='application/json', status=status,
            body=str(_dpi_body))

    @route('dpi', '/dpi/flow', methods=['PUT'])
    def test(self, req, **_kwargs):
        body = req.body
        try:
            dpi_sw = eval(body)['dpi']
        except:
            err_msg = "invalid syntax at body"
            return self._dpi_res(400, body, err_msg)

        if dpi_sw not in self.DPI_REST_LIST['dpi']:
            err_msg = "invalid value at dpi"
            return self._dpi_res(400, body, err_msg)

        return self._dpi_res(200, body)


class DpiRestApi(RestStatsApi):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DpiRestApi, self).__init__(*args, **kwargs)

        flow = Flow()
        sflow = StringifyFlow.from_jsondict(JSON)
        flowlist = FlowList()
        flowlist.add_flows(1,[sflow,flow])
        print flow
        print sflow
        print sflow.to_jsondict()['StringifyFlow']
        print str(flowlist)
        print flowlist.get_switches()
        print flowlist.get_flows(1)
        print flowlist.get_flows(2)
        exit()

        wsgi = kwargs['wsgi']
        wsgi.register(StatsController)

        LOG.debug(("##### DPI #####","**args", args, "**kwargs", kwargs))
        LOG.debug(("##### DPI #####","**CONTEXTS",self._CONTEXTS,"**dpset",self.dpset, "**data",self.data))
        LOG.debug(("##### DPI #####","**dpset get",self.dpset.get_all()))

    def _add_flow(self, datapath, match, actions, cookie=0, priority=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        command = ofproto.OFPFC_ADD
        self._flowmod(datapath, match, actions, cookie, priority, command)

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

    def _flowmod(self, dp, match, actions, cookie, priority, command):
        ofproto = dp.ofproto
        inst = [dp.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = dp.ofproto_parser.OFPFlowMod(
            datapath=dp, cookie=cookie, cookie_mask=0, table_id=0,
            command=command, idle_timeout=0, hard_timeout=0,
            priority=priority, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        dp.send_msg(mod)
        dp.send_barrier()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()

        if dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER)]
            self._add_flow(dp, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        LOG.debug("-------------------packet in--------")
        LOG.debug("packet in dpid=%s, in_port=%s", dpid, in_port)
        LOG.debug(str(pkt))
        LOG.debug("------------------------------------")

    @set_ev_cls(dpset.EventDP)
    def _handler_datapath(self, ev):
        if ev.enter:
            dp = ev.dp
            LOG.debug("-------------------dpset--------")
            LOG.debug("dpid=%s, xid=%s, ports=%s", dp.id, dp.xid, dp.ports)
            LOG.debug("-------------------add flow--------")
            self._define_flow(dp)

    def _define_flow(self, dp):
        match = dp.ofproto_parser.OFPMatch(
            eth_type=0x86dd,
            ipv6_dst=('ff02::','ffff:ffff:ffff:ffff::'))
        actions = [dp.ofproto_parser.OFPActionOutput(dp.ofproto.OFPP_FLOOD)]
        self._add_flow(dp, match, actions)

        match = dp.ofproto_parser.OFPMatch(
            eth_type=0x86dd,
            in_port=1,
            ipv6_dst='fe80::200:ff:fe00:2')
        actions = [dp.ofproto_parser.OFPActionOutput(2)]
        self._add_flow(dp, match, actions)

        match = dp.ofproto_parser.OFPMatch(
            eth_type=0x86dd,
            in_port=2,
            ipv6_dst='fe80::200:ff:fe00:1')
        actions = [dp.ofproto_parser.OFPActionOutput(1)]
        self._add_flow(dp, match, actions)
