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


LOG = logging.getLogger(__name__)


class StatsController(ControllerBase):
    @route('dpi', '/dpi/flow', methods=['PUT'])
    def test(self, req, **_kwargs):
        LOG.debug(("--test--", self, "dir", dir(self), "req", req, "req.body", req.body, "kwargs", _kwargs))
        try:
            dpi = eval(req.body)['dpi']
        except:
            LOG.debug('invalid syntax %s', req.body)
            err_body = {
                "err_msg" : "invalid syntax at body",
                "body" : req.body
            }
            return Response(status=400, body=str(err_body))
        LOG.debug(("--test--", req.body, "dpi", dpi))
        return Response(status=200, body=req.body)


class DpiRestApi(RestStatsApi):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DpiRestApi, self).__init__(*args, **kwargs)

        LOG.debug(("OFP_VERSIONS=", self.OFP_VERSIONS))

        wsgi = kwargs['wsgi']
        wsgi.register(StatsController)

        LOG.debug(("##### DPI #####","**args", args, "**kwargs", kwargs))
        LOG.debug(("##### DPI #####","**CONTEXTS",self._CONTEXTS,"**dpset",self.dpset, "**data",self.data))
        LOG.debug(("##### DPI #####","**dpset get",self.dpset.get_all()))

    def _add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()

        if dp.ofproto.OFP_VERSION == ofproto_v1_3.OFP_VERSION:
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER)]
            self._add_flow(dp, 0, match, actions)

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
        self._flowmod(dp, match, actions)

        match = dp.ofproto_parser.OFPMatch(
            eth_type=0x86dd,
            in_port=1,
            ipv6_dst='fe80::200:ff:fe00:2')
        actions = [dp.ofproto_parser.OFPActionOutput(2)]
        self._flowmod(dp, match, actions)

        match = dp.ofproto_parser.OFPMatch(
            eth_type=0x86dd,
            in_port=2,
            ipv6_dst='fe80::200:ff:fe00:1')
        actions = [dp.ofproto_parser.OFPActionOutput(1)]
        self._flowmod(dp, match, actions)

    def _flowmod(self, dp, match, actions):
        ofproto = dp.ofproto
        inst = [dp.ofproto_parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = dp.ofproto_parser.OFPFlowMod(
            datapath=dp, cookie=0x1, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=100, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        dp.send_msg(mod)
        dp.send_barrier()
