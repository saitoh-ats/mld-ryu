"""
Ryu-App for DPI
"""
import os
import logging
import json
import webob

from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub, ofctl_v1_3
from ryu.lib.packet import packet
from ryu.app.ofctl_rest import StatsController, RestStatsApi
from ryu.app.wsgi import route

LOG = logging.getLogger(__name__)

# Tuning
BARRIER_REPLY_TIMER = 2.0  # sec
FLOW_PKT_IN = {
    "actions": [{"type": "OUTPUT", "port": 0xfffffffd, "max_len": 65535}]}

# Static
DPI_FLOWLIST = {"default": "standard", "dpi": "primary"}
JSONFILE = DPI_FLOWLIST.values()
JSONDIR = "dpiflows"
JSONPATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), JSONDIR)


def to_match(dp, attrs):
    try:
        match = dp.ofproto_parser.OFPMatch(**attrs)
    except Exception as e:
        match = dp.ofproto_parser.OFPMatch()
        LOG.error("### Match-ERR: %s", e)
        LOG.debug("  --> attrs=%s", attrs)
        LOG.debug("  --> match=%s", match.to_jsondict())

    return match


def mod_flow_entry(dp, flow, cmd):
    cookie = int(flow.get("cookie", 0))
    cookie_mask = int(flow.get("cookie_mask", 0))
    table_id = int(flow.get("table_id", 0))
    idle_timeout = int(flow.get("idle_timeout", 0))
    hard_timeout = int(flow.get("hard_timeout", 0))
    priority = int(flow.get("priority", 0))
    buffer_id = int(flow.get("buffer_id", dp.ofproto.OFP_NO_BUFFER))
    out_port = int(flow.get("out_port", dp.ofproto.OFPP_ANY))
    out_group = int(flow.get("out_group", dp.ofproto.OFPG_ANY))
    flags = int(flow.get("flags", 0))
    match = to_match(dp, flow.get("match", {}))
    inst = ofctl_v1_3.to_actions(dp, flow.get("actions", []))

    flow_mod = dp.ofproto_parser.OFPFlowMod(
        dp, cookie, cookie_mask, table_id, cmd, idle_timeout,
        hard_timeout, priority, buffer_id, out_port, out_group,
        flags, match, inst)

    dp.send_msg(flow_mod)


def add_flows(dp, flows):
    LOG.info("<------------------- Flow-Mod(ADD) [dp=%s, flows=%s]",
             dp.id, len(flows))
    cmd = dp.ofproto.OFPFC_ADD
    for flow in flows:
        mod_flow_entry(dp, flow, cmd)


def del_flows(dp, flows):
    LOG.info("<---------------- Flow-Mod(DELETE) [dp=%s, flows=%s]",
             dp.id, len(flows))
    cmd = dp.ofproto.OFPFC_DELETE
    for flow in flows:
        mod_flow_entry(dp, flow, cmd)


def del_cookies(dp, cookies):
    cmd = dp.ofproto.OFPFC_DELETE
    for cookie in cookies:
        flow = {"cookie": cookie, "cookie_mask": 65535}
        mod_flow_entry(dp, flow, cmd)


def wait_barrier(dp, waiters):
    barrier = dp.ofproto_parser.OFPBarrierRequest(dp)
    dp.set_xid(barrier)
    waiters_per_dp = waiters.setdefault(dp.id, {})
    event = hub.Event()
    waiters_per_dp[barrier.xid] = event
    LOG.info("<----------------- Barrier Request [dp=%s, xid=%s, timer=%s]",
             dp.id, barrier.xid, BARRIER_REPLY_TIMER)
    dp.send_msg(barrier)

    ret = event.wait(timeout=BARRIER_REPLY_TIMER)
    if not ret:
        del waiters_per_dp[barrier.xid]

    return ret


def is_exist_file(file):
    return os.path.isfile(file)


class Flowdict(dict):
    """
    Flowdict
    flowdict = {<dpid>: [flow, ...], ...}
    flow = {"cookie": cookie,
            "priority": priority,
            "flags": 0,
            "idle_timeout": 0,
            "hard_timeout": 0,
            "match": match,
            "actions": actions}
    """

    def __init__(self):
        super(Flowdict, self).__init__()

    def from_file(self, file, encoding='utf-8'):
        with open(file, 'r') as f:
            self.update(json.load(f, encoding))

    def from_json(self, j):
        self.update(json.loads(j))
        return self

    def to_json(self, indent=False):
        if indent:
            return json.dumps(self, sort_keys=True, indent=4)
        else:
            return json.dumps(self)

    def get_dpids(self):
        return [int(x) for x in self.keys()]

    def get_items(self):
        return [(int(x), y) for x, y in self.items()]

    def get_flows(self, dpid):
        if str(dpid) in self:
            return self[str(dpid)]
        else:
            return []

    def check_dp(self, dpset):
        for dpid in self.get_dpids():
            if dpset.get(dpid) is None:
                return dpid


class DpiStatsController(StatsController):
    """
    DpiStatsController
    """
    DPI_REST_LIST = {"on": add_flows, "off": del_flows}

    def __init__(self, req, link, data, **config):
        super(DpiStatsController, self).__init__(req, link, data, **config)
        self.dpiflow = data["dpiflow"]

    def _dpi_flows_cmd(self, dp, flows, cmd):
        self.DPI_REST_LIST[cmd](dp, flows)
        return wait_barrier(dp, self.waiters)

    def _dpi_response(self, status, body, err_msg=None):
        if err_msg:
            _dpi_body = {"err_msg": err_msg, "body": body}
            LOG.error("### REST-ERR: %s: %s", err_msg, str(body))
        else:
            _dpi_body = body

        LOG.info("=============== Responded REST DPI")
        return webob.Response(content_type="application/json",
                              status=status, body=json.dumps(_dpi_body))

    @route("dpi", "/dpi/flow", methods=["PUT"])
    def dpi_received(self, req, **_kwargs):
        body = req.body
        LOG.info("================ Received REST DPI")
        LOG.info("Request_body=%s", body)
        LOG.debug("dpset_dps=%s", self.dpset.dps.keys())

        # REST Parameter check
        try:
            dpi_cmd = eval(body)["dpi"]
        except:
            err_msg = "invalid syntax at body"
            return self._dpi_response(400, body, err_msg)

        if dpi_cmd not in self.DPI_REST_LIST:
            err_msg = "invalid value at dpi"
            return self._dpi_response(400, body, err_msg)

        # Datapath check
        flow_tag = DPI_FLOWLIST["dpi"]
        flow_list = self.dpiflow[flow_tag]
        dpid = flow_list.check_dp(self.dpset)
        if dpid is not None:
            err_msg = "Datapath[dp=%s] is None" % dpid
            return self._dpi_response(500, body, err_msg)

        # FlowMod & BariierRequest
        for dpid, flows in flow_list.get_items():
            dp = self.dpset.get(dpid)
            LOG.debug("FlowMod dp=%s flows=%s", dp.id, flow_tag)
            if not self._dpi_flows_cmd(dp, flows, dpi_cmd):
                err_msg = "BarrierRequest Timeout. [dp=%s]" % dp.id
                return self._dpi_response(500, body, err_msg)

        return self._dpi_response(200, body)


class DpiRestApi(RestStatsApi):
    """
    DpiRestApi application
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DpiRestApi, self).__init__(*args, **kwargs)
        self.dpiflow = {}

        LOG.info("=================== REST-API(init)")
        LOG.info("BarrierReplyTimer=%s", BARRIER_REPLY_TIMER)
        LOG.debug("args=%s, kwargs=%s", args, kwargs)

        for f in JSONFILE:
            filepath = os.path.join(JSONPATH, f)
            if is_exist_file(filepath):
                self.dpiflow[f] = Flowdict()
                self.dpiflow[f].from_file(filepath)
                LOG.info("FlowFile=[%s]: %s", f, filepath)
                LOG.debug("flows: %s\n", self.dpiflow[f].to_json())
            else:
                LOG.error("### Init-ERR: cannot access [%s]", f)
                exit(1)

        self.data["dpiflow"] = self.dpiflow
        wsgi = kwargs["wsgi"]
        wsgi.register(DpiStatsController, self.data)
        LOG.debug("==================================")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        LOG.info("==================> SwitchFeatures")
        LOG.info("dp=%s, dpset=%s", dp.id, self.dpset.get_all())

        flows = [FLOW_PKT_IN]
        LOG.debug("FlowMod dp=%s flows=PacketIn", dp.id)
        add_flows(dp, flows)

        LOG.debug("==================================")

    @set_ev_cls(dpset.EventDP)
    def _handler_datapath(self, ev):
        if ev.enter:
            dp = ev.dp
            LOG.info("===================> dpset EventDP")
            LOG.info("dp=%s, xid=%s, dpset=%s",
                     dp.id, dp.xid, self.dpset.dps.keys())

            flow_tag = DPI_FLOWLIST["default"]
            flows = self.dpiflow[flow_tag].get_flows(dp.id)
            LOG.debug("FlowMod dp=%s flows=%s", dp.id, flow_tag)
            add_flows(dp, flows)
            LOG.debug("==================================")

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def _barrier_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        LOG.info("-------------------> Barrier Reply [dp=%s, xid=%s, ofp=%s]",
                 dp.id, msg.xid, msg.version)

        if (dp.id not in self.waiters
                or msg.xid not in self.waiters[dp.id]):
            return

        event = self.waiters[dp.id][msg.xid]
        del self.waiters[dp.id][msg.xid]
        event.set()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        LOG.info("=======================> Packet-in")
        LOG.info("dp=%s, in_port=%s", dp.id, in_port)
        LOG.debug("packet=%s", str(pkt))
        LOG.debug("==================================")
