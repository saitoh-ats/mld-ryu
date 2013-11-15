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
from ryu.app.ofctl_rest import StatsController, RestStatsApi
from ryu.app.wsgi import ControllerBase, route


LOG = logging.getLogger(__name__)
#def LOG(self, *args):
#    logger = logging.getLogger(__name__)
#    logger.debug((self.__class__.__name__, args))


class StatsController(ControllerBase):
    @route('dpi', '/dpi/flow', methods=['PUT'])
    def test(self, req, **_kwargs):
        LOG.debug(("--test--", self.__class__.__name__, str(self), "dir", dir(self), "req", req, "req.body", req.body, "kwargs", _kwargs))
        try:
            dpi = eval(req.body)['dpi']
        #except SyntaxError:
        except:
            LOG.debug('invalid syntax %s', req.body)
            err_body = {
                "err_msg" : "invalid syntax at body",
                "body" : req.body
            }
            return Response(status=400, body=str(err_body))
        LOG.debug(("--test--", req.body, "dpi=", dpi))
        return Response(status=200, body=req.body)


class DpiRestApi(RestStatsApi):
    def __init__(self, *args, **kwargs):
        super(DpiRestApi, self).__init__(*args, **kwargs)

        wsgi = kwargs['wsgi']
        wsgi.register(StatsController)

        LOG.debug(("##### DPI #####","**args", args, "**kwargs", kwargs))
        LOG.debug(("##### DPI #####","**CONTEXTS",self._CONTEXTS,"**dpset",self.dpset, "**data",self.data))
        LOG.debug(("##### DPI #####","**dpset get",self.dpset.get_all()))
