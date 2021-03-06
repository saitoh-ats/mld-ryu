# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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
"""
 Defines some model classes related BGP.

 These class include types used in saving information sent/received over BGP
 sessions.
"""
import logging


LOG = logging.getLogger('bgpspeaker.model')


class Counter(object):
    """Simple counter for keeping count of several keys."""
    def __init__(self):
        self._counters = {}

    def incr(self, counter_name, incr_by=1):
        self._counters[counter_name] = \
            self._counters.get(counter_name, 0) + incr_by

    def get_count(self, counter_name):
        return self._counters.get(counter_name, 0)

    def get_counters(self):
        return self._counters.copy()


class OutgoingRoute(object):
    """Holds state about a route that is queued for being sent to a given sink.
    """

    __slots__ = ('_path', '_for_route_refresh', 'bgp4_format',
                 'sink', 'next_outgoing_route', 'prev_outgoing_route',
                 'next_sink_out_route', 'prev_sink_out_route')

    def __init__(self, path, for_route_refresh=False, bgp4_format=False):
        assert(path)

        self.sink = None

        self._path = path

        # Is this update in response for route-refresh request.
        # No sent-route is queued for the destination for this update.
        self._for_route_refresh = for_route_refresh

        # Construct UPDATE msg using bgp4 format
        self.bgp4_format = bgp4_format

        # Automatically generated, for list off of Destination.
        #
        # self.next_outgoing_route
        # self.prev_outgoing_route

        # Automatically generated for list off of sink.
        #
        # self.next_sink_out_route
        # self.prev_sink_out_route

    @property
    def path(self):
        return self._path

    @property
    def for_route_refresh(self):
        return self._for_route_refresh

    def __str__(self):
        return ('OutgoingRoute(path: %s, for_route_refresh: %s)' %
                (self.path, self.for_route_refresh))


class FlexinetOutgoingRoute(object):
    """Holds state about a route that is queued for being sent to a given sink.

    In this case the sink is flexinet peer and this route information is from
    a VRF which holds Ipv4(v6) NLRIs.
    """

    __slots__ = ('_path', 'sink', 'next_outgoing_route', 'prev_outgoing_route',
                 'next_sink_out_route', 'prev_sink_out_route', '_route_disc')

    def __init__(self, path, route_disc):
        from ryu.services.protocols.bgp.info_base.vrf4 import Vrf4Path
        from ryu.services.protocols.bgp.info_base.vrf6 import Vrf6Path
        assert path.route_family in (Vrf4Path.ROUTE_FAMILY,
                                     Vrf6Path.ROUTE_FAMILY)

        self.sink = None
        self._path = path
        self._route_disc = route_disc

        # Automatically generated, for list off of Destination.
        #
        # self.next_outgoing_route
        # self.prev_outgoing_route

        # Automatically generated for list off of sink.
        #
        # self.next_sink_out_route
        # self.prev_sink_out_route

    @property
    def path(self):
        return self._path

    @property
    def route_disc(self):
        return self._route_disc

    def __str__(self):
        return ('FlexinetOutgoingRoute(path: %s, route_disc: %s)' %
                (self.path, self.route_disc))


class SentRoute(object):
    """Holds the information that has been sent to one or more sinks
    about a particular BGP destination.
    """

    def __init__(self, path, peer):
        assert(path and hasattr(peer, 'version_num'))

        self.path = path

        # Peer to which this path was sent.
        self._sent_peer = peer

        # Automatically generated.
        #
        # self.next_sent_route
        # self.prev_sent_route

    @property
    def sent_peer(self):
        return self._sent_peer
