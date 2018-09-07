#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2018  T+A elektroakustik GmbH & Co. KG
#
# This file is part of StrBo-REST.
#
# StrBo-REST is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 3 as
# published by the Free Software Foundation.
#
# StrBo-REST is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with StrBo-REST.  If not, see <http://www.gnu.org/licenses/>.

import halogen
from threading import Lock
from werkzeug.utils import cached_property
from werkzeug.wrappers import Request

from .endpoint import Endpoint
from .utils import get_logger
log = get_logger()


class EntryPoint(Endpoint):
    """**API Endpoint** - Entry point to API.

    Clients should ``GET`` this endpoint to retrieve links to more API
    endpoints and to find out the TCP port of the event monitor (see
    :class:`strbo.monitor.Monitor`).

    Note that the event monitor is only started on first access. Therefore,
    accessing this endpoint right before doing anything else with the API is a
    good idea (actually, it's mandatory) as it can check if the API is up and
    running, and it ensures that the event monitoring works.

    Also be aware that the monitor port number or any public endpoint URL may
    change *without prior notice*. Always read out the link URLs from this
    resource, and never, *ever* rely on hardcoded paths except on the path to
    this entry point.

    **WARNING:** *ABSOLUTELY NO MEASURES WILL BE TAKEN TO ENSURE STABILITY OF
    ENDPOINT URLS OTHER THAN THE URL OF THIS ENDPOINT.*
    """

    class Schema(halogen.Schema):
        """Representation of entry point."""
        #: Link to self.
        self = halogen.Link(attr='href')

        #: Links to endpoints related to Airable. See :mod:`strbo.airable`.
        airable = halogen.Link(halogen.types.List(Endpoint.Schema))

        #: Links to endpoints related to recovery system management.
        #: See :mod:`strbo.recovery`.
        recovery_data = halogen.Link(halogen.types.List(Endpoint.Schema))

        #: The API version. Not a very RESTful thing to do, but might become
        #: handy at some time.
        api_version = halogen.Attr({'major': 0, 'minor': 1})

        #: TCP port of the event monitor. Field may be missing in case the
        #: monitor has not been started.
        monitor_port = halogen.Attr(required=False)

    #: Path to endpoint.
    href = '/'

    #: Supported HTTP methods.
    methods = ('GET',)

    def __init__(self):
        Endpoint.__init__(self, 'entry_point')

        from .airable import all_endpoints as all_airable_endpoints
        self.airable = all_airable_endpoints

        from .recovery import all_endpoints as all_recovery_endpoints
        self.recovery_data = all_recovery_endpoints

    def __call__(self, request, **values):
        from .utils import jsonify
        return jsonify(request, EntryPoint.Schema.serialize(self))


class JSONRequest(Request):
    """Custom request extension to allow extraction of JSON data.

    All requests passed to the :class:`strbo.endpoint.Endpoint` handlers are of
    this type. This class is derived from :class:`werkzeug.wrappers.Request`.
    """

    @cached_property
    def json(self):
        """Extract JSON data from request, if any.

        If the request's content type hints at JSON content, then this property
        contains the parsed JSON data sent along with the request. Otherwise,
        this property contains ``None``. Note that the correct setting of the
        content type in the request is key to success.
        """
        if self.headers.get('content-type') == 'application/json':
            from json import loads
            return loads(self.data.decode("utf-8"))
        else:
            return None


class StrBo:
    """Our WSGI application."""

    def __init__(self):
        self.lock = Lock()
        self.is_monitor_started = False
        self.entry_point = EntryPoint()

        from .external import Helpers
        Helpers.set_logger(log)

        from .endpoint import register_endpoint
        register_endpoint(self.entry_point)

        from .airable import add_endpoints as add_airable_endpoints
        add_airable_endpoints()

        from .recovery import add_endpoints as add_recovery_endpoints
        add_recovery_endpoints()

        log.info('Up and running')

    def close(self):
        """Shut down API."""
        with self.lock:
            if self.is_monitor_started:
                from . import monitor
                monitor.stop()
                self.is_monitor_started = False

            from .dbus import Bus
            Bus().close()

    def _start_monitor(self, server_port):
        # lock acquired late to avoid locking with each call; there is a
        # minuscule chance of entering this function multiple times, but this
        # case is caught down below by checking :attr:`is_monitor_started` once
        # again
        with self.lock:
            if server_port is None:
                return

            if self.is_monitor_started:
                return

            from . import monitor
            monitor_port = int(server_port) + 1
            monitor.start(monitor_port)
            self.entry_point.monitor_port = monitor_port
            self.is_monitor_started = True

    def wsgi_app(self, environ, start_response):
        """Main entry point into our WSGI application."""
        if not self.is_monitor_started:
            self._start_monitor(environ.get('SERVER_PORT', None))

        from .endpoint import dispatch
        request = JSONRequest(environ)
        response = dispatch(request)
        return response(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)
