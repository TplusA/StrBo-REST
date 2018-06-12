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

from .endpoint import Endpoint
from .utils import get_logger
log = get_logger()

class EntryPoint(Endpoint):
    """API Endpoint: Entry point to API."""
    class Schema(halogen.Schema):
        self = halogen.Link(attr = 'href')
        airable = halogen.Link(halogen.types.List(Endpoint.Schema))
        recovery = halogen.Link(halogen.types.List(Endpoint.Schema))
        api_version = halogen.Attr({'major': 1, 'minor': 0})
        monitor_port = halogen.Attr(required = False)

    href = '/'
    methods = ('GET',)

    def __init__(self):
        Endpoint.__init__(self, 'entry_point')

        from .airable import all_endpoints as all_airable_endpoints
        self.airable = all_airable_endpoints

        from .recovery import all_endpoints as all_recovery_endpoints
        self.recovery = all_recovery_endpoints

    def __call__(self, request, **values):
        from .utils import jsonify
        return jsonify(request, __class__.Schema.serialize(self))

class StrBo:
    def __init__(self):
        self.lock = Lock()
        self.is_monitor_started = False
        self.entry_point = EntryPoint()

        from .endpoint import register_endpoint
        register_endpoint(self.entry_point)

        from .airable import add_endpoints as add_airable_endpoints
        add_airable_endpoints()

        from .recovery import add_endpoints as add_recovery_endpoints
        add_recovery_endpoints()

        log.info('Up and running')

    def close(self):
        with self.lock:
            if self.is_monitor_started:
                from . import monitor
                monitor.stop()
                self.is_monitor_started = False

            from .dbus import Bus
            Bus().close()

    def start_monitor(self, server_port):
        # lock acquired late to avoid locking with each call; there is a
        # minuscule chance of entering this function multiple times, but this
        # case is caught down below by checking ``is_monitor_started`` once
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

    """Our WSGI application."""
    def wsgi_app(self, environ, start_response):
        if not self.is_monitor_started:
            self.start_monitor(environ.get('SERVER_PORT', None))

        from werkzeug.wrappers import Request
        from .endpoint import dispatch
        request = Request(environ)
        response = dispatch(request)
        return response(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)
