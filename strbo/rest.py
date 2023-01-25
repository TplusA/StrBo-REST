#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2018--2023  T+A elektroakustik GmbH & Co. KG
#
# This file is part of StrBo-REST.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.

import halogen
from threading import Lock
from werkzeug.utils import cached_property
from werkzeug.wrappers import Request
from werkzeug.wrappers import Response
from werkzeug.http import parse_options_header
from json import loads
from json.decoder import JSONDecodeError
import traceback
import sys

from .system import all_endpoints as all_system_endpoints
from .system import add_endpoints as add_system_endpoints
from .system import resume_system_update, detach_from_system_update
from .display import all_endpoints as all_display_endpoints
from .display import add_endpoints as add_display_endpoints
from .airable import all_endpoints as all_airable_endpoints
from .airable import add_endpoints as add_airable_endpoints
from .recovery import all_endpoints as all_recovery_endpoints
from .recovery import add_endpoints as add_recovery_endpoints
from .network import all_endpoints as all_network_config_endpoints
from .network import add_endpoints as add_network_config_endpoints
from .listbrowse import all_endpoints as all_listbrowse_endpoints
from .listbrowse import add_endpoints as add_listbrowse_endpoints
from .player import all_endpoints as all_player_endpoints
from .player import add_endpoints as add_player_endpoints
from .player_meta import all_endpoints as all_player_meta_endpoints
from .player_meta import add_endpoints as add_player_meta_endpoints
from .player_roon import all_endpoints as all_roon_player_endpoints
from .player_roon import add_endpoints as add_roon_player_endpoints

from .dbus import Bus
from .endpoint import Endpoint, EndpointSchema, register_endpoint, dispatch
from .external import Helpers, Tools
from .utils import get_logger, jsonify, jsonify_error
log = get_logger()


class EntryPointSchema(halogen.Schema):
    """Representation of entry point."""
    #: Link to self.
    self = halogen.Link(attr='href')

    #: Links to endpoints related to the system. See :mod:`strbo.system`.
    system = halogen.Link(halogen.types.List(EndpointSchema))

    #: Links to endpoints related to Airable. See :mod:`strbo.airable`.
    airable = halogen.Link(halogen.types.List(EndpointSchema))

    #: Links to endpoints related to recovery system management.
    #: See :mod:`strbo.recovery`.
    recovery_data = halogen.Link(halogen.types.List(EndpointSchema))

    #: Link to network configuration management.
    #: See :mod:`strbo.network`.
    network_config = halogen.Link(halogen.types.List(EndpointSchema))

    #: Link to list browser management.
    #: See :mod:`strbo.listbrowse`.
    audio_sources = halogen.Link(halogen.types.List(EndpointSchema))

    #: Link to audio player interfaces.
    #: See :mod:`strbo.player`.
    audio_player = halogen.Link(halogen.types.List(EndpointSchema))

    #: The API version. Not a very RESTful thing to do, but might become
    #: handy at some time.
    api_version = halogen.Attr({
        'major': 0,
        'minor': 24,
    })


class EntryPoint(Endpoint):
    """**API Endpoint** - Entry point to API.

    Clients should ``GET`` this endpoint to retrieve links to more API
    endpoints and to start the WebSocket events entry point (see
    :class:`strbo.monitor.Monitor`).

    Note that registering with the event monitor is required to get
    asynchronous notifications about things going on in the system. In general,
    however, this is only possible after accessing this endpoint. Therefore,
    any client which needs to listen to notifications *must* access the main
    API entry point before trying to subscribe to the WebSocket.

    Also be aware that the event monitor entry URL or any public endpoint URL
    may change *without prior notice*. Always read out the link URLs from this
    resource, and never, *ever* rely on hardcoded paths except on the path to
    this entry point.

    **WARNING:** *ABSOLUTELY NO MEASURES WILL BE TAKEN TO ENSURE STABILITY OF
    ENDPOINT URLS OTHER THAN THE URL OF THIS ENDPOINT.*
    """

    #: Path to endpoint.
    href = '/'

    #: Supported HTTP methods.
    methods = ('GET',)

    def __init__(self):
        super().__init__('entry_point')

        self.system = all_system_endpoints
        self.displays = all_display_endpoints
        self.airable = all_airable_endpoints
        self.recovery_data = all_recovery_endpoints
        self.network_config = all_network_config_endpoints
        self.audio_sources = all_listbrowse_endpoints
        self.audio_player = all_player_endpoints
        self.audio_player += all_player_meta_endpoints
        self.audio_player += all_roon_player_endpoints

    def __call__(self, request, **values):
        return jsonify(request, EntryPointSchema.serialize(self))


class FileResponse(Response):
    def __init__(self, **kwargs):
        super().__init__(kwargs)
        self.headers['Content-Type'] = 'application/octet-stream'
        self.headers['Accept-Ranges'] = 'bytes'


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
        try:
            return loads(self.json_string)
        except JSONDecodeError as e:
            log.error('Failed parsing JSON payload: {}'.format(e))

        return None

    @cached_property
    def json_string(self):
        """Extract unparsed JSON data from request, if any.

        If the request's content type hints at JSON content, then this property
        contains the unparsed JSON data sent along with the request. Otherwise,
        this property contains ``None``. Note that the correct setting of the
        content type in the request is key to success.
        """
        ct = parse_options_header(self.headers.get('content-type'))
        if ct[0] != 'application/json':
            return None

        try:
            return self.data.decode(ct[1].get('charset', 'utf-8'))
        except UnicodeDecodeError as e:
            log.error('Failed reading JSON payload: {}'.format(e))

        return None


class StrBo:
    """Our WSGI application."""

    def __init__(self, root_dir, debug=False):
        self.lock = Lock()
        self.is_monitor_started = False
        self.entry_point = EntryPoint()
        self.root_dir = root_dir
        self.traceback_replace_prefix = '  File "{}'.format(self.root_dir)
        self.debug = debug

        Helpers.set_logger(log)
        Tools.set_logger(log)

        register_endpoint(self.entry_point)

        add_system_endpoints()
        add_display_endpoints()
        add_airable_endpoints()
        add_recovery_endpoints()
        add_network_config_endpoints()
        add_player_endpoints()
        add_player_meta_endpoints()
        add_roon_player_endpoints()
        add_listbrowse_endpoints()

        log.info('Up and running')

        resume_system_update()

    def close(self):
        """Shut down API."""
        with self.lock:
            detach_from_system_update()

            if self.is_monitor_started:
                from . import get_monitor
                get_monitor().stop()
                self.is_monitor_started = False

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

            from . import get_monitor
            monitor_port = int(server_port) + 1
            get_monitor().start(monitor_port)
            self.entry_point.monitor_port = monitor_port
            self.is_monitor_started = True

    def wsgi_app(self, environ, start_response):
        """Main entry point into our WSGI application."""
        if not self.is_monitor_started:
            self._start_monitor(environ.get('SERVER_PORT', None))

        request = JSONRequest(environ)
        log.info('Request: {}'.format(request))

        try:
            response = dispatch(request)
            log.info('Response: {}'.format(response))
        except BaseException as e:
            log.info('Exception: {}'.format(e))
            ex_type, ex_val, ex_tb = sys.exc_info()

            try:
                exception_type_name = str(ex_type).split("'")[1]
            except:  # noqa: E722
                exception_type_name = str(ex_type)

            if exception_type_name.startswith('werkzeug.exceptions.'):
                response = e.get_response()
            elif self.debug:
                raise
            else:
                trace = [
                    line[:8] + line[9 + len(self.root_dir):]
                    if line.startswith(self.traceback_replace_prefix) else line
                    for line in traceback.format_exception(ex_type, ex_val,
                                                           ex_tb)
                ]

                response = jsonify_error(
                        request, log, True, 500, str(ex_val),
                        error='exception',
                        exception_type=exception_type_name,
                        exception_trace=trace)

                log.critical('>>>>> Trace to unhandled exception <<<<<')
                for line in trace:
                    log.critical('{}'.format(line))
                log.critical('>>>>> End of trace <<<<<')

        return response(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)
