#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2021  T+A elektroakustik GmbH & Co. KG
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


from threading import Lock
import dbus.service
from werkzeug.wrappers import Response
from typing import Union
from zlib import adler32
import halogen
import json

import strbo.player
from .endpoint import Endpoint, register_endpoints, register_endpoint
from .utils import get_logger
from .utils import jsonify_e, jsonify_error, jsonify_error_for_missing_fields
from .utils import if_none_match
log = get_logger()


def mk_drcpd_update_display_request(json_obj):
    result = {}
    lines = json_obj.get('lines', None)
    if lines:
        if isinstance(lines, list):
            result['first_line'] = str(lines[0])
            if len(lines) > 1:
                result['second_line'] = str(lines[1])
        elif isinstance(lines, str):
            result['first_line'] = lines
            result['second_line'] = ''
        else:
            result['first_line'] = ''
            result['second_line'] = ''

    if 'title' in json_obj:
        result['title'] = str(json_obj['title'])

    if result:
        result['op'] = 'display_update'
        result['target'] = 'drcpd'

    return result


def mk_drcpd_set_display_request(json_obj):
    lines = json_obj.get('lines', None)
    if lines:
        if isinstance(lines, list):
            result = {
                'first_line': str(lines[0]),
                'second_line': str(lines[1]) if len(lines) > 1 else '',
            }
        elif isinstance(lines, str):
            result = {'first_line': lines, 'second_line': ''}
        else:
            result = {'first_line': '', 'second_line': ''}
    else:
        result = {'first_line': '', 'second_line': ''}
    result['title'] = str(json_obj.get('title', ''))
    result['op'] = 'display_set'
    result['target'] = 'drcpd'
    return result


class DisplaySchema(halogen.Schema):
    """Representation of :class:`Display`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: Link to device which has this display physically built in.
    device_href = halogen.Link()

    #: Maximum number of lines which can be sent to this display.
    maximum_number_of_lines = halogen.Attr(2)


class DisplaySchemaShort(halogen.Schema):
    """Short representation of :class:`Display`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: Link to device which has this display physically built in.
    device_href = halogen.Link()


class SystemDisplaysSchema(halogen.Schema):
    """Representation of :class:`SystemDisplays`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: List of known displays in the system.
    displays = halogen.Embedded(
        halogen.types.List(DisplaySchemaShort),
        attr=lambda value: value._get_all_displays()
    )


class Display(Endpoint):
    """**API Endpoint** - Interaction with one display."""

    #: Supported HTTP methods.
    methods = ('GET', 'POST')

    def __init__(self, endpoint_id, href, link_to_device, send_to_display_fn):
        super().__init__(endpoint_id, href=href)
        self.device_href = link_to_device
        self._etag = self._compute_etag()
        self._send_display_request = send_to_display_fn
        register_endpoint(self)

    def __call__(self, request, **values):
        if request.method == 'GET':
            cached = if_none_match(request, self._etag)
            return cached if cached else \
                jsonify_e(request, self._etag, 24 * 3600,
                          DisplaySchema.serialize(self))

        err = jsonify_error_for_missing_fields(request, log,
                                               ('op', 'secret_key'))
        if err:
            return err

        err = strbo.player.streamplayer_endpoint.check_authorization(
                                                    request, 'display access')
        if err:
            return err

        req = request.json
        opname = str(req['op'])

        if opname == 'set':
            display_request = mk_drcpd_set_display_request(req)
        elif opname == 'update':
            display_request = mk_drcpd_update_display_request(req)
        else:
            return jsonify_error(request, log, True, 400,
                                 'Unknown op: {}'.format(opname))

        if display_request:
            self._send_display_request(display_request)

        return Response()

    def get_etag(self):
        return self._etag

    def _compute_etag(self):
        return "{:08x}".format(adler32(bytes(self.href, 'ascii'), 1))


class SystemDisplaysDBus(dbus.service.Object):
    """Implements de.tahifi.JSONEmitter signal emitter for display control."""
    iface = 'de.tahifi.JSONEmitter'

    def __init__(self, object_path: str):
        super().__init__(strbo.dbus.Bus(), object_path)

    @dbus.service.signal(dbus_interface=iface, signature=('sas'))
    def Object(self, json, extra): pass


class SystemDisplays(Endpoint):
    """**API Endpoint** - Collection of displays in the system."""

    href = '/system/displays'
    href_for_map = [
        '/system/displays',
        '/system/displays/<id>',
    ]

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = Lock()

    def __init__(self):
        super().__init__(
            'system_displays', name='system_displays',
            title='All the displays in the system')

        self._all_displays = {}
        self._dbus_json_emitter = None
        self._etag = None

    def __call__(self, request, **values):
        with self.lock:
            cached = if_none_match(request, self._etag)
            return cached if cached else \
                jsonify_e(request, self._etag, 24 * 3600,
                          SystemDisplaysSchema.serialize(self))

    def set_dbus_json_emitter(self, sigs: SystemDisplaysDBus):
        self._dbus_json_emitter = sigs

    def _send_display_request(self, display_request):
        self._dbus_json_emitter.Object(json.dumps(display_request), [])

    def add_display(self, device_instance_id: str, display_id: Union[int, str],
                    link_to_device: str):
        """Add display to the system."""
        display_id = str(display_id)

        if device_instance_id not in self._all_displays:
            self._all_displays[device_instance_id] = {}

        disp = Display(
            'system_display_{}_{}'.format(device_instance_id, display_id),
            '{}/{}-{}'.format(SystemDisplays.href,
                              device_instance_id, display_id),
            link_to_device, self._send_display_request
        )
        self._all_displays[device_instance_id][display_id] = disp
        self._update_etag()
        return disp

    def remove_display(self, device_instance_id: str,
                       display_id: Union[int, str, None] = None):
        """Remove display from the system."""
        if device_instance_id not in self._all_displays:
            return

        if display_id is None:
            del self._all_displays[device_instance_id]
            self._update_etag()
            return

        display_id = str(display_id)

        if display_id in self._all_displays[device_instance_id]:
            del self._all_displays[device_instance_id][display_id]
            self._update_etag()

    def _get_all_displays(self):
        result = []
        for ds in self._all_displays.values():
            result += ds.values()
        return result

    def _update_etag(self):
        result = 42
        for displays in self._all_displays.values():
            for d in displays.values():
                result = adler32(bytes(d.get_etag(), 'ascii'), result)

        self._etag = "{:08x}".format(result)


displays_endpoint = SystemDisplays()
all_endpoints = [displays_endpoint]


def add_endpoints():
    register_endpoints(all_endpoints)

    displays_endpoint.set_dbus_json_emitter(
                                SystemDisplaysDBus('/de/tahifi/REST_DISPLAY'))
