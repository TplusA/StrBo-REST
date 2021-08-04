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

import strbo.dbus
from .endpoint import Endpoint
from .utils import get_logger
from .utils import jsonify_nc, jsonify_error, jsonify_error_for_missing_fields
log = get_logger('Player')


class PlayerControl(Endpoint):
    """**API Endpoint** - T+A stream player control.

    +-------------+----------------------------------------------------------+
    | HTTP method | Description                                              |
    +=============+==========================================================+
    | ``POST``    | Send commands directly to the stream player to modify    |
    |             | its playback state.                                      |
    +-------------+----------------------------------------------------------+

    The client shall send a JSON object containing a field named ``op`` (for
    operation). The operation is either ``start``, ``stop``, ``pause``, or
    ``seek``.

    The ``start`` and ``pause`` operations do the obvious and do not have any
    parameters.

    The ``stop`` operation stops playback and takes an optional parameter named
    ``reason``. The parameter is a short string which tells the developer what
    is the reason for the stop (user hit stop, app terminated, some error, or
    whatever).

    The ``seek`` operation requires two parameters, ``position`` and ``units``,
    or no parameters at all. Sending only one of them is an error. The
    ``position`` is a numerical value, and ``units`` is the unit of measure for
    ``position``. Valid units are ``s``, ``ms``, ``us``, ``ns``, and ``%``. For
    percentage, ``position`` may be a floating point value or an integer and it
    must be in range 0.0 through 100.0; for the other units, ``position`` must
    be an integer which does not exceed the stream boundaries.
    """

    #: Path to endpoint.
    href = '/player/player/control'

    #: Supported HTTP methods.
    methods = ('POST',)

    lock = Lock()

    def __init__(self):
        Endpoint.__init__(
            self, 'audio_player_control', name='audio_player_control',
            title='T+A stream player control')

    def __call__(self, request, **values):
        with self.lock:
            req = request.json

            if 'op' not in req:
                return jsonify_error(request, log, False, 400, 'Missing op')

            opname = req['op']

            if opname == 'start':
                return _process_start_request(request)

            if opname == 'stop':
                return _process_stop_request(request, req)

            if opname == 'pause':
                return _process_pause_request(request)

            if opname == 'seek':
                return _process_seek_request(request, req)

            return jsonify_error(request, log, False, 400,
                                 'Unknown op "{}"'.format(opname))

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False


def _process_start_request(request):
    iface = strbo.dbus.Interfaces.streamplayer_playback()
    iface.Start()
    return jsonify_nc(request)


def _process_stop_request(request, req):
    iface = strbo.dbus.Interfaces.streamplayer_playback()
    iface.Stop(req.get('reason', ''))
    return jsonify_nc(request)


def _process_pause_request(request):
    iface = strbo.dbus.Interfaces.streamplayer_playback()
    iface.Pause()
    return jsonify_nc(request)


def _process_seek_request(request, req):
    if 'position' not in req and 'units' not in req:
        pos = 0
        units = 'ms'
    else:
        required_fields = ('position', 'units')
        err = jsonify_error_for_missing_fields(request, log, required_fields)
        if err:
            return err

        units = req['units']

        try:
            if units == '%':
                pos = float(req['position'])
                if pos < 0.0 or pos > 100.0:
                    raise RuntimeError()
                pos = int(round(pos, 4) * 10000.0)
            else:
                pos = int(req['position'])
                if pos < 0:
                    raise RuntimeError()
        except:  # noqa: E722
            return jsonify_error(request, log, False, 400, 'Invalid position')

    iface = strbo.dbus.Interfaces.streamplayer_playback()
    iface.Seek(pos, units)
    return jsonify_nc(request)
