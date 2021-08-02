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


class PlayerQueue(Endpoint):
    """**API Endpoint** - T+A stream player queue operations."""

    #: Path to endpoint.
    href = '/player/player/queue'

    #: Supported HTTP methods.
    methods = ('POST',)

    lock = Lock()

    def __init__(self):
        Endpoint.__init__(
            self, 'audio_player_queue', name='audio_player_queue',
            title='T+A stream player queue operations')

    def __call__(self, request, **values):
        with self.lock:
            req = request.json

            if 'op' not in req:
                return jsonify_error(request, log, False, 400, 'Missing op')

            opname = req['op']

            if opname == 'push':
                return _process_push_request(request, req)

            if opname == 'next':
                return _process_next_request(request)

            if opname == 'clear':
                return _process_clear_request(request, req)

            if opname == 'query':
                return _process_query_request(request)

            return jsonify_error(request, log, False, 400,
                                 'Unknown op "{}"'.format(opname))

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False


def fixup_stream_id(id):
    return id if id < 2**32 - 1 else None


def _process_push_request(request, req):
    required_fields = ('stream_id', 'url', 'stream_key')
    err = jsonify_error_for_missing_fields(request, log, required_fields)
    if err:
        return err

    if 'keep' in req:
        keep_first_n_entries = int(req['keep'])
        if keep_first_n_entries <= 0:
            keep_first_n_entries = -2 if req.get('skip_current', False) else 0
    else:
        keep_first_n_entries = -1

    preset_meta_data = req.get('meta_data', None)

    if preset_meta_data:
        log.warning('Preset meta data for raw streams not implemented yet')

    iface = strbo.dbus.Interfaces.streamplayer_urlfifo()
    fifo_overflow, _ = \
        iface.Push(int(req['stream_id']), req['url'],
                   bytearray.fromhex(req['stream_key']),
                   0, 'ms', 0, 'ms',
                   keep_first_n_entries)

    if fifo_overflow:
        return jsonify_error(request, None, False, 503, 'Queue overflow')

    return jsonify_nc(request)


def _process_next_request(request):
    iface = strbo.dbus.Interfaces.streamplayer_urlfifo()
    skipped_id, next_id, play_status = iface.Next()

    if play_status == 0:
        play_status = 'stopped'
    elif play_status == 1:
        play_status = 'playing'
    elif play_status == 2:
        play_status = 'paused'
    else:
        play_status = 'unknown'

    return jsonify_nc(request,
                      skipped_stream_id=fixup_stream_id(skipped_id),
                      next_stream_id=fixup_stream_id(next_id),
                      play_status=play_status)


def _process_clear_request(request, req):
    if 'keep' not in req:
        return _clear_or_query(request, 0)

    keep = int(req['keep'])
    if keep < 0:
        keep = 0

    return _clear_or_query(request, keep)


def _process_query_request(request):
    return _clear_or_query(request, -1)


def _clear_or_query(request, keep):
    iface = strbo.dbus.Interfaces.streamplayer_urlfifo()
    playing_id, queued_ids, removed_ids = iface.Clear(keep)

    return jsonify_nc(request,
                      playing_stream_id=fixup_stream_id(playing_id),
                      queued_stream_ids=queued_ids,
                      removed_stream_ids=removed_ids)
