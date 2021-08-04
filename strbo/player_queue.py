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


from hashlib import md5
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

    # The number 4 is the source ID for REST API. Upper 9 bits for source ID,
    # lower 7 bits for stream cookie.
    _MIN_ID = (4 << 7) + 1
    _MAX_ID = (4 << 7) + 2 ** 7 - 1
    STREAM_ID_RANGE = _MAX_ID - _MIN_ID + 1

    def __init__(self):
        Endpoint.__init__(
            self, 'audio_player_queue', name='audio_player_queue',
            title='T+A stream player queue operations')
        self._next_free_id = PlayerQueue._MIN_ID

    def __call__(self, request, **values):
        with self.lock:
            req = request.json

            if 'op' not in req:
                return jsonify_error(request, log, False, 400, 'Missing op')

            opname = req['op']

            if opname == 'push':
                return _process_push_request(request, req,
                                             self._get_free_stream_id,
                                             PlayerQueue.STREAM_ID_RANGE)

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

    def _get_free_stream_id(self):
        result = self._next_free_id

        if self._next_free_id < PlayerQueue._MAX_ID:
            self._next_free_id += 1
        else:
            self._next_free_id = PlayerQueue._MIN_ID

        return result


def fixup_stream_id(stream_id):
    return stream_id if stream_id < 2**32 - 1 else None


def _process_push_request(request, req, get_new_stream_id, max_items_count):
    err = jsonify_error_for_missing_fields(request, log, ('items',))
    if err:
        return err

    if 'keep' in req:
        keep_first_n_entries = int(req['keep'])
        if keep_first_n_entries <= 0:
            keep_first_n_entries = -2 if req.get('skip_current', False) else 0
    else:
        keep_first_n_entries = -1

    iface = strbo.dbus.Interfaces.streamplayer_urlfifo()

    def check_item(item):
        err = jsonify_error_for_missing_fields(request, log, ('url',), j=item)
        if err:
            return err

        if not item['url']:
            return jsonify_error(request, log, False, 400, 'Empty "url"')

        return None

    def push_item_to_player(item, stream_ids):
        stream_id = get_new_stream_id()
        stream_key = md5(item['url'].encode()).digest()
        preset_meta_data = item.get('meta_data', None)

        if preset_meta_data:
            log.warning('Preset meta data for raw streams not implemented yet')

        fifo_overflow, _ = iface.Push(stream_id, item['url'], stream_key,
                                      0, 'ms', 0, 'ms', keep_first_n_entries)

        if fifo_overflow:
            log.error('Stream player queue overflow, '
                      'some streams have not been pushed')
        else:
            stream_ids.append(stream_id)

        return fifo_overflow

    items = req['items']
    stream_ids = []
    overflow = False

    if isinstance(items, list):
        if len(items) > max_items_count:
            return \
                jsonify_error(request, log, False, 400,
                              'Cannot push more than {} URLs '
                              '(stream IDs exhausted)'
                              .format(max_items_count))

        for item in items:
            err = check_item(item)
            if err:
                return err

        for item in items:
            overflow = push_item_to_player(item, stream_ids)
            if overflow:
                break
            keep_first_n_entries = -1
    elif isinstance(items, dict):
        err = check_item(items)
        if err:
            return err

        overflow = push_item_to_player(items, stream_ids)

    return jsonify_nc(request, stream_ids=stream_ids, overflow=overflow)


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
