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


from enum import Enum
from threading import RLock
import halogen

from .endpoint import Endpoint, register_endpoints
from . import get_monitor
import strbo.dbus
import strbo.player_control
import strbo.player_queue
from .utils import get_logger
from .utils import jsonify_nc, jsonify_error
log = get_logger('Player')


class PlayStatus(Enum):
    """What the player is currently doing."""
    UNKNOWN = 1
    STOPPED = 2
    PLAYING = 3
    PAUSED = 4


class PlayerStatusSchema(halogen.Schema):
    """Representation of :class:`PlayerStatus`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: Name of this player.
    player = halogen.Attr('streamplayer')

    #: Play status (see :enum:`PlayerStatus`).
    status = halogen.Attr(attr=lambda value: value.play_status.name.lower())

    #: Currently playing URL, if any.
    url = halogen.Attr(attr='current_url')

    #: Current set of meta data, if any.
    meta_data = halogen.Attr(attr='current_meta_data')

    #: Current stream ID, if any.
    stream_id = halogen.Attr(attr='current_stream_id')

    #: Current stream key, if any.
    stream_key = halogen.Attr(attr='current_stream_key')


class PlayerStatus(Endpoint):
    """**API Endpoint** - T+A stream player status.

    +-------------+--------------------------------------------------------+
    | HTTP method | Description                                            |
    +=============+========================================================+
    | ``GET``     | Read out player status and meta data for currently     |
    |             | playing stream.                                        |
    +-------------+--------------------------------------------------------+
    """

    #: Path to endpoint.
    href = '/player/player/status'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    play_status = PlayStatus.UNKNOWN
    current_url = None
    current_stream_key = None
    current_meta_data = None
    current_stream_id = 0

    def __init__(self, player):
        super().__init__(
                'audio_player_status', name='audio_player_status',
                title='T+A stream player status')
        self._player = player

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False

    def __call__(self, request, **values):
        with self.lock:
            return jsonify_nc(request, PlayerStatusSchema.serialize(self))

    def set_play_status(self, stream_id, status, *,
                        new_url=None, event_url=None, error=None,
                        stream_key=None, meta_data=None, **kwargs):
        with self.lock:
            changed = False

            if stream_id != self.current_stream_id:
                changed = True
                self.current_stream_id = stream_id

            if new_url is not None:
                temp = new_url if new_url else None

                if self.current_url != temp:
                    changed = True
                    self.current_url = temp
                    self.current_stream_key = stream_key

                    if not self.current_url:
                        self.current_meta_data = None

            if meta_data is not None:
                if not changed and self.current_meta_data != meta_data:
                    changed = True

                self.current_meta_data = meta_data

            if self.play_status == status and not changed:
                return False

            self.play_status = status
            self._send_player_status_event(event_url, error, **kwargs)
            return True

    def update_meta_data(self, stream_id, meta_data):
        if self.current_meta_data != meta_data:
            self.current_meta_data = meta_data
            self._send_player_status_event(None, None)

    def _send_player_status_event(self, url, error, **kwargs):
        msg = PlayerStatusSchema.serialize(self)

        def extend_message(key, value):
            if value is not None:
                msg[key] = value

        extend_message('url', url)
        extend_message('error', error)
        extend_message('queue_status', kwargs.get('queue_status', None))
        extend_message('dropped_stream_ids',
                       kwargs.get('dropped_ids', None))

        get_monitor().send_event('player_status', msg)
        return True


class PlayerStreamplayer(Endpoint):
    """Collection of stream player API endpoints and related data.

    The secret key for direct player control is managed by this class as well.
    """

    lock = RLock()

    def __init__(self):
        self.player_status = PlayerStatus(self)
        self.player_control = strbo.player_control.PlayerControl(self)
        self.player_queue = strbo.player_queue.PlayerQueue(self)
        self._secret_key = None

    def clear_secret_key(self):
        """Remove the secret key for access control."""
        self._secret_key = None

    def set_secret_key(self, key: int):
        """Set the secret key for access control."""
        self._secret_key = key

    def check_authorization(self, request, what):
        req = request.json

        if self.access_granted(req.get('secret_key', None)):
            return None

        log.error('Blocked unauthorized {} from {}'
                  .format(what, request.environ.get('REMOTE_ADDR', None)))
        return jsonify_error(request, log, False, 403,
                             'Wrong key' if 'secret_key' in req
                             else 'Missing secret_key')

    def access_granted(self, key) -> bool:
        """Check if the given key matches the secret key."""
        if self._secret_key is None:
            return False

        try:
            return int(key) == self._secret_key
        except (TypeError, ValueError):
            return False


streamplayer_endpoint = PlayerStreamplayer()
all_endpoints = [
    streamplayer_endpoint.player_status,
    streamplayer_endpoint.player_control,
    streamplayer_endpoint.player_queue,
]


def signal__now_playing(id, stream_key, url, url_fifo_is_full, dropped_ids,
                        meta_data):
    try:
        stream_key = ('{:02x}' * len(stream_key)).format(*stream_key)
    except Exception as e:
        log.error('Failed formatting stream key: {}'.format(e))
        stream_key = None

    streamplayer_endpoint.player_status.set_play_status(
            id, PlayStatus.PLAYING, new_url=url, stream_key=stream_key,
            meta_data={kv[0]: kv[1] for kv in meta_data},
            queue_status='full' if url_fifo_is_full else None,
            dropped_ids=dropped_ids
    )


def signal__meta_data_changed(id, meta_data):
    streamplayer_endpoint.player_status.update_meta_data(
            id, {kv[0]: kv[1] for kv in meta_data}
    )


def signal__stopped_with_error(id, url, url_fifo_is_empty, dropped_ids,
                               reason):
    streamplayer_endpoint.player_status.set_play_status(
            id, PlayStatus.STOPPED, new_url='', event_url=url, error=reason,
            queue_status='empty' if url_fifo_is_empty else None,
            dropped_ids=dropped_ids
    )


def signal__stopped(id, dropped_ids):
    streamplayer_endpoint.player_status.set_play_status(
            id, PlayStatus.STOPPED, new_url='', dropped_ids=dropped_ids
    )


def signal__pause_state(id, is_paused):
    streamplayer_endpoint.player_status.set_play_status(
            id, PlayStatus.PAUSED if is_paused else PlayStatus.PLAYING
    )


def signal__position_changed(id, position, position_units,
                             duration, duration_units):
    get_monitor().send_event(
        'stream_position',
        {
            'position': int(position),
            'position_units': str(position_units),
            'duration': int(duration),
            'duration_units': str(duration_units),
        })


def signal__buffer(fill_level, cumulating):
    get_monitor().send_event(
        'player_buffer_level',
        {
            'percentage': int(fill_level),
            'cumulating': bool(cumulating),
        })


def add_endpoints():
    """Register all endpoints defined in this module."""
    register_endpoints(all_endpoints)

    iface = strbo.dbus.Interfaces.streamplayer_playback()
    iface.connect_to_signal('NowPlaying', signal__now_playing)
    iface.connect_to_signal('StoppedWithError', signal__stopped_with_error)
    iface.connect_to_signal('Stopped', signal__stopped)
    iface.connect_to_signal('PauseState', signal__pause_state)
    iface.connect_to_signal('MetaDataChanged', signal__meta_data_changed)
    iface.connect_to_signal('PositionChanged', signal__position_changed)
    iface.connect_to_signal('Buffer', signal__buffer)
