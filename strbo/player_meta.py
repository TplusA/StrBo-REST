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
from threading import Lock
import dbus.service
from werkzeug.wrappers import Response
import halogen
import random

import strbo.dbus
from .endpoint import Endpoint, register_endpoints
from .utils import get_logger
from .utils import jsonify_nc
from .utils import jsonify_error_for_missing_fields
from .utils import mk_error_object
from . import get_monitor
log = get_logger('Player')


class AudioSourceState(Enum):
    PASSIVE = 1
    HALF = 2
    ACTIVE = 3


class ActiveActorSchema(halogen.Schema):
    """Representation of :class:`_ActiveActor`."""

    #: ID of the session owner, the active actor in the REST API
    id = halogen.Attr(attr=lambda value: value.owner_id)

    #: Where the source is coming from
    origin = halogen.Attr()

    #: Information sent by the client when it took ownership
    client_info = halogen.Attr(required=False)

    #: IP address of REST API client
    address = halogen.Attr(required=False)


class AudioSourceSchema(halogen.Schema):
    """Representation of an audio source in the list of known audio sources."""

    #: What the audio source is all about
    description = halogen.Attr()


class PlayerMetaSchema(halogen.Schema):
    """Representation of :class:`PlayerMeta`."""

    owner = halogen.Attr(
        halogen.types.Nullable(ActiveActorSchema),
        attr=lambda value: value._active_actor
    )

    audio_sources = halogen.Attr(
        attr=lambda value: {
            sid: AudioSourceSchema.serialize(src)
            for sid, src in value._known_audio_sources.items()
        }
    )

    active_audio_source =\
        halogen.Attr(attr=lambda value: value._active_audio_path[0])


class _ActiveActor:
    """Information about the active actor."""
    def __init__(self, client_info, origin: str, address=None):
        self.origin = origin

        if self.origin == 'rest':
            self.owner_id = random.randint(100, 2**32-1)
            self.session_key = random.randint(1, 2**32-1)
        else:
            self.owner_id = 0

        if client_info:
            self.client_info = client_info

        if address:
            self.address = address


class _AudioSourceItem:
    """Information about an audio source."""
    def __init__(self, description):
        self.description = description


class PlayerMeta(Endpoint):
    """**API Endpoint** - T+A player and audio source management."""

    #: Path to endpoint.
    href = '/player/meta'

    #: Supported HTTP methods.
    methods = ('GET', 'POST')

    lock = Lock()

    REST_AUDIO_SOURCE_ID = 'strbo.rest'

    def __init__(self):
        Endpoint.__init__(
            self, 'player_management', name='player_management',
            title='T+A player and audio source management')

        self._active_actor = None
        self._actor_activation = None

        # this is our own state in the role of an audio source
        self._rest_audio_source_state = AudioSourceState.PASSIVE

        # this is the active audio path as reported by TAPSwitch
        self._active_audio_path = (None, None)

        self._known_audio_sources = {}

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False

    def __call__(self, request, **values):
        if request.method == 'POST':
            err = jsonify_error_for_missing_fields(request, log,
                                                   ('audio_source',))
            if err:
                return err

        with self.lock:
            if request.method == 'GET':
                return jsonify_nc(request, PlayerMetaSchema.serialize(self))

            # abort any ongoing activation
            self._actor_activation_done(False, aborted=True)

            req = request.json
            source_id = req['audio_source']
            iface = strbo.dbus.Interfaces.audio_path_manager()

            if source_id != PlayerMeta.REST_AUDIO_SOURCE_ID:
                iface.RequestSource(source_id, {}, ignore_reply=True)
                return Response(status=200)

            self._actor_activation = \
                _ActiveActor(req.get('client_info', None), 'rest',
                             address=request.environ.get('REMOTE_ADDR', None))
            response = \
                jsonify_nc(request, status_code=202,
                           owner_id=self._actor_activation.owner_id,
                           session_key=self._actor_activation.session_key)

        # We must make the D-Bus call unlocked because the asynchronous answer
        # may return very quickly, and as it seems, within the same context of
        # the call. If we make the call while still holding our lock, then we
        # can end up deadlocked in one of the asynchronous handlers.
        iface.RequestSource(source_id, {},
                            reply_handler=self._request_source_done,
                            error_handler=self._request_source_error)
        return response

    def _actor_activation_done(self, switched=False, *,
                               e=None, aborted=False):
        if self._actor_activation is None:
            return

        if e:
            err = \
                mk_error_object(
                    None, log, True, 'Actor activation failed',
                    internal_error_message=str(e),
                    client_id=self._actor_activation.owner_id,
                    error='actor_activation_failed',
                    href=PlayerMeta.href,
                )
            get_monitor().send_error_object(err)
        elif aborted:
            err = \
                mk_error_object(
                    None, log, False, 'Actor activation aborted',
                    internal_error_message='Aborted',
                    client_id=self._actor_activation.owner_id,
                    error='actor_activation_aborted',
                    href=PlayerMeta.href,
                )
            get_monitor().send_error_object(err)
        else:
            self._set_active_actor(self._actor_activation)

        self._actor_activation = None

    def _set_active_actor(self, actor):
        if self._active_actor:
            prev_id = self._active_actor.owner_id
            prev_addr_available = hasattr(self._active_actor, 'address')
            if prev_addr_available:
                prev_addr = self._active_actor.address
        else:
            prev_id = 0
            prev_addr_available = False

        self._active_actor = actor

        msg = {
            'owner_id': actor.owner_id if actor else 0,
            'previous_owner_id': prev_id,
        }

        if prev_addr_available:
            msg['previous_address'] = prev_addr

        if hasattr(actor, 'address'):
            msg['address'] = actor.address

        get_monitor().send_event('rest_audio_source_owner', msg)

    def _request_source_done(self, player_id, switched):
        with self.lock:
            self._actor_activation_done(switched)

    def _request_source_error(self, e):
        with self.lock:
            self._actor_activation_done(False, e=e)

    def set_rest_audio_source_state(self, state: AudioSourceState):
        self._rest_audio_source_state = state

    def set_audio_path_participants(self, source_id, player_id):
        if source_id and player_id:
            if not source_id:
                self._set_active_actor(None)
            elif source_id == 'roon':
                self._set_active_actor(_ActiveActor(None, 'roon'))
            elif source_id != PlayerMeta.REST_AUDIO_SOURCE_ID:
                self._set_active_actor(_ActiveActor(None, 'strbo'))

            self._active_audio_path = (source_id, player_id)
        else:
            self._set_active_actor(None)
            self._active_audio_path = (None, None)

        get_monitor().send_event('audio_path', {
                'audio_source_id': self._active_audio_path[0],
                'audio_player_id': self._active_audio_path[1],
        })

    def add_audio_source(self, source_id, description):
        self._known_audio_sources[source_id] = _AudioSourceItem(description)


class DBusAudioSource(dbus.service.Object):
    """Implements the audio path interface for audio sources.

    This makes the REST API selectable as audio source, i.e., the origin of
    control. When the audio source is switched, our D-Bus methods implemented
    in this class may be called.
    """
    iface = 'de.tahifi.AudioPath.Source'

    def __init__(self, object_path: str, pm: PlayerMeta):
        dbus.service.Object.__init__(self, strbo.dbus.Bus(), object_path)
        self._player_meta = pm

    @dbus.service.method(dbus_interface=iface, in_signature='sa{sv}')
    def SelectedOnHold(self, source_id, request_data):
        with self._player_meta as pm:
            pm.set_rest_audio_source_state(AudioSourceState.HALF)

    @dbus.service.method(dbus_interface=iface, in_signature='sa{sv}')
    def Selected(self, source_id, request_data):
        with self._player_meta as pm:
            pm.set_rest_audio_source_state(AudioSourceState.ACTIVE)

    @dbus.service.method(dbus_interface=iface, in_signature='sa{sv}')
    def Deselected(self, source_id, request_data):
        with self._player_meta as pm:
            pm.set_rest_audio_source_state(AudioSourceState.PASSIVE)

    @staticmethod
    def register_audio_source(iface=None):
        if not iface:
            iface = strbo.dbus.Interfaces.audio_path_manager()

        iface.RegisterSource(
                PlayerMeta.REST_AUDIO_SOURCE_ID,
                'Streams sent by REST API clients',
                'strbo', '/de/tahifi/REST',
                reply_handler=DBusAudioSource._register_source_done,
                error_handler=DBusAudioSource._register_source_error)

    @staticmethod
    def _register_source_done():
        log.info('Registered audio source')

    @staticmethod
    def _register_source_error(e):
        log.error('Registering audio source failed: {}'.format(str(e)))


player_meta = PlayerMeta()
all_endpoints = [player_meta]
dbus_audio_source = None


def signal__audio_path_activated(source_id, player_id):
    with player_meta as pm:
        pm.set_audio_path_participants(source_id, player_id)


def add_endpoints():
    """Register all endpoints defined in this module."""
    register_endpoints(all_endpoints)

    global dbus_audio_source
    dbus_audio_source = DBusAudioSource('/de/tahifi/REST', player_meta)

    iface = strbo.dbus.Interfaces.audio_path_manager()
    iface.connect_to_signal('PathActivated', signal__audio_path_activated)
    dbus_audio_source.register_audio_source(iface)

    def fetch_audio_sources():
        usable, incomplete = iface.GetPaths()
        if incomplete:
            log.warning('TODO: Have incomplete audio paths, '
                        'need to check back later')

        def put_audio_source(source_id):
            if source_id:
                source_name, _, _, _ = iface.GetSourceInfo(source_id)
                player_meta.add_audio_source(source_id, source_name)

        for p in usable:
            put_audio_source(p[0])
        for p in incomplete:
            put_audio_source(p[0])

    fetch_audio_sources()

    source_id, player_id = iface.GetCurrentPath()
    player_meta.set_audio_path_participants(source_id, player_id)
