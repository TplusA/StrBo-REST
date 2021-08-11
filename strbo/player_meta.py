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
import strbo.player_control
from .endpoint import Endpoint, register_endpoints
from .endpoint import url_for
from .utils import get_logger
from .utils import jsonify_nc
from .utils import jsonify_error, jsonify_error_for_missing_fields
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


class PlayerMetaSchema(halogen.Schema):
    """Representation of :class:`PlayerMeta`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: Information about the active actor.
    owner = halogen.Attr(
        halogen.types.Nullable(ActiveActorSchema),
        attr=lambda value: value._active_actor
    )

    #: ID of the active audio source.
    active_audio_source_id =\
        halogen.Attr(attr=lambda value: value._active_audio_path[0])

    #: ID of the active audio player.
    active_audio_player_id =\
        halogen.Attr(attr=lambda value: value._active_audio_path[1])

    #: Link to the active audio source.
    active_audio_source = halogen.Link(attr='_active_audio_source_href')

    #: Link to the active audio player.
    active_audio_player = halogen.Link(attr='_active_audio_player_href')


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

    def is_rest_client(self) -> bool:
        return hasattr(self, 'session_key') and hasattr(self, 'address')


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
        self._streamplayer_endpoint = None

        # this is our own state in the role of an audio source
        self._rest_audio_source_state = AudioSourceState.PASSIVE

        # this is the active audio path as reported by TAPSwitch
        self._active_audio_path = (None, None)
        self._active_audio_source_href = None
        self._active_audio_player_href = None

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
                src_id = self._active_audio_path[0]
                from strbo.listbrowse import audio_sources_endpoint
                self._active_audio_source_href = \
                    url_for(request, audio_sources_endpoint, {'id': src_id}) \
                    if src_id else None

                ply_id = self._active_audio_path[1]
                if not ply_id:
                    self._active_audio_player_href = None
                elif ply_id == 'strbo':
                    from strbo.player import streamplayer_endpoint
                    self._active_audio_player_href = \
                        streamplayer_endpoint.player_status.href
                elif ply_id == 'roon':
                    self._active_audio_player_href = None
                else:
                    log.error('Player ID "{}" not recognized'.format(ply_id))
                    self._active_audio_player_href = None

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

    def set_streamplayer_endpoint(self, ep):
        self._streamplayer_endpoint = ep

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

    def _set_active_actor(self, actor: _ActiveActor):
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

        if actor:
            if hasattr(actor, 'session_key') and actor.session_key > 0:
                self._streamplayer_endpoint.set_secret_key(actor.session_key)
            else:
                self._streamplayer_endpoint.clear_secret_key()

            if hasattr(actor, 'address'):
                msg['address'] = actor.address
        else:
            self._streamplayer_endpoint.clear_secret_key()

        mon = get_monitor()
        mon.invalidate_client_id(prev_id)
        mon.send_event('rest_audio_source_owner', msg)

    def get_active_actor(self) -> _ActiveActor:
        return self._active_actor

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


class PlayerMetaRequestsDBus(dbus.service.Object):
    """Implements DCPD signal emitters for controlling playback.

    The signals are those from the de.tahifi.Dcpd.Playback interface so that
    DRCPD and TARoon can understand them straightaway.
    """
    iface = 'de.tahifi.Dcpd.Playback'

    def __init__(self, object_path: str):
        dbus.service.Object.__init__(self, strbo.dbus.Bus(), object_path)

    @dbus.service.signal(dbus_interface=iface)
    def Start(self): pass
    @dbus.service.signal(dbus_interface=iface)
    def Stop(self): pass
    @dbus.service.signal(dbus_interface=iface)
    def Pause(self): pass
    @dbus.service.signal(dbus_interface=iface)
    def Resume(self): pass
    @dbus.service.signal(dbus_interface=iface)
    def Next(self): pass
    @dbus.service.signal(dbus_interface=iface)
    def Previous(self): pass
    @dbus.service.signal(dbus_interface=iface, signature='xs')
    def Seek(self, position, units): pass


class PlayerMetaRequests(Endpoint):
    """**API Endpoint** - Playback-related requests to the active actor.

    +-------------+----------------------------------------------------------+
    | HTTP method | Description                                              |
    +=============+==========================================================+
    | ``POST``    | Send requests for taking influence on playback. These    |
    |             | requests are forwarded to the active actor which decides |
    |             | what to do with them.                                    |
    +-------------+----------------------------------------------------------+

    A request is sent by sending a request name in field ``op``, and any
    parameters in the fields required by the request.

    Valid values for ``op`` are ``start``, ``stop``, ``pause``, ``resume``,
    ``seek``, ``skip_forward``, and ``skip_backward``. Other requests are
    rejected with HTTP status 400. Requests ``stop`` and ``seek`` are the only
    ones which expect parameters, and they will fail with HTTP status 400 in
    case their are malformed.

    For the ``stop`` request, an optional ``reason`` field may be set which
    tells the callee why the playback has been stopped. This is purely for
    diagnostic purposes.

    For the ``seek`` request, the position can be specified in fields
    ``position`` and ``units``. See :class:`strbo.player_control.PlayerControl`
    for more details.

    In case there is no active actor, the request fails with HTTP status 503.
    A successfully forwarded playback request is responded to with HTTP status
    202.

    In case the active actor is a REST client, the full request object is
    forwarded to that actor as is. The active actor is responsible for input
    validation and taking further actions required to fulfill or reject the
    request. The HTTP response with status code 202 contains a small JSON
    object which tells the caller which client ID the request has been
    forwarded to (primarily useful for debugging). The successful response only
    means that the request has been forwarded; it tells the caller nothing
    about how or when the request is going to be processed.

    In case the active actor is a StrBo process, the request is turned into
    D-Bus signals. The processes are responsible for listening to those signals
    and taking further actions. The successful HTTP response contains no
    content in this case.
    """

    #: Path to endpoint.
    href = '/player/meta/requests'

    #: Supported HTTP methods.
    methods = ('POST',)

    def __init__(self, parent_meta_ep):
        Endpoint.__init__(
            self, 'player_requests', name='player_requests',
            title='Requests forwarded to the active actor')
        self._meta_ep = parent_meta_ep
        self._dbus_playback_signals = None
        self._dbus_signals_map = None

    def set_dbus_playback_signals(self, sigs: PlayerMetaRequestsDBus):
        self._dbus_playback_signals = sigs
        self._dbus_signals_map = {
            'start': self._dbus_playback_signals.Start,
            'stop': self._dbus_playback_signals.Stop,
            'pause': self._dbus_playback_signals.Pause,
            'resume': self._dbus_playback_signals.Resume,
            'skip_forward': self._dbus_playback_signals.Next,
            'skip_backward': self._dbus_playback_signals.Previous,
        }

    def __call__(self, request, **values):
        err = jsonify_error_for_missing_fields(request, log, ('op',))
        if err:
            return err

        opname = request.json['op']

        with self._meta_ep as meta:
            aa = meta.get_active_actor()
            if not aa:
                return jsonify_error(request, log, False, 503,
                                     'No active actor, cannot forward '
                                     'player request {}'.format(opname))

            if opname not in ('start', 'stop', 'pause', 'resume', 'seek',
                              'skip_forward', 'skip_backward'):
                return jsonify_error(request, log, False, 400,
                                     'Unknown op "{}"'.format(opname))

            if not aa.is_rest_client():
                return self._forward_request_to_strbo(aa, request)

            get_monitor().send_event('player_request', request.json,
                                     target_client_id=aa.owner_id)
            return jsonify_nc(request, status_code=202,
                              client_id=aa.owner_id)

    def _forward_request_to_strbo(self, aa: _ActiveActor, request):
        req = request.json
        opname = req['op']
        fun = self._dbus_signals_map.get(opname, None)

        if fun:
            fun()
        elif opname == 'seek':
            err = strbo.player_control.check_seek_request_parameters(request,
                                                                     req)
            if err:
                return err

            try:
                pos, units = \
                    strbo.player_control.get_seek_request_parameters(req)
            except:  # noqa: E722
                return jsonify_error(request, log, False, 400,
                                     'Invalid seek request')

            self._dbus_playback_signals.Seek(pos, units)
        else:
            return jsonify_error(request, log, True, 501,
                                 'Op {} not implemented'.format(opname))

        return jsonify_nc(request, status_code=202)


player_meta = PlayerMeta()
player_meta_requests = PlayerMetaRequests(player_meta)
all_endpoints = [player_meta, player_meta_requests]
dbus_audio_source = None


def signal__audio_path_activated(source_id, player_id):
    with player_meta as pm:
        pm.set_audio_path_participants(source_id, player_id)


def add_endpoints():
    from strbo.player import streamplayer_endpoint
    player_meta.set_streamplayer_endpoint(streamplayer_endpoint)

    """Register all endpoints defined in this module."""
    register_endpoints(all_endpoints)

    player_meta_requests.set_dbus_playback_signals(
                                PlayerMetaRequestsDBus('/de/tahifi/REST_DCPD'))

    global dbus_audio_source
    dbus_audio_source = DBusAudioSource('/de/tahifi/REST', player_meta)

    iface = strbo.dbus.Interfaces.audio_path_manager()
    iface.connect_to_signal('PathActivated', signal__audio_path_activated)
    dbus_audio_source.register_audio_source(iface)
    source_id, player_id = iface.GetCurrentPath()
    player_meta.set_audio_path_participants(source_id, player_id)
