#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2018, 2020, 2021  T+A elektroakustik GmbH & Co. KG
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

import threading
import selectors
import socket
import os
import json
from queue import Queue

from .endpoint import Endpoint, SerializeError, EmptyError
from .endpoint import EndpointSchema
from .utils import get_logger
log = get_logger('Monitor')


class Client:
    def __init__(self):
        self._input_buffer = bytearray()

        # this is filled in by the client when it introduces itself over the
        # WebSocket connection
        self.client_id = 0

    def append_data(self, data):
        self._input_buffer += bytearray(data)

    def have_data(self):
        return self._input_buffer != b''

    def take_data(self):
        result = self._input_buffer
        self._input_buffer = bytearray()
        return result

    def invalidate_ownership(self, client_id):
        if self.client_id == client_id:
            self.client_id = 0


class ClientListener:
    def __init__(self, port, add_cb, remove_cb):
        self.is_ready = threading.Event()
        self.is_running = True
        self.thread = threading.Thread(name='Monitor client listener',
                                       target=self._worker,
                                       args=(port, add_cb, remove_cb))
        self.thread.start()
        self.is_ready.wait()

    @staticmethod
    def _create_listening_socket(family, port):
        s = socket.socket(family=family)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', port))
        s.listen(100)
        s.setblocking(False)
        return s

    @staticmethod
    def _accept_connection(sock, mask, sel, **kwargs):
        conn, addr = sock.accept()
        log.info('New client {0[0]}:{0[1]}'.format(addr))
        conn.setblocking(False)
        sel.register(conn, selectors.EVENT_READ, ClientListener._read)
        kwargs['add_cb'](conn)

    @staticmethod
    def _read(conn, mask, sel, **kwargs):
        try:
            data = conn.recv(1024)
        except ConnectionResetError as e:
            log.error('Client disappeared: {}'.format(e))
            data = b''

        if data == b'':
            try:
                log.info('Lost client {0[0]}:{0[1]}'
                         .format(conn.getpeername()))
            except:  # noqa: E722
                log.info('Lost client {}'.format(conn))

            sel.unregister(conn)
            conn.close()
            kwargs['remove_cb'](conn)
            return

        from . import get_monitor
        clients_manager = get_monitor()
        client = clients_manager.get_client_by_connection(conn)

        while data:
            pos = data.find(b'\0')

            if pos == -1:
                client.append_data(data)
                return

            if not client.have_data() and pos == len(data) - 1:
                # optimization for the common case: received one complete
                # message
                try:
                    msg = json.loads(data[:-1].decode('utf-8'))
                except json.decoder.JSONDecodeError as e:
                    log.error('Dropping malformed message: {}'.format(e))
                    msg = None
                data = bytes()
            else:
                # received fragments or multiple messages
                client.append_data(data[:pos])
                data = data[pos + 1:]
                try:
                    msg = json.loads(client.take_data().decode('utf-8'))
                except json.decoder.JSONDecodeError:
                    msg = None

            if msg is not None:
                ClientListener._handle_websocket_message(msg, conn,
                                                         clients_manager)

    @staticmethod
    def _handle_websocket_message(msg, conn, clients_manager):
        try:
            log.info('Client message from {}: {}'
                     .format(conn.getpeername(), msg))
        except:  # noqa: E722
            log.info('Client message from <unknown>: {}'.format(msg))

        opname = msg.get('op', None)
        if opname is None:
            return

        if opname == 'register':
            client_id = int(msg.get('client_id', 0))

            if client_id > 0:
                clients_manager.set_client_id(conn, client_id)
            else:
                clients_manager.unset_client_id(conn)

    def kick_client(self, conn):
        ClientListener._read(conn, None, self.sel,
                             remove_cb=self.remove_client_cb)

    def stop(self):
        os.write(self.stop_fd_write, b'exit\n\0')
        os.close(self.stop_fd_write)
        self.thread.join()
        self.thread = None

    def _terminate(self, *args, **kwargs):
        self.is_running = False

    def _worker(self, port, add_cb, remove_cb):
        self.sel = selectors.DefaultSelector()
        self.remove_client_cb = remove_cb

        try:
            self.server_sock = \
                ClientListener._create_listening_socket(socket.AF_INET6, port)
        except OSError:
            self.server_sock = \
                ClientListener._create_listening_socket(socket.AF_INET, port)

        self.sel.register(self.server_sock, selectors.EVENT_READ,
                          ClientListener._accept_connection)

        self.stop_fd_read, self.stop_fd_write = os.pipe()
        self.sel.register(self.stop_fd_read, selectors.EVENT_READ,
                          self._terminate)

        log.info('Server thread listening on port {}'.format(port))
        self.is_ready.set()

        while self.is_running:
            events = self.sel.select()

            for key, mask in events:
                key.data(key.fileobj, mask, self.sel,
                         add_cb=add_cb, remove_cb=remove_cb)

        log.info('Server thread terminates')
        os.close(self.stop_fd_read)


class Event:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


class EndpointEvent(Event):
    def __init__(self, endpoint, **kwargs):
        super().__init__(**kwargs)
        self.endpoint = endpoint
        self.target_client_id = kwargs.get('target_client_id', None)


class ObjectEvent(Event):
    def __init__(self, json_object, **kwargs):
        super().__init__(**kwargs)
        self.json_object = json_object
        self.target_client_id = kwargs.get('target_client_id', None)


def _send_message_to_client(bytes, conn):
    offset = 0

    while offset < len(bytes):
        try:
            # we do not use sendall() so that we can deal with EINTR in a
            # correct and predictable way
            bytes_sent = conn.send(bytes[offset:])

            if bytes_sent == 0:
                raise RuntimeError('Connection broken')

            offset += bytes_sent

        except InterruptedError:
            pass

    try:
        conn.send(b'\0')
    except InterruptedError:
        pass


class EventDispatcher:
    def __init__(self, clients_manager):
        self.events = Queue(50)
        self.is_ready = threading.Event()
        self.thread = threading.Thread(name='Monitor event dispatcher',
                                       target=self._worker,
                                       args=(clients_manager,))
        self.thread.start()
        self.is_ready.wait()

    def stop(self):
        self.events.put(None)
        self.thread.join()
        self.thread = None

    def put(self, ev):
        if ev is not None:
            self.events.put(ev)
        else:
            log.warning('Not putting empty event into queue')

    def _worker(self, clients_manager):
        log.info('Event dispatcher thread running')
        self.is_ready.set()

        while self.events:
            ev = self.events.get()

            if ev is None:
                self.events.task_done()
                break

            try:
                if isinstance(ev, EndpointEvent):
                    message = ev.endpoint.get_json(**ev.kwargs)
                    client_id = ev.target_client_id
                elif isinstance(ev, ObjectEvent):
                    message = ev.json_object
                    client_id = ev.target_client_id
                else:
                    log.error('Unhandled event type {}' .format(type(ev)))
                    message = None
                    client_id = None
            except (SerializeError, EmptyError) as e:
                log.error('Endpoint exception while processing event: {}'
                          .format(e.message))
                message = None
            except Exception as e:
                log.error('Exception exception while processing event: {}'
                          .format(e.message))
                message = None

            self.events.task_done()

            if message is None:
                continue

            message_as_bytes = bytes(message, 'UTF-8')
            bad_connections = []

            def send_to_connection(c):
                try:
                    _send_message_to_client(message_as_bytes, c)
                except Exception as e:
                    log.error('Error while sending data to client {}: {}'
                              .format(c, e))
                    bad_connections.append(c)

            if client_id is None:
                with clients_manager as clients:
                    log.debug('Send event to {} clients'.format(len(clients)))

                    for c in clients:
                        log.debug('Send to {}'.format(c))
                        send_to_connection(c)
            else:
                c = clients_manager.get_connection_by_client_id(client_id)
                if c:
                    log.debug('Send event to client {}'.format(client_id))
                    send_to_connection(c)

            if bad_connections:
                clients_manager._handle_bad_connections(bad_connections)

        log.info('Event dispatcher thread terminates')


class Monitor:
    """Event handling and distribution to listening clients."""

    def __init__(self):
        #: Lock for this object. The :attr:`event_dispatcher` synchronizes on
        #: this lock when it makes use of this object via context manager.
        self._lock = threading.RLock()

        self._reset()

    def _reset(self):
        """Reset this monitor to factory defaults.

        Caller must have acquired :attr:`_lock`.
        """
        #: A dictionary for keeping track of client connections. Its keys are
        #: socket objects. This object is a "hot" object in the sense that it
        #: is concurrently accessed by the two worker threads as well as from
        #: any context adding new events such as :meth:`send_object` or
        #: :meth:`send_endpoint`.
        self.clients = None

        #: An instance of a :class:`ClientListener`, created when the
        #: :class:`Monitor` instance is started.
        self.client_listener = None

        #: An instance of a :class:`EventDispatcher`, created when the
        #: :class:`Monitor` instance is started.
        self.event_dispatcher = None

    def start(self, port):
        """Start the client listener and event dispatching threads.

        The client listener will listen on TCP port ``port`` and accept any
        connections. There is currently no authentication required nor any
        other kind of access control.

        It is safe to call this method multiple times. It is guaranteed that
        only a single set of threads is started.
        """
        with self._lock:
            if self._is_started():
                return

            self.clients = {}
            self.client_listener = ClientListener(port, self._add_client,
                                                  self._remove_client)
            self.event_dispatcher = EventDispatcher(self)

    def stop(self):
        """Shut down the client listener and event dispatching threads.

        It is safe to call this method multiple times, but a warning will be
        emitted to the log when trying to stop a stopped :class:`Monitor`
        instance.
        """
        with self._lock:
            if not self._is_started():
                log.warning('Cannot stop monitor, already stopped')
                return

            self.client_listener.stop()
            self.event_dispatcher.stop()
            self._reset()

    def _is_started(self):
        """Check if this monitor has been started.

        Caller must have acquired :attr:`_lock`.
        """
        return self.clients is not None

    def __enter__(self):
        self._lock.acquire()
        return self.clients

    def __exit__(self, exc_type, exc_value, traceback):
        self._lock.release()
        return False

    def get_client_by_connection(self, conn):
        with self._lock:
            return self.clients[conn]

    def get_connection_by_client_id(self, client_id):
        with self._lock:
            for conn, client in self.clients.items():
                if client.client_id == client_id:
                    return conn

            return None

    def set_client_id(self, conn, client_id):
        with self._lock:
            client = self.clients[conn]
            if client:
                client.client_id = client_id

    def unset_client_id(self, conn):
        self.set_client_id(conn, 0)

    def invalidate_client_id(self, client_id):
        with self._lock:
            if not self.clients:
                return

            for client in self.clients.values():
                client.invalidate_ownership(client_id)

    def _add_client(self, conn):
        """Callback for :class:`ClientListener`, called for each new client.

        This function runs in the context of the worker thread started by the
        :class:`ClientListener` instance referenced by the
        :attr:`client_listener` attribute.
        """
        with self._lock:
            self.clients[conn] = Client()

    def _remove_client(self, conn):
        """Callback for :class:`ClientListener`, called for each remove client.

        This function runs in the context of the worker thread started by the
        :class:`ClientListener` instance referenced by the
        :attr:`client_listener` attribute.
        """
        with self._lock:
            del self.clients[conn]

    def _handle_bad_connections(self, conns):
        """Function called by the worker thread in :class:`EventDispatcher`
        when it has determined that some client connections turned out bad.

        This function runs in the context of the worker thread started by the
        :class:`EventDispatcher` instance referenced by the
        :attr:`event_dispatcher` attribute.
        """
        log.debug('Have {} bad connections'.format(len(conns)))

        with self._lock:
            for c in conns:
                try:
                    log.info('Kicking bad client {0[0]}:{0[1]}'
                             .format(c.getpeername()))
                except:  # noqa: E722
                    log.info('Kicking bad client {}'.format(c))

                self.client_listener.kick_client(c)

    def send_event(self, event_name, json_object, **kwargs):
        """Send a generic event to all listening clients.

        This method adds the field `event` to the object and assigns it the
        value passed in `event_name`.

        See :meth:`Monitor.send_object` for `kwargs` documentation.
        """
        json_object['event'] = event_name
        self.send_object(json_object, **kwargs)

    def send_error_object(self, error_object, **kwargs):
        """Send an event which contains an error object.

        Ideally, but not necessarily, the error object would have been built by
        :meth:`strbo.utils.mk_error_object`. This method adds the field `event`
        to the error object and assigns it the value `error`.

        See :meth:`Monitor.send_object` for `kwargs` documentation.
        """
        error_object['event'] = 'error'
        self.send_object(error_object)

    def send_object(self, json_object, **kwargs):
        """Send a generic object to all listening clients.

        In case `kwargs` contains `ep`, then a field named `endpoint` is added
        to the object which contains a JSON representation of that endpoint,
        serialized by :class:`strbo.endpoint.EndpointSchema`.

        In case `kwargs` contains ``target_client_id``, then this shall be the
        client ID of the client that should receive the ``json_object``. That
        is, the object is not sent to all connected clients, but only to a
        single one.

        Note: usually, this method is not called directly. Consider using
        :meth:`send_event` or :meth:`send_error_object` before resorting to
        this method.
        """
        if isinstance(json_object, dict):
            ep = kwargs.get('ep')
            if ep:
                json_object['endpoint'] = EndpointSchema.serialize(ep)

            json_object = json.dumps(json_object)

        with self._lock:
            if self._is_started():
                self.event_dispatcher.put(ObjectEvent(json_object, **kwargs))

    def send_endpoint(self, endpoint, **kwargs):
        """Send event to all connected clients.

        All connected clients are informed about changes on ``endpoint``, an
        object of type :class:`strbo.endpoint.Endpoint`. This event is stored
        in an internal queue which is processed by a thread dedicated to
        sending events to clients.

        In case `kwargs` contains ``target_client_id``, then the endpoint is
        not sent to all clients, but only to the one with the client ID passed
        in ``target_client_id``.

        This method usually returns fast unless the event queue is congested.
        In case of congestion, this method will block until there is an empty
        slot in the queue.

        The method will also block if the :class:`Monitor` object is locked.
        Typically, this will only happen if some thread locks the monitor for a
        long time by means of the context manager; thus, if this happens at
        all, then it will typically be inside the event dispatcher's worker
        thread.
        """
        if not isinstance(endpoint, Endpoint):
            raise TypeError(
                'Only objects of type Endpoint can be sent to monitor')

        if not hasattr(endpoint, 'get_json'):
            raise TypeError('Endpoint {} has no get_json() method'
                            .format(str(endpoint)))

        with self._lock:
            if self._is_started():
                self.event_dispatcher.put(EndpointEvent(endpoint, **kwargs))
