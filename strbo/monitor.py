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

import threading
import selectors

from .endpoint import Endpoint
from .utils import get_logger
log = get_logger('Monitor')


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
        from socket import socket, SOL_SOCKET, SO_REUSEADDR
        s = socket(family=family)
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
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
            log.info('Lost client {0[0]}:{0[1]}'.format(conn.getpeername()))
        except:
            log.info('Lost client {}'.format(conn))

        sel.unregister(conn)
        conn.close()
        kwargs['remove_cb'](conn)

    def kick_client(self, conn):
        ClientListener._read(conn, None, self.sel,
                             remove_cb=self.remove_client_cb)

    def stop(self):
        from os import close
        close(self.stop_fd_write)
        close(self.stop_fd_read)
        self.thread.join()
        self.thread = None

    def _terminate(self, *args, **kwargs):
        self.is_running = False

    def _worker(self, port, add_cb, remove_cb):
        from socket import AF_INET, AF_INET6
        self.sel = selectors.DefaultSelector()
        self.remove_client_cb = remove_cb

        try:
            self.server_sock = \
                ClientListener._create_listening_socket(AF_INET6, port)
        except:
            self.server_sock = \
                ClientListener._create_listening_socket(AF_INET, port)

        self.sel.register(self.server_sock, selectors.EVENT_READ,
                          ClientListener._accept_connection)

        from os import pipe
        self.stop_fd_read, self.stop_fd_write = pipe()
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


class Event:
    def __init__(self, endpoint, **kwargs):
        self.endpoint = endpoint
        self.kwargs = kwargs


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


class EventDispatcher:
    def __init__(self, clients_manager):
        from queue import Queue
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

            from .endpoint import SerializeError, EmptyError

            try:
                message = ev.endpoint.get_json(**ev.kwargs)
            except (SerializeError, EmptyError) as e:
                log.error('Endpoint exception while processing event: {}'.format(e.message))
                message = None
            except Exception as e:
                log.error('Exception exception while processing event: {}'.format(e.message))
                message = None

            self.events.task_done()

            if message is None:
                continue

            message_as_bytes = bytes(message, 'UTF-8')
            bad_connections = []

            with clients_manager as clients:
                log.debug('Send event to {} clients'.format(len(clients)))

                for c in clients:
                    log.debug('Send to {}'.format(c))

                    try:
                        _send_message_to_client(message_as_bytes, c)
                    except Exception as e:
                        log.error('Error while sending data to client {}: {}'.format(c, e))
                        bad_connections.append(c)

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
        #: any context adding new events via :meth:`send`.
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

    def _add_client(self, conn):
        """Callback for :class:`ClientListener`, called for each new client.

        This function runs in the context of the worker thread started by the
        :class:`ClientListener` instance referenced by the
        :attr:`client_listener` attribute.
        """
        with self._lock:
            self.clients[conn] = None

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
                    log.info('Kicking bad client {0[0]}:{0[1]}'.format(c.getpeername()))
                except:
                    log.info('Kicking bad client {}'.format(c))

                self.client_listener.kick_client(c)

    def send(self, endpoint, **kwargs):
        """Send event to all connected clients.

        All connected clients are informed about changes on ``endpoint``, an
        object of type :class:`strbo.endpoint.Endpoint`. This event is stored
        in an internal queue which is processed by a thread dedicated to
        sending events to clients.

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
            raise TypeError('Only objects of type Endpoint can be sent to monitor')

        if not hasattr(endpoint, 'get_json'):
            raise TypeError('Endpoint {} has no get_json() method'.format(str(endpoint)))

        with self._lock:
            if self._is_started():
                self.event_dispatcher.put(Event(endpoint, **kwargs))
