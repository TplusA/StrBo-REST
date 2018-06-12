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

from .endpoint import Endpoint
from .utils import get_logger
log = get_logger('Monitor')

import threading
import selectors

class ClientLister:
    def __init__(self, port, add_cb, remove_cb):
        self.is_ready = threading.Event()
        self.is_running = True
        self.thread = threading.Thread(name = 'Monitor client listener',
                                       target = self.worker,
                                       args = (port, add_cb, remove_cb))
        self.thread.start()
        self.is_ready.wait()

    @staticmethod
    def create_listening_socket(family, port):
        from socket import socket, SOL_SOCKET, SO_REUSEADDR
        s = socket(family = family)
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        s.bind(('', port))
        s.listen(100)
        s.setblocking(False)
        return s

    @staticmethod
    def accept_connection(sock, mask, sel, **kwargs):
        conn, addr = sock.accept()
        log.info('New client {0[0]}:{0[1]}'.format(addr))
        conn.setblocking(False)
        sel.register(conn, selectors.EVENT_READ, ClientLister.read)
        kwargs['add_cb'](conn)

    @staticmethod
    def read(conn, mask, sel, **kwargs):
        try:
            log.info('Lost client {0[0]}:{0[1]}'.format(conn.getpeername()))
        except:
            log.info('Lost client {}'.format(conn))

        sel.unregister(conn)
        conn.close()
        kwargs['remove_cb'](conn)

    def kick_client(self, conn):
        ClientLister.read(conn, None, self.sel, remove_cb = self.remove_client_cb)

    def stop(self):
        self.stop_fd_write.write('\0')
        self.thread.join()
        self.thread = None

    def _terminate(self):
        self.is_running = False

    def worker(self, port, add_cb, remove_cb):
        from socket import AF_INET, AF_INET6
        self.sel = selectors.DefaultSelector()
        self.remove_client_cb = remove_cb

        try:
            self.server_sock = ClientLister.create_listening_socket(AF_INET6, port)
        except:
            self.server_sock = ClientLister.create_listening_socket(AF_INET, port)

        self.sel.register(self.server_sock, selectors.EVENT_READ, ClientLister.accept_connection)

        from os import pipe
        self.stop_fd_read, self.stop_fd_write = pipe()
        self.sel.register(self.stop_fd_read, selectors.EVENT_READ, self._terminate)

        log.info('Server thread listening on port {}'.format(port))
        self.is_ready.set()

        while self.is_running:
            events = self.sel.select()

            for key, mask in events:
                key.data(key.fileobj, mask, self.sel,
                         add_cb = add_cb, remove_cb = remove_cb)

        log.info('Server thread terminates')

class Event:
    def __init__(self, endpoint, **kwargs):
        self.endpoint = endpoint
        self.kwargs = kwargs

def send_message_to_client(bytes, conn):
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
        self.thread = threading.Thread(name = 'Monitor event dispatcher',
                                       target = self.worker,
                                       args = (clients_manager,))
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

    def worker(self, clients_manager):
        log.info('Event dispatcher thread running')
        self.is_ready.set()

        while self.events:
            ev = self.events.get()

            if ev is None:
                self.events.task_done()
                break

            message = ev.endpoint.get_json(**ev.kwargs)
            self.events.task_done()

            message_as_bytes = bytes(message, 'UTF-8')
            bad_connections = []

            with clients_manager as clients:
                log.debug('Send event to {} clients'.format(len(clients)))

                for c in clients:
                    log.debug('Send to {}'.format(c))

                    try:
                        send_message_to_client(message_as_bytes, c)
                    except Exception as e:
                        log.error('Error while sending data to client {}: {}'.format(c, e))
                        bad_connections.append(c)

            if bad_connections:
                clients_manager.handle_bad_connections(bad_connections)

        log.info('Event dispatcher thread terminates')

class Monitor:
    def __init__(self):
        self.lock = threading.RLock()
        self.reset()

    def reset(self):
        self.clients = None
        self.client_listener = None
        self.event_dispatcher = None

    def start(self, port):
        with self.lock:
            if self._is_started():
                return

            self.clients = {}
            self.client_listener = ClientLister(port, self.add_client, self.remove_client)
            self.event_dispatcher = EventDispatcher(self)

    def stop(self):
        with self.lock:
            if not self._is_started():
                log.warning('Cannot stop monitor, already stopped')
                return

            self.client_listener.stop()
            self.event_dispatcher.stop()
            self.reset()

    def _is_started(self):
        return self.clients is not None

    def __enter__(self):
        self.lock.acquire()
        return self.clients

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False

    def add_client(self, conn):
        with self.lock:
            self.clients[conn] = None

    def remove_client(self, conn):
        with self.lock:
            del self.clients[conn]

    def handle_bad_connections(self, conns):
        log.debug('Have {} bad connections'.format(len(conns)))

        with self.lock:
            for c in conns:
                try:
                    log.info('Kicking bad client {0[0]}:{0[1]}'.format(c.getpeername()))
                except:
                    log.info('Kicking bad client {}'.format(c))

                self.client_listener.kick_client(c)

    def send(self, endpoint, **kwargs):
        if not isinstance(endpoint, Endpoint):
            raise TypeError('Only objects of type Endpoint can be sent to monitor')

        if not hasattr(endpoint, 'get_json'):
            raise TypeError('Endpoint {} has no get_json() method'.format(str(endpoint)))

        with self.lock:
            if self._is_started():
                self.event_dispatcher.put(Event(endpoint, **kwargs))
