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

from threading import RLock
import halogen

from .endpoint import Endpoint
from .utils import jsonify, jsonify_simple
from .utils import get_logger
from . import monitor
from . import listerrors
import strbo.dbus
log = get_logger()

service_curie = halogen.Curie(name = 'id', href = '/airable/service/{id}', templated = True)

class Service:
    """Information about a service accessible through Airable."""
    class Schema(halogen.Schema):
        self = halogen.Link(attr = 'id', curie = service_curie)
        id = halogen.Attr()
        description = halogen.Attr()
        login_status = halogen.Attr()

    def __init__(self, id, description):
        self.id = id
        self.description = description
        self.login_status = None

    def update_login_status(self, data):
        self.login_status = data

class ServiceAny(Endpoint):
    """API Endpoint: Accessing an external service provided by Airable.

    To avoid issues with (lack of) locking, this class should not accessed
    directly, but through the ``Services`` class.
    """
    href = '/airable/service/<id>'
    methods = ('GET',)
    lock = RLock()

    def __init__(self, services):
        Endpoint.__init__(self, 'airable_service', 'Airable external service')
        self.services = services

    def __call__(self, request, id, **values):
        with self.lock:
            service = self.services.get_service_by_id(id)

            if service is None:
                return jsonify(request, {})

            return jsonify(request, Service.Schema.serialize(service))

    def get_json(self, **kwargs):
        with self.lock:
            service = self.services.get_service_by_id(kwargs['service_id'])

            if service is None:
                return jsonify_simple({})

            return jsonify_simple(Service.Schema.serialize(service))

class Services(Endpoint):
    """API Endpoint: Information about all external services provided by Airable.

    Method ``GET``: Return the list of external services. These information are
    read out from the Airable list broker via D-Bus the first time this
    endpoint is accessed. All information are cached unless the client asks for
    non-cached information.
    """
    class Schema(halogen.Schema):
        self = halogen.Link(attr = 'href')
        services = halogen.Attr(attr=lambda value: {id: Service.Schema.serialize(value.services[id]) for id in value.services} if value.services is not None else None)

    href = '/airable/services'
    methods = ('GET',)
    lock = RLock()

    services = None

    def __init__(self):
        Endpoint.__init__(self, 'airable_services', 'Airable external services')
        self.service_mapper = ServiceAny(self)

    def __call__(self, request = None, **values):
        cc = None if request is None else request.environ.get('HTTP_CACHE_CONTROL', None)

        with self.lock:
            if cc and cc == 'no-cache':
                self.services = None

            if self.services is None:
                self.refresh()

            return self if request is None else jsonify(request, __class__.Schema.serialize(self))

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False

    def clear(self):
        services = None

    def refresh(self):
        self.clear()

        try:
            iface = strbo.dbus.Interfaces.credentials_read()
            self.services = {c[0]: Service(c[0], c[1]) for c in iface.GetKnownCategories()}
        except:
            log.error('Failed retrieving list of external services')
            self.clear()
            raise

    def get_service_by_id(self, id):
        with self.lock:
            if self.services is None:
                self.refresh()

            return None if self.services is None else self.services.get(id, None)

    def get_json(self, **kwargs):
        with self.lock:
            return self.service_mapper.get_json(**kwargs)

    def update_login_status(self, id, data, send_to_monitor = True):
        with self.lock:
            s = self.get_service_by_id(id)

            if not s:
                return

            s.update_login_status(data)

        if send_to_monitor:
            monitor.send(self, service_id = id)

class Info(Endpoint):
    """API Endpoint: Entry point for interfacing with Airable.

    Method ``GET``: Return information about Airable API and external
    services accessible through Airable.
    """
    class Schema(halogen.Schema):
        self = halogen.Link(attr = 'href')
        root_url = halogen.Attr()
        services = halogen.Attr(Services.Schema)

    href = '/airable'
    methods = ('GET',)
    lock = RLock()

    are_data_available = False
    root_url = None
    services = Services()

    def __init__(self):
        Endpoint.__init__(self, 'airable_info', 'Interfacing with Airable')

    def __call__(self, request, **values):
        cc = request.environ.get('HTTP_CACHE_CONTROL', None)

        with self.lock:
            if cc and cc == 'no-cache':
                self.are_data_available = False

            if not self.are_data_available:
                self.refresh()

            return jsonify(request, __class__.Schema.serialize(self))

    def clear(self):
        self.are_data_available = False
        self.root_url = None
        self.services.clear()

    def refresh(self):
        self.clear()

        try:
            iface = strbo.dbus.Interfaces.airable()
            self.root_url = iface.GetRootURL()
            self.services.refresh()
            self.are_data_available = True
        except:
            log.error('Failed retrieving information about Airable')
            self.clear()
            raise

info_endpoint = Info()
all_endpoints = [info_endpoint, info_endpoint.services]

def signal__external_service_login_status(service_id, actor_id, log_in, error_code, info):
    login_status = {
        'logged_in': error_code == 0 and log_in != 0,
        'info': info
    }

    if listerrors.is_error(error_code):
        login_status['last_error_code'] = error_code
        login_status['last_error'] = listerrors.decode(error_code)

    info_endpoint.services.update_login_status(service_id, login_status)

def add_endpoints():
    from .endpoint import register_endpoints, register_endpoint
    register_endpoints(all_endpoints)
    register_endpoint(info_endpoint.services.service_mapper)

    strbo.dbus.Interfaces.airable().connect_to_signal('ExternalServiceLoginStatus',
                                                      signal__external_service_login_status)
