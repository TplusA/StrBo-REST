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
from werkzeug.wrappers import Response
import halogen

from .endpoint import Endpoint
from .utils import jsonify, jsonify_simple
from .utils import get_logger
from . import monitor
from . import listerrors
import strbo.dbus
log = get_logger()

class Credentials(Endpoint):
    """API Endpoint: Management of credentials for external music services."""
    class Data:
        def __init__(self, id):
            iface = strbo.dbus.Interfaces.credentials_read()
            self.username, self.password = iface.GetDefaultCredentials(id)
            self.id = id

            if not self.username:
                self.username = None
                self.password = None

    class Schema(halogen.Schema):
        self = halogen.Link(attr = lambda value: '/airable/service/' + value.id + '/credentials')
        id = halogen.Attr()
        username = halogen.Attr()
        password = halogen.Attr()

    class SchemaShort(halogen.Schema):
        self = halogen.Link(attr = lambda value: '/airable/service/' + value.id + '/credentials')

    href = '/airable/service/{id}/credentials'
    href_for_map = '/airable/service/<id>/credentials'
    methods = ('GET', 'PUT')
    lock = RLock()

    def __init__(self):
        Endpoint.__init__(self, 'airable_service_credentials', 'Management of credentials for external music services')

    def __call__(self, request, id, **values):
        if request.method == 'GET':
            return jsonify(request, Credentials.Schema.serialize(Credentials.Data(id)))

        with self.lock:
            userpass = request.json

            # input sanitation
            try:
                if userpass:
                    username = userpass['username']
                    password = userpass['password']

                    if not isinstance(username, str) or not isinstance(password, str):
                        raise TypeError("User name and password must be strings")

                    if not username:
                        raise ValueError("Empty user name")
            except Exception as e:
                return Response('Exception: ' + str(e), status = 400)

            # update credentials database
            try:
                wcred_iface = strbo.dbus.Interfaces.credentials_write()
                login_iface = strbo.dbus.Interfaces.airable()

                LOGIN_LOGOUT_ACTOR_ID = 3

                if userpass:
                    wcred_iface.SetCredentials(id, username, password, True)
                    login_iface.ExternalServiceLogout(id, "", True, LOGIN_LOGOUT_ACTOR_ID)
                    login_iface.ExternalServiceLogin(id, username, True, LOGIN_LOGOUT_ACTOR_ID)
                else:
                    wcred_iface.DeleteCredentials(id, "")
                    login_iface.ExternalServiceLogout(id, "", True, LOGIN_LOGOUT_ACTOR_ID)
            except Exception as e:
                return Response('Exception: ' + str(e), status = 500)

        return Response(status = 204)

class Service:
    """Information about a service accessible through Airable."""
    class Schema(halogen.Schema):
        self = halogen.Link(attr = lambda value: '/airable/service/' + value.id)
        id = halogen.Attr()
        credentials = halogen.Embedded(Credentials.SchemaShort, attr = lambda value: value)
        description = halogen.Attr()
        login_status = halogen.Attr()

    class SchemaShort(halogen.Schema):
        self = halogen.Link(attr = lambda value: '/airable/service/' + value.id)
        id = halogen.Attr()

    def __init__(self, id, description):
        self.id = id
        self.description = description
        self.login_status = None

    def update_login_status(self, data):
        self.login_status = data

class ServiceInfo(Endpoint):
    """API Endpoint: Accessing an external service provided by Airable.

    To avoid issues with (lack of) locking, this class should not accessed
    directly, but through the ``Services`` class.
    """
    href = '/airable/service/{id}'
    href_for_map = '/airable/service/<id>'
    methods = ('GET',)
    lock = RLock()

    def __init__(self, services):
        Endpoint.__init__(self, 'airable_service', 'Accessing a specific Airable external streaming service')
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
                from .endpoint import EmptyError
                raise EmptyError(self)

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
        services = halogen.Embedded(halogen.types.List(Service.Schema), attr = lambda value: [value.services[id] for id in value.services], required = False)

    class SchemaShort(halogen.Schema):
        self = halogen.Link(attr = 'href')
        services = halogen.Embedded(halogen.types.List(Service.SchemaShort), attr = lambda value: [value.services[id] for id in value.services], required = False)

    href = '/airable/services'
    methods = ('GET',)
    lock = RLock()

    services = None

    def __init__(self):
        Endpoint.__init__(self, 'airable_services', 'List of external streaming services available through Airable')
        self.service_infos = ServiceInfo(self)

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
            return self.service_infos.get_json(**kwargs)

    def update_login_status(self, id, data, send_to_monitor = True):
        with self.lock:
            s = self.get_service_by_id(id)

            if not s:
                return

            s.update_login_status(data)

        if send_to_monitor:
            monitor.send(self, service_id = id)

class Auth(Endpoint):
    """API Endpoint: Authentication with Airable using the appliance key.

    Method ``GET``: Return authentication URL.
    """
    href = '/airable/authentication{?locale}'
    href_for_map = '/airable/authentication'
    methods = ('GET',)

    def __init__(self):
        Endpoint.__init__(self, 'airable_authentication', 'Airable authentication URL')

    def __call__(self, request, **values):
        try:
            locale = request.args.get('locale', 'de-DE')
            iface = strbo.dbus.Interfaces.airable()
            auth_url = iface.GenerateAuthenticationURL(locale)
            return jsonify(request, {'url': auth_url, 'locale': locale})
        except:
            log.error('Failed generating Airable authentication URL')
            raise

class Password(Endpoint):
    """API Endpoint: Generate temporary password for Airable protocol.

    Method ``GET``: Return password based on token and timestamp.
    """
    href = '/airable/password{?token,time}'
    href_for_map = '/airable/password'
    methods = ('GET',)

    def __init__(self):
        Endpoint.__init__(self, 'airable_password', 'Airable password generator')

    def __call__(self, request, **values):
        try:
            token = request.args.get('token', None)
            timestamp = request.args.get('time', None)

            if token is None or timestamp is None:
                return jsonify(request, {})

            iface = strbo.dbus.Interfaces.airable()
            password = iface.GeneratePassword(token, timestamp)
            return jsonify(request, {'password': password, 'token': token, 'time': timestamp})
        except:
            log.error('Failed generating Airable authentication URL')
            raise

class Redirect(Endpoint):
    """API Endpoint: Follow Airable redirect found at given path, redirect to
    URL the path redirects to.

    Method ``GET``: Redirect to the URL the Airable path points to.
    """
    href = '/airable/redirect/{+path}'
    href_for_map = '/airable/redirect/<path:path>'
    methods = ('GET',)

    def __init__(self):
        Endpoint.__init__(self, 'airable_redirect', 'Follow Airable redirect')
        self.root_url = None

    def __call__(self, request, path, **values):
        try:
            iface = strbo.dbus.Interfaces.airable()

            if self.root_url is None:
                self.root_url = iface.GetRootURL()

            airable_url = '{}/{}'.format(self.root_url, path)
            error_code, url = iface.ResolveRedirect(airable_url)

            if listerrors.is_error(error_code):
                result = jsonify(request,
                                 path = path, url = airable_url,
                                 error_code = error_code,
                                 error = listerrors.to_string(error_code))

                ec = listerrors.to_code(error_code)

                if ec is listerrors.ErrorCode.INTERNAL:
                    result.status_code = 500
                elif ec is listerrors.ErrorCode.INTERRUPTED:
                    result.status_code = 503
                elif ec is listerrors.ErrorCode.NET_IO:
                    result.status_code = 504
                elif ec is listerrors.ErrorCode.PROTOCOL:
                    result.status_code = 502
                elif ec in [listerrors.ErrorCode.AUTHENTICATION,
                            listerrors.ErrorCode.PERMISSION_DENIED]:
                    result.status_code = 403
                elif ec is listerrors.ErrorCode.NOT_SUPPORTED:
                    result.status_code = 501
                elif ec in [listerrors.ErrorCode.INVALID_URI,
                            listerrors.ErrorCode.INVALID_STREAM_URL,
                            listerrors.ErrorCode.INVALID_STRBO_URL]:
                    result.status_code = 400
                else:
                    result.status_code = 404
            else:
                result = Response(status = 307)
                result.location = url

            return result
        except:
            log.error('Failed following Airable redirect')
            raise

class Info(Endpoint):
    """API Endpoint: Entry point for interfacing with Airable.

    Method ``GET``: Return information about Airable API and external
    services accessible through Airable.
    """
    class Schema(halogen.Schema):
        self = halogen.Link(attr = 'href')
        root_url = halogen.Attr()
        music_services = halogen.Embedded(Services.SchemaShort)

    href = '/airable'
    methods = ('GET',)
    lock = RLock()

    are_data_available = False
    root_url = None
    music_services = Services()

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
        self.music_services.clear()

    def refresh(self):
        self.clear()

        try:
            iface = strbo.dbus.Interfaces.airable()
            self.root_url = iface.GetRootURL()
            self.music_services.refresh()
            self.are_data_available = True
        except:
            log.error('Failed retrieving information about Airable')
            self.clear()
            raise

info_endpoint = Info()
all_endpoints = [info_endpoint, info_endpoint.music_services, info_endpoint.music_services.service_infos,
                 Credentials(), Auth(), Password(), Redirect()]

def signal__external_service_login_status(service_id, actor_id, log_in, error_code, info):
    login_status = {
        'logged_in': error_code == 0 and log_in != 0,
        'info': info
    }

    if listerrors.is_error(error_code):
        login_status['last_error_code'] = error_code
        login_status['last_error'] = listerrors.to_string(error_code)

    info_endpoint.music_services.update_login_status(service_id, login_status)

def add_endpoints():
    from .endpoint import register_endpoints, register_endpoint
    register_endpoints(all_endpoints)

    strbo.dbus.Interfaces.airable().connect_to_signal('ExternalServiceLoginStatus',
                                                      signal__external_service_login_status)
