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
    """**API Endpoint** - Management of credentials for external music
    services.

    +-------------+---------------------------------------------------------+
    | HTTP method | Description                                             |
    +=============+=========================================================+
    | ``GET``     | Read out credentials (user name and password) for music |
    |             | service with ID `{id}`.                                 |
    +-------------+---------------------------------------------------------+
    | ``PUT``     | Replace credentials for music service with ID `{id}`    |
    |             | (``application/json``).                                 |
    +-------------+---------------------------------------------------------+

    Details on method ``PUT``:
        The credentials must be sent as JSON object, not as URL parameters. We
        do this to avoid use of URLs containing sensitive data.

        The JSON object must contain fields ``username`` and ``password``
        containing the respective entities for service `{id}`. Following
        Airable policies, the Streaming Board will try to log into the service
        using the new credentials. In case *no* JSON object is sent with the
        request, the credentials for service `{id}` will be removed and the
        device will log out from the service. Login and logout events are
        observable through the event monitor.

        The HTTP status will be 204 on success, or either 400 or 500 in case of
        client error or server error, respectively.

        Note that wrong login data are not considered an error at this point:
        any credentials sent are simply accepted and stored. They are used by
        an unrelated, completely independent part of the system, and that part
        will communicate status through the monitor while it is using these
        data.
    """

    class _Data:
        """Helper structure for serialization."""

        def __init__(self, id):
            iface = strbo.dbus.Interfaces.credentials_read()
            self.username, self.password = iface.GetDefaultCredentials(id)
            self.id = id

            if not self.username:
                self.username = None
                self.password = None

    class Schema(halogen.Schema):
        """Representation of :class:`Credentials`."""

        #: Link to self.
        self = halogen.Link(attr=lambda value: '/airable/service/' +
                                               value.id + '/credentials')

        #: Music service ID.
        id = halogen.Attr()

        #: User name used for this music service.
        username = halogen.Attr()

        #: Password used for this music service.
        password = halogen.Attr()

    class SchemaShort(halogen.Schema):
        """Partial representation of :class:`Credentials`."""

        #: Link to self.
        self = halogen.Link(attr=lambda value: '/airable/service/' +
                                               value.id + '/credentials')

    #: Path to endpoint.
    href = '/airable/service/{id}/credentials'
    href_for_map = '/airable/service/<id>/credentials'

    #: Supported HTTP methods.
    methods = ('GET', 'PUT')

    lock = RLock()

    def __init__(self):
        Endpoint.__init__(
            self, 'airable_service_credentials', name='service_credentials',
            title='Management of credentials for external music services'
        )

    def __call__(self, request, id, **values):
        if request.method == 'GET':
            return jsonify(request,
                           Credentials.Schema.serialize(Credentials._Data(id)))

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
                return Response('Exception: ' + str(e), status=400)

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
                return Response('Exception: ' + str(e), status=500)

        return Response(status=204)


class Service:
    """Information about a service accessible through Airable."""

    class Schema(halogen.Schema):
        """Representation of :class:`Service`."""

        #: Link to self.
        self = halogen.Link(attr=lambda value: '/airable/service/' + value.id)

        #: Music service ID.
        id = halogen.Attr()

        #: Embedded :class:`Credentials.SchemaShort` object. It's the partial
        #: representation so that we don't spam around sensitive data.
        service_credentials = halogen.Embedded(Credentials.SchemaShort,
                                               attr=lambda value: value)

        #: Human-readable description of music service.
        description = halogen.Attr()

        #: Login status, if known. The status may be unknown (never tried to
        #: access the music service up to this point), in which case the value
        #: is ``null``.
        login_status = halogen.Attr()

    class SchemaShort(halogen.Schema):
        """Partial representation of :class:`Service`."""

        #: Link to self.
        self = halogen.Link(attr=lambda value: '/airable/service/' + value.id)

        #: Music service ID.
        id = halogen.Attr()

    def __init__(self, id, description):
        self.id = id
        self.description = description
        self.login_status = None

    def update_login_status(self, data):
        """Set login status data. Called from
        :meth:`Services.update_login_status`."""
        self.login_status = data


class ServiceInfo(Endpoint):
    """**API Endpoint** - Accessing an external service provided by Airable.

    +-------------+--------------------------------------------------+
    | HTTP method | Description                                      |
    +=============+==================================================+
    | ``GET``     | Read out information about music service `{id}`. |
    |             | See :class:`Service.Schema`.                     |
    +-------------+--------------------------------------------------+

    To avoid issues with (lack of) locking, this class should not accessed
    directly, but through the :class:`Services` class.
    """

    #: Path to endpoint.
    href = '/airable/service/{id}'
    href_for_map = '/airable/service/<id>'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    def __init__(self, services):
        Endpoint.__init__(
            self, 'airable_service', name='service_info',
            title='Accessing a specific Airable external streaming service'
        )

        self.services = services

    def __call__(self, request, id, **values):
        with self.lock:
            service = self.services.get_service_by_id(id)

            if service is None:
                return jsonify(request, {})

            return jsonify(request, Service.Schema.serialize(service))

    def get_json(self, **kwargs):
        """**Event monitor support** - Called from :mod:`strbo.monitor`."""
        with self.lock:
            service = self.services.get_service_by_id(kwargs['service_id'])

            if service is None:
                from .endpoint import EmptyError
                raise EmptyError(self)

            return jsonify_simple({self.id: Service.Schema.serialize(service)})


class Services(Endpoint):
    """**API Endpoint** - Information about all external music services
    provided by Airable.

    +-------------+-----------------------------------------------------+
    | HTTP method | Description                                         |
    +=============+=====================================================+
    | ``GET``     | Retrieve list of external music services accessible |
    |             | through Airable. See :class:`Services.Schema`.      |
    +-------------+-----------------------------------------------------+

    Details on method ``GET``:
        The information are read out from the Airable list broker via D-Bus the
        first time this endpoint is accessed. All information are cached unless
        the client asks for fresh information (``Cache-Control: no-cache``).

        Note that first-time access and non-cached accesses imply network
        access over the Internet. Such accesses can be slow, may result in
        errors, or may time out. While the network access is in progress, any
        further access to this endpoint will be blocked until the network
        access has finished. Pending requests will be handled successively,
        including non-cached requests; therefore, use non-cached requests
        sparingly, especially if the network seems to be slow.
    """

    class Schema(halogen.Schema):
        """Representation of :class:`Services`."""

        #: Link to self.
        self = halogen.Link(attr='href')

        #: Embedded list of :class:`Service` objects
        #: (see :class:`Service.Schema`). Field may be missing.
        service_info = halogen.Embedded(
            halogen.types.List(Service.Schema),
            attr=lambda value: [value.services[id] for id in value.services],
            required=False
        )

    class SchemaShort(halogen.Schema):
        """Partial representation of :class:`Services`."""

        #: Link to self.
        self = halogen.Link(attr='href')

        #: Embedded list of partial :class:`Service` objects
        #: (see :class:`Service.SchemaShort`). Field may be missing.
        service_info = halogen.Embedded(
            halogen.types.List(Service.SchemaShort),
            attr=lambda value: [value.services[id] for id in value.services],
            required=False
        )

    #: Path to endpoint.
    href = '/airable/services'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    services = None

    def __init__(self):
        Endpoint.__init__(
            self, 'airable_services', name='external_services',
            title='List of external streaming services available through Airable'
        )

        self.service_infos = ServiceInfo(self)

    def __call__(self, request=None, **values):
        cc = None if request is None else request.environ.get('HTTP_CACHE_CONTROL', None)

        with self.lock:
            if cc and cc == 'no-cache':
                self.services = None

            if self.services is None:
                self._refresh()

            return self if request is None else jsonify(request, Services.Schema.serialize(self))

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False

    def _clear(self):
        """Remove all services. Called internally and from :class:`Info`."""
        self.services = None

    def _refresh(self):
        """Reload all services. Called internally and from :class:`Info`."""
        self._clear()

        try:
            iface = strbo.dbus.Interfaces.credentials_read()
            self.services = {c[0]: Service(c[0], c[1])
                             for c in iface.GetKnownCategories()}
        except:
            log.error('Failed retrieving list of external services')
            self._clear()
            raise

    def get_service_by_id(self, id):
        """Return :class:`Service` object matching given `id`."""
        with self.lock:
            if self.services is None:
                self._refresh()

            return None if self.services is None else self.services.get(id, None)

    def get_json(self, **kwargs):
        """**Event monitor support** - Called from :mod:`strbo.monitor`."""
        with self.lock:
            return self.service_infos.get_json(**kwargs)

    def update_login_status(self, id, data, send_to_monitor=True):
        """Set login status. Called from D-Bus signal handler."""
        with self.lock:
            s = self.get_service_by_id(id)

            if not s:
                return

            s.update_login_status(data)

        if send_to_monitor:
            monitor.send(self, service_id=id)


class Auth(Endpoint):
    """**API Endpoint** - Authentication with Airable using the appliance key.

    +-------------+----------------------------------------------------------+
    | HTTP method | Description                                              |
    +=============+==========================================================+
    | ``GET``     | Return object containing the Airable authentication URL. |
    +-------------+----------------------------------------------------------+

    Details on method ``GET``:
        The language can be set using the optional `{locale}` parameter. It can
        be omitted and defaults to the string ``de-DE``, but real-world clients
        should always fill in this parameter.

        The value passed as `{locale}` is always taken verbatim and passed to
        Airable as-is, meaningful or not. No checks are done because there is
        no reliable way to check validity.

        Data returned by this method is different for each request and is
        therefore not cacheable. A corresponding HTTP header is sent along with
        the response.
    """

    #: Path to endpoint.
    href = '/airable/authentication{?locale}'
    href_for_map = '/airable/authentication'

    #: Supported HTTP methods.
    methods = ('GET',)

    def __init__(self):
        Endpoint.__init__(
            self, 'airable_authentication', name='authentication_url',
            title='Airable authentication URL'
        )

    def __call__(self, request, **values):
        try:
            locale = request.args.get('locale', 'de-DE')
            iface = strbo.dbus.Interfaces.airable()
            auth_url = iface.GenerateAuthenticationURL(locale)
            result = jsonify(request, {'url': auth_url, 'locale': locale})
            result.headers['Cache-Control'] = 'no-store, must-revalidate'
            return result
        except:
            log.error('Failed generating Airable authentication URL')
            raise


class Password(Endpoint):
    """**API Endpoint** - Generate temporary password for Airable protocol.

    +-------------+-----------------------------------------------------------+
    | HTTP method | Description                                               |
    +=============+===========================================================+
    | ``GET``     | Retrieve a password based on login token and current time |
    |             | stamp.                                                    |
    +-------------+-----------------------------------------------------------+

    Details on method ``GET``:
        The login token obtained from Airable must be passed as URL parameter
        `{token}`, and the current time stamp must be passed as parameter
        `{time}`.

        This method does not access the network. It is a pure computation step.
        It will always generate the same answer given the same input.
    """

    #: Path to endpoint.
    href = '/airable/password{?token,time}'
    href_for_map = '/airable/password'

    #: Supported HTTP methods.
    methods = ('GET',)

    def __init__(self):
        Endpoint.__init__(self, 'airable_password', name='password_generator',
                          title='Airable password generator')

    def __call__(self, request, **values):
        try:
            token = request.args.get('token', None)
            timestamp = request.args.get('time', None)

            if token is None or timestamp is None:
                return jsonify(request, {})

            iface = strbo.dbus.Interfaces.airable()
            password = iface.GeneratePassword(token, timestamp)
            return jsonify(request, {'password': password, 'token': token,
                                     'time': timestamp})
        except:
            log.error('Failed generating Airable authentication URL')
            raise


class Redirect(Endpoint):
    """**API Endpoint** - Follow Airable redirect found at given path, redirect
    to URL the path redirects to.

    +-------------+-------------------------------------------------+
    | HTTP method | Description                                     |
    +=============+=================================================+
    | ``GET``     | Redirect to the URL the Airable path points to. |
    +-------------+-------------------------------------------------+

    Details on method ``GET``:
        The path `{path}` appended to the endpoint base URL shall be a relative
        path within Airable's directory. It shall point to an Airable
        ``redirect`` object.

        On success, the response is a redirect with status code 307 so that an
        HTTP client configured to follow redirects may play a stream directly
        from this endpoint.

        On error, one of the various HTTP status codes is returned, in an
        attempt of mapping the internal error codes to HTTP status codes.
        Along, a JSON object is returned which contains the relative path
        passed with the request, the failed Airable URL, the internal error
        code, and an error name. These information are primarily useful for
        debugging, not for presentation to the user.
    """

    #: Path to endpoint.
    href = '/airable/redirect/{+path}'
    href_for_map = '/airable/redirect/<path:path>'

    #: Supported HTTP methods.
    methods = ('GET',)

    def __init__(self):
        Endpoint.__init__(self, 'airable_redirect', name='redirect',
                          title='Follow Airable redirect')
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
                                 path=path, url=airable_url,
                                 error_code=error_code,
                                 error=listerrors.to_string(error_code))

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
                result = Response(status=307)
                result.location = url

            return result
        except:
            log.error('Failed following Airable redirect')
            raise


class Info(Endpoint):
    """**API Endpoint** - Entry point for interfacing with Airable.

    +-------------+------------------------------------------------------+
    | HTTP method | Description                                          |
    +=============+======================================================+
    | ``GET``     | Entry point for everything Airable, most notably the |
    |             | Airable root URL (Airable API entry point).          |
    |             | See :class:`Info.Schema`.                            |
    +-------------+------------------------------------------------------+
    """

    class Schema(halogen.Schema):
        """Representation of :class:`Info`."""

        #: Link to self.
        self = halogen.Link(attr='href')

        #: Airable API entry point.
        root_url = halogen.Attr()

        #: Embedded list of partial :class:`Service` objects
        #: (see :class:`Service.SchemaShort`).
        external_services = halogen.Embedded(Services.SchemaShort)

    #: Path to endpoint.
    href = '/airable'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    are_data_available = False
    root_url = None
    external_services = Services()

    def __init__(self):
        Endpoint.__init__(self, 'airable_info', name='info',
                          title='Interfacing with Airable')

    def __call__(self, request, **values):
        cc = request.environ.get('HTTP_CACHE_CONTROL', None)

        with self.lock:
            if cc and cc == 'no-cache':
                self.are_data_available = False

            if not self.are_data_available:
                self._refresh()

            return jsonify(request, Info.Schema.serialize(self))

    def _clear(self):
        self.are_data_available = False
        self.root_url = None
        self.external_services._clear()

    def _refresh(self):
        self._clear()

        try:
            iface = strbo.dbus.Interfaces.airable()
            self.root_url = iface.GetRootURL()
            self.external_services._refresh()
            self.are_data_available = True
        except:
            log.error('Failed retrieving information about Airable')
            self._clear()
            raise


info_endpoint = Info()
all_endpoints = [info_endpoint, info_endpoint.external_services,
                 info_endpoint.external_services.service_infos,
                 Credentials(), Auth(), Password(), Redirect()]


def signal__external_service_login_status(service_id, actor_id, log_in,
                                          error_code, info):
    login_status = {
        'logged_in': error_code == 0 and log_in != 0,
        'info': info
    }

    if listerrors.is_error(error_code):
        login_status['last_error_code'] = error_code
        login_status['last_error'] = listerrors.to_string(error_code)

    info_endpoint.external_services.update_login_status(service_id, login_status)


def add_endpoints():
    """Register all endpoints defined in this module, start listening to
    relevant D-Bus signals."""
    from .endpoint import register_endpoints
    register_endpoints(all_endpoints)

    strbo.dbus.Interfaces.airable().connect_to_signal(
        'ExternalServiceLoginStatus', signal__external_service_login_status)
