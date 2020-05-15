#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2018, 2020  T+A elektroakustik GmbH & Co. KG
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

from threading import RLock
from werkzeug.wrappers import Response
from zlib import adler32
import halogen

from .endpoint import Endpoint, EmptyError, register_endpoints
from .utils import jsonify_e, jsonify_nc, jsonify_simple
from .utils import if_none_match
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

    class DataSchema(halogen.Schema):
        """Representation of :class:`Credentials._Data`."""

        #: Link to self.
        self = halogen.Link(attr=lambda value:
                            Credentials.url_for_music_service(value.id))

        #: Music service ID.
        id = halogen.Attr()

        #: User name used for this music service.
        username = halogen.Attr()

        #: Password used for this music service.
        password = halogen.Attr()

    #: Path to endpoint.
    href = '/airable/services/{id}/credentials'
    href_for_map = '/airable/services/<id>/credentials'

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
            return jsonify_nc(
                request,
                Credentials.DataSchema.serialize(Credentials._Data(id))
            )

        with self.lock:
            userpass = request.json

            # input sanitation
            try:
                if userpass:
                    username = userpass['username']
                    password = userpass['password']

                    if not isinstance(username, str) or\
                       not isinstance(password, str):
                        raise TypeError(
                            'User name and password must be strings')

                    if not username:
                        raise ValueError('Empty user name')
            except Exception as e:
                return Response('Exception: ' + str(e), status=400)

            # update credentials database
            try:
                wcred_iface = strbo.dbus.Interfaces.credentials_write()
                login_iface = strbo.dbus.Interfaces.airable()

                LOGIN_LOGOUT_ACTOR_ID = 3

                if userpass:
                    wcred_iface.SetCredentials(id, username, password, True)
                    login_iface.ExternalServiceLogout(
                        id, "", True, LOGIN_LOGOUT_ACTOR_ID)
                    login_iface.ExternalServiceLogin(
                        id, username, True, LOGIN_LOGOUT_ACTOR_ID)
                else:
                    wcred_iface.DeleteCredentials(id, "")
                    login_iface.ExternalServiceLogout(
                        id, "", True, LOGIN_LOGOUT_ACTOR_ID)
            except Exception as e:
                return Response('Exception: ' + str(e), status=500)

        return Response(status=204)

    @staticmethod
    def url_for_music_service(music_service_id):
        """Generate URL to credentials endpoint for given music service."""
        return '/airable/services/' + music_service_id + '/credentials'


class ServiceSchema(halogen.Schema):
    """Representation of :class:`Service`."""

    #: Link to self.
    self = halogen.Link(attr=lambda value: '/airable/services/' + value.id)

    #: Music service ID.
    id = halogen.Attr()

    #: Link to service credentials so that we don't spam around sensitive data
    #: in this place.
    service_credentials = halogen.Link(
        attr=lambda value: Credentials.url_for_music_service(value.id)
    )

    #: Human-readable description of music service.
    description = halogen.Attr()

    #: Login status, if known. The status may be unknown (never tried to
    #: access the music service up to this point), in which case the value
    #: is ``null``.
    login_status = halogen.Attr()


class ServiceSchemaShort(halogen.Schema):
    """Partial representation of :class:`Service`."""

    #: Link to self.
    self = halogen.Link(attr=lambda value: '/airable/services/' + value.id)

    #: Music service ID.
    id = halogen.Attr()


class Service:
    """Information about a service accessible through Airable."""

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
    |             | See :class:`ServiceSchema`.                      |
    +-------------+--------------------------------------------------+

    To avoid issues with (lack of) locking, this class should not accessed
    directly, but through the :class:`Services` class.
    """

    #: Path to endpoint.
    href = '/airable/services/{id}'
    href_for_map = '/airable/services/<id>'

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
            cached = if_none_match(request, self.services.get_etag())
            if cached:
                return cached

            service = self.services.get_service_by_id(id)

            if service is None:
                return jsonify_e(request, self.services.get_etag(), 20, {})

            return jsonify_e(request, self.services.get_etag(), 12 * 3600,
                             ServiceSchema.serialize(service))

    def get_json(self, **kwargs):
        """**Event monitor support** - Called from :mod:`strbo.monitor`."""
        with self.lock:
            service = self.services.get_service_by_id(kwargs['service_id'])

            if service is None:
                raise EmptyError(self)

            return jsonify_simple({self.id: ServiceSchema.serialize(service)})


class ServicesSchema(halogen.Schema):
    """Representation of :class:`Services`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: Embedded list of :class:`Service` objects
    #: (see :class:`ServiceSchema`). Field may be missing.
    service_info = halogen.Embedded(
        halogen.types.List(ServiceSchema),
        attr=lambda value: [value.services[id] for id in value.services],
        required=False
    )


class ServicesSchemaShort(halogen.Schema):
    """Partial representation of :class:`Services`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: Embedded list of partial :class:`Service` objects
    #: (see :class:`ServiceSchemaShort`). Field may be missing.
    service_info = halogen.Embedded(
        halogen.types.List(ServiceSchemaShort),
        attr=lambda value: [value.services[id] for id in value.services],
        required=False
    )


class Services(Endpoint):
    """**API Endpoint** - Information about all external music services
    provided by Airable.

    +-------------+-----------------------------------------------------+
    | HTTP method | Description                                         |
    +=============+=====================================================+
    | ``GET``     | Retrieve list of external music services accessible |
    |             | through Airable. See :class:`ServicesSchema`.       |
    +-------------+-----------------------------------------------------+

    Details on method ``GET``:
        The information are read out from the Airable list broker via D-Bus the
        first time this endpoint is accessed.

        Note that first-time access and non-cached accesses imply network
        access over the Internet. Such accesses can be slow, may result in
        errors, or may time out. While the network access is in progress, any
        further access to this endpoint will be blocked until the network
        access has finished. Pending requests will be handled successively,
        including non-cached requests; therefore, use non-cached requests
        sparingly, especially if the network seems to be slow.
    """

    #: Path to endpoint.
    href = '/airable/services'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    services = None
    services_etag = None

    def __init__(self):
        Endpoint.__init__(
            self, 'airable_services', name='external_services',
            title='List of external streaming services available '
                  'through Airable'
        )

        self.service_infos = ServiceInfo(self)

    def __call__(self, request=None, **values):
        with self.lock:
            cached = if_none_match(request, self.get_etag())
            if cached:
                return cached

            self._refresh()

            # we return ``self`` when being serialized as embedded object
            return self if request is None \
                else jsonify_e(request, self.get_etag(), 12 * 3600,
                               ServicesSchema.serialize(self))

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False

    def _clear(self):
        """Remove all services. Called internally and from :class:`Info`."""
        self.services = None
        self.services_etag = Services._compute_etag(self.services)

    def _refresh(self):
        """Reload all services. Called internally and from :class:`Info`."""
        self._clear()

        try:
            iface = strbo.dbus.Interfaces.credentials_read()
            self.services = {c[0]: Service(c[0], c[1])
                             for c in iface.GetKnownCategories()}
            self.services_etag = Services._compute_etag(self.services)
        except:  # noqa: E722
            log.error('Failed retrieving list of external services')
            self._clear()
            raise

    def get_service_by_id(self, id):
        """Return :class:`Service` object matching given `id`."""
        with self.lock:
            if self.services is None:
                self._refresh()

            return None if self.services is None \
                else self.services.get(id, None)

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

    def get_etag(self):
        with self.lock:
            return self.services_etag

    @staticmethod
    def _compute_etag(services):
        i = 0
        etag = 1

        if services:
            for k in sorted(services.keys()):
                i += 1
                s = services[k]
                temp = str(i) + k + s.id + s.description + str(s.login_status)
                etag = adler32(bytes(temp, 'UTF-8'), etag)

        return "{:08x}".format(etag)


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
            return jsonify_nc(request, {'url': auth_url, 'locale': locale})
        except:  # noqa: E722
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
                return jsonify_nc(request, {})

            iface = strbo.dbus.Interfaces.airable()
            password = iface.GeneratePassword(token, timestamp)
            return jsonify_nc(request, {'password': password, 'token': token,
                                        'time': timestamp})
        except:  # noqa: E722
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
                result = jsonify_nc(request,
                                    path=path, url=airable_url,
                                    error_code=error_code,
                                    error=listerrors.to_string(error_code))

                if result.status_code == 406:
                    return result

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
        except:  # noqa: E722
            log.error('Failed following Airable redirect')
            raise


class InfoSchema(halogen.Schema):
    """Representation of :class:`Info`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: Airable API entry point.
    root_url = halogen.Attr()

    #: Embedded list of partial :class:`Service` objects
    #: (see :class:`ServiceSchemaShort`).
    external_services = halogen.Embedded(ServicesSchemaShort)


class Info(Endpoint):
    """**API Endpoint** - Entry point for interfacing with Airable.

    +-------------+------------------------------------------------------+
    | HTTP method | Description                                          |
    +=============+======================================================+
    | ``GET``     | Entry point for everything Airable, most notably the |
    |             | Airable root URL (Airable API entry point).          |
    |             | See :class:`InfoSchema`.                             |
    +-------------+------------------------------------------------------+
    """

    #: Path to endpoint.
    href = '/airable'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    root_url = None
    external_services = Services()

    def __init__(self):
        Endpoint.__init__(self, 'airable_info', name='info',
                          title='Interfacing with Airable')

    def __call__(self, request, **values):
        with self.lock:
            cached = if_none_match(request, self.get_etag())
            if cached:
                return cached

            self._refresh()
            return jsonify_e(request, self.get_etag(), 24 * 3600,
                             InfoSchema.serialize(self))

    def _clear(self):
        self.root_url = None
        self.external_services._clear()

    def _refresh(self):
        self._clear()

        try:
            iface = strbo.dbus.Interfaces.airable()
            self.root_url = iface.GetRootURL()
            self.external_services._refresh()
        except:  # noqa: E722
            log.error('Failed retrieving information about Airable')
            self._clear()
            raise

    def get_etag(self):
        with self.lock:
            return self.external_services.get_etag()


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

    info_endpoint.external_services.update_login_status(service_id,
                                                        login_status)


def add_endpoints():
    """Register all endpoints defined in this module, start listening to
    relevant D-Bus signals."""
    register_endpoints(all_endpoints)

    strbo.dbus.Interfaces.airable().connect_to_signal(
        'ExternalServiceLoginStatus', signal__external_service_login_status)
