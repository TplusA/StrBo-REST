#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2018, 2020, 2021, 2023  T+A elektroakustik GmbH & Co. KG
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

from threading import Lock
from werkzeug.wrappers import Request
from werkzeug.routing import Map, Rule
import halogen


class Error(Exception):
    """Base class for exceptions thrown by :mod:`strbo.endpoint`.

    ``message`` is an error description string, used as prefix of the final
    message stored in the exception. If left empty, then a generic message is
    inserted.

    ``ep`` is an :class:`Endpoint` instance, some object with a string
    representation, or ``None``. The exception message will vary according to
    the value of ``ep``.

    ``ep_name`` is an alternative way to pass an endpoint name in case no
    proper :class:`Endpoint` instance is within reach. It is only considered if
    ``ep`` is ``None`` and if ``ep_name`` is a string, otherwise this parameter
    will be ignored.

    Set ``just_the_message`` to ``True`` to use ``message`` as final exception
    message string so that nothing will be appended to ``message``. This flag
    is only considered if both, ``ep`` and ``ep_name``, are ``None``.
    """

    def __init__(self, message, ep=None, ep_name=None, just_the_message=False):
        if not message:
            #: Formatted exception message.
            self.message = "Unknown error"
        elif isinstance(ep, Endpoint):
            self.message = message + ' endpoint ID {}'.format(ep.id)
        elif ep is not None:
            self.message = message + ' non-endpoint {}'.format(ep)
        elif isinstance(ep_name, str):
            self.message = message + ' endpoint {}'.format(ep_name)
        elif just_the_message:
            self.message = message
        else:
            self.message = message + ' unknown endpoint'


class GenericError(Error):
    """Any kind of error that doesn't fit into the more specific errors."""

    def __init__(self, message, ep=None, ep_name=None):
        super().__init__(message, ep, ep_name, just_the_message=True)


class NotCallableError(Error):
    """Thrown if an :class:`Endpoint` is called which doesn't override
    :meth:`Endpoint.__call__`."""

    def __init__(self, ep=None, ep_name=None):
        if isinstance(ep, Endpoint):
            super().__init__("Not callable at {}:".format(ep.href),
                             ep, ep_name)
        else:
            super().__init__("Not callable:", ep, ep_name)


class SerializeError(Error):
    """Thrown in case a resource at some :class:`Endpoint` cannot be
    serialized as JSON object.

    This exception is thrown in conjunction with the monitoring mechanism.
    """

    def __init__(self, ep=None, ep_name=None):
        super().__init__('Failed serializing', ep, ep_name)


class EmptyError(Error):
    """Thrown in case a resource at some :class:`Endpoint` is empty when it
    shouldn't be.

    This might be the case if the resource does not exist or if it requires
    some parameter which is wrong or missing.

    This exception is thrown in conjunction with the monitoring mechanism.
    """

    def __init__(self, ep=None, ep_name=None):
        super().__init__('Have no data for', ep, ep_name)


class EndpointSchema(halogen.Schema):
    """Simple schema for generating links to endpoints."""

    href = halogen.Attr()
    title = halogen.Attr(required=False)
    name = halogen.Attr()
    templated = halogen.Attr(
        attr=lambda value: len(value.href_for_map) > 0,
        required=False
    )


class Endpoint:
    """Definition of an API endpoint.

    Parameters:
        ``id`` is a non-empty string defining the endpoint ID. It is used to
        initialize object attribute :attr:`id`. This identifier must be unique
        across the whole API as it is used by :mod:`werkzeug` for mapping URLs
        to endpoints.

        ``name`` is an optional string identifier containing the Link Relation
        Type (identifies the semantics of the link (see :rfc:`5988`)). It is
        used to initialize object attribute :attr:`name`. May also be ``None``,
        in which case :attr:`name` is set to the value passed in ``id``.

        ``title`` is an optional string containing a short description of this
        endpoint. May also be ``None``.

        ``href`` is a string defining the URL path to this endpoint. It is the
        initializer for object attribute :attr:`href`. In case the deriving
        class presets the :attr:`href` attribute with a non-empty value (which
        is to be preferred if at all possible), this parameter is optional and
        may be used to override the preset; otherwise, a non-empty string must
        be passed.

        ``href_for_map`` is an optional string defining the URL path as a
        pattern for use with :mod:`werkzeug`, stored in attribute
        :attr:`href_for_map`. If a URI Template is passed in the `href`
        parameter, then most likely this parameter will have to be set as well,
        expressing the URI Template in syntax suitable for :mod:`werkzeug`. See
        also :class:`werkzeug.routing.Rule`.

    All StrBo endpoints should derive from this class. It contains the most
    basic data about endpoints required by :mod:`werkzeug` and :mod:`halogen`
    to build our API.

    Derived classes shall explicitly define the HTTP methods allowed for the
    endpoint (``GET``, ``POST``, etc.) in the :attr:`methods` attribute of
    their objects. We cannot rely on defaults imposed by :mod:`werkzeug`.

    An :class:`Endpoint` is callable. Derived classes must override the
    :meth:`Endpoint.__call__` method as the default implementation simply
    throws an exception. This method is passed an WSGI which it is supposed to
    process.

    Use functions :func:`register_endpoint` or :func:`register_endpoints` to
    register an API endpoint, i.e., any object of this class, with
    :mod:`werkzeug`.
    """

    def __init__(self, id, *,
                 name=None, title=None, href=None, href_for_map=None):
        if not isinstance(id, str):
            raise TypeError("Parameter id must be a string")

        #: Endpoint ID for :mod:`werkzeug`.
        self.id = id

        if name is None:
            #: This is the Link Relation Type that clients can use to find the
            #: endpoint they are interested in.
            self.name = id
        else:
            if not isinstance(name, str):
                raise TypeError("Parameter name must be a string")

            self.name = name

        if href:
            if not isinstance(href, str):
                raise TypeError("Parameter href must be a string")

            #: Derived classes shall define their path in this attribute.
            #: This string may also be a URI Template (:rfc:`6570`), in which
            #: case :attr:`href_for_map` must also be defined using
            #: :mod:`werkzeug` syntax (see :class:`werkzeug.routing.Rule`).
            #
            #: Optionally, this path may also be passed to the constructor if
            #: required, but static paths should be preferred, if possible, and
            #: preset by the derived class.
            self.href = href

        if href_for_map:
            if not isinstance(href_for_map, str):
                raise TypeError("Parameter href_for_map must be a string")

            #: Similar to :attr:`href`, but using :mod:`werkzeug` syntax for
            #: URL routing. If :attr:`href` contains a plain URI, then this
            #: attribute shall not be present at all. As with :attr:`href`,
            #: static definition of :attr:`href_for_map` in the derived class
            #: is preferable over passing it through the constructor.
            self.href_for_map = href_for_map

        if not hasattr(self, 'href'):
            raise GenericError('No href defined', self)
        elif not self.href:
            raise GenericError('Empty href', self)

        if hasattr(self, 'href_for_map') and not self.href_for_map:
            raise GenericError('Empty href_for_map', self)

        if not hasattr(self, 'methods'):
            raise GenericError('No methods defined', self)
        elif not self.methods:
            raise GenericError('Empty methods', self)

        if title:
            #: Optional endpoint description serving as documentation when
            #: navigating the API.
            if not isinstance(title, str):
                raise TypeError("Parameter title must be a string")

            self.title = title

    def __call__(self, request, **values):
        raise NotCallableError(self)


url_map = Map()
url_map_lock = Lock()
dispatchers = {}


def register_endpoint(e):
    """Register one endpoint."""
    hrefs = getattr(e, 'href_for_map', e.href)

    with url_map_lock:
        if isinstance(hrefs, list):
            for href in hrefs:
                url_map.add(Rule(href, endpoint=e.id, methods=e.methods))
        else:
            url_map.add(Rule(hrefs, endpoint=e.id, methods=e.methods))

    dispatchers[e.id] = e


def register_endpoints(es):
    """Register a set of endpoints."""
    for e in es:
        register_endpoint(e)


def dispatch(request):
    """Dispatch one request of type :class:`werkzeug.wrappers.Request`.

    This function must be called for each WSGI request passed into our
    application. Basically, it matches the URL in the WSGI request against the
    hrefs of all registered :class:`Endpoint` objects, and calls the matching
    :class:`Endpoint`, if any, or throws an exception in case no
    :class:`Endpoint` is found for the URL.
    """
    with url_map_lock:
        adapter = url_map.bind_to_environ(request.environ)
        id, values = adapter.match()

    return dispatchers[id](request, **values)


def url_for(environ_or_request, endpoint, values=None):
    """Generate a URL for an :class:`Endpoint`.

    Never, ever try to generate URLs by hand, always use this function. This
    function hands over :attr:`Endpoint.id` to :mod:`werkzeug` to generate
    URLs; thus, whenever an :attr:`Endpoint.href` is changed, this function
    will still return valid URLs. Whenever a new :class:`Endpoint` is added, it
    can automatically be handled by this function, and whenever an endpoint is
    removed, a meaningful error is thrown.

    This function requires a WSGI request or a WSGI environment to work. This
    is because URLs can only be generated given some context to incorporate the
    original request URL. In practice, this should never be a problem; if it
    is, then its most likely a problem with the API design.
    """
    environ = \
        environ_or_request.environ if isinstance(environ_or_request, Request) \
        else environ_or_request

    # For some reason, `SCRIPT_NAME` is set incorrectly by lighttpd (?). This
    # causes URLs generated by ``url_map`` to be prefixed with ``/v1.fcgi``. As
    # a workaround, we replace `SCRIPT_NAME` with the expected value `/v1`
    # before generating the URL, and put back the old value when done.
    script_name = environ['SCRIPT_NAME']
    environ['SCRIPT_NAME'] = '/v1'

    with url_map_lock:
        adapter = url_map.bind_to_environ(environ)
        result = adapter.build(endpoint.id, values=values)

    # Put back original value of `SCRIPT_NAME`.
    environ['SCRIPT_NAME'] = script_name

    return result
