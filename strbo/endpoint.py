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

from werkzeug.wrappers import Request
from werkzeug.routing import Map, Rule
import halogen

class Endpoint:
    """Definition of an API endpoint.

    This class also defines a simple Halogen schema for links to self.

    All StrBo endpoints should derive from this class. It contains the most
    basic data about endpoints required by Werkzeug and Halogen to build our
    API.

    Use functions `register_endpoint` or `register_endpoints` to register any
    API endpoints.

    Attributes:
        id: Endpoint ID for Werkzeug. Set in constructor.
        title: Optional endpoint description. Set in constructor.
        href: Derived classes shall define their path in this attribute. This
            may also be a URI Template (RFC 6570), in which case
            ``href_for_map`` must also be defined using Werkzeug syntax.
            Optionally, this path may also be passed to the constructor if
            required, but static paths should be defined at class level.
        href_for_map: Similar to ``href``, but using Werkzeug syntax for URL
            routing. In case of plain URI, this attribute shall not be present.
        methods: Derived classes shall explicitly define the methods allowed
            for the endpoint in their 'methods' attribute (``GET``, ``POST``,
            etc.). We do not want to rely on defaults imposed by Werkzeug.
    """
    class Schema(halogen.Schema):
        href = halogen.Attr()
        title = halogen.Attr(required = False)
        templated = halogen.Attr(attr = lambda value: len(value.href_for_map) > 0, required = False)

    def __init__(self, id, title = None, *, href = None, href_for_map = None):
        self.id = id

        if href:
            self.href = href

        if href_for_map:
            self.href_for_map = href_for_map

        if not hasattr(self, 'href'):
            raise Exception("No href defined")
        elif not self.href:
            raise Exception("Empty href")

        if hasattr(self, 'href_for_map') and not self.href_for_map:
            raise Exception("Empty href_for_map")

        if not hasattr(self, 'methods'):
            raise Exception("No methods defined")
        elif not self.methods:
            raise Exception("Empty methods")

        if title:
            self.title = title

    def __call__(self, request, **values):
        raise Exception("Endpoint '" + self.id + "' at " + self.href + " not callable")

url_map = Map()
dispatchers = {}

def register_endpoint(e):
    url_map.add(Rule(getattr(e, 'href_for_map', e.href), endpoint = e.id, methods = e.methods))

    dispatchers[e.id] = e

def register_endpoints(es):
    for e in es:
        register_endpoint(e)

def dispatch(request):
    adapter = url_map.bind_to_environ(request.environ)
    id, values = adapter.match()
    return dispatchers[id](request, **values)

def url_for(environ_or_request, endpoint):
    if isinstance(environ_or_request, Request):
        adapter = url_map.bind_to_environ(environ_or_request.environ)
    else:
        adapter = url_map.bind_to_environ(environ_or_request)

    return adapter.build(endpoint.id)
