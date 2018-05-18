#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from werkzeug.wrappers import Request
from werkzeug.routing import Map, Rule
import halogen

class Endpoint:
    class Schema(halogen.Schema):
        href = halogen.Attr()
        title = halogen.Attr(required = False)

    def __init__(self, id, href, title = None):
        self.id = id
        self.href = href

        if title:
            self.title = title

    def __call__(self, request, **values):
        raise Exception("Endpoint '" + self.id + "' at " + self.href + " not callable")

url_map = Map()
dispatchers = {}

def register_endpoint(e):
    url_map.add(Rule(e.href, endpoint = e.id))
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
