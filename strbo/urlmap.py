#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from werkzeug.wrappers import Request
from werkzeug.routing import Map, Rule

url_map = Map([
    Rule('/', endpoint = 'entry_point'),
    Rule('/recovery',        endpoint = 'recovery_system'),
    Rule('/recovery/info',   endpoint = 'recovery_system_info'),
    Rule('/recovery/verify', endpoint = 'recovery_system_verify'),
])

def url_for(environ_or_request, endpoint):
    if isinstance(environ_or_request, Request):
        adapter = url_map.bind_to_environ(environ_or_request.environ)
    else:
        adapter = url_map.bind_to_environ(environ_or_request)

    return adapter.build(endpoint)
