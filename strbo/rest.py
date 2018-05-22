#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from werkzeug.wrappers import Request
from werkzeug.exceptions import HTTPException
import halogen

from .endpoint import Endpoint, dispatch
from .utils import jsonify

class EntryPoint(Endpoint):
    """API Endpoint: Entry point to API."""
    class Schema(halogen.Schema):
        self = halogen.Link(attr = 'href')
        recovery = halogen.Link(halogen.types.List(Endpoint.Schema))
        api_version = halogen.Attr({'major': 1, 'minor': 0})

    href = '/'
    methods = ('GET',)

    def __init__(self):
        Endpoint.__init__(self, 'entry_point')

        from .recovery import all_endpoints as all_recovery_endpoints
        self.recovery = all_recovery_endpoints

    def __call__(self, request, **values):
        return jsonify(request, EntryPoint.Schema.serialize(self))

def error_response_from_exception(request, e, kind, code):
    import traceback
    return jsonify(request,
                   error = {
                       'message': kind + ': ' + str(e),
                       'code': code,
                       'trace': traceback.extract_tb(tb = e.__traceback__),
                       'environment': str(request.environ)
                   })

class StrBo:
    """Our WSGI application."""
    def wsgi_app(self, environ, start_response):
        try:
            request = Request(environ)
            response = dispatch(request)
        except HTTPException as e:
            response = error_response_from_exception(request, e, 'HTTP exception', e.code)
        except Exception as e:
            response = error_response_from_exception(request, e, 'Python exception', 500)

        return response(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)
