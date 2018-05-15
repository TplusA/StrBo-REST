#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from werkzeug.wrappers import Request
from werkzeug.exceptions import HTTPException

import strbo.urlmap
from .utils import jsonify
from .recovery import on_recovery_system, on_recovery_system_info, on_recovery_system_verify

def on_entry_point(request, **values):
    return jsonify(request,
                   recovery_system = strbo.urlmap.url_for(request, 'recovery_system'))

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
    def dispatch_request(self, request):
        adapter = strbo.urlmap.url_map.bind_to_environ(request.environ)

        try:
            endpoint, values = adapter.match()
            return globals()['on_' + endpoint](request, **values)
        except HTTPException as e:
            return error_response_from_exception(request, e, 'HTTP exception', e.code)
        except Exception as e:
            return error_response_from_exception(request, e, 'Python exception', 500)

    def wsgi_app(self, environ, start_response):
        request = Request(environ)
        response = self.dispatch_request(request)
        return response(environ, start_response)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)

app = StrBo()
