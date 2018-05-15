#! /usr/bin/env python3

from flipflop import WSGIServer
from werkzeug.contrib.fixers import CGIRootFix
from strbo.rest import app

if __name__ == '__main__':
    app.wsgi_app = CGIRootFix(app.wsgi_app, app_root = 'v1')
    WSGIServer(app).run()
