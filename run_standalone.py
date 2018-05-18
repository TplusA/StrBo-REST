#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from werkzeug.serving import run_simple
from strbo import app

run_simple('0.0.0.0', 5000, app, use_debugger = True, use_reloader = False, threaded = True)
