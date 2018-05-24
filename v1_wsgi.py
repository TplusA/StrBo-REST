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

from flipflop import WSGIServer
from werkzeug.contrib.fixers import CGIRootFix
from strbo import app

if __name__ == '__main__':
    app.wsgi_app = CGIRootFix(app.wsgi_app, app_root = 'v1')
    WSGIServer(app).run()
