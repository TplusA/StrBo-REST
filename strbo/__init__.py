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

from .rest import EntryPoint, StrBo
from .endpoint import Endpoint, register_endpoint
from .monitor import Monitor

MONITOR_PORT = 8468
monitor = Monitor()
monitor.start(MONITOR_PORT)

register_endpoint(EntryPoint())

from .recovery import add_endpoints as add_recovery_endpoints
add_recovery_endpoints()

app = StrBo()
