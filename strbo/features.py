#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2023  T+A elektroakustik GmbH & Co. KG
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

import os
import dbus

is_airable_available = \
    os.path.isfile('/usr/share/dbus-1/services/de.tahifi.TuneInBroker.service')

try:
    dbus.Interface(dbus.SystemBus().get_object('org.freedesktop.systemd1',
                                               '/org/freedesktop/systemd1'),
                   dbus_interface='org.freedesktop.systemd1.Manager') \
        .GetUnit('taroon.service')
except dbus.exceptions.DBusException:
    is_roon_available = False
else:
    is_roon_available = True
