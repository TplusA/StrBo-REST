#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2018, 2020, 2021  T+A elektroakustik GmbH & Co. KG
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

import threading
import dbus
import dbus.service

from dbus.mainloop.glib import DBusGMainLoop, threads_init
from gi.repository import GLib

from .utils import get_logger
log = get_logger('D-Bus')


def _dbus_worker(dbh):
    """The main function of the thread created in the :class:`DBusHandler`
    constructor."""
    if dbh._dbus_mainloop:
        log.info('Thread running')
        dbh._dbus_mainloop.run()

    log.info('Thread terminates')


class DBusHandler:
    """A thread for handling D-Bus signals."""

    def __init__(self):
        log.debug('Init handler')

        threads_init()
        self._loop = DBusGMainLoop(set_as_default=True)

        self._dbus_mainloop = GLib.MainLoop()

        self._dbus_thread = threading.Thread(name='D-Bus worker',
                                             target=_dbus_worker,
                                             args=(self,))
        log.debug('Start thread ' + str(self._dbus_thread))
        self._dbus_thread.start()

    def stop(self):
        """Stop the D-Bus main loop and worker thread."""
        if not self._dbus_mainloop:
            log.warning('Cannot stop D-Bus, already stopped')
            return

        self._dbus_mainloop.quit()
        self._dbus_mainloop = None
        self._dbus_thread = None
        self._loop = None


class Bus(dbus.bus.BusConnection):
    """The D-Bus instance. We always use this one.

    We must use this class derived from :class:`dbus.bus.BusConnection` because
    there is no way for telling the regular D-Bus classes defined in the
    :mod:`dbus` module how to connect with our D-Bus daemon.

    This, and we also need a thread for receiving and processing D-Bus signals.
    Such a thread is managed by a :class:`DBusHandler` object, which is created
    as a member of our :class:`Bus` class. On :meth:`close()`, this thread is
    stopped as well.
    """

    _shared_instance = None
    _dbus_handler = None

    def __new__(cls, private=False, mainloop=None):
        if not private and cls._shared_instance:
            return cls._shared_instance

        if not cls._shared_instance:
            Bus._dbus_handler = DBusHandler()

        bus = dbus.bus.BusConnection.__new__(Bus,
                                             'unix:path=/tmp/strbo_bus_socket',
                                             mainloop=mainloop)
        bus._bus_name = None

        if not private:
            cls._shared_instance = bus

        return bus

    def close(self):
        """Shut down D-Bus."""
        self._bus_name = None
        if Bus._shared_instance is self:
            Bus._shared_instance = None
        super(Bus, self).close()

        Bus._dbus_handler.stop()

    def register_bus_name(self, name):
        self._bus_name = dbus.service.BusName(name, self)

    def __repr__(self):
        return '<%s.%s (StrBo) at %#x>' % (Bus.__module__, Bus.__name__,
                                           id(self))

    __str__ = __repr__


class ProxyWithInterfaces:
    def __init__(self, bus_name, object_path):
        self.proxy = Bus().get_object(bus_name, object_path,
                                      follow_name_owner_changes=True)
        self.interfaces = {}

    def get_interface(self, iface_name):
        iface = self.interfaces.get(iface_name, None)

        if not iface:
            iface = dbus.Interface(self.proxy, dbus_interface=iface_name)

            if iface:
                self.interfaces[iface_name] = iface

        return iface


class InterfaceCache:
    """Cache of proxies to D-Bus objects.

    Creating proxies to D-Bus objects always triggers D-Bus introspection,
    enabling the :mod:`dbus` module to generate callable functions based on
    exported D-Bus interfaces. This is a great feature to have, but it implies
    that creating a new proxy is a quite expensive operation, plus constant
    introspection makes D-Bus monitoring harder than necessary. Therefore, we
    strive to minimize the amount of proxy creation by caching them.
    """

    def __init__(self):
        self.proxies_with_interfaces = {}

    def _get_proxy_with_interfaces(self, bus_name, object_path):
        pwi = self.proxies_with_interfaces.get((bus_name, object_path), None)

        if not pwi:
            pwi = ProxyWithInterfaces(bus_name, object_path)

            if pwi:
                self.proxies_with_interfaces[(bus_name, object_path)] = pwi

        return pwi

    def get_interface(self, bus_name, object_path, iface_name):
        """Lookup existing or create new proxy to object.

        Any newly created proxy instance is stored in the cache.
        """
        proxy = self._get_proxy_with_interfaces(bus_name, object_path)
        if not proxy:
            raise RuntimeError('No D-Bus proxy for object {} at {}'
                               .format(object_path, bus_name))

        result = proxy.get_interface(iface_name)
        if not result:
            raise RuntimeError('No D-Bus interface {} on object {} at {}'
                               .format(iface_name, object_path, bus_name))

        return result

    def remove_proxy(self, bus_name, object_path):
        """Remove proxy to object at given path `object_path` on connection
        with given bus name `bus_name`.

        Use this function to remove temporary or defunct proxies from the
        cache."""
        del self.proxies_with_interfaces[(bus_name, object_path)]


class Interfaces:
    """Collection of convenience functions for retrieval of specific D-Bus
    objects.

    The objects returned by these functions are cached in an
    :class:`InterfaceCache` object.
    """

    _cache = InterfaceCache()

    @staticmethod
    def airable():
        """Proxy to Airable list broker (``de.tahifi.Airable``)."""
        return Interfaces._cache.get_interface('de.tahifi.TuneInBroker',
                                               '/de/tahifi/TuneInBroker',
                                               'de.tahifi.Airable')

    @staticmethod
    def credentials_read():
        """Proxy to Airable list broker (``de.tahifi.Credentials.Read``)."""
        return Interfaces._cache.get_interface('de.tahifi.TuneInBroker',
                                               '/de/tahifi/TuneInBroker',
                                               'de.tahifi.Credentials.Read')

    @staticmethod
    def credentials_write():
        """Proxy to Airable list broker (``de.tahifi.Credentials.Write``)."""
        return Interfaces._cache.get_interface('de.tahifi.TuneInBroker',
                                               '/de/tahifi/TuneInBroker',
                                               'de.tahifi.Credentials.Write')

    @staticmethod
    def dcpd_network():
        """Proxy to DCPD networking facilities (``de.tahifi.Dcpd.Network``)."""
        return Interfaces._cache.get_interface('de.tahifi.Dcpd',
                                               '/de/tahifi/Dcpd',
                                               'de.tahifi.Dcpd.Network')

    @staticmethod
    def mounta():
        """Proxy to MounTA (``de.tahifi.MounTA``)."""
        return Interfaces._cache.get_interface('de.tahifi.MounTA',
                                               '/de/tahifi/MounTA',
                                               'de.tahifi.MounTA')

    @staticmethod
    def streamplayer_urlfifo():
        """Proxy to Streamplayer (``de.tahifi.Streamplayer.URLFIFO``)."""
        return Interfaces._cache.get_interface(
            'de.tahifi.Streamplayer', '/de/tahifi/Streamplayer',
            'de.tahifi.Streamplayer.URLFIFO')

    @staticmethod
    def streamplayer_playback():
        """Proxy to Streamplayer (``de.tahifi.Streamplayer.Playback``)."""
        return Interfaces._cache.get_interface(
            'de.tahifi.Streamplayer', '/de/tahifi/Streamplayer',
            'de.tahifi.Streamplayer.Playback')
