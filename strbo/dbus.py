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

import dbus

from .utils import get_logger
log = get_logger('D-Bus')

def _dbus_worker(dbh):
    """The main function of the thread created in the :class:`DBusHandler`
    constructor."""
    if dbh._dbus_mainloop:
        log.info('Thread running')
        log.debug('Main loop ' + str(hex(dbh._dbus_mainloop)))
        dbh._glib_handle.g_main_loop_run(dbh._dbus_mainloop)

    log.info('Thread terminates')

class DBusHandler:
    """A thread for handling D-Bus signals."""
    def __init__(self):
        log.debug('Init handler')

        from dbus.mainloop.glib import DBusGMainLoop, threads_init
        threads_init()
        loop = DBusGMainLoop(set_as_default = True)

        import ctypes

        # So we need a GMainLoop from GLib...
        #
        # Since PyGObject ("gi") is a completely useless shitload of crapware
        # that cannot seriously be used in a cross-compilation environment, we
        # need other means of tapping into GLib. Fortunately, Python comes with
        # the ctypes package and thus provides a really good way for ad-hoc
        # incorporation of C library code. We simply load GLib by ourselves,
        # pull out the few symbols we need, and use them.
        #
        # Using RTLD_NOLOAD makes sure that the library is *not* actually
        # loaded, but instead the previously loaded instance is used, if any.
        # We should end up with a handle pointing to the library dynamically
        # linked by the lines above to set up dbus. If not, then there is a
        # general problem that we cannot solve here anyway; in this case, we'll
        # just run into an exception a few lines later and be done with it.
        from os import RTLD_NOLOAD
        glib = ctypes.CDLL('libglib-2.0.so.0',
                           mode = ctypes.RTLD_GLOBAL | RTLD_NOLOAD)

        log.debug('GLib handle: ' + str(glib))
        glib.g_main_loop_new.argtypes = [ctypes.c_void_p, ctypes.c_bool]
        glib.g_main_loop_new.restype = ctypes.c_void_p
        glib.g_main_loop_unref.argtypes = [ctypes.c_void_p]
        glib.g_main_loop_unref.restype = None
        glib.g_main_loop_run.argtypes = [ctypes.c_void_p]
        glib.g_main_loop_run.restype = None
        glib.g_main_loop_quit.argtypes = [ctypes.c_void_p]
        glib.g_main_loop_quit.restype = None
        self._glib_handle = glib
        self._dbus_mainloop = glib.g_main_loop_new(None, False)

        import threading
        self._dbus_thread = threading.Thread(name = 'D-Bus worker',
                                             target = _dbus_worker,
                                             args = (self,))
        log.debug('Start thread ' + str(self._dbus_thread))
        self._dbus_thread.start()

    def stop(self):
        """Stop the D-Bus main loop and worker thread."""
        if not self._dbus_mainloop:
            log.warning('Cannot stop D-Bus, already stopped')
            return

        self._glib_handle.g_main_loop_quit(self._dbus_mainloop)
        self._glib_handle.g_main_loop_unref(self._dbus_mainloop)
        self._dbus_mainloop = None
        self._dbus_thread = None

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

    def __new__(cls, private = False, mainloop = None):
        if not private and cls._shared_instance:
            return cls._shared_instance

        if not cls._shared_instance:
            Bus._dbus_handler = DBusHandler()

        bus = dbus.bus.BusConnection.__new__(Bus, 'unix:path=/tmp/strbo_bus_socket', mainloop = mainloop)

        if not private:
            cls._shared_instance = bus

        return bus

    def close(self):
        """Shut down D-Bus."""
        if Bus._shared_instance is self:
            Bus._shared_instance = None
        super(Bus, self).close()

        Bus._dbus_handler.stop()

    def __repr__(self):
        return '<%s.%s (StrBo) at %#x>' % (Bus.__module__, Bus.__name__, id(self))

    __str__ = __repr__

class ProxyWithInterfaces:
    def __init__(self, bus_name, object_path):
        self.proxy = Bus().get_object(bus_name, object_path, follow_name_owner_changes = True)
        self.interfaces = {}

    def get_interface(self, iface_name):
        iface = self.interfaces.get(iface_name, None)

        if not iface:
            iface = dbus.Interface(self.proxy, dbus_interface = iface_name)

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
        return self._get_proxy_with_interfaces(bus_name, object_path).get_interface(iface_name)

    def remove_proxy(self, bus_name, object_path):
        """Remove proxy to object at given path `object_path` on connection
        with given bus name `bus_name`.

        Use this function to remove temporary or defunct proxies from the
        cache."""
        del self.proxies_with_interfaces[(bus_name, object_path)]

class Interfaces:
    """Collection of convenience functions for retrieval of specific D-Bus
    objects.

    The objects returned by these functions are cached in an :class:`InterfaceCache` object.
    """
    _cache = InterfaceCache()

    @staticmethod
    def airable():
        """Proxy to Airable list broker (``de.tahifi.Airable``)."""
        return Interfaces._cache.get_interface('de.tahifi.TuneInBroker', '/de/tahifi/TuneInBroker',
                                               'de.tahifi.Airable')

    @staticmethod
    def credentials_read():
        """Proxy to Airable list broker (``de.tahifi.Credentials.Read``)."""
        return Interfaces._cache.get_interface('de.tahifi.TuneInBroker', '/de/tahifi/TuneInBroker',
                                               'de.tahifi.Credentials.Read')

    @staticmethod
    def credentials_write():
        """Proxy to Airable list broker (``de.tahifi.Credentials.Write``)."""
        return Interfaces._cache.get_interface('de.tahifi.TuneInBroker', '/de/tahifi/TuneInBroker',
                                               'de.tahifi.Credentials.Write')
