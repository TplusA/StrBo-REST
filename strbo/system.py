#! /usr/bin/env python3 # -*- coding: utf-8 -*-

# Copyright (C) 2020  T+A elektroakustik GmbH & Co. KG
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

from threading import RLock
from werkzeug.wrappers import Response
from zlib import adler32
import halogen
import configparser

from .endpoint import Endpoint, register_endpoints
from .external import Files
from .utils import jsonify_e
from .utils import if_none_match
from .utils import get_logger
from .version import read_strbo_release_file
log = get_logger()


class DeviceSchema(halogen.Schema):
    """Representation of :class:`Device`."""

    #: Link to self.
    self = halogen.Link(attr=lambda value: '/system/devices/' + value.id)

    #: Device instance ID.
    id = halogen.Attr()

    #: Device ID.
    device_id = halogen.Attr()

    #: Human-readable description of device.
    description = halogen.Attr()

    #: Software version information, device-dependent format
    software_versions = halogen.Attr()


class DeviceSchemaShort(halogen.Schema):
    """Partial representation of :class:`Device`."""

    #: Link to self.
    self = halogen.Link(attr=lambda value: '/system/devices/' + value.id)

    #: Device instance ID.
    id = halogen.Attr()

    #: Device ID.
    device_id = halogen.Attr()


class Device:
    """Information about a T+A device."""

    def __init__(self, id, device_id, description, software_versions):
        self.id = id
        self.description = description
        self.device_id = device_id
        self.software_versions = software_versions


class DeviceInfo(Endpoint):
    """**API Endpoint** - Accessing a device connected to the system.

    +-------------+-------------------------------------------------+
    | HTTP method | Description                                     |
    +=============+=================================================+
    | ``GET``     | Read out information about music device `{id}`. |
    |             | See :class:`DeviceSchema`.                      |
    +-------------+-------------------------------------------------+

    To avoid issues with (lack of) locking, this class should not accessed
    directly, but through the :class:`Devices` class.
    """

    #: Path to endpoint.
    href = '/system/devices/{id}'
    href_for_map = '/system/devices/<id>'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    def __init__(self, devices):
        Endpoint.__init__(
            self, 'tahifi_device', name='device_info',
            title='Accessing a specific device in the T+A HiFi system'
        )

        self.devices = devices

    def __call__(self, request, id, **values):
        with self.lock:
            cached = if_none_match(request, self.devices.get_etag())
            if cached:
                return cached

            device = self.devices.get_device_by_id(id)

            if device is None:
                return jsonify_e(request, self.devices.get_etag(), 20, {})

            return jsonify_e(request, self.devices.get_etag(), 12 * 3600,
                             DeviceSchema.serialize(device))


class DevicesSchema(halogen.Schema):
    """Representation of :class:`Devices`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: Embedded list of :class:`Device` objects
    #: (see :class:`DeviceSchema`). Field may be missing.
    device_info = halogen.Embedded(
        halogen.types.List(DeviceSchema),
        attr=lambda value: [value.devices[id] for id in value.devices],
        required=False
    )


class DevicesSchemaShort(halogen.Schema):
    """Partial representation of :class:`Devices`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: Embedded list of partial :class:`Device` objects
    #: (see :class:`DeviceSchemaShort`). Field may be missing.
    device_info = halogen.Embedded(
        halogen.types.List(DeviceSchemaShort),
        attr=lambda value: [value.devices[id] for id in value.devices],
        required=False
    )


class Devices(Endpoint):
    """**API Endpoint** - Information about all devices connected to the T+A
    music system.

    +-------------+-------------------------------------------------------+
    | HTTP method | Description                                           |
    +=============+=======================================================+
    | ``GET``     | Retrieve list of devices. See :class:`DevicesSchema`. |
    +-------------+-------------------------------------------------------+

    Details on method ``GET``:
        TODO
    """

    #: Path to endpoint.
    href = '/system/devices'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    devices = None
    devices_etag = None

    _appliance_mapping = {
        'unknown': ('*** UNKNOWN DEVICE ***', None),
        'strbo': ('T+A Streaming Board Appliance', None),
        'R1000E': ('T+A R 1000 E', {
            'update': {'description': 'Update Package'},
            'main_bootloader': {'description': 'Application CPU Bootloader'},
            'main_application': {'description': 'Application CPU Main'},
            'dab_fm': {'description': 'DAB/FM Module'},
            'decoder': {'description': 'Decoder'},
            'bluetooth': {'description': 'Bluetooth Module'},
        }),
    }

    def __init__(self):
        Endpoint.__init__(
            self, 'system_devices', name='all_devices',
            title='List of all T+A devices connected to the system'
        )

        self.device_infos = DeviceInfo(self)

    def __call__(self, request=None, **values):
        with self.lock:
            cached = if_none_match(request, self.get_etag())
            if cached:
                return cached

            self._refresh()

            # we return ``self`` when being serialized as embedded object
            return self if request is None \
                else jsonify_e(request, self.get_etag(), 24 * 3600,
                               DevicesSchema.serialize(self))

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False

    def _clear(self):
        """Remove all devices. Called internally and from :class:`System`."""
        self.devices = None
        self.devices_etag = Devices._compute_etag(self.devices)

    def _refresh(self):
        """Reload all devices. Called internally and from :class:`System`."""
        self._clear()

        try:
            v = {'strbo': {'description': 'T+A Streaming Board'}}

            # add ourselves
            sr = read_strbo_release_file(Files.get('strbo-release'))
            if sr is not None:
                sv = v['strbo']
                sv['number'] = 'V' + sr.get_version_number(True)
                sv['release_line'] = sr.get_release_line()
                sv['flavor'] = sr.get_flavor()
                sv['timestamp'] = sr.get_time_stamp()
                sv['commit_id'] = sr.get_commit_id()

            # add the appliance we are living in
            cfg = configparser.ConfigParser()
            cfg.read(Files.get('appliance.ini'))
            try:
                device_id = cfg['appliance']['id']
            except KeyError:
                device_id = 'strbo'

            try:
                device_description, sw = Devices._appliance_mapping[device_id]
            except KeyError:
                device_description, sw = Devices._appliance_mapping['strbo']

            if sw:
                v.update(sw)

            # that's us
            this_device = Device('self', device_id, device_description, v)
            self.devices = {this_device.id: this_device}

            self.devices_etag = Devices._compute_etag(self.devices)
        except:  # noqa: E722
            log.error('Failed retrieving list of connected devices')
            self._clear()
            raise

    def get_device_by_id(self, id):
        """Return :class:`Device` object matching given `id`."""
        with self.lock:
            if self.devices is None:
                self._refresh()

            return None if self.devices is None \
                else self.devices.get(id, None)

    def get_etag(self):
        with self.lock:
            return self.devices_etag

    @staticmethod
    def _compute_etag(devices):
        i = 0
        etag = 1

        if devices:
            for k in sorted(devices.keys()):
                i += 1
                d = devices[k]
                temp = str(i) + k + d.id + d.description
                etag = adler32(bytes(temp, 'UTF-8'), etag)

        return "{:08x}".format(etag)


class SystemSchema(halogen.Schema):
    """Representation of :class:`System`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: Embedded list of partial :class:`Device` objects
    #: (see :class:`DeviceSchemaShort`).
    devices = halogen.Embedded(DevicesSchemaShort)


class System(Endpoint):
    """**API Endpoint** - Appliance global system information and management.

    +-------------+-----------------------------------------------------+
    | HTTP method | Description                                         |
    +=============+=====================================================+
    | ``GET``     | TODO                                                |
    +-------------+-----------------------------------------------------+

    Details on method ``GET``:
        TODO
    """

    #: Path to endpoint.
    href = '/system'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    devices = Devices()

    def __init__(self):
        Endpoint.__init__(self, 'hifi_system', title='T+A HiFi system')

    def __call__(self, request, **values):
        with self.lock:
            cached = if_none_match(request, self.get_etag())
            if cached:
                return cached

            self._refresh()
            return jsonify_e(request, self.get_etag(), 24 * 3600,
                             SystemSchema.serialize(self))

    def _clear(self):
        self.devices._clear()

    def _refresh(self):
        self._clear()

        try:
            self.devices._refresh()
        except:  # noqa: E722
            log.error('Failed refreshing system information')
            self._clear()
            raise

    def get_etag(self):
        with self.lock:
            return self.devices.get_etag()


system_endpoint = System()
all_endpoints = [
    system_endpoint, system_endpoint.devices,
    system_endpoint.devices.device_infos,
]

def add_endpoints():
    """Register all endpoints defined in this module."""
    register_endpoints(all_endpoints)
