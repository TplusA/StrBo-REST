#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2021  T+A elektroakustik GmbH & Co. KG
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
import halogen

from .endpoint import Endpoint, register_endpoints, register_endpoint
from .utils import jsonify, jsonify_error
from .utils import get_logger
import strbo.dbus
import strbo.usb
import dbus.exceptions
log = get_logger()


class AudioSourceSchemaShort(halogen.Schema):
    """Short representation of :class:`AudioSource`."""

    #: Link to self.
    self = halogen.Link(attr=lambda value: '/sources/' + value.id)

    #: ID of the audio service
    id = halogen.Attr()


class AudioSourceSchema(halogen.Schema):
    """Short representation of :class:`AudioSource`."""

    #: Link to self.
    self = halogen.Link(attr=lambda value: '/sources/' + value.id)

    #: ID of the audio service
    id = halogen.Attr()

    #: List of browsable lists
    lists = halogen.Attr()


class AudioSource(Endpoint):
    #: Path to endpoint.
    href = '/sources/{id}'
    href_for_map = '/sources/<id>'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    #: List of browsable lists
    lists = []

    def __init__(self, id):
        Endpoint.__init__(self, 'audio_source',
                          name='audio_source',
                          title='Information about a specific audio source')
        self.id = id

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False

    def __call__(self, request, id, **values):
        return jsonify(request, AudioSourceSchema.serialize(self))


class USBDeviceSchema(halogen.Schema):
    name = halogen.Attr()
    partitions = halogen.Attr(attr=lambda value: value.partition_uuids)


class USBPartitionSchema(halogen.Schema):
    name = halogen.Attr()
    device = halogen.Attr(attr=lambda value: value.device_uuid)


class USBAudioSourceSchema(halogen.Schema):
    """Short representation of :class:`AudioSource`."""

    #: Link to self.
    self = halogen.Link(attr=lambda value: '/sources/' + value.id)

    #: ID of the audio service
    id = halogen.Attr()

    #: List of browsable lists
    lists = halogen.Attr()

    #: List of USB devices
    devices = halogen.Attr(
            attr=lambda value: {
                d.uuid: USBDeviceSchema.serialize(d)
                for d in value.get_all_devices().values()
            })

    #: List of all partitions across all devices
    partitions = halogen.Attr(
            attr=lambda value: {
                p.uuid: USBPartitionSchema.serialize(p)
                for p in value.get_all_partitions().values()
            })


class USBAudioSource(AudioSource):
    def __init__(self):
        super().__init__('strbo.usb')
        self._devices_and_partitions = strbo.usb.DevicesAndPartitions()
        register_endpoint(self)

    def __call__(self, request, id, **values):
        with self.lock:
            devs = None
            self._devices_and_partitions.clear()

            try:
                iface = strbo.dbus.Interfaces.mounta()
                devs = iface.GetAll()
            except dbus.exceptions.DBusException as e:
                return jsonify_error(
                            request, log, True, 500,
                            'Exception [MounTA]: ' + e.get_dbus_message(),
                            error='mounta')

            for d in devs[0]:
                dev = strbo.usb.Device(d[0], d[1], d[2])
                self._devices_and_partitions.add_device(dev)

            for p in devs[1]:
                part = strbo.usb.Partition(p[0], p[3], p[1], p[2])
                self._devices_and_partitions.add_partition(part)

            return jsonify(request, USBAudioSourceSchema.serialize(self))

    def get_all_devices(self):
        return {
            dev.uuid: dev
            for dev in self._devices_and_partitions.get_devices().values()
        }

    def get_all_partitions(self):
        return {
            part.uuid: part
            for parts in self._devices_and_partitions.get_partitions().values()
            for part in parts.values()
        }


class AudioSourcesSchema(halogen.Schema):
    """Representation of :class:`AudioSources`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: List of audio source links
    sources = halogen.Embedded(
        halogen.types.List(AudioSourceSchemaShort),
        attr=lambda value: value._all_audio_sources
    )


class AudioSources(Endpoint):
    #: Path to endpoint.
    href = '/sources'

    #: Supported HTTP methods.
    methods = ('GET',)

    _all_audio_sources = None

    def __init__(self):
        Endpoint.__init__(self, 'audio_sources', name='audio_sources',
                          title='List of Streaming Board audio sources')
        self._all_audio_sources = [USBAudioSource()]

    def __call__(self, request, **values):
        return jsonify(request, AudioSourcesSchema.serialize(self))


audio_sources_endpoint = AudioSources()
all_endpoints = [
    audio_sources_endpoint,
]


def add_endpoints():
    """Register all endpoints defined in this module."""
    register_endpoints(all_endpoints)
