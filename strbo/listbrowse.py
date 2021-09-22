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
from werkzeug.wrappers import Response
import halogen
import urllib.parse

from .endpoint import Endpoint, register_endpoints, register_endpoint
from .endpoint import url_for
from .utils import jsonify, jsonify_error
from .utils import if_none_match
from .utils import get_logger
from . import get_monitor
import strbo.dbus
import strbo.usb
import strbo.rest
import dbus.exceptions
log = get_logger()


class AudioSourceSchemaShort(halogen.Schema):
    """Short representation of :class:`AudioSource`."""

    #: Link to self.
    self = halogen.Link(attr=lambda value: '/sources/' + value.id)

    #: ID of the audio service
    id = halogen.Attr()

    #: Description of the audio source
    title = halogen.Attr()


class AudioSourceSchema(halogen.Schema):
    """Representation of :class:`AudioSource`."""

    #: Link to self.
    self = halogen.Link(attr=lambda value: '/sources/' + value.id)

    #: ID of the audio source
    id = halogen.Attr()

    #: Description of the audio source
    title = halogen.Attr()

    #: List of browsable lists
    lists = halogen.Attr(required=False)


class AudioSource(Endpoint):
    """**API Endpoint** - Information about one audio source.

    +-------------+----------------------------------------------------------+
    | HTTP method | Description                                              |
    +=============+==========================================================+
    | ``GET``     | Read out generic audio source information using schema   |
    |             | :class:`AudioSourceSchema`.                              |
    +-------------+----------------------------------------------------------+
    """

    #: Path to endpoint.
    href = '/sources/{id}'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    def __init__(self, id, endpoint_title, endpoint_id, *, auto_register=True,
                 is_browsable=True):
        super().__init__(endpoint_id, name=endpoint_id, title=endpoint_title)
        self.id = id

        if is_browsable:
            #: List of browsable lists
            self.lists = []

        if auto_register:
            register_endpoint(self)

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False

    def __call__(self, request, **values):
        return jsonify(request, AudioSourceSchema.serialize(self))


class USBDeviceSchema(halogen.Schema):
    """Representation of :class:`strbo.usb.Device`."""

    #: Name of the USB device.
    name = halogen.Attr()

    #: List of partitions on the USB device.
    partitions = halogen.Attr(attr=lambda value: value.partition_uuids)

    #: Flag which is ``True`` if the device UUID is known to be unstable. A
    # flaky UUID shall not be stored and thus cannot be used for reliable
    # device recognition.
    flaky_uuid = \
        halogen.Attr(attr=lambda value: value.uuid.startswith('DO-NOT-STORE:'))


class USBPartitionSchema(halogen.Schema):
    """Representation of :class:`strbo.usb.Partition`."""

    #: Name of the USB partition.
    name = halogen.Attr()

    #: Device the USB partition is stored on.
    device = halogen.Attr(attr=lambda value: value.device_uuid)

    #: Link to USB partition content.
    browse_href = \
        halogen.Attr(attr=lambda value: '/browse/usbfs/' + value.uuid + '/')

    #: Flag which is ``True`` if the partition UUID is known to be unstable. A
    # flaky UUID shall not be stored and thus cannot be used for reliable
    # partition recognition.
    flaky_uuid = \
        halogen.Attr(attr=lambda value: value.uuid.startswith('DO-NOT-STORE:'))


class USBAudioSourceSchema(halogen.Schema):
    """Short representation of :class:`AudioSource`."""

    #: Link to self.
    self = halogen.Link(attr=lambda value: '/sources/' + value.id)

    #: ID of the audio source
    id = halogen.Attr()

    #: Description of the audio source
    title = halogen.Attr()

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
    """**API Endpoint** - USB file system audio source.

    +-------------+----------------------------------------------------------+
    | HTTP method | Description                                              |
    +=============+==========================================================+
    | ``GET``     | Read out information about USB audio source using schema |
    |             | :class:`USBAudioSourceSchema`.                           |
    +-------------+----------------------------------------------------------+
    """

    def __init__(self, audio_source_id, description):
        super().__init__(audio_source_id, description, 'audio_source_usb',
                         auto_register=False)
        self._devices_and_partitions = strbo.usb.DevicesAndPartitions()
        register_endpoint(self)

    def __call__(self, request, **values):
        with self.lock:
            try:
                cached = if_none_match(request,
                                       self._devices_and_partitions.get_etag())
            except dbus.exceptions.DBusException as e:
                return jsonify_error(
                            request, log, True, 500,
                            'Exception [MounTA]: ' + e.get_dbus_message(),
                            error='mounta')

            if cached:
                return cached

            return jsonify(request, USBAudioSourceSchema.serialize(self))

    def get_all_devices(self):
        """Get all known USB devices."""
        with self.lock:
            return {
                dev.uuid: dev
                for dev in self._devices_and_partitions.get_devices().values()
            }

    def get_all_partitions(self):
        """Get all known USB partitions."""
        with self.lock:
            return {
                part.uuid: part
                for parts in
                self._devices_and_partitions.get_partitions().values()
                for part in parts.values()
            }

    def get_device_uuid_for_mounta_id(self, id):
        """Get UUID of the USB device referred to by MounTA ID."""
        with self.lock:
            dev = self._devices_and_partitions \
                                    .get_devices_as_stored().get(id, None)
            return dev.uuid if dev else None

    def invalidate(self):
        """Mark this object as modified so that the next ``GET`` returns a
        fresh object not from cache."""
        with self.lock:
            self._devices_and_partitions.invalidate()


class AudioSourcesSchema(halogen.Schema):
    """Representation of :class:`AudioSources`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: List of audio source links
    sources = halogen.Embedded(
        halogen.types.List(AudioSourceSchemaShort),
        attr=lambda value: value._all_audio_sources.values()
    )


class AudioSources(Endpoint):
    """**API Endpoint** - List of audio sources.

    +-------------+----------------------------------------------------------+
    | HTTP method | Description                                              |
    +=============+==========================================================+
    | ``GET``     | Read out audio source information, either a list of all  |
    |             | known audio sources using :class:`AudioSourcesSchema`,   |
    |             | or one specified by an audio source ID.                  |
    +-------------+----------------------------------------------------------+

    Read out ``/sources`` to get a full list, read out ``/sources/<id>`` to get
    information for the audio source with ID ``<id>``.
    """

    #: Path to endpoint.
    href = '/sources'
    href_for_map = [
        '/sources',
        '/sources/<id>'
    ]

    #: Supported HTTP methods.
    methods = ('GET',)

    def __init__(self):
        super().__init__('audio_sources', name='audio_sources',
                         title='List of Streaming Board audio sources')
        self._all_audio_sources = {}

    def __call__(self, request, **values):
        source_id = values.get('id', None)
        if source_id is None:
            return jsonify(request, AudioSourcesSchema.serialize(self))

        src = self._all_audio_sources.get(source_id, None)
        return \
            src(request, **values) if src is not None else Response(status=404)

    def get_usb_audio_source(self):
        """Return the USB audio source object."""
        return self._all_audio_sources.get('strbo.usb', None)

    def add_audio_source(self, source_id, source_name):
        """Add some audio source to the container.

        This method generates an object of class :class:`AudioSource` or one of
        its derived classes, depending on `source_id`.
        """
        if source_id == 'strbo.usb':
            self._all_audio_sources[source_id] = \
                USBAudioSource(source_id, source_name)
        else:
            is_browsable = \
                source_id not in ('roon', 'strbo.plainurl', 'strbo.rest')
            api_id = 'audio_source_' + source_id.replace('.', '_')
            self._all_audio_sources[source_id] = \
                AudioSource(source_id, source_name, api_id,
                            is_browsable=is_browsable)


class ListBrowsersSchema(halogen.Schema):
    """Representation of :class:`ListBrowsers`."""

    #: Link to self.
    self = halogen.Link(attr='href')


class ListBrowser(Endpoint):
    """Base class for list browsers."""
    def __init__(self, name, title, list_browsers_endpoint):
        super().__init__('list_browser', name=name, title=title)
        self.lock = RLock()
        self.list_browsers_endpoint = list_browsers_endpoint

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False


def _get_offset_and_page_and_maximum_size(args):
    size = args.get('size', None)
    page = args.get('page', 0)

    if size is None:
        return 0, None, None

    try:
        size = int(size)
        page = int(page)
    except:  # noqa: E722
        return None, -1, -1

    if size < 0 or page < 0:
        return None, -1, -1

    # offset, page number, maximum size of a page
    return page * size, page, size


class ListBrowserUSBFS(ListBrowser):
    """**API Endpoint** - USB file system browsing.

    +-------------+----------------------------------------------------------+
    | HTTP method | Description                                              |
    +=============+==========================================================+
    | ``GET``     | Read out USB partition contents.                         |
    +-------------+----------------------------------------------------------+

    Pagination is controlled via URL parameters.

    There are two parameters to control the pagination, ``page`` and ``size``.
    The ``size`` parameter sets the desired page size, and the ``page``
    parameter asks for the corresponding page of the specified size. The last
    page may contain fewer items than ``size``, and pages requested beyond the
    last page will be empty.

    If the ``size`` parameter is not set, then the ``page`` parameter will be
    ignored (the full list will be returned in this case). The first page is
    page 0, which is also the default value in case the ``page`` parameter is
    not set.

    As an example, parameters ``?size=5&page=0`` cause the ``GET`` request to
    return the first five items from the requested list, and ``?size=6&page=4``
    returns items 24 through 29 (first item has index 0).

    List contents are returned as JSON object. The ``meta`` entry in that
    object always contains fields ``offset`` and ``total_size``. The ``offset``
    is the index of the first item in the full list, and ``total_size`` is the
    number of items in the full list. In addition, in case pagination
    parameters were set in the request, these are repeated in the ``meta``
    entry to make the returned JSON object more self-contained.
    """

    #: Path to endpoint.
    href = '/browse/usbfs/{partition}/{path}'
    href_for_map = [
        '/browse/usbfs/<partition>/',
        '/browse/usbfs/<partition>/<path:path>',
    ]

    #: Supported HTTP methods.
    methods = ('GET', )

    def __init__(self, list_browsers_endpoint):
        super().__init__('usbfs_list_browser',
                         'List of USB mass storage devices',
                         list_browsers_endpoint)

    def __call__(self, request, partition, path='', **values):
        with self.lock:
            return self._do_call_unlocked(request, partition, path, **values)

    def _do_call_unlocked(self, request, partition, path='', **values):
        list_offset, list_page, list_maxsize = \
            _get_offset_and_page_and_maximum_size(request.args)

        if list_offset is None:
            return jsonify_error(request, log, False, 400,
                                 'Invalid pagination parameters',
                                 error='usbfs')

        def get_items_and_meta():
            if list_maxsize is None or list_maxsize > 0:
                items = sorted(real_path.glob('*'))
                meta = {
                    'total_size': len(items),
                    'offset': list_offset,
                }

                if list_maxsize is not None:
                    items = items[list_offset:list_offset + list_maxsize]
                    meta['page'] = list_page
                    meta['size'] = list_maxsize
            else:
                items = None
                meta = {'total_size': len(list(real_path.glob('*')))}

            return items, meta

        def get_item_info_object(file):
            relpath = file.relative_to(part.mountpoint)
            href = url_for(request, self, {
                               'partition': partition,
                               'path': str(relpath)
                           })
            obj = {'name': file.name, 'href': href}

            if file.is_file():
                obj['type'] = 'file'
                obj['playurl'] = urllib.parse.urlunparse((
                    'strbo-usb', '',
                    urllib.parse.quote('/{}/{}'.format(partition, relpath)),
                    None, None, None
                ))
            elif file.is_dir():
                obj['type'] = 'dir'

            return obj

        def get_items_from_usb_directory():
            result = []

            for it in items:
                result.append(get_item_info_object(it))

            return result

        part, real_path = self._get_partition_and_real_path(partition, path)

        if not real_path or not real_path.exists():
            return jsonify_error(request, log, False, 404,
                                 'Does not exist', error='usbfs')

        if real_path.is_file():
            if strbo.utils.request_accepts_json(request):
                return jsonify(request, get_item_info_object(real_path))
            else:
                response = strbo.rest.FileResponse(status=200)

                if request.range is None:
                    response.data = real_path.read_bytes()
                else:
                    barr = bytearray()
                    with real_path.open('rb') as f:
                        for r in request.range.ranges:
                            f.seek(r[0])
                            barr += bytearray(f.read(r[1] - r[0]))

                    response.data = bytes(barr)

                return response

        if not real_path.is_dir():
            return jsonify_error(request, log, False, 403,
                                 'Unsupported file type', error='usbfs')

        items, meta = get_items_and_meta()
        result = {'meta': meta}

        if items is not None:
            result['items'] = get_items_from_usb_directory()

        return jsonify(request, result)

    def _get_partition_and_real_path(self, partition, path):
        usb = \
            self.list_browsers_endpoint.audio_sources_ep.get_usb_audio_source()
        part = usb.get_all_partitions().get(partition)
        real_path = part.mountpoint / path if part else None
        return part, real_path

    def add_new_usb_device(self, id, devname, uuid, rootpath, usbport):
        """Insert new USB device which may contain browsable partitions.

        This method is called in D-Bus context when MounTA announces a new USB
        mass storage device.
        """
        with self.lock:
            src = self.list_browsers_endpoint.audio_sources_ep \
                                                    .get_usb_audio_source()
            src.invalidate()
            self._all_lists_etag = None
            get_monitor().send_event('new_usb_device',
                                     {'id': src.id, 'uuid': uuid}, ep=src)

    def remove_usb_device(self, id, uuid, rootpath):
        """Remove USB device, and thus all of its partitions.

        This method is called in D-Bus context when MounTA tells us that a USB
        mass storage device has been removed.
        """
        with self.lock:
            src = self.list_browsers_endpoint.audio_sources_ep \
                                                    .get_usb_audio_source()
            src.invalidate()
            self._all_lists_etag = None
            get_monitor().send_event('removed_usb_device',
                                     {'id': src.id, 'uuid': uuid}, ep=src)

    def add_new_usb_partition(self, number, label, mountpoint,
                              parent_id, uuid):
        """Insert new USB partition.

        This method is called in D-Bus context when MounTA announces a new USB
        partition.
        """
        with self.lock:
            self.list_browsers_endpoint.audio_sources_ep \
                                        .get_usb_audio_source().invalidate()
            self._all_lists_etag = None
            get_monitor().send_event('new_usb_partition',
                                     {'partition': uuid, 'path': ''}, ep=self)


class _AllLists:
    def __init__(self):
        self.lock = RLock()
        self.list_urls = []

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False

    def __iter__(self):
        return iter(self._list_urls)


class ListBrowsers(Endpoint):
    """**API Endpoint** - Collection of list browsers."""

    href = '/browse'
    methods = ('GET', )
    lock = RLock()
    _all_lists = None
    _all_lists_etag = None

    def __init__(self, audio_sources_ep):
        super().__init__('list_browsers', name='list_browsers', title='Lists')
        self.audio_sources_ep = audio_sources_ep
        self.usb_browser_ep = ListBrowserUSBFS(self)

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()
        return False

    def __call__(self, request, **values):
        with self.lock:
            cached = if_none_match(request, self.get_etag())
            if cached:
                return cached

            self._refresh()
            return jsonify(request, ListBrowsersSchema.serialize(self))

    def _refresh(self):
        self._all_lists = _AllLists()
        self._all_lists_etag = None

    def get_etag(self):
        return self._all_lists_etag


audio_sources_endpoint = AudioSources()
list_browsers_endpoint = ListBrowsers(audio_sources_endpoint)
all_endpoints = [
    audio_sources_endpoint,
    list_browsers_endpoint, list_browsers_endpoint.usb_browser_ep,
]


def signal__new_usb_device(id, devname, uuid, rootpath, usbport):
    """D-Bus signal handler: New USB device added."""
    with list_browsers_endpoint as ep:
        with ep.usb_browser_ep as usb:
            usb.add_new_usb_device(id, devname, uuid, rootpath, usbport)


def signal__new_volume(number, label, mountpoint, parent_id, uuid):
    """D-Bus signal handler: New USB partition added."""
    with list_browsers_endpoint as ep:
        with ep.usb_browser_ep as usb:
            usb.add_new_usb_partition(number, label, mountpoint,
                                      parent_id, uuid)


def signal__device_removed(id, uuid, rootpath):
    """D-Bus signal handler: USB device removed."""
    with list_browsers_endpoint as ep:
        with ep.usb_browser_ep as usb:
            usb.remove_usb_device(id, uuid, rootpath)


def add_endpoints():
    """Register all endpoints defined in this module."""
    register_endpoints(all_endpoints)

    iface = strbo.dbus.Interfaces.mounta()
    iface.connect_to_signal('NewUSBDevice', signal__new_usb_device)
    iface.connect_to_signal('NewVolume', signal__new_volume)
    iface.connect_to_signal('DeviceRemoved', signal__device_removed)

    iface = strbo.dbus.Interfaces.audio_path_manager()

    usable, incomplete = iface.GetPaths()
    if incomplete:
        log.warning('TODO: Have incomplete audio paths, '
                    'need to check back later')

    def put_audio_source(source_id):
        if source_id:
            source_name, _, _, _ = iface.GetSourceInfo(source_id)
            audio_sources_endpoint.add_audio_source(source_id, source_name)

    for p in usable:
        put_audio_source(p[0])
    for p in incomplete:
        put_audio_source(p[0])
