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


import pathlib


class Device:
    def __init__(self, mounta_id, name, rootpath):
        self.mounta_id = int(mounta_id)
        self.name = str(name)
        self.rootpath = str(rootpath)
        self.uuid = 'TODO-DEVICE-UUID-{}'.format(mounta_id)
        self.partition_uuids = []


class Partition:
    def __init__(self, part_number, mounta_device_id, name, mountpoint):
        self.part_number = int(part_number)
        self.mounta_device_id = int(mounta_device_id)
        self.name = str(name)
        self.mountpoint = pathlib.Path(mountpoint)
        self.uuid = 'TODO-PARTITION-UUID-{}-{}' \
                    .format(mounta_device_id, part_number)
        self.device_uuid = None


class DevicesAndPartitions:
    def __init__(self):
        self.clear()

    def clear(self):
        self._devices = {}
        self._partitions = {}

    def add_partition(self, p):
        if p.mounta_device_id not in self._partitions:
            self._partitions[p.mounta_device_id] = {p.part_number: p}
        else:
            self._partitions[p.mounta_device_id][p.part_number] = p

        if p.mounta_device_id in self._devices:
            dev = self._devices[p.mounta_device_id]
            p.device_uuid = dev.uuid
            dev.partition_uuids.append(p.uuid)

    def add_device(self, device):
        if device.mounta_id in self._partitions:
            for p in self._partitions[device.mounta_id]:
                p.device_uuid = device.uuid
                device.partitions_uuids.append(p.uuid)

        self._devices[device.mounta_id] = device

    def remove_device(self, id):
        self._devices.pop(id, None)
        self._partitions.pop(id, None)

    def get_devices(self):
        return self._devices

    def get_partitions(self):
        return self._partitions
