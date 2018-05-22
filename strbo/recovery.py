#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from pathlib import Path, PurePath
from hashlib import sha256
from time import time
from threading import RLock

from .utils import try_mount_partition, MountResult
from .utils import try_unmount_partition, UnmountResult

def generate_file_info(file, checksums):
    expected = 'unavailable' if not checksums or file.name not in checksums else checksums[file.name]

    fi = {
        'name': file.name,
        'expected_checksum': expected
    }

    h = sha256()

    if file.exists():
        with file.open('rb') as f:
            while True:
                data = f.read(512 * 1024)

                if not data:
                    break

                h.update(data)

        computed = h.hexdigest()
    else:
        computed = 'file missing'

    if expected != computed:
        fi['computed_checksum'] = computed

    fi['is_valid'] = expected == computed

    return fi

def get_info_and_verify(request, mountpoint, **values):
    p = mountpoint / 'images'
    mount_result = try_mount_partition(mountpoint)
    version_info = None
    fileset = None

    if mount_result is MountResult.ALREADY_MOUNTED:
        overall_valid_state = 'locked'
    elif mount_result is MountResult.MOUNTED:
        temp = p / 'SHA256SUMS'
        checksums = None
        if temp.exists() and temp.is_file():
            with temp.open() as f:
                checksums = {}
                for l in f:
                    checksum, filename = re.split(r' +', l.strip())
                    checksums[filename] = checksum

        temp = p / 'version.txt'
        version_file = None
        if temp.exists() and temp.is_file():
            with temp.open() as f:
                version_file = f.readlines()

        if version_file and len(version_file) == 3:
            version_info = {
                'number':    version_file[0].strip(),
                'timestamp': version_file[1].strip(),
                'commit_id': version_file[2].strip(),
            }

        fileset = []
        fileset.append(generate_file_info(temp, checksums))

        for temp in sorted(p.glob('*.bin')):
            fileset.append(generate_file_info(temp, checksums))

        overall_valid_state = 'valid' if all([f['is_valid'] for f in fileset]) else 'broken'
    else:
        overall_valid_state = 'unavailable'

    return version_info, {
               'recovery_files': fileset,
               'state': overall_valid_state
           }

def verify_wrapper(request, **values):
    mountpoint = Path('/mnt')

    try:
        version_info, status = get_info_and_verify(request, mountpoint, **values)
    except:
        try_unmount_partition(mountpoint)
        raise

    try_unmount_partition(mountpoint)

    return version_info, status


import halogen

from .endpoint import Endpoint
from .utils import jsonify

class Status(Endpoint):
    """API Endpoint: Read out status of the recovery system data."""
    class Schema(halogen.Schema):
        self = halogen.Link(attr = 'href')
        version_info = halogen.Attr()
        status = halogen.Attr()
        age = halogen.Attr(attr = lambda value: value.get_age())

    href = '/recovery/status'
    methods = ('GET',)
    lock = RLock()

    version_info = None
    status = None
    timestamp = None

    def __init__(self):
        Endpoint.__init__(self, 'recovery_system_info', 'Status of the recovery system data')

    def __call__(self, request, **values):
        with self.lock:
            return jsonify(request, Status.Schema.serialize(self))

    def set(self, version_info, status):
        with self.lock:
            self.version_info = version_info
            self.status = status
            self.timestamp = time()

    def get_age(self):
        return time() - self.timestamp if self.timestamp else None

class Verify(Endpoint):
    """API Endpoint: Verify the recovery system data.

    Method ``GET``: Read out state of the verification process.

    Method ``POST``: Start verification process. Data is returned after the
    verification has been performed, which will usually take a few seconds.
    Simultaneous ``POST`` requests are blocked, and there is a rate limit of
    one verification request per three seconds.
    """
    class Schema(halogen.Schema):
        self = halogen.Link(attr = 'href')
        state = halogen.Attr(attr = lambda value: value.get_state_string())

    href =  '/recovery/verify'
    methods = ('GET', 'POST')
    lock = RLock()

    def __init__(self, status):
        Endpoint.__init__(self, 'recovery_system_verify', 'Verification of recovery system data')
        self.status = status
        self.processing = False
        self.failed = False

    def __call__(self, request, **values):
        with self.lock:
            if request.method == 'GET' or self.processing or self.rate_limit():
                return jsonify(request, Verify.Schema.serialize(self))

            self.processing = True
            self.failed = False

        # this section is protected by self.processing
        try:
            failed = False
            inf, st = verify_wrapper(request, **values)
        except Exception as e:
            failed = True
            inf = None
            st = None

        with self.lock:
            self.status.set(inf, st)
            self.processing = False
            self.failed = failed
            return jsonify(request, Verify.Schema.serialize(self))

    def rate_limit(self):
        if self.status:
            age = self.status.get_age();

            if age and age < 3:
                return True

        return False

    def get_state_string(self):
        if self.processing:
            return 'verifying'
        elif self.failed:
            return 'failed'
        else:
            return 'idle'

status_endpoint = Status()
all_endpoints = [status_endpoint, Verify(status_endpoint)]

def add_endpoints():
    from .endpoint import register_endpoints
    register_endpoints(all_endpoints)
