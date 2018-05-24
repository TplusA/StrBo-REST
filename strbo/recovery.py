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

from pathlib import Path, PurePath
from hashlib import sha256
from time import time
from threading import RLock

from .utils import try_mount_partition, MountResult
from .utils import try_unmount_partition, UnmountResult
from .utils import remove_directory

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

def get_info_and_verify(mountpoint, **values):
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
                    import re
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

def verify_wrapper(**values):
    mountpoint = Path('/mnt')

    try:
        version_info, status = get_info_and_verify(mountpoint, **values)
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
            inf, st = verify_wrapper(**values)
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

def get_data_file_from_form(request):
    f = request.files.get('datafile', None)

    if f and f.content_type != 'application/octet-stream':
        raise Exception('Unexpected content type')

    return f

def create_workdir():
    workdir = Path('/var/local/data/recovery_data_update')

    try:
        remove_directory(workdir, False)
    except:
        pass

    try:
        workdir.mkdir()
    except FileExistsError:
        pass

    return workdir

def replace_recovery_system_data(request, status):
    url_from_form = request.values.get('dataurl', None)

    if url_from_form:
        status.set_retrieving(url_from_form)
        file_from_form = None
    else:
        status.set_retrieving()
        file_from_form = get_data_file_from_form(request)

    workdir = create_workdir()
    gpgfile = workdir / 'recoverydata.gpg'
    payload = workdir / 'recoverydata'
    is_mounted = False

    try:
        if url_from_form:
            from urllib.request import urlopen
            from werkzeug.datastructures import FileStorage
            url = urlopen(url_from_form)
            f = FileStorage(url, gpgfile.name)
            f.save(str(gpgfile))
        elif file_from_form:
            file_from_form.save(str(gpgfile))
        else:
            raise Exception('No data file specified')

        status.set_step_name('verifying signature')
        import subprocess

        cmd = subprocess.Popen(['gpg',
                                '--homedir', str(gpgfile.parent),
                                '--keyring', '/usr/share/opkg/keyrings/key-93CD60C9.gpg',
                                str(gpgfile)],
                                cwd = str(gpgfile.parent))
        if cmd.wait(600) != 0:
            return jsonify(request, result = 'error', reason = 'invalid signature')

        status.set_step_name('verifying archive')
        cmd = subprocess.Popen(['tar', 'tf', str(payload)])
        if cmd.wait(150) != 0:
            return jsonify(request, result = 'error', reason = 'broken archive')

        status.set_step_name('extracting')
        mountpoint = Path('/mnt')
        mount_result = try_mount_partition(mountpoint, True)

        if mount_result is MountResult.MOUNTED:
            is_mounted = True

            imgdir = mountpoint / 'images'
            remove_directory(imgdir, False)

            cmd = subprocess.Popen(['tar', 'xf', str(payload)], cwd = str(imgdir))
            if cmd.wait(300) != 0:
                result = jsonify(request, result = 'error', reason = 'write error')
            else:
                result = jsonify(request, result = 'success', reason = 'super hero')
        elif mount_result is MountResult.ALREADY_MOUNTED:
            result = jsonify(request, result = 'error', reason = 'locked')
        elif mount_result is MountResult.FAILED:
            result = jsonify(request, result = 'error', reason = 'inaccessible')
        elif mount_result is MountResult.TIMEOUT:
            result = jsonify(request, result = 'error', reason = 'mount timeout')
        else:
            result = jsonify(request, result = 'error', reason = 'unknown')

        status.set_step_name('finalizing')
        try_unmount_partition(mountpoint)
        is_mounted = False

        remove_directory(workdir)

        return result
    except:
        if is_mounted:
            try_unmount_partition(mountpoint)

        remove_directory(workdir)

        raise

class Replace(Endpoint):
    """API Endpoint: Replace the recovery system data.

    Method ``GET``: Read out state of the replacement process.

    Method ``POST``: Start the replacement process. The recovery data archive
    is passed as form, either as download URL (``dataurl``) or as direct data
    stream (``datafile``). If both are passed, then ``dataurl`` is preferred
    and ``datafile`` gets ignored. The result is returned after the replacement
    has been performed. Simultaneous ``POST`` requests are blocked.
    """
    class Schema(halogen.Schema):
        self = halogen.Link(attr = 'href')
        state = halogen.Attr(attr = lambda value: value.get_state_string())
        origin = halogen.Attr(attr = lambda value: value.get_data_origin() if value.processing else value.does_not_exist(), required = False)

    href = '/recovery/replace'
    methods = ('GET', 'POST')
    lock = RLock()

    def __init__(self):
        Endpoint.__init__(self, 'recovery_system_replace', 'Replace recovery system data')
        self.reset()

    def __call__(self, request, **values):
        with self.lock:
            if request.method == 'GET' or self.processing:
                return jsonify(request, Replace.Schema.serialize(self))

            self.processing = True
            self.step = 'receiving request'
            self.url = '<unknown>'

        # this section is protected by self.processing
        try:
            result = replace_recovery_system_data(request, self)
            self.reset()
            return result
        except:
            self.reset()
            raise

    def reset(self):
        with self.lock:
            self.processing = False
            self.step = None
            self.url = None

    def set_retrieving(self, url = None):
        with self.lock:
            self.step = 'downloading' if url else 'retrieving'
            self.url = url if url else '<form data>'

    def set_step_name(self, name):
        with self.lock:
            self.step = name

    def get_state_string(self):
        return self.step if self.processing else 'idle'

    def get_data_origin(self):
        return self.url if self.processing else None

status_endpoint = Status()
all_endpoints = [status_endpoint, Verify(status_endpoint), Replace()]

def add_endpoints():
    from .endpoint import register_endpoints
    register_endpoints(all_endpoints)
