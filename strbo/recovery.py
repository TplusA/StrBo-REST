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

from pathlib import Path
from hashlib import sha256
from time import time
from threading import RLock
from werkzeug.wrappers import Response

from .utils import try_mount_partition, MountResult
from .utils import try_unmount_partition, UnmountResult
from .utils import remove_directory
from .utils import get_logger
log = get_logger()


def _generate_file_info(file, checksums):
    expected = 'unavailable' if not checksums or file.name not in checksums else checksums[file.name]

    fi = {
        'name': file.name,
        'expected_checksum': expected
    }

    h = sha256()

    if file.exists():
        log.debug('Computing checksum of file {}'.format(file))
        with file.open('rb') as f:
            while True:
                data = f.read(512 * 1024)

                if not data:
                    break

                h.update(data)

        computed = h.hexdigest()
    else:
        log.warning('File {} missing, cannot compute checksum'.format(file))
        computed = 'file missing'

    if expected != computed:
        fi['computed_checksum'] = computed

    fi['is_valid'] = expected == computed

    if fi['is_valid']:
        log.debug('Checksum of file {} is valid'.format(file))
    else:
        log.error('Checksum of file {} is INVALID! Expected: {} - Computed: {}'.format(file, expected, computed))

    return fi


def _log_mount_attempt(mountpoint, result):
    if result is MountResult.ALREADY_MOUNTED:
        log.warning('Path {} is already mounted, operation in progress'.format(mountpoint))
    elif result is MountResult.MOUNTED:
        log.info('Successfully mounted {}'.format(mountpoint))
    elif result is MountResult.FAILED:
        log.critical('Mounting {} failed'.format(mountpoint))
    elif result is MountResult.TIMEOUT:
        log.critical('Mounting {} failed because of a timeout'.format(mountpoint))


def _log_unmount_attempt(mountpoint, result):
    if result is UnmountResult.NOT_MOUNTED:
        log.warning('Path {} is not mounted, cannot unmount'.format(mountpoint))
    elif result is UnmountResult.UNMOUNTED:
        log.info('Successfully unmounted {}'.format(mountpoint))
    elif result is UnmountResult.FAILED:
        log.critical('Unmounting {} failed'.format(mountpoint))
    elif result is UnmountResult.TIMEOUT:
        log.critical('Unmounting {} failed because of a timeout'.format(mountpoint))


def _get_info_and_verify(mountpoint, **values):
    p = mountpoint / 'images'
    mount_result = try_mount_partition(mountpoint)
    _log_mount_attempt(mountpoint, mount_result)
    version_info = None
    fileset = None

    if mount_result is MountResult.ALREADY_MOUNTED:
        overall_valid_state = 'locked'
    elif mount_result is MountResult.MOUNTED:
        log.debug('Reading checksum file')
        temp = p / 'SHA256SUMS'
        checksums = None
        if temp.exists() and temp.is_file():
            with temp.open() as f:
                checksums = {}
                for l in f:
                    import re
                    checksum, filename = re.split(r' +', l.strip())
                    checksums[filename] = checksum
        else:
            log.error('Required file {} not found'.format(temp))

        log.debug('Reading version file')
        temp = p / 'version.txt'
        version_file = None
        if temp.exists() and temp.is_file():
            with temp.open() as f:
                version_file = f.readlines()
        else:
            log.error('Required file {} not found'.format(temp))

        if version_file and len(version_file) == 3:
            version_info = {
                'number': version_file[0].strip(),
                'timestamp': version_file[1].strip(),
                'commit_id': version_file[2].strip(),
            }

            log.info('Recovery data version {} as of {}, commit {}'.format(version_info['number'],
                                                                           version_info['timestamp'],
                                                                           version_info['commit_id']))
        else:
            log.error('No version information for recovery data')

        fileset = []
        fileset.append(_generate_file_info(temp, checksums))

        for temp in sorted(p.glob('*.bin')):
            fileset.append(_generate_file_info(temp, checksums))

        overall_valid_state = \
            'valid' if all([fs['is_valid'] for fs in fileset]) else 'broken'
    else:
        overall_valid_state = 'unavailable'

    return version_info, {'recovery_files': fileset,
                          'state': overall_valid_state}


def _verify_wrapper(**values):
    log.info('Start verification of recovery data')
    mountpoint = Path('/mnt')

    try:
        version_info, status = _get_info_and_verify(mountpoint, **values)
    except:
        unmount_result = try_unmount_partition(mountpoint)
        _log_unmount_attempt(mountpoint, unmount_result)
        log.error('Verification of recovery data failed')
        raise

    unmount_result = try_unmount_partition(mountpoint)
    _log_unmount_attempt(mountpoint, unmount_result)
    log.info('Verification of recovery data done: {}'.format(status['state']))

    return version_info, status


import halogen

from .endpoint import Endpoint, url_for
from .utils import jsonify, jsonify_nc


class Status(Endpoint):
    """**API Endpoint** - Read out status of the recovery system data.

    +-------------+---------------------------------------------------------+
    | HTTP method | Description                                             |
    +=============+=========================================================+
    | ``GET``     | Retrieve the status of the recovery system data as of   |
    |             | last verification. See :class:`Status.Schema`; see also |
    |             | :class:`Verify` for information on verification.        |
    +-------------+---------------------------------------------------------+
    """

    class Schema(halogen.Schema):
        """Representation of :class:`Status`."""

        #: Link to self.
        self = halogen.Link(attr='href')

        #: Version information about recovery data stored on Streaming Board
        #: flash memory.
        version_info = halogen.Attr()

        #: Result of last check/current status. Will be ``null`` until
        #: verification of stored data has been triggered.
        status = halogen.Attr()

        #: Number of seconds since last verification, i.e., the age of this
        #: verification status.
        age = halogen.Attr(attr=lambda value: value.get_age())

    #: Path to endpoint.
    href = '/recovery/status'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    version_info = None
    status = None
    timestamp = None

    def __init__(self):
        Endpoint.__init__(self, 'recovery_data_info', name='data_info',
                          title='Status of the recovery system data')

    def __call__(self, request, **values):
        with self.lock:
            return jsonify(request, Status.Schema.serialize(self))

    def _set(self, version_info, status):
        """Set status data. Called from :class:`Verify`."""
        with self.lock:
            self.version_info = version_info
            self.status = status
            self.timestamp = time()

    def get_age(self):
        """Determine the age of recovery system data status in seconds."""
        return time() - self.timestamp if self.timestamp else None


class Verify(Endpoint):
    """**API Endpoint** - Verify the recovery system data.

    +-------------+--------------------------------------------------+
    | HTTP method | Description                                      |
    +=============+==================================================+
    | ``GET``     | Retrieve status of verification process, if any. |
    |             | See :class:`Verify.Schema`.                      |
    +-------------+--------------------------------------------------+
    | ``POST``    | Start verification process.                      |
    +-------------+--------------------------------------------------+

    Details on method ``POST``:
        Any data sent with the request is ignored. For the time being, clients
        should not send any data with the request.

        If no verification is in progress when a ``POST`` request is sent, then
        the request will start verification. The response is sent after
        verification has finished, which may time quite some time (several
        seconds). When done, the response contains the verification status
        object which can also be retrieved with ``GET`` (see also
        :class:`Verify.Schema`). This saves clients to set off another ``GET``
        request after verification and provides safe synchronization with end
        of verification.

        If there is a verification is in progress, then the response will be an
        immediate redirect to this endpoint with an HTTP status code 303.

        There is a rate limit of one verification request per three seconds.
        That is, in case no verification is in progress, but the last
        verification has finished no longer than three seconds ago, the
        response will follow immediately with HTTP status code 429.

        Either way, clients should always wait for a response before sending
        another ``POST`` request. Impatiently aborting "long" requests and
        trying to restart them will not be of any help with progress, plus
        things will become much more complicated on client side as its
        application state will be disrupted. You have been warned.

    A detailed status summery of the last verification can be retrieved from
    endpoint :class:`Status`.
    """

    class Schema(halogen.Schema):
        """Representation of :class:`Verify`."""

        #: Link to self.
        self = halogen.Link(attr='href')

        #: State, either ``idle``, ``verifying``, or ``failed``.
        state = halogen.Attr(attr=lambda value: value._get_state_string())

    #: Path to endpoint.
    href = '/recovery/verify'

    #: Supported HTTP methods.
    methods = ('GET', 'POST')

    lock = RLock()

    def __init__(self, status):
        Endpoint.__init__(self, 'recovery_data_verify', name='verify_data',
                          title='Verification of recovery system data')
        self.status = status
        self.processing = False
        self.failed = False

    def __call__(self, request, **values):
        with self.lock:
            if request.method == 'GET':
                result = jsonify_nc(request, Verify.Schema.serialize(self))
            elif self.processing:
                result = Response(status=303)
                result.location = url_for(request, self)
            elif self._rate_limit():
                result = Response(status=429)
            else:
                result = None

            if result:
                return result

            self.processing = True
            self.failed = False

        # this section is protected by self.processing
        try:
            failed = False
            inf, st = _verify_wrapper(**values)
        except Exception:
            failed = True
            inf = None
            st = None

        with self.lock:
            self.status._set(inf, st)
            self.processing = False
            self.failed = failed
            return jsonify_nc(request, Verify.Schema.serialize(self))

    def _rate_limit(self):
        if self.status:
            age = self.status.get_age()

            if age and age < 3:
                return True

        return False

    def _get_state_string(self):
        if self.processing:
            return 'verifying'
        elif self.failed:
            return 'failed'
        else:
            return 'idle'


def _get_data_file_from_form(request):
    f = request.files.get('datafile', None)

    if f and f.content_type != 'application/octet-stream':
        raise Exception('Unexpected content type')

    return f


def _create_workdir():
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


def _replace_recovery_system_data(request, status):
    log.info('Start replacing recovery data')
    url_from_form = request.values.get('dataurl', None)

    if url_from_form:
        log.info('Downloading recovery data from {}'.format(url_from_form))
        status.set_retrieving(url_from_form)
        file_from_form = None
    else:
        log.info('Taking recovery data from HTTP stream')
        status.set_retrieving()
        file_from_form = _get_data_file_from_form(request)

    workdir = _create_workdir()
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
            log.error('No recovery data file specified')
            raise Exception('No data file specified')

        log.info('Verifying recovery data signature')
        status.set_step_name('verifying signature')
        import subprocess

        cmd = subprocess.Popen(
            ['gpg',
             '--homedir', str(gpgfile.parent),
             '--keyring', '/usr/share/opkg/keyrings/key-93CD60C9.gpg',
             str(gpgfile)],
            cwd=str(gpgfile.parent))

        if cmd.wait(600) != 0:
            log.error('Invalid signature, rejecting downloaded recovery data')
            return jsonify_nc(request, result='error', reason='invalid signature')

        log.info('Testing recovery data archive')
        status.set_step_name('verifying archive')
        cmd = subprocess.Popen(['tar', 'tf', str(payload)])
        if cmd.wait(150) != 0:
            log.error('Broken archive, rejecting downloaded recovery data')
            return jsonify_nc(request, result='error', reason='broken archive')

        status.set_step_name('extracting')
        mountpoint = Path('/mnt')
        mount_result = try_mount_partition(mountpoint, True)
        _log_mount_attempt(mountpoint, mount_result)

        succeeded = False

        if mount_result is MountResult.MOUNTED:
            is_mounted = True

            log.warning('POINT OF NO RETURN: Deleting old recovery data')
            imgdir = mountpoint / 'images'
            remove_directory(imgdir, False)

            log.info('Extracting recovery data archive')
            cmd = subprocess.Popen(['tar', 'xf', str(payload)],
                                   cwd=str(imgdir))

            if cmd.wait(300) != 0:
                log.critical('Error while extracting recovery data archive')
                result = jsonify_nc(request, result='error', reason='write error')
            else:
                succeeded = True
                result = jsonify_nc(request,
                                    result='success', reason='super hero')
        elif mount_result is MountResult.ALREADY_MOUNTED:
            log.warning('Recovery data locked, cannot replace')
            result = jsonify_nc(request, result='error', reason='locked')
        elif mount_result is MountResult.FAILED:
            log.critical('Recovery data unaccessible in file system')
            result = jsonify_nc(request, result='error', reason='inaccessible')
        elif mount_result is MountResult.TIMEOUT:
            log.critical('Recovery data unaccessible in file system')
            result = jsonify_nc(request, result='error', reason='mount timeout')
        else:
            log.critical('Cannot replace recovery data due to some unknown error while mounting')
            result = jsonify_nc(request, result='error', reason='unknown')

        if succeeded:
            log.info('Cleaning up to make new recovery data usable')
        else:
            log.info('Cleaning up')

        status.set_step_name('finalizing')
        unmount_result = try_unmount_partition(mountpoint)
        _log_unmount_attempt(mountpoint, unmount_result)
        is_mounted = False

        remove_directory(workdir)

        if succeeded:
            log.info('Recovery data replaced successfully')
        else:
            log.error('Replacing recovery data FAILED')

        return result
    except Exception as e:
        log.error('Replacing recovery data FAILED: {}'.format(e))

        if is_mounted:
            unmount_result = try_unmount_partition(mountpoint)
            _log_unmount_attempt(mountpoint, unmount_result)

        remove_directory(workdir)

        raise


class Replace(Endpoint):
    """**API Endpoint** - Replace the recovery system data.

    +-------------+------------------------------------------------------+
    | HTTP method | Description                                          |
    +=============+======================================================+
    | ``GET``     | Retrieve status of data replacement process, if any. |
    |             | See :class:`Replace.Schema`.                         |
    +-------------+------------------------------------------------------+
    | ``POST``    | Send recovery data as a substitute for the data      |
    |             | currently stored on flash memory.                    |
    +-------------+------------------------------------------------------+

    Details on method ``GET``:
        The recovery data replacement process does not emit any events to the
        event monitor. Thus, polling this endpoint is an acceptable way for
        monitoring the state of the replacement process. The poll interval
        should not exceed 2 seconds.

    Details on method ``POST``:
        There are two ways for uploading recovery data to the system: either by
        sending a download URL, or by sending the data directly as form data.
        If a download URL is sent, then this URL must point to a location from
        which the Streaming Board can pull a *recovery data archive*. If sent
        as form data, then the data pushed to the Streaming Board must be the
        *recovery data archive* itself.

        A download URL is passed in as parameter ``dataurl``. It shall contain
        a valid URL of a recovery data archive. A request of this kind is small
        and sent quickly. In this case, the Streaming Board is responsible for
        retrieving the archive.

        Alternatively, direct recovery data archive upload can be done through
        parameter ``datafile``. A request of this kind will take a long time to
        be sent off completely because the archive files are pretty big. While
        the request is in progress of being sent, no meaningful update of the
        recovery data replacement process is going to take place.

        If both, ``dataurl`` and ``datafile``, are present, then the former is
        preferred and the latter gets ignored. The content type must be
        ``multipart/form-data`` in any case.

        If there is a data replacement is in progress, then the response will
        be an immediate redirect to this endpoint with an HTTP status code 303.

        When done, the response contains the data replacement process status
        object which can also be retrieved with ``GET`` (see also
        :class:`Replace.Schema`). This saves clients to set off another ``GET``
        request after recovery data replacement and provides safe
        synchronization with end of replacement.

        It is a *very* good idea to verify the recovery data after the data
        have been replaced (see :class:`Verify`). Even though there is only a
        very small chance of verification failures after successful replacement
        of recovery data, but in this particular case it is much better to be
        safe than sorry.

        Clients should always wait for a response before sending another
        ``POST`` request. Impatiently aborting "long" requests and trying to
        restart them will not be of any help with progress, plus things will
        become much more complicated on client side as its application state
        will be disrupted. You have been warned.
    """

    class Schema(halogen.Schema):
        """Representation of :class:`Replace`."""

        #: Link to self.
        self = halogen.Link(attr='href')

        #: Short string describing the currently running step in the
        #: replacement process. Possible values are  ``idle``,
        #: ``receiving request``, ``retrieving``, ``downloading``,
        #: ``verifying signature``, ``verifying archive``, ``extracting``, and
        #: ``finalizing``. These strings are suitable for display of progress
        #: in a user interface.
        state = halogen.Attr(attr=lambda value: value._get_state_string())

        #: Where the recovery data is coming from, either a URL or ``null``
        #: (i.e., recovery data was sent as request form data). The field will
        #: be missing in case no replacement process in active.
        origin = halogen.Attr(
            attr=lambda value: value._get_data_origin() if value.processing else value.does_not_exist(),
            required=False
        )

    #: Path to endpoint.
    href = '/recovery/replace'

    #: Supported HTTP methods.
    methods = ('GET', 'POST')

    lock = RLock()

    def __init__(self):
        Endpoint.__init__(self, 'recovery_data_replace', name='replace_data',
                          title='Replace recovery system data')
        self._reset()

    def __call__(self, request, **values):
        with self.lock:
            if request.method == 'GET':
                result = jsonify_nc(request, Replace.Schema.serialize(self))
            elif self.processing:
                result = Response(status=303)
                result.location = url_for(request, self)
            else:
                result = None

            if result:
                return result

            self.processing = True
            self.step = 'receiving request'
            self.url = '<unknown>'

        # this section is protected by self.processing
        try:
            result = _replace_recovery_system_data(request, self)
            self._reset()
            return result
        except:
            self._reset()
            raise

    def _reset(self):
        with self.lock:
            self.processing = False
            self.step = None
            self.url = None

    def set_retrieving(self, url=None):
        """Set progress step: retrieving form data or downloading."""
        with self.lock:
            if self.processing:
                self.step = 'downloading' if url else 'retrieving'
                self.url = url if url else '<form data>'

    def set_step_name(self, name):
        """Set progress step: any short string describing the step."""
        with self.lock:
            if self.processing:
                self.step = name

    def _get_state_string(self):
        return self.step if self.processing else 'idle'

    def _get_data_origin(self):
        return self.url if self.processing else None


status_endpoint = Status()
all_endpoints = [status_endpoint, Verify(status_endpoint), Replace()]


def add_endpoints():
    """Register all endpoints defined in this module."""
    from .endpoint import register_endpoints
    register_endpoints(all_endpoints)
