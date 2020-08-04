#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2018, 2020  T+A elektroakustik GmbH & Co. KG
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

from pathlib import Path
from hashlib import sha256
from time import time
from threading import RLock
from werkzeug.wrappers import Response
from werkzeug.datastructures import FileStorage
from urllib.request import urlopen
from zlib import adler32
import halogen
import re
import shlex
import dbus

from .endpoint import Endpoint, url_for, register_endpoints
from .external import Tools, Files, Directories, Helpers
from .utils import jsonify_e, jsonify_nc, if_none_match
from .utils import jsonify_error, mk_error_object
from .utils import try_mount_partition, MountResult
from .utils import try_unmount_partition, UnmountResult
from .utils import is_mountpoint
from .utils import remove_directory, remove_file
from .utils import get_logger
log = get_logger()


def _compute_file_checksum(file):
    h = sha256()

    if not file.exists():
        log.warning('File {} missing, cannot compute checksum'.format(file))
        return None

    log.debug('Computing checksum of file {}'.format(file))
    with file.open('rb') as f:
        while True:
            data = f.read(512 * 1024)

            if not data:
                break

            h.update(data)

    return h.hexdigest()


def _generate_file_info(file, checksums):
    expected = 'unavailable' if not checksums or file.name not in checksums\
               else checksums[file.name]

    fi = {
        'name': file.name,
        'expected_checksum': expected
    }

    computed = _compute_file_checksum(file)
    if computed is None:
        log.warning('File {} missing, cannot compute checksum'.format(file))
        computed = 'file missing'

    if expected != computed:
        fi['computed_checksum'] = computed

    fi['is_valid'] = expected == computed

    if fi['is_valid']:
        log.debug('Checksum of file {} is valid'.format(file))
    else:
        log.error(
            'Checksum of file {} is INVALID! Expected: {} - Computed: {}'
            .format(file, expected, computed))

    return fi


def _log_mount_attempt(mountpoint, result):
    if result is MountResult.ALREADY_MOUNTED:
        log.warning('Path {} is already mounted, operation in progress'
                    .format(mountpoint))
    elif result is MountResult.MOUNTED:
        log.info('Successfully mounted {}'.format(mountpoint))
    elif result is MountResult.FAILED:
        log.critical('Mounting {} failed'.format(mountpoint))
    elif result is MountResult.TIMEOUT:
        log.critical('Mounting {} failed because of a timeout'
                     .format(mountpoint))


def _log_unmount_attempt(mountpoint, result):
    if result is UnmountResult.NOT_MOUNTED:
        log.warning('Path {} is not mounted, cannot unmount'
                    .format(mountpoint))
    elif result is UnmountResult.UNMOUNTED:
        log.info('Successfully unmounted {}'.format(mountpoint))
    elif result is UnmountResult.FAILED:
        log.critical('Unmounting {} failed'.format(mountpoint))
    elif result is UnmountResult.TIMEOUT:
        log.critical('Unmounting {} failed because of a timeout'
                     .format(mountpoint))


def _parse_old_version_txt(f):
    """Parse old version.txt file associated with partition images.

    The old format is a simple ASCII file containing just three lines where
    each line has a fixed meaning. It has been replaced by a strbo-release file
    in line V2.
    """
    version_file = f.readlines()

    if not version_file:
        return None

    try:
        return {
            'number': version_file[0].strip(),
            'timestamp': version_file[1].strip(),
            'commit_id': version_file[2].strip(),
        }
    except KeyError:
        return None


_strbo_to_version_info_key = {
    'STRBO_VERSION': 'number',
    'STRBO_RELEASE_LINE': 'release_line',
    'STRBO_FLAVOR': 'flavor',
    'STRBO_DATETIME': 'timestamp',
    'STRBO_GIT_COMMIT': 'commit_id',
}


def _parse_strbo_release_file(f):
    """Parse strbo-release file associated with the partition images.

    This file contains shell-style key/value assignments.
    """
    version_file = f.read()
    if not version_file:
        return None

    version_info = {}

    for line in shlex.split(version_file):
        key, value = line.split('=', 1)
        if key:
            version_info[_strbo_to_version_info_key.get(key, key)] = value

    return version_info


def _get_info_and_verify_data(mountpoint, **values):
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
                for line in f:
                    checksum, filename = re.split(r' +', line.strip())
                    checksums[filename] = checksum
        else:
            log.error('Required file {} not found'.format(temp))

        log.debug('Reading version file')

        def read_version(fname, is_kv_file):
            if not fname.exists():
                return None, None

            if not fname.is_file():
                return None, None

            with fname.open() as f:
                if is_kv_file:
                    version_info = _parse_strbo_release_file(f)
                else:
                    version_info = _parse_old_version_txt(f)

            try:
                log.info('Recovery data version {} as of {}, commit {}'
                         .format(version_info['number'],
                                 version_info['timestamp'],
                                 version_info['commit_id']))
            except KeyError as e:
                log.error('Version information not recognized: missing key {}'
                          .format(e))
                version_info = None

            return fname, version_info

        strbo_release = p / 'strbo-release'
        version_txt = p / 'version.txt'
        fileset = []

        vfile, version_info = read_version(strbo_release, True)
        if version_info is None:
            if vfile:
                fileset.append(_generate_file_info(vfile, checksums))

            vfile, version_info = read_version(version_txt, False)
            if version_info is None:
                if vfile:
                    fileset.append(_generate_file_info(vfile, checksums))

        if version_info is None:
            log.error('No version information for recovery data')
        else:
            fileset.append(_generate_file_info(vfile, checksums))

        for temp in sorted(p.glob('*.bin')):
            fileset.append(_generate_file_info(temp, checksums))

        overall_valid_state = \
            'valid' if all([fs['is_valid'] for fs in fileset]) \
            and version_info is not None else 'broken'
    else:
        overall_valid_state = 'unavailable'

    return version_info, {'recovery_files': fileset,
                          'state': overall_valid_state}


def _verify_data_wrapper(**values):
    log.info('Start verification of recovery data')
    mountpoint = Path('/src')

    try:
        version_info, status = _get_info_and_verify_data(mountpoint, **values)
    except:  # noqa: E722
        unmount_result = try_unmount_partition(mountpoint)
        _log_unmount_attempt(mountpoint, unmount_result)
        log.error('Verification of recovery data failed')
        raise

    unmount_result = try_unmount_partition(mountpoint)
    _log_unmount_attempt(mountpoint, unmount_result)
    log.info('Verification of recovery data done: {}'.format(status['state']))

    return version_info, status


class DStatusSchema(halogen.Schema):
    """Representation of :class:`DStatus`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: Version information about recovery data stored on Streaming Board
    #: flash memory.
    version_info = halogen.Attr()

    #: Result of last check/current status. Will be ``null`` until
    #: verification of stored data has been triggered.
    status = halogen.Attr()


class DStatus(Endpoint):
    """**API Endpoint** - Read out status of the recovery data.

    +-------------+-----------------------------------------------------+
    | HTTP method | Description                                         |
    +=============+=====================================================+
    | ``GET``     | Retrieve the status of the recovery data as of last |
    |             | verification. See :class:`DStatusSchema`; see also  |
    |             | :class:`DVerify` for information on verification.   |
    +-------------+-----------------------------------------------------+
    """

    #: Path to endpoint.
    href = '/recovery/data/status'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    version_info = None
    status = None
    timestamp = None
    etag = None

    def __init__(self):
        Endpoint.__init__(self, 'recovery_data_info', name='data_info',
                          title='Status of the recovery data')
        self.etag = DStatus._compute_etag(self.version_info, self.status)

    def __call__(self, request, **values):
        with self.lock:
            cached = if_none_match(request, self.get_etag())
            if cached:
                return cached

            return jsonify_e(request, self.get_etag(), 5,
                             DStatusSchema.serialize(self))

    def _set(self, version_info, status):
        """Set status data. Called from :class:`DVerify`."""
        with self.lock:
            self.version_info = version_info
            self.status = status
            self.timestamp = time()
            self.etag = DStatus._compute_etag(self.version_info, self.status)

    def get_age(self):
        """Determine the age of recovery data status in seconds."""
        return time() - self.timestamp if self.timestamp else None

    def get_etag(self):
        with self.lock:
            return self.etag

    @staticmethod
    def _compute_etag(version_info, status):
        temp = 'VERSION|' + str(version_info) + '|STATUS|' + str(status)
        return "{:08x}".format(adler32(bytes(temp, 'UTF-8')))


class DVerifySchema(halogen.Schema):
    """Representation of :class:`DVerify`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: State, either ``idle``, ``verifying``, or ``failed``.
    state = halogen.Attr(attr=lambda value: value._get_state_string())


class DVerify(Endpoint):
    """**API Endpoint** - Verify the recovery data.

    +-------------+--------------------------------------------------+
    | HTTP method | Description                                      |
    +=============+==================================================+
    | ``GET``     | Retrieve status of verification process, if any. |
    |             | See :class:`DVerifySchema`.                      |
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
        :class:`DVerifySchema`). This saves clients to set off another ``GET``
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
    endpoint :class:`DStatus`.
    """

    #: Path to endpoint.
    href = '/recovery/data/verify'

    #: Supported HTTP methods.
    methods = ('GET', 'POST')

    lock = RLock()

    def __init__(self, status):
        Endpoint.__init__(self, 'recovery_data_verify', name='verify_data',
                          title='Verification of recovery data')
        self.status = status
        self.processing = False
        self.failed = False

    def __call__(self, request, **values):
        with self.lock:
            if request.method == 'GET':
                cached = if_none_match(request, self.get_etag())
                if cached:
                    result = cached
                else:
                    result = jsonify_e(request, self.get_etag(), 5,
                                       DVerifySchema.serialize(self))
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
            inf, st = _verify_data_wrapper(**values)
        except Exception:
            failed = True
            inf = None
            st = None

        with self.lock:
            self.status._set(inf, st)
            self.processing = False
            self.failed = failed
            return jsonify_e(request, self.get_etag(), 15,
                             DVerifySchema.serialize(self))

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

    def get_etag(self):
        with self.lock:
            return self._get_state_string()


def _get_data_file_from_form(request):
    f = request.files.get('datafile', None)

    if f and f.content_type != 'application/octet-stream':
        raise Exception('Unexpected content type')

    return f


def _create_workdir(dir_id):
    workdir = Directories.get(dir_id)

    try:
        remove_directory(workdir, False)
    except FileNotFoundError:
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

    workdir = _create_workdir('recovery_data_workdir')
    gpgfile = workdir / 'recoverydata.gpg'
    payload = workdir / 'recoverydata'
    is_mounted = False

    try:
        if url_from_form:
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

        gpghome = Directories.get('gpg_home')
        gpghome.mkdir(mode=0o700, exist_ok=True)

        if Tools.invoke_cwd(gpgfile.parent, 15,
                            'gpg', '--homedir', gpghome,
                            '--import', Files.get('gpg_key')) != 0:
            error = mk_error_object(request, log, False,
                                    'Failed to import GPG public key')
            return jsonify_nc(request,
                              result='error', reason='no public key',
                              error_object=error)

        if Tools.invoke_cwd(gpgfile.parent, 600,
                            'gpg', '--homedir', gpghome, gpgfile) != 0:
            error = mk_error_object(
                    request, log, False,
                    'Invalid signature, rejecting downloaded recovery data')
            return jsonify_nc(request,
                              result='error', reason='invalid signature',
                              error_object=error)

        log.info('Testing recovery data archive')
        status.set_step_name('verifying archive')

        if Tools.invoke(150, 'tar', 'tf', payload) != 0:
            error = mk_error_object(
                    request, log, False,
                    'Broken archive, rejecting downloaded recovery data')
            return jsonify_nc(request, result='error', reason='broken archive',
                              error_object=error)

        status.set_step_name('extracting')
        mountpoint = Path('/src')
        mount_result = try_mount_partition(mountpoint, True)
        _log_mount_attempt(mountpoint, mount_result)

        succeeded = False

        if mount_result is MountResult.MOUNTED:
            is_mounted = True

            log.warning('POINT OF NO RETURN: Deleting old recovery data')
            imgdir = mountpoint / 'images'

            log.info('Extracting recovery data archive')

            if Helpers.invoke('replace_recovery_data', payload, imgdir) != 0:
                error = mk_error_object(
                        request, log, True,
                        'Error while extracting recovery data archive')
                result = jsonify_nc(request,
                                    result='error', reason='write error',
                                    error_object=error)
            else:
                succeeded = True
                result = jsonify_nc(request,
                                    result='success', reason='super hero')
        elif mount_result is MountResult.ALREADY_MOUNTED:
            error = mk_error_object(request, log, False,
                                    'Recovery data locked, cannot replace')
            result = jsonify_nc(request, result='error', reason='locked',
                                error_object=error)
        elif mount_result is MountResult.FAILED:
            error = mk_error_object(
                    request, log, True,
                    'Recovery data unaccessible in file system (failure)')
            result = jsonify_nc(request, result='error', reason='inaccessible',
                                error_object=error)
        elif mount_result is MountResult.TIMEOUT:
            error = mk_error_object(
                    request, log, True,
                    'Recovery data unaccessible in file system (timeout)')
            result = jsonify_nc(request,
                                result='error', reason='mount timeout',
                                error_object=error)
        else:
            error = mk_error_object(
                    request, log, True,
                    'Cannot replace recovery data due to some unknown '
                    'error while mounting')
            result = jsonify_nc(request, result='error', reason='unknown',
                                error_object=error)

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


class DReplaceSchema(halogen.Schema):
    """Representation of :class:`DReplace`."""

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
        attr=lambda value: value._get_data_origin()
        if value.processing else value.does_not_exist(),
        required=False
    )


class DReplace(Endpoint):
    """**API Endpoint** - Replace the recovery data.

    +-------------+------------------------------------------------------+
    | HTTP method | Description                                          |
    +=============+======================================================+
    | ``GET``     | Retrieve status of data replacement process, if any. |
    |             | See :class:`DReplaceSchema`.                         |
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
        :class:`DReplaceSchema`). This saves clients to set off another ``GET``
        request after recovery data replacement and provides safe
        synchronization with end of replacement.

        It is a *very* good idea to verify the recovery data after the data
        have been replaced (see :class:`DVerify`). There is only a very small
        chance of verification failures after successful replacement of
        recovery data, but in this particular case it is much better to be
        safe than sorry.

        Clients should always wait for a response before sending another
        ``POST`` request. Impatiently aborting "long" requests and trying to
        restart them will not be of any help with progress, plus things will
        become much more complicated on client side as its application state
        will be disrupted. You have been warned.
    """

    #: Path to endpoint.
    href = '/recovery/data/replace'

    #: Supported HTTP methods.
    methods = ('GET', 'POST')

    lock = RLock()

    def __init__(self):
        Endpoint.__init__(self, 'recovery_data_replace', name='replace_data',
                          title='Replace recovery data')
        self._reset()

    def __call__(self, request, **values):
        with self.lock:
            if request.method == 'GET':
                result = jsonify_nc(request, DReplaceSchema.serialize(self))
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
        except:  # noqa: E722
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


# just a few, not all of them
_required_boot_files = (
    'bootcode.bin', 'config.txt', 'fixup_cd.dat', 'start_cd.elf',
)


def _get_info_and_verify_system(p, **values):
    version_info = None
    fileset = None

    if p.is_dir() and is_mountpoint(str(p)) == MountResult.ALREADY_MOUNTED:
        log.debug('Reading version file')
        temp = p / 'strbo-release'
        if temp.exists() and temp.is_file():
            with temp.open() as f:
                version_info = _parse_strbo_release_file(f)
        else:
            log.info('Version file {} not found'.format(temp))
            version_info = None

        log.debug('Computing checksums')

        fileset = []
        missing_important = set(_required_boot_files)

        for file in [f for f in p.glob('**/*') if f.is_file()]:
            cs = _compute_file_checksum(file)
            relname = str(file.relative_to(p))
            fileset.append({
                'name': relname,
                'computed_checksum': cs,
            })
            missing_important.discard(relname)

        if not missing_important:
            overall_valid_state = 'valid'
        else:
            log.error('Missing files: {}'.format(', '.join(missing_important)))
            overall_valid_state = 'broken'

    else:
        overall_valid_state = 'unavailable'

    return version_info, {'boot_files': fileset,
                          'state': overall_valid_state}


def _verify_system_wrapper(**values):
    log.info('Start verification of recovery system')
    p = Path('/bootpartr')

    try:
        version_info, status = _get_info_and_verify_system(p, **values)
    except:  # noqa: E722
        log.error('Verification of recovery system failed')
        raise

    log.info('Verification of recovery system done: {}'
             .format(status['state']))

    return version_info, status


class SStatusSchema(halogen.Schema):
    """Representation of :class:`SStatus`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: Version information about recovery system stored on Streaming Board
    #: flash memory.
    version_info = halogen.Attr()

    #: Result of last check/current status. Will be ``null`` until
    #: verification of stored data has been triggered.
    status = halogen.Attr()


class SStatus(Endpoint):
    """**API Endpoint** - Read out status of the recovery system.

    +-------------+-------------------------------------------------------+
    | HTTP method | Description                                           |
    +=============+=======================================================+
    | ``GET``     | Retrieve the status of the recovery system as of last |
    |             | verification. See :class:`SStatusSchema`; see also    |
    |             | :class:`SVerify` for information on verification.     |
    +-------------+-------------------------------------------------------+
    """

    #: Path to endpoint.
    href = '/recovery/system/status'

    #: Supported HTTP methods.
    methods = ('GET',)

    lock = RLock()

    version_info = None
    status = None
    timestamp = None
    etag = None

    def __init__(self):
        Endpoint.__init__(self, 'recovery_system_info', name='system_info',
                          title='Status of the recovery system')
        self.etag = SStatus._compute_etag(self.version_info, self.status)

    def __call__(self, request, **values):
        with self.lock:
            cached = if_none_match(request, self.get_etag())
            if cached:
                return cached

            return jsonify_e(request, self.get_etag(), 5,
                             SStatusSchema.serialize(self))

    def _set(self, version_info, status):
        """Set status data. Called from :class:`SVerify`."""
        with self.lock:
            self.version_info = version_info
            self.status = status
            self.timestamp = time()
            self.etag = SStatus._compute_etag(self.version_info, self.status)

    def get_age(self):
        """Determine the age of recovery system status in seconds."""
        return time() - self.timestamp if self.timestamp else None

    def get_etag(self):
        with self.lock:
            return self.etag

    @staticmethod
    def _compute_etag(version_info, status):
        temp = 'VERSION|' + str(version_info) + '|STATUS|' + str(status)
        return "{:08x}".format(adler32(bytes(temp, 'UTF-8')))


class SVerifySchema(halogen.Schema):
    """Representation of :class:`SVerify`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: State, either ``idle``, ``verifying``, or ``failed``.
    state = halogen.Attr(attr=lambda value: value._get_state_string())


class SVerify(Endpoint):
    """**API Endpoint** - Verify the recovery system.

    +-------------+--------------------------------------------------+
    | HTTP method | Description                                      |
    +=============+==================================================+
    | ``GET``     | Retrieve status of verification process, if any. |
    |             | See :class:`SVerifySchema`.                      |
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
        :class:`SVerifySchema`). This saves clients to set off another ``GET``
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
    endpoint :class:`SStatus`.
    """

    #: Path to endpoint.
    href = '/recovery/system/verify'

    #: Supported HTTP methods.
    methods = ('GET', 'POST')

    lock = RLock()

    def __init__(self, status):
        Endpoint.__init__(self, 'recovery_system_verify', name='verify_system',
                          title='Verification of recovery system')
        self.status = status
        self.processing = False
        self.failed = False

    def __call__(self, request, **values):
        with self.lock:
            if request.method == 'GET':
                cached = if_none_match(request, self.get_etag())
                if cached:
                    result = cached
                else:
                    result = jsonify_e(request, self.get_etag(), 5,
                                       SVerifySchema.serialize(self))
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
            inf, st = _verify_system_wrapper(**values)
        except Exception:
            failed = True
            inf = None
            st = None

        with self.lock:
            self.status._set(inf, st)
            self.processing = False
            self.failed = failed
            return jsonify_e(request, self.get_etag(), 15,
                             SVerifySchema.serialize(self))

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

    def get_etag(self):
        with self.lock:
            return self._get_state_string()


def _replace_recovery_system(request, status):
    log.info('Start replacing recovery system')
    url_from_form = request.values.get('dataurl', None)

    if url_from_form:
        log.info('Downloading recovery system from {}'.format(url_from_form))
        status.set_retrieving(url_from_form)
        file_from_form = None
    else:
        log.info('Taking recovery system from HTTP stream')
        status.set_retrieving()
        file_from_form = _get_data_file_from_form(request)

    workdir = _create_workdir('recovery_system_workdir')
    gpgfile = workdir / 'recoverysystem.gpg'
    payload = workdir / 'flash_recovery_system.sh'
    is_mounted = True

    try:
        if url_from_form:
            url = urlopen(url_from_form)
            f = FileStorage(url, gpgfile.name)
            f.save(str(gpgfile))
        elif file_from_form:
            file_from_form.save(str(gpgfile))
        else:
            log.error('No recovery system file specified')
            raise Exception('No recovery system file specified')

        log.info('Verifying recovery system signature')
        status.set_step_name('verifying signature')

        gpghome = Directories.get('gpg_home')
        gpghome.mkdir(mode=0o700, exist_ok=True)

        if Tools.invoke_cwd(gpgfile.parent, 15,
                            'gpg', '--homedir', gpghome,
                            '--import', Files.get('gpg_key')) != 0:
            error = mk_error_object(request, log, True,
                                    'Failed to import GPG public key')
            return jsonify_nc(request,
                              result='error', reason='no public key',
                              error_object=error)

        if Tools.invoke_cwd(gpgfile.parent, 600,
                            'gpg', '--homedir', gpghome,
                            '--output', payload, gpgfile) != 0:
            error = mk_error_object(
                    request, log, False,
                    'Invalid signature, rejecting downloaded recovery system')
            return jsonify_nc(request,
                              result='error', reason='invalid signature',
                              error_object=error)

        status.set_step_name('flashing and verifying')
        payload.chmod(0o700)
        mountpoint = Path('/bootpartr')
        unmount_result = try_unmount_partition(mountpoint)
        _log_unmount_attempt(mountpoint, unmount_result)

        succeeded = False

        if unmount_result is UnmountResult.UNMOUNTED or \
                unmount_result is UnmountResult.NOT_MOUNTED:
            is_mounted = False

            log.warning('POINT OF NO RETURN: '
                        'Overwriting recovery boot partition')
            log.info('Executing recovery system installer')

            if Helpers.invoke('replace_recovery_system', workdir) != 0:
                error = mk_error_object(
                        request, log, True,
                        'Error while replacing recovery system')
                result = jsonify_nc(request,
                                    result='error', reason='write error',
                                    error_object=error)
            else:
                succeeded = True
                result = jsonify_nc(request,
                                    result='success', reason='super hero')
        elif unmount_result is UnmountResult.FAILED:
            error = mk_error_object(
                    request, log, True,
                    'Recovery system partition unaccessible '
                    'in file system (failure)')
            result = jsonify_nc(request, result='error', reason='inaccessible',
                                error_object=error)
        elif unmount_result is UnmountResult.TIMEOUT:
            error = mk_error_object(
                    request, log, True,
                    'Recovery system partition unaccessible '
                    'in file system (timeout)')
            result = jsonify_nc(request,
                                result='error', reason='mount timeout',
                                error_object=error)
        else:
            error = mk_error_object(
                    request, log, True,
                    'Cannot replace recovery system due to some unknown '
                    'error while unmounting')
            result = jsonify_nc(request, result='error', reason='unknown',
                                error_object=error)

        if succeeded:
            log.info('Cleaning up to make new recovery system usable')
        else:
            log.info('Cleaning up')

        status.set_step_name('finalizing')
        mount_result = try_mount_partition(mountpoint, False)
        _log_mount_attempt(mountpoint, mount_result)
        is_mounted = True

        remove_directory(workdir)

        if succeeded:
            log.info('Recovery system replaced successfully')
        else:
            log.error('Replacing recovery system FAILED')

        return result
    except Exception as e:
        log.error('Replacing recovery system FAILED: {}'.format(e))

        if not is_mounted:
            mount_result = try_mount_partition(mountpoint, False)
            _log_mount_attempt(mountpoint, mount_result)

        remove_directory(workdir)

        raise


class SReplaceSchema(halogen.Schema):
    """Representation of :class:`SReplace`."""

    #: Link to self.
    self = halogen.Link(attr='href')

    #: Short string describing the currently running step in the
    #: replacement process. Possible values are  ``idle``,
    #: ``receiving request``, ``retrieving``, ``downloading``,
    #: ``verifying signature``, ``executing installer``, and
    #: ``finalizing``. These strings are suitable for display of progress
    #: in a user interface.
    state = halogen.Attr(attr=lambda value: value._get_state_string())

    #: Where the recovery system is coming from, either a URL or ``null``
    #: (i.e., recovery system package was sent as request form data). The field
    #: will be missing in case no replacement process in active.
    origin = halogen.Attr(
        attr=lambda value: value._get_data_origin()
        if value.processing else value.does_not_exist(),
        required=False
    )


class SReplace(Endpoint):
    """**API Endpoint** - Replace the recovery system.

    +-------------+--------------------------------------------------------+
    | HTTP method | Description                                            |
    +=============+========================================================+
    | ``GET``     | Retrieve status of system replacement process, if any. |
    |             | See :class:`SReplaceSchema`.                           |
    +-------------+--------------------------------------------------------+
    | ``POST``    | Send recovery system package as a substitute for the   |
    |             | system currently stored on flash memory.               |
    +-------------+--------------------------------------------------------+

    Details on method ``GET``:
        The recovery system replacement process does not emit any events to the
        event monitor. Thus, polling this endpoint is an acceptable way for
        monitoring the state of the replacement process. The poll interval
        should not exceed 2 seconds.

    Details on method ``POST``:
        There are two ways for uploading a recovery system package to the
        system: either by sending a download URL, or by sending the package
        data directly as form data. If a download URL is sent, then this URL
        must point to a location from which the Streaming Board can pull a
        *recovery system archive*. If sent as form data, then the data pushed
        to the Streaming Board must be the *recovery system archive* itself.

        A download URL is passed in as parameter ``dataurl``. It shall contain
        a valid URL of a recovery system archive. A request of this kind is
        small and sent quickly. In this case, the Streaming Board is
        responsible for retrieving the archive.

        Alternatively, direct recovery system archive upload can be done
        through parameter ``datafile``. A request of this kind will take a long
        time to be sent off completely because the archive files are pretty
        big. While the request is in progress of being sent, no meaningful
        update of the recovery system replacement process is going to take
        place.

        If both, ``dataurl`` and ``datafile``, are present, then the former is
        preferred and the latter gets ignored. The content type must be
        ``multipart/form-data`` in any case.

        If there is a recovery system replacement is in progress, then the
        response will be an immediate redirect to this endpoint with an HTTP
        status code 303.

        When done, the response contains the recovery system replacement
        process status object which can also be retrieved with ``GET`` (see
        also :class:`SReplaceSchema`). This saves clients to set off another
        ``GET`` request after recovery system replacement and provides safe
        synchronization with end of replacement.

        It is a *very* good idea to verify the recovery system after the system
        has been replaced (see :class:`SVerify`). There is only a very small
        chance of verification failure after successful replacement of the
        recovery system, but in this particular case it is much better to be
        safe than sorry.

        Clients should always wait for a response before sending another
        ``POST`` request. Impatiently aborting "long" requests and trying to
        restart them will not be of any help with progress, plus things will
        become much more complicated on client side as its application state
        will be disrupted. You have been warned.
    """

    #: Path to endpoint.
    href = '/recovery/system/replace'

    #: Supported HTTP methods.
    methods = ('GET', 'POST')

    lock = RLock()

    def __init__(self):
        Endpoint.__init__(self, 'recovery_system_replace',
                          name='replace_system',
                          title='Replace recovery system')
        self._reset()

    def __call__(self, request, **values):
        with self.lock:
            if request.method == 'GET':
                result = jsonify_nc(request, SReplaceSchema.serialize(self))
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
            result = _replace_recovery_system(request, self)
            self._reset()
            return result
        except:  # noqa: E722
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


class SystemReboot(Endpoint):
    """**API Endpoint** - Boot the recovery system.

    +-------------+-----------------------------------------------------------+
    | HTTP method | Description                                               |
    +=============+===========================================================+
    | ``POST``    | Ask the system to shutdown and boot the recovery system.  |
    |             | To protect the innocent (i.e., avoid accidental reboots), |
    |             | a JSON object must be sent which contains a magic value   |
    |             | and further request parameters.                           |
    +-------------+-----------------------------------------------------------+

    Details on method ``POST``:
        A JSON object must be sent which contains the field ``request`` set to
        the deliberately long string value,
        ``Please kindly recover the system: I really know what I am doing``.

        The JSON object may also contain the field ``keep_user_data``, which
        must, if present, be set to either ``true`` or ``false``. If the field
        is missing, then its value is assumed as ``false``, i.e., a complete
        recovery to factory defaults.

        An update by image files can be done by setting ``keep_user_data`` to
        ``true``, but please be aware of the implied side effects. Keeping old
        configuration data around may lead to random problems at runtime in
        case the newly installed software cannot cope with the existing
        configuration files. It is also possible for different versions of
        software to have their configuration data in different places. Thus,
        installing a different version without involvement of a package manager
        may lead to two sets of configuration data: one for the previous
        version, and one for the current version. Switching back and forth
        between versions also switches between the two sets of configuration
        data, which will be very confusing to the user.
    """

    #: Path to endpoint.
    href = '/recovery/system/reboot'

    #: Supported HTTP methods.
    methods = ('POST',)

    def __init__(self):
        Endpoint.__init__(self, 'recovery_system_reboot',
                          name='reboot_system',
                          title='Reboot and enter recovery system')

    def __call__(self, request, **values):
        req = request.json
        if not req:
            return jsonify_error(request, log, False, 400,
                                 'JSON object missing')

        keep_user_data = req.get('keep_user_data', False)
        magic = req.get('request', None)

        try:
            if magic is None:
                raise TypeError('Request missing')

            if not isinstance(magic, str):
                raise TypeError('Request must be string')

            if not isinstance(keep_user_data, bool):
                raise TypeError('Parameter keep_user_data must be bool')

            if magic != 'Please kindly recover the system: ' \
                        'I really know what I am doing':
                return jsonify_error(request, log, False, 403,
                                     'Request blocked')
        except Exception as e:
            return jsonify_error(request, log, True, 400,
                                 'Exception: ' + str(e))

        boot_config = \
            Directories.get('recovery_system_config') / \
            'recovery_system_boot.rc'

        if keep_user_data:
            with boot_config.open('w') as f:
                f.write('KEEP_USER_DATA="yes"\n')
        else:
            remove_file(boot_config)

        log.info('Rebooting into recovery system {}'
                 .format('(preserving user data)' if keep_user_data
                         else 'for full recovery'))

        try:
            bus = dbus.SystemBus()
            systemd = bus.get_object('org.freedesktop.systemd1',
                                     '/org/freedesktop/systemd1')
            manager = dbus.Interface(systemd,
                                     'org.freedesktop.systemd1.Manager')
            manager.StartUnit('recovery.target', 'isolate')
            return Response()
        except Exception as e:
            return jsonify_error(request, log, True, 400,
                                 'Reboot failed due to exception: ' + str(e))


data_status_endpoint = DStatus()
system_status_endpoint = SStatus()

all_endpoints = [
    data_status_endpoint, DVerify(data_status_endpoint), DReplace(),
    system_status_endpoint, SVerify(system_status_endpoint), SReplace(),
    SystemReboot(),
]


def add_endpoints():
    """Register all endpoints defined in this module."""
    register_endpoints(all_endpoints)
