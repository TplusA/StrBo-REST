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

from enum import Enum
from werkzeug.wrappers import Request, Response
import json


class MountResult(Enum):
    """Result of a mount attempt by :func:`try_mount_partition`."""
    ALREADY_MOUNTED = 1
    MOUNTED = 2
    FAILED = 3
    TIMEOUT = 4


class UnmountResult(Enum):
    """Result of an unmount attempt by :func:`try_unmount_partition`."""
    NOT_MOUNTED = 1
    UNMOUNTED = 2
    FAILED = 3
    TIMEOUT = 4


def try_mount_partition(mountpoint, writable=False):
    """Try to mount a partition using an ``/etc/fstab`` entry.

    We don't try to support generic mounting of any device to any location as
    this would, in general, require root privileges. Going through
    ``/etc/fstab`` means we can rely on system configuration which grants (or
    denies) us the required permissions.

    Call :func:`try_unmount_partition` to unmount later.

    :return: A result of type :class:`MountResult`.
    """
    try:
        import subprocess

        cmd = subprocess.Popen(['mountpoint', '-q', str(mountpoint)])
        if cmd.wait(2) == 0:
            return MountResult.ALREADY_MOUNTED

        cmd = subprocess.Popen(['mount', '-o' + ('rw' if writable else 'ro'),
                                str(mountpoint)])
        if cmd.wait(20) != 0:
            return MountResult.FAILED

        cmd = subprocess.Popen(['mountpoint', '-q', str(mountpoint)])
        if cmd.wait(1) == 0:
            return MountResult.MOUNTED

    except TimeoutError:
        return MountResult.TIMEOUT

    return MountResult.FAILED


def try_unmount_partition(mountpoint):
    """Try to unmount a partition previously mounted by a call of
    :func:`try_mount_partition`.

    :return: A result of type :class:`UnmountResult`.
    """
    try:
        import subprocess

        cmd = subprocess.Popen(['mountpoint', '-q', str(mountpoint)])
        if cmd.wait(2) != 0:
            return UnmountResult.NOT_MOUNTED

        cmd = subprocess.Popen(['umount', str(mountpoint)])
        if cmd.wait(20) != 0:
            return UnmountResult.FAILED

        cmd = subprocess.Popen(['mountpoint', '-q', str(mountpoint)])
        if cmd.wait(1) != 0:
            return UnmountResult.UNMOUNTED

    except TimeoutError:
        return UnmountResult.TIMEOUT

    return UnmountResult.FAILED


def remove_directory(dir, remove_dir=True):
    """Recursively remove a directory.

    All contents of directory `dir` are removed by this function, including
    `dir` itself iff `remove_dir` is ``True``. If `remove_dir` is ``False``,
    then `dir` will not be removed and should be empty when this function
    returns.

    This function does not follow symlinks.

    If `remove_dir` is ``True``, then this function behaves exactly like
    ``rm -r dir``.
    """
    for item in dir.iterdir():
        if item.is_dir() and not item.is_symlink():
            remove_directory(item, True)
            item.rmdir()
        else:
            item.unlink()

    if remove_dir:
        dir.rmdir()


def request_wants_haljson(request):
    """Check whether or not the WSGI request accepts JSON data in response."""
    best = request.accept_mimetypes.best_match(['application/hal+json',
                                                'text/html'])
    return best == 'application/hal+json' and \
        request.accept_mimetypes[best] > request.accept_mimetypes['text/html']


def request_accepts_utf8(request):
    """Check whether or not the WSGI request accepts UTF-8 encoded response."""
    return request.accept_charsets.find('utf-8') >= 0


def _pack_json_into_response(json):
    """Create a :class:`werkzeug.wrappers.Response` instance with content type
    ``application/hal+json`` containing the passed string as response data.

    `json` should be a string containing JSON data, hence the name of the
    parameter. Technically, `json` is put into the response unchecked and may
    just be any kind of string; in this case, however, the content type might
    be incorrect.
    """
    return Response(json, mimetype='application/hal+json')


def jsonify(is_utf8_ok, *args, **kwargs):
    """Create a :class:`werkzeug.wrappers.Response` instance with content type
    ``application/hal+json`` containing the passed data structure serialized as
    JSON object.

    `is_utf8_ok` can be either a boolean, or, more frequently, an instance of
    :class:`werkzeug.wrappers.Request`, which includes
    :class:`strbo.rest.JSONRequest` instances. This parameter takes influence
    on JSON serialization via :func:`json.dumps` whose `ensure_ascii` parameter
    will be set accordingly. If `is_utf8_ok` is a boolean, then `ensure_ascii`
    will be `is_utf8_ok` negated; otherwise, `ensure_ascii` will be set to the
    negated outcome of :func:`request_accepts_utf8`.

    The values in `args` and `kwargs` are passed to :func:`json.dumps`, and its
    outcome is packed into a newly created :class:`werkzeug.wrappers.Response`
    instance which is returned by this function
    """
    if args and kwargs:
        raise TypeError(
            'jsonify() behavior undefined when passed both args and kwargs')
    elif len(args) == 1:
        data = args[0]
    else:
        data = args or kwargs

    if isinstance(is_utf8_ok, Request):
        use_utf8 = request_accepts_utf8(is_utf8_ok)
    else:
        use_utf8 = is_utf8_ok

    return _pack_json_into_response(json.dumps(data, skipkeys=True,
                                               ensure_ascii=not use_utf8))


def jsonify_nc(is_utf8_ok, *args, **kwargs):
    """Like :func:`jsonify()`, but add HTTP headers that disallow caching of
    the response."""
    result = jsonify(is_utf8_ok, *args, **kwargs)
    result.headers['Cache-Control'] = 'no-store, must-revalidate'
    return result


def jsonify_simple(*args, **kwargs):
    """Serialize `args` and `kwargs` as JSON object.

    This function strives to provide the same intuitive interface as
    :func:`jsonify`, but it returns a plain string containing the JSON object.
    It is really just a simple wrapper around :func:`json.dumps`.
    """
    if args and kwargs:
        raise TypeError('jsonify_simple() behavior undefined when passed '
                        'both args and kwargs')
    elif len(args) == 1:
        data = args[0]
    else:
        data = args or kwargs

    return json.dumps(data, skipkeys=True, ensure_ascii=False)


def _create_syslog_handler():
    from logging.handlers import SysLogHandler
    from logging import Formatter

    h = SysLogHandler(address='/dev/log')
    f = Formatter('%(name)s: %(message)s')
    h.setFormatter(f)

    return h


_syslog_handler = _create_syslog_handler()


def get_logger(suffix=None, *, prefix='REST', full_name=None):
    """Create a logger with a specific name, logging to ``syslog``.

    This function is primarily concerned with the generation of a logger name
    and adding a ``syslog`` handler to new logger instances. See
    :func:`logging.getLogger` from the :mod:`logging` module for reference.

    The logger name is created from `suffix`, `prefix`, and `full_name`. In
    case `full_name` is not ``None``, it will be used as logger name as is; the
    other parameters will be ignored in this case. Otherwise, the name will be
    `prefix` and `suffix` separated by a slash if `suffix` is not ``None``,
    else it will be just ``prefix``.
    """
    if full_name is not None:
        name = full_name
    elif suffix is None:
        name = prefix
    else:
        name = prefix + '/' + suffix

    import logging
    log = logging.getLogger(name)

    if not log.handlers:
        log.addHandler(_syslog_handler)

    log.setLevel(logging.INFO)

    return log
