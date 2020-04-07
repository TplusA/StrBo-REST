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
        from .external import Tools, Helpers

        if Tools.invoke(2, 'mountpoint', '-q', mountpoint) == 0:
            return MountResult.ALREADY_MOUNTED

        if Helpers.invoke('mountpoint_mount',
                          mountpoint, 'rw' if writable else 'ro') != 0:
            return MountResult.FAILED

        if Tools.invoke(2, 'mountpoint', '-q', mountpoint) == 0:
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
        from .external import Tools, Helpers

        if Tools.invoke(2, 'mountpoint', '-q', mountpoint) != 0:
            return UnmountResult.NOT_MOUNTED

        if Helpers.invoke('mountpoint_unmount', mountpoint) != 0:
            return UnmountResult.FAILED

        if Tools.invoke(2, 'mountpoint', '-q', mountpoint) != 0:
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


def request_accepts_json(request):
    """Check whether or not the WSGI request accepts JSON data in response."""
    best = request.accept_mimetypes.best_match(['application/hal+json',
                                                'application/json',
                                                '*/*'])
    return best is not None and best > '*/*'


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

    In case the request didn't specify to accept JSON responses, an object
    containing a 406 response is returned. (The request is usually passed in
    `is_utf8_ok`, see below.)

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

        if not request_accepts_json(is_utf8_ok):
            return Response(status=406)

    else:
        use_utf8 = is_utf8_ok

    return _pack_json_into_response(json.dumps(data, skipkeys=True,
                                               ensure_ascii=not use_utf8))


def jsonify_e(is_utf8_ok, etag, max_age, *args, **kwargs):
    """Like :func:`jsonify()`, but add HTTP ``ETag:`` to support caching.

    The ETag is simply the string pass in `etag`. If `etag` is empty or
    ``None``, then no ``ETag:`` header is set.

    The maximum time an HTTP client should hold the resource in its cache is
    passed in `max_age`. If `max_age` is negative, then that cache control
    variable will not be set.

    Use in conjunction with :func:`if_none_match()`.
    """
    result = jsonify(is_utf8_ok, *args, **kwargs)

    if result:
        if etag:
            result.set_etag(etag)

        if max_age >= 0:
            result.cache_control.max_age = max_age

    return result


def jsonify_nc(is_utf8_ok, *args, **kwargs):
    """Like :func:`jsonify()`, but add HTTP headers that disallow caching of
    the response."""
    result = jsonify(is_utf8_ok, *args, **kwargs)
    result.cache_control.no_store = True
    result.cache_control.must_revalidate = True
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


def if_none_match(request, etag):
    """Check if requested ETag matches the current ETag.

    `request` is a :class:`werkzeug.wrappers.Request` whose ``if_none_match``
    property is compared to the given `etag`. This property is set only if the
    request HTTP header ``If-None-Match:`` was sent by the HTTP client.

    The `etag` parameter contains the tag for the current version of the
    requested object as returned in previous responses. See :func:`jsonify_e()`
    for a way to set ETags in HTTP responses.

    This function returns a 304 :class:`werkzeug.wrappers.Response` object if
    and only if the request ETag matches the `etag` parameter. The caller
    should return this response object as-is to the HTTP client.

    In case the ETag does not match or was not set by the HTTP client, or if
    the `etag` is ``None`` or emptye, this function returns ``None``. In this
    case, the caller should return the requested resource along with its ETag.
    """
    if not request:
        return None

    if not request.if_none_match:
        return None

    if not etag:
        return None

    return Response(status=304) if etag in request.if_none_match else None


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
