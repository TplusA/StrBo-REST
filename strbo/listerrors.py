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

from enum import Enum, unique


@unique
class ErrorCode(Enum):
    """Error codes used throughout the StrBo software stack."""
    OK = 0
    INTERNAL = 1
    INTERRUPTED = 2
    INVALID_ID = 3
    PHYSICAL_MEDIA_IO = 4
    NET_IO = 5
    PROTOCOL = 6
    AUTHENTICATION = 7
    INCONSISTENT = 8
    NOT_SUPPORTED = 9
    PERMISSION_DENIED = 10
    INVALID_URI = 11
    BUSY_500 = 12
    BUSY_1000 = 13
    BUSY_1500 = 14
    BUSY_3000 = 15
    BUSY_5000 = 16
    BUSY = 17
    OUT_OF_RANGE = 18
    EMPTY = 19
    OVERFLOWN = 20
    UNDERFLOWN = 21
    INVALID_STREAM_URL = 22
    INVALID_STRBO_URL = 23
    NOT_FOUND = 24


def is_error(code):
    """Check whether or not the given error code is actually an error.

    The `code` may be either an :class:`ErrorCode` or a plain integer.
    Note that no range check will be performed for plain integers.
    """
    if isinstance(code, int):
        return code != 0
    else:
        return code is not ErrorCode.OK


def to_string(code):
    """Convert error code to string representation, no exceptions thrown.

    The `code` may be either an :class:`ErrorCode` or a plain integer.

    If `code` is an integer which is out of range, or if `code` is not an
    instance of :class:`ErrorCode`, then a distinguishable string hinting at
    the problem with `code` is returned.
    """
    try:
        if isinstance(code, int):
            code = int(code)
            return ErrorCode(code).name

        if isinstance(code, ErrorCode):
            return code.name
    except ValueError:
        pass

    try:
        return "*** UNKNOWN: {} ***".format(code)
    except Exception:
        return "*** UNKNOWN ERROR CODE WITH NO STRING REPRESENTATION ***"


def to_code(code):
    """Convert integer code to :class:`ErrorCode`.

    In case the integer passed in `code` is out of range, no exception is
    thrown and ``ErrorCode.INTERNAL`` is returned.

    For convenience, it is permissible to pass :class:`ErrorCode` instances in
    `code`, in which case this function will simply return `code`.
    """
    try:
        if isinstance(code, int):
            return ErrorCode(code)

        if isinstance(code, ErrorCode):
            return code
    except ValueError:
        pass

    return ErrorCode.INTERNAL
