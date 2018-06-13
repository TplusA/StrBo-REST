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
    OK                 = 0
    INTERNAL           = 1
    INTERRUPTED        = 2
    INVALID_ID         = 3
    PHYSICAL_MEDIA_IO  = 4
    NET_IO             = 5
    PROTOCOL           = 6
    AUTHENTICATION     = 7
    INCONSISTENT       = 8
    NOT_SUPPORTED      = 9
    PERMISSION_DENIED  = 10
    INVALID_URI        = 11
    BUSY_500           = 12
    BUSY_1000          = 13
    BUSY_1500          = 14
    BUSY_3000          = 15
    BUSY_5000          = 16
    BUSY               = 17
    OUT_OF_RANGE       = 18
    EMPTY              = 19
    OVERFLOWN          = 20
    UNDERFLOWN         = 21
    INVALID_STREAM_URL = 22
    INVALID_STRBO_URL  = 23
    NOT_FOUND          = 24

def is_error(code):
    if isinstance(code, int):
        return code != 0
    else:
        return code is not ErrorCode.OK

def to_string(code):
    try:
        if isinstance(code, int):
            code = int(code)
            return ErrorCode(code).name

        if isinstance(code, ErrorCode):
            return code.name
    except ValueError:
        pass

    return "*** UNKNOWN: {} ***".format(code)

def to_code(code):
    try:
        if isinstance(code, int):
            return ErrorCode(code)

        if isinstance(code, ErrorCode):
            return code
    except ValueError:
        pass

    return ErrorCode.INTERNAL
