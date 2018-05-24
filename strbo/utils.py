#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from enum import Enum
from werkzeug.wrappers import Request, Response
import json

class MountResult(Enum):
    ALREADY_MOUNTED = 1
    MOUNTED = 2
    FAILED = 3
    TIMEOUT = 4

class UnmountResult(Enum):
    NOT_MOUNTED = 1
    UNMOUNTED = 2
    FAILED = 3
    TIMEOUT = 4

def try_mount_partition(mountpoint, writable = False):
    try:
        import subprocess

        cmd = subprocess.Popen(['mountpoint', '-q', str(mountpoint)])
        if cmd.wait(2) == 0:
            return MountResult.ALREADY_MOUNTED

        cmd = subprocess.Popen(['mount', '-o' + ('rw' if writable else 'ro'), str(mountpoint)])
        if cmd.wait(20) != 0:
            return MountResult.FAILED

        cmd = subprocess.Popen(['mountpoint', '-q', str(mountpoint)])
        if cmd.wait(1) == 0:
            return MountResult.MOUNTED

    except TimeoutError:
        return MountResult.TIMEOUT

    return MountResult.FAILED

def try_unmount_partition(mountpoint):
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

def remove_directory(dir, remove_dir = True):
    for item in dir.iterdir():
        if item.is_dir():
            remove_directory(item, True)
            item.rmdir()
        else:
            item.unlink()

    if remove_dir:
        dir.rmdir()

def request_wants_haljson(request):
    best = request.accept_mimetypes.best_match(['application/hal+json', 'text/html'])
    return best == 'application/hal+json' and request.accept_mimetypes[best] > request.accept_mimetypes['text/html']

def request_accepts_utf8(request):
    return request.accept_charsets.find('utf-8') >= 0

def pack_json_into_response(json):
    return Response(json, mimetype = 'application/json')

def jsonify(is_utf8_ok, *args, **kwargs):
    if args and kwargs:
        raise TypeError('jsonify() behavior undefined when passed both args and kwargs')
    elif len(args) == 1:
        data = args[0]
    else:
        data = args or kwargs

    if isinstance(is_utf8_ok, Request):
        use_utf8 = request_accepts_utf8(is_utf8_ok)
    else:
        use_utf8 = is_utf8_ok

    return pack_json_into_response(json.dumps(data, skipkeys = True, ensure_ascii = not use_utf8))
