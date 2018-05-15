#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from pathlib import Path, PurePath
from hashlib import sha256

from .urlmap import url_for
from .utils import jsonify
from .utils import try_mount_partition, MountResult
from .utils import try_unmount_partition, UnmountResult

def generate_file_info(file, checksums, with_verify):
    expected = 'unavailable' if not checksums or file.name not in checksums else checksums[file.name]

    fi = {
        'name': file.name,
        'expected_checksum': expected,
        'verified': with_verify
    }

    if with_verify:
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

def get_info_or_verify(request, mountpoint, with_verify, **values):
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
        fileset.append(generate_file_info(temp, checksums, with_verify))

        for temp in sorted(p.glob('*.bin')):
            fileset.append(generate_file_info(temp, checksums, with_verify))

        if not with_verify:
            overall_valid_state = 'unknown'
        else:
            overall_valid_state = 'valid' if all([f['is_valid'] for f in fileset]) else 'broken'
    else:
        overall_valid_state = 'unavailable'

    if not version_info:
        version_info = { 'is_valid': 'false' }

    return jsonify(request,
                   version_info = version_info,
                   recovery_system_state = {
                       'recovery_files': fileset,
                       'state': overall_valid_state
                   })

def get_info_or_verify_wrapper(request, with_verify, **values):
    mountpoint = Path('/mnt')

    try:
        result = get_info_or_verify(request, mountpoint, with_verify, **values)
    except:
        try_unmount_partition(mountpoint)
        raise

    try_unmount_partition(mountpoint)

    return result

def on_recovery_system_info(request, **values):
    return get_info_or_verify_wrapper(request, False, **values)

def on_recovery_system_verify(request, **values):
    return get_info_or_verify_wrapper(request, True, **values)

def on_recovery_system(request, **values):
    return jsonify(request,
                   info = url_for(request, 'recovery_system_info'),
                   verify = url_for(request, 'recovery_system_verify'))
