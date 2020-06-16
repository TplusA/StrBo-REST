#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2020  T+A elektroakustik GmbH & Co. KG
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
import json

from .external import Directories, Tools, Helpers
from .utils import get_logger
log = get_logger()


def _execute_update_plan(plan_file, lockfile):
    # pure update without a reboot
    if Helpers.invoke('updata_execute', str(plan_file), 'update') != 0:
        plan = json.load(plan_file.open('r'))
        log.error('Update plan FAILED: {}'.format(plan))
        plan_file.unlink()
        return

    lockfile.unlink()

    # execute for possible reboot
    log.info('Execute for reboot')
    Helpers.invoke('updata_execute', str(plan_file), 'reboot')

    plan_file.unlink()


_update_name_to_cmdline_arg = {
    'base_url': '--base-url',
    'target_version': '--target-version',
    'target_release_line': '--target-release-line',
    'target_flavor': '--target-flavor',
}

_update_name_to_cmdline_flag = {
    'force_update_through_image_files': '--force-image-files',
    'force_recovery_system_update': '--force-rsys-update',
    'keep_user_data': '--keep-user-data',
}


def _perform_parameterized_update(request, lockfile):
    args = []

    for k in request.keys():
        arg = _update_name_to_cmdline_arg.get(k, None)
        if arg is not None:
            if request[k]:
                args.append(arg)
                args.append(request[k])
            continue

        arg = _update_name_to_cmdline_flag.get(k, None)
        if arg is not None:
            if request[k]:
                args.append(arg)

    pf = Directories.get('update_workdir') / 'rest_update.plan'
    args.append('--output-file')
    args.append(pf)

    if Tools.invoke(15, 'updata_plan', args) == 0:
        _execute_update_plan(pf, lockfile)
        return

    log.error('Failed generating upgrade plan')

    if pf.exists():
        pf.unlink()


def update(request, lockfile):
    """Interpret update request for Streaming Board and execute it.

    This function tries to perform the update as requested. To this end, it
    creates or takes an update plan and utilizes UpdaTA via a helper script to
    execute the plan.

    Note that UpdaTA may make use of the REST API in case the recovery system
    gets involved. Also note that UpdaTA may request a system reboot.
    """

    log.info('Updating Streaming Board: {}'.format(request))

    # figure out what the request wants us to do
    if 'base_url' in request:
        # parameters from which UpdaTA can create a plan
        _perform_parameterized_update(request, lockfile)
    elif 'plan' in request:
        # embedded update plan
        pf = Directories.get('update_workdir') / 'rest_update.plan'
        with pf.open('w') as f:
            f.write(json.dumps(request['plan']))

        _execute_update_plan(pf, lockfile)
    elif 'plan_file' in request:
        # update plan stored on file in our local file system
        _execute_update_plan(Path(request['plan_file']), lockfile)
    else:
        log.warning('Don\'t know what to do for StrBo update request')
