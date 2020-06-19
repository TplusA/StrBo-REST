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
from threading import Thread
from enum import Enum
import json
import time

from .external import Directories, Tools, Helpers
from .utils import get_logger
log = get_logger()


def _execute_update_plan(plan_file, lockfile):
    """Generate a script which executes the update plan on its own, and run it.

    The script works independently of the REST API so that the REST API itself
    or the web server can safely be updated. If the update would be run as part
    of the REST API, then the web server may be stopped, and the update process
    itself would be killed as well.

    The generated script is initially started from here, but it may continue to
    run or be restarted during startup outside of the REST API. It maintains a
    set of files to store state of execution so that the the script, the REST
    API, and some startup script can find out out the update process is doing.
    """

    tfile = Path('/usr/share/updata/updata_system_update.template.sh')
    workdir = Directories.get('update_workdir')
    shfile = workdir / 'system_update.sh'

    try:
        shfile.unlink()
    except FileNotFoundError:
        pass

    with tfile.open('r') as tf:
        with shfile.open('w') as sh:
            for line in tf.readlines():
                line = line \
                        .replace('@THE_PLAN@', str(plan_file)) \
                        .replace('@STAMP_DIR@', str(workdir)) \
                        .replace('@ALLOW_EXECUTION@', 'yes')
                sh.write(line)

    shfile.chmod(0o775)

    lockfile.unlink()

    if Helpers.invoke('updata_execute', str(shfile), str(workdir)) != 0:
        plan = json.load(plan_file.open('r'))
        log.error('Executing plan FAILED: {}'.format(plan))
        plan_file.unlink()
        with (workdir / 'update_failure').open('w') as f:
            print('REST API failed to execute system updater script', file=f)
        (workdir / 'update_failure_again').touch()


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


class UpdateStatus(Enum):
    """Result of a Streaming Board update as observed by
    :class:`UpdateMonitor`.
    """
    SUCCESS = 1
    ABORTED = 2
    FAILED_FIRST_TIME = 3
    FAILED_SECOND_TIME = 4


class UpdateMonitor(Thread):
    """Start thread which polls the Streaming Board update process.

    The script generated from an UpdaTA template script by internal function
    :func:`_execute_update_plan` maintains a set of files in a working
    directory owned by the REST API. That script runs completely on its own. It
    exposes its state through the file system in form of a few files.

    This class implements a function (running in a thread) which monitors these
    files to find out the progress and act accordingly.
    """
    def __init__(self, workdir, *, start, on_done):
        super().__init__(name='Update Progress Monitor')
        self._workdir = workdir
        self._running = True
        self._on_done = on_done

        if start:
            self.start()

    def request_stop(self):
        """Request termination of the monitoring thread."""
        self._running = False

    def get_workdir(self):
        """Return working directory this thread is monitoring."""
        return self._workdir

    def run(self):
        """Method representing the thread’s activity.

        Please do not call this function directly (except from tests, maybe).
        Instead, set the constructor's ``start`` parameter to ``True`` or call
        :meth:`UpdateMonitor.start` to start the thread.
        """
        log.info('StrBo Update: Monitoring StrBo update process in {}'
                 .format(self._workdir))

        status = UpdateStatus.ABORTED

        while self._running:
            if not self._workdir.exists():
                log.info('StrBo Update: Work directory does not exist, '
                         'we are done here')
                break

            if not (self._workdir / 'update_started').exists():
                log.info('StrBo Update: Not started yet')
                time.sleep(0.5)
                continue

            if not (self._workdir / 'update_done').exists():
                time.sleep(3)
                continue

            if (self._workdir / 'update_failure').exists():
                log.error('StrBo Update: Failed')
                with (self._workdir / 'update_failure').open('r') as f:
                    errors = f.readlines()

                    if errors:
                        log.error('StrBo Update: Captured error messages:\n{}'
                                  .format(''.join(errors)))
                    else:
                        log.error('StrBo Update: No error messages logged')

                if (self._workdir / 'update_failure_again').exists():
                    status = UpdateStatus.FAILED_SECOND_TIME
                else:
                    status = UpdateStatus.FAILED_FIRST_TIME
            else:
                log.info('StrBo Update: Complete')
                status = UpdateStatus.SUCCESS

            self._running = False

        if self._on_done:
            self._on_done(status)
