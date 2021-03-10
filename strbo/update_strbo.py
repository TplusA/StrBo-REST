#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2020, 2021  T+A elektroakustik GmbH & Co. KG
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
from enum import Enum, IntEnum
import json
import time

from .external import Directories, Files, Helpers
from .utils import get_logger, is_process_running, remove_file
log = get_logger()


class ExecResult(Enum):
    """Result of an update execution request.
    """
    NOT_STARTED = 1
    RUNNING = 2
    BAD_REQUEST = 3
    PLANNING_FAILED = 4
    NO_PLAN = 5
    EXECUTION_FAILED = 6
    FAILED_CREATE_LOCKFILE = 7


def _execute_update_plan(plan_file, lockfile, keep_existing_script=False):
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

    workdir = Directories.get('update_workdir')
    shfile = workdir / 'system_update.sh'

    if not shfile.exists() or not keep_existing_script:
        if shfile.exists():
            log.info('Replacing existing system update script')

        tfile = Files.get('updata_script_template')

        remove_file(shfile)

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

    if Helpers.invoke('updata_execute', str(shfile), str(workdir)) == 0:
        return ExecResult.RUNNING

    if plan_file.exists():
        exec_result = ExecResult.EXECUTION_FAILED
        plan = json.load(plan_file.open('r'))
        log.error('Executing plan FAILED: {}'.format(plan))
        plan_file.unlink()
    else:
        exec_result = ExecResult.NO_PLAN

    # create state RF with our own error message so that the
    # :class:`UpdateMonitor` can see it
    remove_file(workdir / 'update_failure')
    remove_file(workdir / 'update_done')
    remove_file(workdir / 'update_reboot_failed')
    remove_file(workdir / 'update_reboot_stderr')
    remove_file(workdir / 'update_reboot_started')
    remove_file(workdir / 'update_failure_again')

    (workdir / 'update_started').touch()

    file = workdir / 'update_failure'
    with file.open('w') as f:
        print('REST API failed to execute system updater script', file=f)

    (workdir / 'update_failure_again').touch()
    remove_file(workdir / 'update.pid')

    return exec_result


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
    args = [Directories.get('update_workdir')]

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

    try:
        if Helpers.invoke('updata_plan', args) == 0:
            return _execute_update_plan(pf, lockfile)
    except Exception as e:
        log.error('Failed generating upgrade plan: {}'.format(e))
    else:
        log.error('Failed generating upgrade plan')

    remove_file(pf)
    return ExecResult.PLANNING_FAILED


def exec_update(request, lockfile):
    """Interpret update request for Streaming Board and execute it.

    This function tries to perform the update as requested. To this end, it
    creates or takes an update plan and utilizes UpdaTA via a helper script to
    execute the plan.

    Note that UpdaTA may make use of the REST API in case the recovery system
    gets involved. Also note that UpdaTA may request a system reboot.
    """
    if is_process_running(Directories.get('update_workdir') / 'update.pid'):
        log.error('Failed starting update because another update process '
                  'is already running')
        return

    log.info('Updating Streaming Board: {}'.format(request))

    # figure out what the request wants us to do
    if 'base_url' in request:
        # parameters from which UpdaTA can create a plan
        exec_result = _perform_parameterized_update(request, lockfile)
    elif 'plan' in request:
        # embedded update plan
        pf = Directories.get('update_workdir') / 'rest_update.plan'
        with pf.open('w') as f:
            f.write(json.dumps(request['plan']))

        exec_result = _execute_update_plan(pf, lockfile)
    elif 'plan_file' in request:
        # update plan stored on file in our local file system
        exec_result = \
            _execute_update_plan(Path(request['plan_file']), lockfile,
                                 request.get('keep_existing_updata_script',
                                             False))
    else:
        log.warning('Don\'t know what to do for StrBo update request')
        exec_result = ExecResult.BAD_REQUEST

    return exec_result


class UpdateStatus(Enum):
    """Result of a Streaming Board update as observed by
    :class:`UpdateMonitor`.
    """
    DETACH_UPDATE_MONITOR = 0
    SUCCESS = 1
    ABORTED = 2
    FAILED_FIRST_TIME = 3
    FAILED_SECOND_TIME = 4
    FINAL_REBOOT_FAILED = 5


class UpdateScriptState(IntEnum):
    """State of update script derived from the various stamp files."""
    INIT = 0
    U = 1 << 0
    US = 1 << 0 | 1 << 1
    UR = 1 << 0 | 1 << 1 | 1 << 4
    UR2 = 1 << 0 | 1 << 1 | 1 << 4 | 1 << 5
    URF = 1 << 0 | 1 << 1 | 1 << 4 | 1 << 5 | 1 << 6
    UF = 1 << 0 | 1 << 2
    RF = 1 << 0 | 1 << 2 | 1 << 3
    FR = 1 << 0 | 1 << 2 | 1 << 4
    FR2 = 1 << 0 | 1 << 2 | 1 << 4 | 1 << 5
    FRF = 1 << 0 | 1 << 2 | 1 << 4 | 1 << 5 | 1 << 6
    DONE = 1 << 7
    NOT_RUNNING = 1 << 8
    INVALID = 1 << 9


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
        self._stop_requested = False
        self._running = True
        self._on_done = on_done

        if start:
            self.start()

    def request_stop(self):
        """Request termination of the monitoring thread."""
        self._stop_requested = True
        self._running = False

    def get_workdir(self):
        """Return working directory this thread is monitoring."""
        return self._workdir

    def determine_script_state(self):
        if not self._workdir.is_dir():
            return UpdateScriptState.NOT_RUNNING

        if (self._workdir / 'update_finished').exists():
            return UpdateScriptState.DONE

        files = \
            ((self._workdir / 'update_started').exists() << 0) | \
            ((self._workdir / 'update_done').exists() << 1) | \
            ((self._workdir / 'update_failure').exists() << 2) | \
            ((self._workdir / 'update_failure_again').exists() << 3) | \
            ((self._workdir / 'update_reboot_started').exists() << 4) | \
            ((self._workdir / 'update_reboot_stderr').exists() << 5) | \
            ((self._workdir / 'update_reboot_failed').exists() << 6)

        try:
            return UpdateScriptState(files)
        except ValueError:
            return UpdateScriptState.INVALID

    def run(self):
        """Method representing the thread’s activity.

        Please do not call this function directly (except from tests, maybe).
        Instead, set the constructor's ``start`` parameter to ``True`` or call
        :meth:`UpdateMonitor.start` to start the thread.
        """
        log.info('StrBo Update: Monitoring StrBo update process in {}'
                 .format(self._workdir))

        status = UpdateStatus.ABORTED
        log_counter = 0
        pid_file = self._workdir / 'update.pid'

        while self._running:
            script_state = self.determine_script_state()

            if script_state == UpdateScriptState.INVALID:
                # ignore transients
                log.info('StrBo Update: Invalid state (ignored)')
                time.sleep(0.5)
                continue

            if script_state == UpdateScriptState.NOT_RUNNING:
                log.info('StrBo Update: Work directory does not exist, '
                         'we are done here')
                self._running = False
                continue

            if script_state == UpdateScriptState.INIT:
                log.info('StrBo Update: Not started yet')
                status = UpdateStatus.SUCCESS
                time.sleep(0.5)
                continue

            if is_process_running(pid_file):
                if log_counter == 0:
                    log.info('StrBo Update: Not finished yet: {}'
                             .format(script_state))
                    log_counter = 4
                else:
                    log_counter -= 1

                time.sleep(3)
                continue

            def dump_file_as_error(fname, what, must_exist=True):
                try:
                    f = (self._workdir / fname).open('r')
                except Exception as e:
                    if must_exist:
                        log.error('StrBo Update: Expected error file {} '
                                  'does not exist ({})'.format(fname, e))
                    return

                errors = f.readlines()

                if errors:
                    log.error('StrBo Update: Captured {} error messages:\n{}'
                              .format(what, ''.join(errors)))
                else:
                    log.error('StrBo Update: No error messages logged for {}'
                              .format(what))

            if script_state in (UpdateScriptState.UR2, UpdateScriptState.FR2):
                # rebooting regularly
                log.info('StrBo Update: Expecting reboot')
                time.sleep(2)
                continue

            if script_state is UpdateScriptState.DONE:
                # complete and done, over and out
                status = UpdateStatus.SUCCESS
            elif script_state is UpdateScriptState.URF:
                # update OK, but reboot request failed
                log.critical('StrBo Update: Reboot failed')
                dump_file_as_error('update_reboot_failed', 'reboot')
                status = UpdateStatus.FINAL_REBOOT_FAILED
            elif script_state is UpdateScriptState.FRF:
                # update failed, reboot request failed as well
                log.critical('StrBo Update: Failed, reboot failed as well')
                dump_file_as_error('update_failure', 'update')
                dump_file_as_error('update_reboot_failed', 'reboot')
                status = UpdateStatus.FAILED_FIRST_TIME
            elif script_state is UpdateScriptState.RF:
                # repeated failure
                log.error('StrBo Update: Failed')
                dump_file_as_error('update_failure', 'update')
                status = UpdateStatus.FAILED_SECOND_TIME
            else:
                # update stopped in unexpected state
                log.critical('StrBo Update: Stopped in unexpected state {}'
                             .format(script_state))
                dump_file_as_error('update_failure', 'update', False)
                dump_file_as_error('update_reboot_failed', 'reboot', False)
                status = UpdateStatus.ABORTED

            self._running = False

        if self._on_done:
            if self._stop_requested:
                self._on_done(UpdateStatus.DETACH_UPDATE_MONITOR)
            else:
                self._on_done(status)
