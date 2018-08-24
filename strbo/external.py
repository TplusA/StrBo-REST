#! /usr/bin/env python3 # -*- coding: utf-8 -*-

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

from pathlib import Path
import os


class Tools:
    """Keep track of external tools used by endpoint implementations and
    external helper scripts.

    This is the central point to check for OS distribution packagers.

    Creators of REST API distribution packages are responsible for adding
    dependencies on packages containing the executables listed in this class.
    """
    _external_tools = {
        # package: coreutils
        'test':         '/bin/test',
        'rm':           '/bin/rm',
        'readlink':     '/usr/bin/readlink',

        # package: util-linux
        'mountpoint':   '/usr/bin/mountpoint',

        # package: util-linux-mount
        'mount':        '/bin/mount',

        # package: util-linux-umount
        'umount':       '/bin/umount',

        # package: tar
        'tar':          '/bin/tar',

        # package: gnupg
        'gpg':          '/usr/bin/gpg',

        # package: sudo
        'sudo':         '/usr/bin/sudo',

        # package: bash or similar
        'sh':           '/bin/sh',
    }

    @staticmethod
    def get(tool_id):
        """Return path to known executable or throw a :class:`KeyError`
        exception in case the tool is unknown."""
        try:
            return Tools._external_tools[tool_id]
        except KeyError:
            raise KeyError('Tool {} not registered'.format(tool_id))

    @staticmethod
    def invoke(timeout, tool_id, *args):
        """Convenience method for running an external tool with parameters."""
        import subprocess
        cmd = subprocess.Popen([Tools.get(tool_id)] + [str(a) for a in args])
        return cmd.wait(timeout)

    @staticmethod
    def invoke_cwd(cwd, timeout, tool_id, *args):
        """Convenience method for running an external tool with parameters in
        a given working directory."""
        import subprocess
        cmd = subprocess.Popen([Tools.get(tool_id)] + [str(a) for a in args],
                               cwd=str(cwd))
        return cmd.wait(timeout)


class _Helper:
    def __init__(self, script_name, cwd, timeout):
        self._script_name = script_name
        self._timeout = timeout
        self._cwd = str(cwd) if cwd else '/tmp'

    def invoke(self, logger, *args):
        if logger:
            logger.info('Executing helper {} {}'.
                        format(self._script_name,
                               ' '.join([str(a) for a in args])))

        import subprocess
        cmd = subprocess.Popen(
            ['/usr/bin/sudo', str(self._script_name)] + [str(a) for a in args],
            cwd=self._cwd)
        result = cmd.wait(self._timeout)

        if logger:
            if result == 0:
                logger.info('Helper {} succeeded'.format(self._script_name))
            else:
                logger.error('Helper {} exit code {}'.
                             format(self._script_name, result))

        return result


class Helpers:
    """Keep track of external helper scripts.

    These are scripts running with **superuser privileges**.

    Each helper is run by ``sudo``.
    Please keep this in mind when registering a new helper!

    Please, please, please **double and triple check** that helper scripts
    follow best practices for implementing secure shell scripts.
    Put only as much into each helper as is necessary to fulfill its intended
    task with extended privileges, not more.
    Watch out for malicious variable expansions and sanitize untrusted input.

    Murphy's law applies everywhere and at all times.
    """
    _all_helpers = {}
    _path = None
    _logger = None

    @staticmethod
    def set_path(path):
        """Set path to directory of helper scripts."""
        Helpers._path = Path(path)

    @staticmethod
    def set_logger(logger):
        """Set logger instance for logging helper invocations."""
        Helpers._logger = logger

    @staticmethod
    def register(name, dependencies, *, cwd=None, timeout=10):
        """Register a new helper script.

        The `name` serves as helper ID and stem of the helper script name.
        Registering a helper with a name `name` implies the existence of a
        script of the same name with the extension ``.sh`` appended to it.
        You will also use this name when running the helper by calling
        :func:`strbo.external.Helpers.invoke`.

        External dependencies are specified in array or list `dependencies`.
        These are the IDs of external tools the helper script relies on
        (see :class:`strbo.external.Tools`). The purpose of explicitly stating
        dependencies here is to enable keeping track of packages that must be
        installed along with the REST API.

        The dependency on ``sudo`` is always implied and does not
        have to be stated explicitly.

        The working directory for the helper script is passed in `cwd`.

        If the helper has not terminated after `timeout` seconds, then it
        will be killed. In this case, a :class:`subprocess.TimeoutExpired`
        exception will be thrown.
        """
        if name in Helpers._all_helpers:
            raise RuntimeError('Helper {} registered already'.format(name))

        for dep in dependencies:
            try:
                Tools.get(dep)
            except:  # noqa: E722
                raise NameError(
                    'Cannot register helper {} with unmet dependencies'.
                    format(name))

        script = Helpers._path / (name + '.sh')

        if not script.is_file():
            raise FileNotFoundError(
                'Helper script {} does not exist'.format(script))
        elif not os.access(str(script), os.X_OK):
            raise PermissionError(
                'Helper script {} is not executable'.format(script))

        helper = _Helper(script, cwd, timeout)
        Helpers._all_helpers[name] = helper

    @staticmethod
    def invoke(name, *args):
        """Run a registered helper script with superuser privileges."""
        try:
            return Helpers._all_helpers[name].invoke(Helpers._logger, *args)
        except KeyError:
            raise KeyError('Helper {} not registered'.format(name))


def register_helpers(path):
    """Register all helper scripts expected to be found below ``path``."""
    Helpers.set_path(path)
    Helpers.register('mountpoint_mount', ('mount', 'test'), timeout=20)
    Helpers.register('mountpoint_unmount', ('umount', 'test'), timeout=20)
    Helpers.register('replace_recovery_data',
                     ('rm', 'tar', 'readlink', 'test'), timeout=300)
