#! /bin/sh
#
# Script with runs another script in a hard-coded location. This other script
# is the installer which replaces the recovery partition.
#
# Parameters:
# 1. Path to directory containing the recovery system installer.
#

set -eu

if /usr/bin/test $# -ne 1; then exit 99; fi

if /usr/bin/test -d "$1"
then
    cd "$1"
else
    exit 2
fi

INSTALLER="./flash_recovery_system.sh"

if /usr/bin/test -x "${INSTALLER}"
then
    exec "${INSTALLER}"
fi

exit 3
