#! /bin/sh
#
# Execute an update plan using updata_execute.py
#
# Parameters:
# 1. Path to update plan.
# 2. Which part of the update shall be executed, either 'update' or 'reboot'.
#

set -eu

if /usr/bin/test $# -ne 2; then exit 99; fi

PLAN="$1"
MODE="$2"

if /usr/bin/test "x${MODE}" = 'xupdate'
then
    MODE='--avoid-reboot'
elif /usr/bin/test "x${MODE}" = 'xreboot'
then
    MODE='--reboot-only'
else
    exit 1
fi

exec /usr/bin/updata_execute.py ${MODE} -p "${PLAN}"
