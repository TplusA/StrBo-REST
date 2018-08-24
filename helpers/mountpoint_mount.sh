#! /bin/sh
#
# Mount a mountpoint configured in fstab.
#
# Parameters:
# 1. Path to mountpoint.
# 2. Restricted mount options string, either 'rw' or 'ro'.
#

set -eu

if /usr/bin/test $# -ne 2; then exit 99; fi

MOUNTPOINT="$1"
OPTION="$2"

if /usr/bin/test "x${OPTION}" != 'xrw' && /usr/bin/test "x${OPTION}" != 'xro'
then
    exit 1
fi

exec /bin/mount -o ${OPTION} "${MOUNTPOINT}"
