#! /bin/sh
#
# Unmount a mountpoint.
#
# Parameters:
# 1. Path to mountpoint.
#

set -eu

if /usr/bin/test $# -ne 1; then exit 99; fi

MOUNTPOINT="$1"

exec /bin/umount "${MOUNTPOINT}"
