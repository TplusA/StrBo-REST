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

MPPATTERN="$(echo ${MOUNTPOINT} | sed 's,/,\\/,g')"
TUPLE="$(sed -n '/ '"${MPPATTERN}"' /{s,^\([^ ]\+\) [^ ]\+ \([^ ]\+\) .*,\1 \2,gp}' </etc/fstab)"
if /usr/bin/test "x${TUPLE}" = 'x'; then exit 2; fi

DEVICE="$(echo "${TUPLE}" | cut -f 1 -d ' ')"
if /usr/bin/test "x${DEVICE}" = 'x'; then exit 3; fi

set +e
TRIES=5
while /usr/bin/test ${TRIES} -gt 0
do
    if /sbin/fsck -y "${DEVICE}"; then break; fi
    TRIES=$(expr ${TRIES} - 1)
done
set -e

if /bin/mount -o ${OPTION} "${MOUNTPOINT}"
then
    LAF="${MOUNTPOINT}/lost+found"
    if test ! -d "${LAF}"; then exit 0; fi
    if test "x$(find "${LAF}" -maxdepth 0 -empty)" != x; then exit 0; fi
    cd "${LAF}" && find . -maxdepth 1 ! -name . -exec rm -rf {} \;
    exit 0
fi

# cannot mount file system even after multiple runs of fsck: let's format it
. /etc/systeminfo.rc

PARTITION_RECDATA_DEVICE=${PARTITION_RECDATA_DEVICE:-invalid}

if /usr/bin/test "${DEVICE}" = "${PARTITION_CONFIGFS_DEVICE}"
then
    MKFS_OPTIONS="${PARTITION_CONFIGFS_MKFS_OPTIONS}"
    FSTYPE="${PARTITION_CONFIGFS_TYPE}"
elif /usr/bin/test "${DEVICE}" = "${PARTITION_SPAREFS_DEVICE}"
then
    MKFS_OPTIONS="${PARTITION_SPAREFS_MKFS_OPTIONS}"
    FSTYPE="${PARTITION_SPAREFS_TYPE}"
elif /usr/bin/test "${DEVICE}" = "${PARTITION_RECDATA_DEVICE}"
then
    MKFS_OPTIONS="${PARTITION_RECDATA_MKFS_OPTIONS}"
    FSTYPE="${PARTITION_RECDATA_TYPE}"
else
    FSTYPE="$(echo "${TUPLE}" | cut -f 2 -d ' ')"

    if /usr/bin/test "${FSTYPE}" = 'ext4'
    then
        MKFS_OPTIONS='-m 0 -i 4096'
    else
        MKFS_OPTIONS=
    fi
fi

if /usr/bin/test "x${FSTYPE}" = 'x'; then exit 4; fi

/sbin/mkfs.${FSTYPE} ${MKFS_OPTIONS} "${DEVICE}"

exec /bin/mount -o ${OPTION} "${MOUNTPOINT}"
