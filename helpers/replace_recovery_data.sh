#! /bin/sh
#
# Remove existing partition images from flash memory, extract new
# image files from tar archive.
#
# Parameters:
# 1. Path to tar archive containing the image files.
# 2. Path to directory containing the partition images.
#

set -eu

if /usr/bin/test $# -ne 2; then exit 99; fi

TARFILE="$1"
DESTDIR="$(/usr/bin/readlink -e $2)"

if /usr/bin/test "x${TARFILE}" != 'x' && /usr/bin/test -f "${TARFILE}"
then
    if /usr/bin/test "x${DESTDIR}" != 'x' && /usr/bin/test -d "${DESTDIR}"
    then
        :
    else
        exit 2
    fi
else
    exit 1
fi

if /usr/bin/test "x${DESTDIR}" = 'x/'
then
    exit 3
fi

cd "${DESTDIR}"

/bin/rm -rf *
exec /bin/tar xf "${TARFILE}"
