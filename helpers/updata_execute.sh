#! /bin/sh
#
# Execute an update plan using the generated script system_update.sh as user
# "updata". The update script is executed in the background, i.e., this script
# will exit very quickly. The update script will continue to run in the
# background.
#
# Parameters:
# 1. Absolute path to the generated script.
# 2. Absolute path to stamp directory.
#

set -eu

if /usr/bin/test $# -ne 2; then exit 99; fi

SCRIPT="$1"
STAMPDIR="$2"

if /usr/bin/test ! -f "${SCRIPT}"; then exit 50; fi
if /usr/bin/test ! -d "${STAMPDIR}"; then exit 51; fi

chown updata:rest "${STAMPDIR}"
chmod 775 "${STAMPDIR}"

PIDFILE="${STAMPDIR}/update.pid"

if test -f "${PIDFILE}"
then
    read -r PID <"${PIDFILE}"
    if /usr/bin/test -d "/proc/${PID}"; then exit 52; fi
    /bin/echo -n '' >"${PIDFILE}"
else
    /bin/touch "${PIDFILE}"
fi

chown updata:rest "${PIDFILE}"

cd /
su updata -c "${SCRIPT}" </dev/null >/dev/null 2>&1 &

echo $! >"${PIDFILE}"
