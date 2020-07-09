#! /bin/sh
#
# Generate an update plan by running updata_determine_strategy.py as user
# "updata". We need to run it under that user ID because the script may need to
# mount and unmount the recover system data partition. It make use of sudo, and
# sudo will be configured for updata accordingly.
#
# Parameters:
# 1. Absolute path to directory the plan will be written to.
# 2. This and all the parameters that follow are passed directly to the
#    updata_determine_strategy.py script.
#


set -eu

if /usr/bin/test $# -le 1; then exit 99; fi

WORKDIR="$1"
shift

if /usr/bin/test ! -d "${WORKDIR}"; then exit 51; fi

chown updata:rest "${WORKDIR}"
chmod 775 "${WORKDIR}"

cd /
exec su updata -c "/usr/bin/updata_determine_strategy.py $*"
