#!/usr/bin/env bash
# Called only inside the fresh disposable Debian VM, never on the runner/host.
set -euo pipefail
source /opt/mano-lab/scripts/guest_guard.sh
require_disposable_guest
expected_sha=$1
[[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]]
printf '%s  %s\n' "$expected_sha" /var/tmp/mano-runtime.deb | sha256sum -c -
python3 /opt/mano-lab/scripts/probe_stock_runtime.py baseline
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends /var/tmp/mano-runtime.deb
dpkg-query -W > /opt/mano-lab/evidence/stock-runtime-packages.tsv
# This driver dependency is test-only and is installed after runtime dependency resolution.
apt-get install -y --no-install-recommends python3-pyatspi
script --quiet --return --command 'mano-runtime-setup lab --enable' /dev/null
python3 - "$expected_sha" <<'PY'
import json,sys
from pathlib import Path
value=dict(package_sha256=sys.argv[1],package_bytes=Path('/var/tmp/mano-runtime.deb').stat().st_size,
    no_recommends=True,test_only_packages=['python3-pyatspi'],
    build=json.loads(Path('/usr/share/doc/mano-runtime/build-info.json').read_text()))
Path('/opt/mano-lab/evidence/stock-runtime-install.json').write_text(json.dumps(value,indent=2)+'\n')
PY
PYTHONDONTWRITEBYTECODE=1 python3 /opt/mano-lab/scripts/probe_stock_runtime.py before
