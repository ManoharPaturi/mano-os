#!/usr/bin/env bash
# Trusted display launcher only; per-task cookie, never the real user's Xauthority.
set -euo pipefail
if [ "$(id -un)" != mano-agent ] || [ ! -f /run/mano-agent/x11-cookie ]; then
  echo 'Lab display identity and task-only cookie required.' >&2
  exit 2
fi
display=
for arg in "$@"; do
  if [[ "$arg" =~ ^:[0-9]+$ ]]; then display=$arg; break; fi
done
test -n "$display"
cookie=$(cat /run/mano-agent/x11-cookie)
printf 'add %s MIT-MAGIC-COOKIE-1 %s\n' "$display" "$cookie" | xauth -f /run/mano-agent/Xauthority
printf '%s\n' "$display" > /run/mano-agent/x11-display
exec /usr/bin/Xwayland "$@" -auth /run/mano-agent/Xauthority
