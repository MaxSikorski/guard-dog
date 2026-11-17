#!/usr/bin/env bash
# Remove Guard Dog's regtest lab completely: containers, the lab network, any
# volume, and lab/.data (the generated regtest logins and the manifest).
# The pulled images stay cached so the next start is quick.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT=gd-lab
# shellcheck source=lab/lib.sh
. "$LAB_DIR/lib.sh"

# The same lock as lab/up.sh, so the two never run at once. Always taken here:
# up.sh's own clean-up calls lab_teardown directly, while it already holds it.
lab_lock || { echo "lab/down.sh: FAILED: lab/up.sh or another lab/down.sh is running" >&2; exit 1; }
trap lab_unlock EXIT
trap 'exit 130' INT TERM HUP

lab_teardown || { echo "lab/down.sh: FAILED: the lab was not fully removed" >&2; exit 1; }
echo "gd-lab removed: 0 containers, 0 networks, 0 volumes, lab/.data deleted"
