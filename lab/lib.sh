# shellcheck shell=bash
# Shared by lab/up.sh and lab/down.sh (sourced, never run on its own).
# The caller sets LAB_DIR and PROJECT=gd-lab first.

LOCK="$LAB_DIR/.lock"

# One lab operation at a time. The lock is a symlink named lab/.lock whose
# target is the owner's process id: making a symlink is atomic, and a lock left
# behind by a crash (SIGKILL, power loss) is recognised as stale, because its
# owner is gone or is no longer one of our scripts, and is then taken over.
lab_lock() {
  local pid seen moved
  if ln -s "$$" "$LOCK" 2>/dev/null; then return 0; fi
  seen="$(readlink "$LOCK" 2>/dev/null || true)"
  if [[ $seen =~ ^[0-9]+$ ]] && kill -0 "$seen" 2>/dev/null; then
    pid="$seen"
    if ps -p "$pid" -o command= 2>/dev/null | grep -Eq '(up|down)[.]sh'; then return 1; fi
  fi
  # Stale. Move it aside (only one racing process can), check it was the stale
  # one we looked at, then take the lock.
  moved="$LOCK.stale.$$"
  mv "$LOCK" "$moved" 2>/dev/null || return 1
  if [ "$(readlink "$moved" 2>/dev/null || true)" != "$seen" ]; then
    ln -s "$(readlink "$moved")" "$LOCK" 2>/dev/null || true
    rm -f "$moved"
    return 1
  fi
  rm -f "$moved"
  ln -s "$$" "$LOCK" 2>/dev/null
}

# Release the lock, but only if this process owns it.
lab_unlock() {
  if [ "$(readlink "$LOCK" 2>/dev/null || true)" = "$$" ]; then rm -f "$LOCK"; fi
}

# Remove the lab completely. By project name only, so it works even if
# lab/.data/lab.env is already gone. The caller must hold the lock.
lab_teardown() {
  local left_c left_n left_v
  docker compose -p "$PROJECT" down --volumes --remove-orphans --timeout 10 || return 1
  rm -rf "$LAB_DIR/.data"
  left_c="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" | wc -l | tr -d ' ')"
  left_n="$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT" | wc -l | tr -d ' ')"
  left_v="$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT" | wc -l | tr -d ' ')"
  if [ "$left_c$left_n$left_v" != "000" ]; then
    echo "lab: FAILED: left behind $left_c containers, $left_n networks, $left_v volumes" >&2
    return 1
  fi
}
