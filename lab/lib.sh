# shellcheck shell=bash
# Shared by lab/up.sh and lab/down.sh (sourced, never run on its own).
# The caller sets LAB_DIR and PROJECT=gd-lab first.

LOCK="$LAB_DIR/.lock"

# One lab operation at a time. The lock is a directory, lab/.lock, with the
# owner's process id inside. `mkdir` is atomic and fails if anything at all
# already exists at that path. A lock is never taken over automatically, not even
# one left by a crash: the person checks, then runs `lab/down.sh --unlock`.
lab_lock() {
  local holder state=""
  if mkdir "$LOCK" 2>/dev/null; then
    if printf '%s\n' "$$" > "$LOCK/pid"; then return 0; fi
    rm -f "$LOCK/pid"
    rmdir "$LOCK" 2>/dev/null || true
    echo "lab: could not write the lock's owner file" >&2
    return 1
  fi
  holder="$(cat "$LOCK/pid" 2>/dev/null || true)"
  if [[ $holder =~ ^[0-9]+$ ]]; then
    if kill -0 "$holder" 2>/dev/null; then state="running"; else state="not running"; fi
    echo "lab: lab/.lock exists, left by process $holder ($state)." >&2
  else
    echo "lab: lab/.lock exists, and names no process." >&2
  fi
  echo "lab: once you have checked that no lab/up.sh or lab/down.sh is running, run: lab/down.sh --unlock" >&2
  return 1
}

# Release the lock, but only if this process owns it.
lab_unlock() {
  if [ -d "$LOCK" ] && [ ! -L "$LOCK" ] && [ "$(cat "$LOCK/pid" 2>/dev/null || true)" = "$$" ]; then
    rm -f "$LOCK/pid"
    rmdir "$LOCK"
  fi
}

# `lab/down.sh --unlock`: remove the lock directory and nothing else.
lab_force_unlock() {
  if [ ! -e "$LOCK" ] && [ ! -L "$LOCK" ]; then
    echo "lab: no lock to remove"
    return 0
  fi
  if [ -L "$LOCK" ] || [ ! -d "$LOCK" ]; then
    echo "lab: lab/.lock is not a lock directory; leaving it for you to look at" >&2
    return 1
  fi
  rm -f "$LOCK/pid" || return 1
  rmdir "$LOCK" || { echo "lab: lab/.lock holds something besides its owner file; leaving it" >&2; return 1; }
  echo "lab: lock removed"
}

# Remove the lab completely. By project name only, so it works even if
# lab/.data/lab.env is already gone. The caller must hold the lock.
lab_teardown() {
  local left_c left_n left_v
  docker compose -p "$PROJECT" down --volumes --remove-orphans --timeout 10 || return 1
  rm -rf "$LAB_DIR/.data" || return 1
  left_c="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" | wc -l | tr -d ' ')" || return 1
  left_n="$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT" | wc -l | tr -d ' ')" || return 1
  left_v="$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT" | wc -l | tr -d ' ')" || return 1
  if [ "$left_c$left_n$left_v" != "000" ]; then
    echo "lab: FAILED: left behind $left_c containers, $left_n networks, $left_v volumes" >&2
    return 1
  fi
}
