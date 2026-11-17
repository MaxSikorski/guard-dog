#!/usr/bin/env bash
# Remove Guard Dog's regtest lab completely: containers, the lab network, any
# volume, and lab/.data (the generated regtest logins and the manifest).
# The pulled images stay cached so the next start is quick.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT=gd-lab

# By project name only, so it works even if lab/.data/lab.env is already gone.
docker compose -p "$PROJECT" down --volumes --remove-orphans --timeout 10
rm -rf "$LAB_DIR/.data"

left_c="$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT" | wc -l | tr -d ' ')"
left_n="$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT" | wc -l | tr -d ' ')"
left_v="$(docker volume ls -q --filter "label=com.docker.compose.project=$PROJECT" | wc -l | tr -d ' ')"
if [ "$left_c$left_n$left_v" != "000" ]; then
  echo "lab/down.sh: FAILED: left behind $left_c containers, $left_n networks, $left_v volumes" >&2
  exit 1
fi
echo "gd-lab removed: 0 containers, 0 networks, 0 volumes, lab/.data deleted"
