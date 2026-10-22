#!/usr/bin/env bash
set -euo pipefail

POC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
mapfile -t MODES < <(find "$POC_DIR/profiles" -mindepth 1 -maxdepth 1 -type d -exec test -f '{}/reproduce/profile.conf' ';' -printf '%f\n' | sort)

((${#MODES[@]} > 0)) || { echo "no runnable profiles under $POC_DIR" >&2; exit 2; }

if (($# == 0)); then
  if ((${#MODES[@]} != 1)); then
    printf 'usage: %s <%s>\n' "$0" "$(IFS='|'; echo "${MODES[*]}")" >&2
    exit 2
  fi
  mode=${MODES[0]}
else
  mode=$1
  shift
fi

case "$mode" in bare|sv39|sv48) ;; *) echo "invalid profile mode: $mode" >&2; exit 2 ;; esac
entry="$POC_DIR/profiles/$mode/reproduce/run.sh"
[[ -x "$entry" ]] || { echo "profile entry not found: $entry" >&2; exit 2; }
exec "$entry" "$@"
