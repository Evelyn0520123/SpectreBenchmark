#!/usr/bin/env bash
set -euo pipefail

# Compatibility dispatcher. The actual commands live beside each profile in
# profiles/{bare,sv39,sv48}/reproduce/run.sh; this file never points at the old
# shared code/build tree or at an external EMU.

BASE=${BASE:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}

usage() {
  cat >&2 <<'USAGE'
usage:
  ./run_verified_pocs.sh --list
  ./run_verified_pocs.sh <processor>/<poc>/<profile>
  ./run_verified_pocs.sh <poc>/<profile>
  ./run_verified_pocs.sh all

Examples:
  ./run_verified_pocs.sh xiangshan-v2/spectre-v1-poc-kmhv2/bare
  ./run_verified_pocs.sh spectre-v1-priv-kmhv2/sv48
USAGE
}

mapfile -t CONFIGS < <(find "$BASE" -type f -path '*/profiles/*/reproduce/profile.conf' | sort)
PROFILES=()
for config in "${CONFIGS[@]}"; do
  PROFILES+=("${config%/reproduce/profile.conf}")
done

if [[ "${1:-}" == --list ]]; then
  printf '%s\n' "${PROFILES[@]}" | sed "s#^$BASE/##"
  exit 0
fi

selected=${1:-all}
if [[ "$selected" == all ]]; then
  ((${#PROFILES[@]} > 0)) || { echo 'no profile configurations found' >&2; exit 2; }
  for profile in "${PROFILES[@]}"; do
    echo "=== profile=${profile#"$BASE/"} ==="
    "$profile/reproduce/run.sh"
  done
  exit 0
fi

matches=()
for profile in "${PROFILES[@]}"; do
  rel=${profile#"$BASE/"}
  processor=${rel%%/*}
  rest=${rel#*/}
  poc=${rest%%/profiles/*}
  mode=${rel##*/}
  case "$selected" in
    "$rel"|"$processor/$poc/$mode"|"$poc/$mode") matches+=("$profile") ;;
  esac
done
if ((${#matches[@]} != 1)); then
  echo "profile selector is ambiguous or unknown: $selected" >&2
  usage
  printf 'candidates:\n%s\n' "${matches[@]#"$BASE/"}" >&2
  exit 2
fi
exec "${matches[0]}/reproduce/run.sh"
