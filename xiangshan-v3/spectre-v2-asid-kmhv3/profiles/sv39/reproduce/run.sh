#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROFILE_DIR=$(cd "$HERE/.." && pwd)
REPO_ROOT=$(cd "$HERE/../../../../.." && pwd)

case "$(basename "$0")" in
  run.sh) STAGE=all ;;
  verify.sh) STAGE=verify ;;
  build.sh) STAGE=build ;;
  parse.sh) STAGE=parse ;;
  *) echo "invoke this file as run.sh, verify.sh, build.sh, or parse.sh" >&2; exit 2 ;;
esac

exec bash "$REPO_ROOT/tools/profile_runner.sh" "$PROFILE_DIR" "$STAGE" "$@"
