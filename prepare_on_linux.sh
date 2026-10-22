#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
find "$ROOT" -type f -name "*.sh" -exec chmod +x {} +
find "$ROOT/xiangshan-v3" -path "*/runtime/kmhv3-emu/emu" -type f -exec chmod +x {} +

echo "Prepared executable bits."
echo "Profiles:"
"$ROOT/run_verified_pocs.sh" --list
