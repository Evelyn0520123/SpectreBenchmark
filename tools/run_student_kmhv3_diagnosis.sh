#!/usr/bin/env bash
set -euo pipefail

ROOT=$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")
XIANGSHAN_V3_ROOT="$ROOT/xiangshan-v3"
CREATE_SCRIPT="$ROOT/tools/create_student_kmhv3_diagnosis_profiles.sh"

if [[ ! -f "$CREATE_SCRIPT" ]]; then
  echo "missing create script: $CREATE_SCRIPT" >&2
  exit 2
fi

if [[ ! -d "$XIANGSHAN_V3_ROOT/spectre-v2-poc-kmhv3-diag" ]]; then
  bash "$CREATE_SCRIPT"
fi

RUN_PREFIX=${RUN_PREFIX:-student-diag-$(date -u +%Y%m%dT%H%M%SZ)}

run_one() {
  local poc_dir="$1"
  local short_name="$2"
  local run_id="${RUN_PREFIX}-${short_name}"
  local entry="$poc_dir/profiles/bare/reproduce/run.sh"
  local status_json="$poc_dir/profiles/bare/runs/$run_id/status.json"
  local rc status

  echo
  echo "[student-kmhv3-diag] running $short_name with RUN_ID=$run_id"

  set +e
  RUN_ID="$run_id" bash "$entry"
  rc=$?
  set -e

  if [[ -f "$status_json" ]]; then
    status=$(python3 - "$status_json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    print(json.load(fh).get("status", "STATUS_MISSING"))
PY
)
  else
    status="STATUS_JSON_MISSING"
  fi

  printf '[student-kmhv3-diag] %-10s exit=%s status=%s\n' "$short_name" "$rc" "$status"
  printf '[student-kmhv3-diag] status_json=%s\n' "$status_json"
  return 0
}

run_one "$XIANGSHAN_V3_ROOT/spectre-v2-poc-kmhv3-diag" "v2-byte0"
run_one "$XIANGSHAN_V3_ROOT/spectre-v5-poc-kmhv3-diag" "v5-byte0"

echo
echo "[student-kmhv3-diag] done. Review the two status.json and result.json files under xiangshan-v3/*-diag/profiles/bare/runs/$RUN_PREFIX-*"
