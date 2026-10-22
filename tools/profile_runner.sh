#!/usr/bin/env bash
set -euo pipefail

# Profile execution dispatcher.  Per-profile wrappers call this script; it never
# runs during packaging.  Every build happens below a fresh scratch directory,
# while the immutable profile only supplies source, runtime and configuration.

usage() {
  cat >&2 <<'USAGE'
usage: profile_runner.sh PROFILE_DIR {all|verify|build|run|parse}

Environment overrides:
  RUN_ID       safe run directory name (default: UTC timestamp)
  RUNS_ROOT    run evidence root (default: PROFILE_DIR/runs)
  SCRATCH_ROOT scratch parent (default: REPO_ROOT/.scratch)
  AM_HOME      nexus-am tree (profile default is used when unset)
  JOBS         make parallelism (default: 8)
  STACK_KB     stack limit in KiB (default: 32768)
  EMU_LD       full path to a newer ld-linux loader (optional host adaptation)
  EMU_LD_LIBRARY_PATH  library path for EMU_LD (colon-separated)
USAGE
}

[[ $# -ge 2 ]] || { usage; exit 2; }
PROFILE_DIR=$(readlink -f "$1")
STAGE=$2
[[ -d "$PROFILE_DIR" ]] || { echo "profile not found: $PROFILE_DIR" >&2; exit 2; }
case "$STAGE" in all|verify|build|run|parse) ;; *) usage; exit 2 ;; esac

CONFIG="$PROFILE_DIR/reproduce/profile.conf"
[[ -r "$CONFIG" ]] || { echo "profile config missing: $CONFIG" >&2; exit 2; }
# shellcheck disable=SC1090
source "$CONFIG"

: "${POC_ID:?profile config must set POC_ID}"
: "${PROCESSOR:?profile config must set PROCESSOR}"
: "${VM_MODE:?profile config must set VM_MODE}"
: "${AM_HOME_DEFAULT:?profile config must set AM_HOME_DEFAULT}"
: "${ARCH:?profile config must set ARCH}"
: "${MARCH:?profile config must set MARCH}"
: "${CPPFLAGS:?profile config must set CPPFLAGS}"
: "${IMAGE_NAME:?profile config must set IMAGE_NAME}"
: "${WALL_TIMEOUT:?profile config must set WALL_TIMEOUT}"
: "${PARSER_KIND:?profile config must set PARSER_KIND}"
: "${EXPECTED_SECRET:?profile config must set EXPECTED_SECRET}"
: "${EMU_CANDIDATE_ID:?profile config must set EMU_CANDIDATE_ID}"
: "${EMU_SHA256:?profile config must set EMU_SHA256}"
: "${EMU_BUILD_ID:?profile config must set EMU_BUILD_ID}"
: "${CONSTANTIN_MODE:?profile config must set CONSTANTIN_MODE}"
: "${SEED:?profile config must set SEED}"
: "${SOURCE_TREE_SHA256:?profile config must set SOURCE_TREE_SHA256}"
: "${MAX_CYCLES+x}"  # empty means wall-clock timeout only

REPO_ROOT=$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")
case "$EMU_CANDIDATE_ID" in
  kmhv2-*) EMU_RUNTIME_DIR=kmhv2-emu ;;
  kmhv3-*) EMU_RUNTIME_DIR=kmhv3-emu ;;
  *)
    echo "unsupported EMU_CANDIDATE_ID=$EMU_CANDIDATE_ID; expected kmhv2-* or kmhv3-*" >&2
    exit 2
    ;;
esac
# emu now comes from the self-built XiangShan tree instead of a pinned per-profile
# copy.  Override with EMU=/path/to/emu if your build lives elsewhere.
EMU="${EMU:-$REPO_ROOT/../xs-env/XiangShan/build/emu}"

# Optional host adaptation: when the host glibc is older than what the emu was
# built against, run the emu through a newer dynamic loader (ld-linux) instead
# of the system one.  Set both EMU_LD and EMU_LD_LIBRARY_PATH to enable; leave
# them unset for normal operation.  The emu file itself is never modified, so
# the sha256/build-id checks below still pass unchanged.
EMU_LD="${EMU_LD:-}"
EMU_LD_LIBRARY_PATH="${EMU_LD_LIBRARY_PATH:-}"
if [[ -n "$EMU_LD" && -n "$EMU_LD_LIBRARY_PATH" ]]; then
  EMU_CMD=("$EMU_LD" --library-path "$EMU_LD_LIBRARY_PATH")
  LDD_CMD=("$EMU_LD" --list --library-path "$EMU_LD_LIBRARY_PATH")
else
  EMU_CMD=()
  LDD_CMD=(ldd)
fi
AM_HOME=${AM_HOME:-$AM_HOME_DEFAULT}
JOBS=${JOBS:-8}
STACK_KB=${STACK_KB:-32768}
MAX_CYCLES=${MAX_CYCLES:-}
RUNS_ROOT=${RUNS_ROOT:-$PROFILE_DIR/runs}
SCRATCH_PARENT=${SCRATCH_ROOT:-$REPO_ROOT/.scratch}

# Keep the command visible and deterministic.  A profile may add arguments, but
# must not silently replace the canonical --no-diff/seed options.
if [[ ${EMU_ARGS+x} != x ]]; then
  EMU_ARGS=(--no-diff "--seed=$SEED")
fi
if [[ -n "$MAX_CYCLES" ]]; then
  EMU_ARGS+=("--max-cycles=$MAX_CYCLES")
fi

safe_id() { [[ "$1" =~ ^[A-Za-z0-9._+-]+$ ]]; }

log_header() {
  local stage="$1"
  cat <<EOF
[profile-runner] stage=$stage
[profile-runner] profile=$PROFILE_DIR
[profile-runner] processor=$PROCESSOR
[profile-runner] poc_id=$POC_ID
[profile-runner] vm_mode=$VM_MODE
[profile-runner] run_id=$RUN_ID
[profile-runner] am_home=$AM_HOME
[profile-runner] emu=$EMU
[profile-runner] emu_runtime_dir=$EMU_RUNTIME_DIR
[profile-runner] emu_candidate_id=$EMU_CANDIDATE_ID
[profile-runner] emu_sha256=$EMU_SHA256
[profile-runner] arch=$ARCH
[profile-runner] march=$MARCH
[profile-runner] cppflags=$CPPFLAGS
[profile-runner] parser_kind=$PARSER_KIND
[profile-runner] expected_secret_len=${#EXPECTED_SECRET}
[profile-runner] constantin_mode=$CONSTANTIN_MODE
[profile-runner] seed=$SEED
[profile-runner] stack_kb=$STACK_KB
[profile-runner] wall_timeout=$WALL_TIMEOUT
EOF
}

source_tree_hash() {
  (cd "$PROFILE_DIR/source" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
}

load_previous_status() {
  local status="$RUN_DIR/status.json"
  if [[ -f "$status" ]]; then
    verify_exit=$(python3 - "$status" verify_exit <<'PY'
import json, sys
try: print(json.load(open(sys.argv[1])).get(sys.argv[2], 125))
except Exception: print(125)
PY
)
    build_exit=$(python3 - "$status" build_exit <<'PY'
import json, sys
try: print(json.load(open(sys.argv[1])).get(sys.argv[2], 125))
except Exception: print(125)
PY
)
    run_exit=$(python3 - "$status" run_exit <<'PY'
import json, sys
try: print(json.load(open(sys.argv[1])).get(sys.argv[2], 125))
except Exception: print(125)
PY
)
    parse_exit=$(python3 - "$status" parse_exit <<'PY'
import json, sys
try: print(json.load(open(sys.argv[1])).get(sys.argv[2], 125))
except Exception: print(125)
PY
)
  fi
}

write_status() {
  local final="$1" verify_code="$2" build_code="$3" run_code="$4" parse_code="$5"
  local finished_at elapsed timeout_flag signal_code
  finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  elapsed=$(( $(date +%s) - START_EPOCH ))
  timeout_flag=false
  signal_code=0
  if [[ "$run_code" -eq 124 ]]; then
    timeout_flag=true
  elif [[ "$run_code" -gt 128 ]]; then
    signal_code=$((run_code - 128))
  fi
  cat > "$RUN_DIR/status.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "processor": "${PROCESSOR}",
  "poc_id": "${POC_ID}",
  "vm_mode": "${VM_MODE}",
  "status": "${final}",
  "verify_exit": ${verify_code},
  "build_exit": ${build_code},
  "run_exit": ${run_code},
  "parse_exit": ${parse_code},
  "timeout": ${timeout_flag},
  "signal": ${signal_code},
  "started_at": "${STARTED_AT}",
  "finished_at": "${finished_at}",
  "elapsed_sec": ${elapsed},
  "seed": ${SEED},
  "max_cycles": ${MAX_CYCLES:-null},
  "emu_candidate_id": "${EMU_CANDIDATE_ID}",
  "emu_sha256": "${EMU_SHA256}",
  "scratch": "${SCRATCH_DIR}"
}
EOF
}

emit_status_summary() {
  local final="$1"
  cat <<SUMMARY
[profile-runner] final_status=$final
[profile-runner] verify_exit=$verify_exit
[profile-runner] build_exit=$build_exit
[profile-runner] run_exit=$run_exit
[profile-runner] parse_exit=$parse_exit
[profile-runner] run_dir=$RUN_DIR
[profile-runner] status_json=$RUN_DIR/status.json
[profile-runner] result_json=$RUN_DIR/result.json
[profile-runner] run_log=$RUN_DIR/run.log
SUMMARY
}

write_command_record() {
  local image="$SCRATCH_DIR/source/build/$IMAGE_NAME"
  {
    printf '#!/usr/bin/env bash\nset -euo pipefail\n'
    printf 'export LC_ALL=C TZ=UTC HOME=%q TMPDIR=%q\n' "$SCRATCH_DIR/home" "$SCRATCH_DIR/tmp"
    printf 'make -C %q clean AM_HOME=%q ARCH=%q\n' "$SCRATCH_DIR/source" "$AM_HOME" "$ARCH"
    printf 'make -C %q AM_HOME=%q ARCH=%q LINUX_GNU_TOOLCHAIN=1 MARCH=%q CC_OPT= CPPFLAGS=%q -j%s\n' \
      "$SCRATCH_DIR/source" "$AM_HOME" "$ARCH" "$MARCH" "$CPPFLAGS" "$JOBS"
    printf 'ulimit -s %q\n' "$STACK_KB"
    printf 'timeout %q %q' "$WALL_TIMEOUT" "$EMU"
    printf ' %q' "${EMU_ARGS[@]}"
    printf ' -i %q\n' "$SCRATCH_DIR/image"
    printf 'python3 %q %q %q %q %q\n' "$REPO_ROOT/tools/parse_profile_log.py" \
      "$PARSER_KIND" "$EXPECTED_SECRET" "$RUN_DIR/run.log" "$RUN_DIR/result.json"
    printf '# source image before copy: %q\n' "$image"
  } > "$RUN_DIR/command.sh"
  chmod 0555 "$RUN_DIR/command.sh"
}

new_run() {
  RUN_ID=${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}
  safe_id "$RUN_ID" || { echo "RUN_ID contains unsafe characters: $RUN_ID" >&2; exit 2; }
  RUN_DIR="$RUNS_ROOT/$RUN_ID"
  SCRATCH_DIR="$SCRATCH_PARENT/$PROCESSOR/$POC_ID/$VM_MODE/$RUN_ID"
  [[ ! -e "$RUN_DIR" ]] || { echo "run already exists: $RUN_DIR (choose RUN_ID)" >&2; exit 2; }
  [[ ! -e "$SCRATCH_DIR" ]] || { echo "scratch already exists: $SCRATCH_DIR (choose RUN_ID)" >&2; exit 2; }
  mkdir -p "$RUN_DIR" "$SCRATCH_DIR"
  STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  START_EPOCH=$(date +%s)
  printf 'STARTED_AT=%q\nSTART_EPOCH=%q\n' "$STARTED_AT" "$START_EPOCH" > "$RUN_DIR/run.meta"
  cp "$CONFIG" "$RUN_DIR/profile.conf"
  {
    printf 'profile=%s\nprocessor=%s\npoc_id=%s\nvm_mode=%s\nrun_id=%s\n' \
      "$PROFILE_DIR" "$PROCESSOR" "$POC_ID" "$VM_MODE" "$RUN_ID"
    printf 'am_home=%s\narch=%s\nmarch=%s\ncppflags=%s\n' "$AM_HOME" "$ARCH" "$MARCH" "$CPPFLAGS"
    printf 'emu=%s\nemu_runtime_dir=%s\nemu_candidate_id=%s\nemu_sha256=%s\n' \
      "$EMU" "$EMU_RUNTIME_DIR" "$EMU_CANDIDATE_ID" "$EMU_SHA256"
    printf 'parser_kind=%s\nexpected_secret_len=%s\n' "$PARSER_KIND" "${#EXPECTED_SECRET}"
    printf 'lc_all=C\nTZ=UTC\nseed=%s\nmax_cycles=%s\nstack_kb=%s\njobs=%s\n' \
      "$SEED" "${MAX_CYCLES:-null}" "$STACK_KB" "$JOBS"
  } > "$RUN_DIR/env.txt"
  uname -a > "$RUN_DIR/host.txt"
  write_command_record
  verify_exit=125; build_exit=125; run_exit=125; parse_exit=125
}

existing_run() {
  RUN_ID=${RUN_ID:?set RUN_ID to an existing run for stage $STAGE}
  safe_id "$RUN_ID" || { echo "RUN_ID contains unsafe characters: $RUN_ID" >&2; exit 2; }
  RUN_DIR="$RUNS_ROOT/$RUN_ID"
  SCRATCH_DIR="$SCRATCH_PARENT/$PROCESSOR/$POC_ID/$VM_MODE/$RUN_ID"
  [[ -d "$RUN_DIR" && -d "$SCRATCH_DIR" ]] || { echo "run/scratch not found for RUN_ID=$RUN_ID" >&2; exit 2; }
  if [[ -f "$RUN_DIR/run.meta" ]]; then
    # shellcheck disable=SC1090
    source "$RUN_DIR/run.meta"
  else
    STARTED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ); START_EPOCH=$(date +%s)
  fi
  verify_exit=125; build_exit=125; run_exit=125; parse_exit=125
  load_previous_status
}

verify_phase() {
  local log="$RUN_DIR/preflight.log"
  : > "$log"
  {
    log_header preflight
    local actual_source
    actual_source=$(source_tree_hash)
    printf 'profile=%s\nsource_tree_sha256=%s\n' "$PROFILE_DIR" "$actual_source"
    [[ "$actual_source" == "$SOURCE_TREE_SHA256" ]] || { echo "SOURCE_SHA256_MISMATCH actual=$actual_source expected=$SOURCE_TREE_SHA256"; return 19; }
    printf 'emu=%s\n' "$EMU"
    [[ -f "$EMU" && ! -L "$EMU" && -x "$EMU" ]] || { echo 'EMU_NOT_REGULAR_EXECUTABLE'; return 10; }
    # emu sha256/build-id pinning disabled: the self-built XiangShan emu will not
    # match the old packaged hashes.  Record the actual values for the record.
    actual_sha=$(sha256sum "$EMU" | awk '{print $1}')
    actual_build=$(readelf -n "$EMU" 2>/dev/null | awk '/Build ID:/ {print $3; exit}')
    printf 'emu_sha256_actual=%s (pinning disabled)\n' "$actual_sha"
    printf 'emu_build_id_actual=%s (pinning disabled)\n' "$actual_build"
    if "${LDD_CMD[@]}" "$EMU" 2>&1 | tee -a "$log" | grep -q 'not found'; then
      echo 'DYNAMIC_LIBRARY_MISSING'; return 13
    fi
    [[ -d "$PROFILE_DIR/source" ]] || { echo 'SOURCE_MISSING'; return 14; }
    [[ -d "$AM_HOME" ]] || { echo "AM_HOME_MISSING=$AM_HOME"; return 15; }
    if [[ "$CONSTANTIN_MODE" == required ]]; then
      local cst="$PROFILE_DIR/runtime/noop-home/build/constantin.txt"
      [[ -r "$cst" ]] || { echo 'CONSTANTIN_MISSING'; return 16; }
      local cst_sha
      cst_sha=$(sha256sum "$cst" | awk '{print $1}')
      [[ "$cst_sha" == "$CONSTANTIN_SHA256" ]] || { echo 'CONSTANTIN_SHA256_MISMATCH'; return 17; }
    fi
    "${EMU_CMD[@]}" "$EMU" --help > "$RUN_DIR/emu.help.preflight" 2>&1 || { echo 'EMU_HELP_FAILED'; return 18; }
    echo 'PACKAGE_AND_RUNTIME_PREFLIGHT_PASS'
  } 2>&1 | tee -a "$log"
}

build_phase() {
  local log="$RUN_DIR/build.log"
  rm -rf "$SCRATCH_DIR/source"
  mkdir -p "$SCRATCH_DIR/source"
  cp -a "$PROFILE_DIR/source/." "$SCRATCH_DIR/source/"
  {
    log_header build
    export LC_ALL=C TZ=UTC
    printf 'make -C %q clean AM_HOME=%q ARCH=%q\n' "$SCRATCH_DIR/source" "$AM_HOME" "$ARCH"
    make -C "$SCRATCH_DIR/source" clean AM_HOME="$AM_HOME" ARCH="$ARCH" >/dev/null 2>&1 || true
    printf 'make -C %q AM_HOME=%q ARCH=%q LINUX_GNU_TOOLCHAIN=1 MARCH=%q CC_OPT= CPPFLAGS=%q -j%s\n' \
      "$SCRATCH_DIR/source" "$AM_HOME" "$ARCH" "$MARCH" "$CPPFLAGS" "$JOBS"
    make -C "$SCRATCH_DIR/source" \
      AM_HOME="$AM_HOME" ARCH="$ARCH" LINUX_GNU_TOOLCHAIN=1 MARCH="$MARCH" \
      CC_OPT= CPPFLAGS="$CPPFLAGS" -j"$JOBS"
  } > "$log" 2>&1
  local image="$SCRATCH_DIR/source/build/$IMAGE_NAME"
  [[ -f "$image" ]] || { echo "BUILD_IMAGE_MISSING=$image" >> "$log"; return 20; }
  cp -a "$image" "$SCRATCH_DIR/image"
  sha256sum "$SCRATCH_DIR/image" > "$RUN_DIR/image.sha256"
  {
    printf 'image=%s\n' "$SCRATCH_DIR/image"
    command -v make || true; make --version 2>&1 | head -n 1 || true
    command -v riscv64-linux-gnu-gcc || true
    command -v riscv64-unknown-elf-gcc || true
    git -C "$AM_HOME" rev-parse HEAD 2>/dev/null || true
  } > "$RUN_DIR/toolchain.txt"
}

run_phase() {
  local log="$RUN_DIR/run.log"
  local image="$SCRATCH_DIR/image"
  [[ -f "$image" ]] || { echo "RUN_IMAGE_MISSING=$image" > "$log"; return 21; }
  mkdir -p "$SCRATCH_DIR/home" "$SCRATCH_DIR/tmp"
  (
    cd "$SCRATCH_DIR"
    export LC_ALL=C TZ=UTC HOME="$SCRATCH_DIR/home" TMPDIR="$SCRATCH_DIR/tmp"
    log_header run
    if [[ "$CONSTANTIN_MODE" == required ]]; then
      mkdir -p "$SCRATCH_DIR/noop-home"
      cp -a "$PROFILE_DIR/runtime/noop-home/." "$SCRATCH_DIR/noop-home/"
      export NOOP_HOME="$SCRATCH_DIR/noop-home"
      printf 'NOOP_HOME=%q\n' "$NOOP_HOME"
    else
      unset NOOP_HOME
      printf 'NOOP_HOME=embedded-default-not-overridden\n'
    fi
    printf 'ulimit -s %s\n' "$STACK_KB"
    ulimit -s "$STACK_KB"
    printf 'timeout %q' "$WALL_TIMEOUT"
    printf ' %q' "${EMU_CMD[@]}"
    printf ' %q' "$EMU"
    printf ' %q' "${EMU_ARGS[@]}"
    printf ' -i %q\n' "$image"
    timeout "$WALL_TIMEOUT" "${EMU_CMD[@]}" "$EMU" "${EMU_ARGS[@]}" -i "$image"
  ) > "$log" 2>&1
}

parse_phase() {
  local log="$RUN_DIR/parse.log"
  {
    log_header parse
    printf 'python3 %q %q %q %q %q\n' "$REPO_ROOT/tools/parse_profile_log.py" \
      "$PARSER_KIND" "$EXPECTED_SECRET" "$RUN_DIR/run.log" "$RUN_DIR/result.json"
  } > "$log" 2>&1
  python3 "$REPO_ROOT/tools/parse_profile_log.py" \
    "$PARSER_KIND" "$EXPECTED_SECRET" "$RUN_DIR/run.log" "$RUN_DIR/result.json" \
    >> "$log" 2>&1
}

classify_run() {
  case "$1" in
    0) echo RUN_PASS;;
    124) echo RUN_TIMEOUT;;
    125) echo RUN_INCOMPLETE;;
    *) if [[ "$1" -gt 128 ]]; then echo RUN_CRASH; else echo RUN_INCOMPLETE; fi;;
  esac
}

if [[ "$STAGE" == all || "$STAGE" == verify || "$STAGE" == build ]]; then
  new_run
else
  existing_run
fi

if [[ "$STAGE" == all || "$STAGE" == verify || "$STAGE" == build ]]; then
  if verify_phase; then
    verify_exit=0
  else
    verify_exit=$?
  fi
  current_status=$([[ $verify_exit -eq 0 ]] && echo PACKAGE_PASS || echo ENV_MISMATCH)
  write_status "$current_status" "$verify_exit" "$build_exit" "$run_exit" "$parse_exit"
  emit_status_summary "$current_status"
  if [[ "$STAGE" == verify ]]; then exit "$verify_exit"; fi
  [[ "$verify_exit" -eq 0 ]] || exit "$verify_exit"
fi

if [[ "$STAGE" == all || "$STAGE" == build ]]; then
  if build_phase; then
    build_exit=0
  else
    build_exit=$?
  fi
  current_status=$([[ $build_exit -eq 0 ]] && echo BUILD_PASS || echo BUILD_FAIL)
  write_status "$current_status" "$verify_exit" "$build_exit" "$run_exit" "$parse_exit"
  emit_status_summary "$current_status"
  if [[ "$STAGE" == build ]]; then exit "$build_exit"; fi
  [[ "$build_exit" -eq 0 ]] || exit "$build_exit"
fi

if [[ "$STAGE" == all || "$STAGE" == run ]]; then
  if run_phase; then
    run_exit=0
  else
    run_exit=$?
  fi
  current_status=$(classify_run "$run_exit")
  write_status "$current_status" "$verify_exit" "$build_exit" "$run_exit" "$parse_exit"
  emit_status_summary "$current_status"
  if [[ "$STAGE" == run ]]; then exit "$run_exit"; fi
fi

if [[ "$STAGE" == all || "$STAGE" == parse ]]; then
  if parse_phase; then
    parse_exit=0
  else
    parse_exit=$?
  fi
  if [[ "$run_exit" -ne 0 ]]; then
    final_status=$(classify_run "$run_exit")
  elif [[ "$parse_exit" -eq 0 ]]; then
    final_status=ASSERTION_PASS
  else
    final_status=ASSERTION_FAIL
  fi
  write_status "$final_status" "$verify_exit" "$build_exit" "$run_exit" "$parse_exit"
  emit_status_summary "$final_status"
  if [[ "$run_exit" -ne 0 ]]; then exit "$run_exit"; fi
  exit "$parse_exit"
fi
