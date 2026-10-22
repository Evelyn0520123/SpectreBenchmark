#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: create_student_kmhv3_tuned_profiles.sh [--force]

Create fresh student-owned Kunminghu-v3 tuned profiles for:
  - spectre-v2-poc-kmhv3-tuned
  - spectre-v5-poc-kmhv3-tuned

These profiles keep the original reference bundles untouched and carry tuned
source variants aimed at making the basic KMHv3 reruns finish and produce
byte-level output.

Options:
  --force    remove an existing tuned profile before recreating it
USAGE
}

FORCE=0
case "${1:-}" in
  "")
    ;;
  --force)
    FORCE=1
    shift
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 2
    ;;
esac

[[ $# -eq 0 ]] || { usage; exit 2; }

ROOT=$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")
WORKSPACE_ROOT=$(readlink -f "$ROOT/../..")
XIANGSHAN_V3_ROOT="$ROOT/xiangshan-v3"
RUNTIME_TEMPLATE="$XIANGSHAN_V3_ROOT/spectre-v1-poc-kmhv3/profiles/bare/runtime"
POC_RUN_TEMPLATE="$XIANGSHAN_V3_ROOT/spectre-v1-poc-kmhv3/run.sh"
PROFILE_WRAPPER_TEMPLATE="$XIANGSHAN_V3_ROOT/spectre-v1-poc-kmhv3/profiles/bare/reproduce/run.sh"
TEMPLATE_ROOT="$ROOT/tools/tuned_templates"

need_path() {
  local path="$1"
  [[ -e "$path" ]] || { echo "missing required path: $path" >&2; exit 2; }
}

copy_profile_wrappers() {
  local reproduce_dir="$1"
  mkdir -p "$reproduce_dir"
  for name in run.sh verify.sh build.sh parse.sh; do
    cp -f "$PROFILE_WRAPPER_TEMPLATE" "$reproduce_dir/$name"
    chmod 0555 "$reproduce_dir/$name"
  done
}

source_tree_hash() {
  local source_dir="$1"
  (cd "$source_dir" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')
}

write_profile_conf() {
  local conf="$1"
  local poc_id="$2"
  local cppflags="$3"
  local image_name="$4"
  local wall_timeout="$5"
  local parser_kind="$6"
  local expected_secret="$7"
  local source_tree_sha="$8"

  cat > "$conf" <<EOF
POC_ID="$poc_id"
PROCESSOR="xiangshan-v3"
VM_MODE="bare"
AM_HOME_DEFAULT="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")/../../../../../../.." && pwd)/.scratch/nexus-am-kmhv3"
ARCH="riscv64-xs-flash"
MARCH="rv64gc_zba_zbb_zbc_zbs_zbkb_zbkc_zbkx_zknd_zkne_zknh_zkr_zksed_zksh_zkt_zicbom_zicboz"
CPPFLAGS="$cppflags"
IMAGE_NAME="$image_name"
WALL_TIMEOUT="$wall_timeout"
PARSER_KIND="$parser_kind"
EMU_CANDIDATE_ID="kmhv3-emu-v2-baseline"
EMU_SHA256="7886cdf6081378bfcd84fb9397cd192f19c499ca607fb8b403f91b47c5c88bd1"
EMU_BUILD_ID="761c266eee6ae2e7dc5ab7d930081e63a92a6b68"
CONSTANTIN_MODE="required"
CONSTANTIN_SHA256="24d63281992fab97959d385b91d1356261acb0a8da3b4737cf42ce8a37db46bd"
EXPECTED_SECRET="$expected_secret"
SEED=0
MAX_CYCLES=""
SOURCE_TREE_SHA256="$source_tree_sha"
EOF
  chmod 0444 "$conf"
}

write_poc_readme() {
  local readme="$1"
  local poc_name="$2"
  local kmhv2_source="$3"
  local reference_source="$4"
  local reproduce_conf="$5"
  local note="$6"

  cat > "$readme" <<EOF
# $poc_name

This is a student-owned KMHv3 tuned bundle created from local references.

- Base KMHv2 source: $kmhv2_source
- Reference KMHv3 bare source: $reference_source
- Active run config: $reproduce_conf
- Tuning note: $note

To inspect the migration diff on Linux:

\`\`\`bash
git diff --no-index -- "$kmhv2_source" "$reference_source"
\`\`\`
EOF
}

create_tuned_poc() {
  local tuned_name="$1"
  local kmhv2_source_root="$2"
  local reference_source_root="$3"
  local template_source="$4"
  local template_dest_name="$5"
  local cppflags="$6"
  local image_name="$7"
  local wall_timeout="$8"
  local parser_kind="$9"
  local expected_secret="${10}"
  local note="${11}"

  local dest="$XIANGSHAN_V3_ROOT/$tuned_name"
  local profile_dir="$dest/profiles/bare"
  local source_sha

  if [[ -e "$dest" ]]; then
    if [[ "$FORCE" -eq 1 ]]; then
      rm -rf "$dest"
    else
      echo "destination already exists: $dest" >&2
      echo "rerun with --force to recreate it" >&2
      exit 2
    fi
  fi

  mkdir -p "$profile_dir"
  cp -a "$reference_source_root" "$profile_dir/source"
  cp -a "$RUNTIME_TEMPLATE" "$profile_dir/runtime"
  mkdir -p "$profile_dir/runs"
  copy_profile_wrappers "$profile_dir/reproduce"
  cp -f "$template_source" "$profile_dir/source/src/$template_dest_name"

  source_sha=$(source_tree_hash "$profile_dir/source")
  write_profile_conf \
    "$profile_dir/reproduce/profile.conf" \
    "$tuned_name" \
    "$cppflags" \
    "$image_name" \
    "$wall_timeout" \
    "$parser_kind" \
    "$expected_secret" \
    "$source_sha"
  cp -f "$POC_RUN_TEMPLATE" "$dest/run.sh"
  chmod 0555 "$dest/run.sh"
  write_poc_readme \
    "$dest/README.md" \
    "$tuned_name" \
    "$kmhv2_source_root" \
    "$reference_source_root" \
    "$profile_dir/reproduce/profile.conf" \
    "$note"

  printf 'created %s\n' "$dest"
}

need_path "$WORKSPACE_ROOT/spectre-v2-kmhv2/code/src/spectre-v2.c"
need_path "$WORKSPACE_ROOT/spectre-v5-kmhv2/code/src/spectre-v5.c"
need_path "$RUNTIME_TEMPLATE/kmhv3-emu/emu"
need_path "$PROFILE_WRAPPER_TEMPLATE"
need_path "$POC_RUN_TEMPLATE"
need_path "$TEMPLATE_ROOT/spectre-v2-kmhv3-tuned.c"
need_path "$TEMPLATE_ROOT/spectre-v5-kmhv3-tuned.c"

create_tuned_poc \
  "spectre-v2-poc-kmhv3-tuned" \
  "$WORKSPACE_ROOT/spectre-v2-kmhv2/code" \
  "$XIANGSHAN_V3_ROOT/spectre-v2-poc-kmhv3/profiles/bare/source" \
  "$TEMPLATE_ROOT/spectre-v2-kmhv3-tuned.c" \
  "spectre-v2.c" \
  "-DSECRET_SZ=1 -DUSE_FIXED_CACHE_HIT_THRESHOLD=1 -DCACHE_HIT_THRESHOLD=95 -DV2_ATTACK_TRIES=3 -DV2_TRAINING_LOOPS=16 -DFLUSH_CANDIDATE_LINES_ONLY=1 -DSUBTRACT_CONTROL_HITS=1 -DEARLY_STOP=1 -DEARLY_STOP_MIN_SCORE=2 -DEARLY_STOP_GAP=1" \
  "spectre-v2-riscv64-xs-flash.bin" \
  "30m" \
  "v2_basic" \
  "S" \
  "1-byte tuned rerun with candidate-only flush, fixed threshold 95, and control-hit subtraction to suppress KMHv3 noise."

create_tuned_poc \
  "spectre-v5-poc-kmhv3-tuned" \
  "$WORKSPACE_ROOT/spectre-v5-kmhv2/code" \
  "$XIANGSHAN_V3_ROOT/spectre-v5-poc-kmhv3/profiles/bare/source" \
  "$TEMPLATE_ROOT/spectre-v5-kmhv3-tuned.c" \
  "spectre-v5.c" \
  "-DSECRET_SZ=1 -DUSE_FIXED_CACHE_HIT_THRESHOLD=1 -DCACHE_HIT_THRESHOLD=80 -DATTACK_SAME_ROUNDS=3 -DPROBE_CANDIDATES=62 -DFLUSH_CANDIDATE_LINES_ONLY=1 -DEARLY_STOP=1 -DEARLY_STOP_MIN_SCORE=2 -DEARLY_STOP_GAP=1" \
  "spectre-v5-riscv64-xs-flash.bin" \
  "30m" \
  "v5_basic" \
  "V" \
  "1-byte tuned rerun with candidate-only flush/probe and per-round progress."

cat <<EOF

Student KMHv3 tuned profiles are ready under:
  $XIANGSHAN_V3_ROOT/spectre-v2-poc-kmhv3-tuned
  $XIANGSHAN_V3_ROOT/spectre-v5-poc-kmhv3-tuned

Suggested next step on hwfuzz:
  bash "$ROOT/tools/run_student_kmhv3_tuned.sh"
EOF
