#!/usr/bin/env bash
set -euo pipefail

BASE=${BASE:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
EMU_V2_SOURCE=${EMU_V2_SOURCE:-/nfs/home/leizhenyu/opt/DUTs/XiangShan/build/emu-16threads}
EMU_V3_SOURCE=${EMU_V3_SOURCE:-/nfs/home/leizhenyu/opt/DUTs/XiangShan-V3/build/emu}
V2_CONSTANTIN=${V2_CONSTANTIN:-/nfs/home/leizhenyu/opt/DUTs/XiangShan/build/constantin.txt}
V2_DTS=${V2_DTS:-/nfs/home/leizhenyu/opt/DUTs/XiangShan/build/dts}
V3_CONSTANTIN=${V3_CONSTANTIN:-/nfs/home/leizhenyu/opt/DUTs/XiangShan-V3/build/constantin.txt}
V3_DTS=${V3_DTS:-/nfs/home/leizhenyu/opt/DUTs/XiangShan-V3/build/dts}

copy_runtime() {
  local poc=$1
  local processor=$2
  local emu_source=$3
  local constantin_source=$4
  local dts_source=$5
  local constantin_mode=$6
  local root="$BASE/$poc"
  local runtime="$root/runtime"
  local emu_dir="$runtime/${processor}-emu"
  local emu="$emu_dir/emu"
  local help="$runtime/emu.help"
  local build_id
  local emu_sha
  local constantin_sha=NOT_USED
  local dts_sha=NOT_USED

  case "$processor" in
    kmhv2|kmhv3) ;;
    *) echo "unsupported processor runtime tag: $processor" >&2; return 2 ;;
  esac

  test -d "$root"
  test -f "$emu_source"
  test ! -L "$emu_source"
  mkdir -p "$emu_dir" "$runtime/noop-home/build"

  if [[ -e "$emu" ]]; then
    chmod u+w "$emu"
  fi
  cp -L --reflink=auto "$emu_source" "$emu"
  chmod 0555 "$emu"
  test -f "$emu"
  test ! -L "$emu"

  emu_sha=$(sha256sum "$emu" | awk '{print $1}')
  build_id=$(readelf -n "$emu" 2>/dev/null | awk '/Build ID:/ {print $3; exit}')
  : "${build_id:=UNKNOWN}"

  (cd "$runtime" && sha256sum "${processor}-emu/emu" > emu.sha256)
  readelf -n "$emu" > "$runtime/emu.readelf.txt" 2>&1 || true
  file "$emu" > "$runtime/emu.file"
  ldd "$emu" > "$runtime/emu.ldd" 2>&1 || true
  "$emu" --help > "$help" 2>&1 || true
  stat -c 'path=%n\nsize=%s\nmode=%a\nmtime=%y' "$emu" > "$runtime/emu.stat"

  if [[ "$constantin_mode" == required || "$constantin_mode" == optional ]]; then
    test -f "$constantin_source"
    cp -L "$constantin_source" "$runtime/noop-home/build/constantin.txt"
    constantin_sha=$(sha256sum "$runtime/noop-home/build/constantin.txt" | awk '{print $1}')
  fi
  if [[ -f "$dts_source" ]]; then
    cp -L "$dts_source" "$runtime/noop-home/build/dts"
    dts_sha=$(sha256sum "$runtime/noop-home/build/dts" | awk '{print $1}')
  fi

  {
    printf 'schema_version=POC-RP-1.0\n'
    printf 'poc=%s\n' "$poc"
    printf 'processor=%s\n' "$processor"
    printf 'emu_source=%s\n' "$emu_source"
    printf 'emu_relpath=runtime/%s/emu\n' "${processor}-emu"
    printf 'emu_sha256=%s\n' "$emu_sha"
    printf 'emu_build_id=%s\n' "$build_id"
    printf 'emu_compile_banner=%s\n' "$(sed -n '1p' "$help")"
    printf 'constantin_mode=%s\n' "$constantin_mode"
    printf 'constantin_relpath=runtime/noop-home/build/constantin.txt\n'
    printf 'constantin_sha256=%s\n' "$constantin_sha"
    printf 'dts_sha256=%s\n' "$dts_sha"
  } > "$runtime/manifest.tsv"

  printf '%s\t%s\t%s\n' "$poc" "$emu_sha" "$build_id"
}

copy_runtime xiangshan-v2/spectre-v1-poc-kmhv2 kmhv2 "$EMU_V2_SOURCE" "$V2_CONSTANTIN" "$V2_DTS" optional
copy_runtime xiangshan-v2/spectre-v2-poc-kmhv2 kmhv2 "$EMU_V2_SOURCE" "$V2_CONSTANTIN" "$V2_DTS" optional
copy_runtime xiangshan-v2/spectre-v1-priv-kmhv2 kmhv2 "$EMU_V2_SOURCE" "$V2_CONSTANTIN" "$V2_DTS" optional
copy_runtime xiangshan-v2/spectre-v1-asid-kmhv2 kmhv2 "$EMU_V2_SOURCE" "$V2_CONSTANTIN" "$V2_DTS" optional
copy_runtime xiangshan-v2/spectre-v1-vmid-kmhv2 kmhv2 "$EMU_V2_SOURCE" "$V2_CONSTANTIN" "$V2_DTS" optional
copy_runtime xiangshan-v2/spectre-v2-privilege-kmhv2 kmhv2 "$EMU_V2_SOURCE" "$V2_CONSTANTIN" "$V2_DTS" optional
copy_runtime xiangshan-v3/spectre-v1-poc-kmhv3 kmhv3 "$EMU_V3_SOURCE" "$V3_CONSTANTIN" "$V3_DTS" required
