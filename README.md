# KMHv3 Portable POCs 20260904

This directory is a clean, portable KMHv3 code bundle for the local educational Spectre V1/V2/V5 migration.

## What Is In This Bundle

- `xiangshan-v3/`: clean runnable app directories. Directory names intentionally omit `student`, dates, and tuning suffixes.
- `tools/`: runner and parser scripts used by every profile.
- `.scratch/nexus-am-kmhv3/`: the AM tree expected by the relative `AM_HOME_DEFAULT`.
- `evidence/`: final successful run evidence and reports, kept out of `profiles/*/runs`.
- `APP_TABLE_COVERAGE.tsv`: maps the APP list from the question to the clean KMHv3 directory/profile.
- `PROFILE_MANIFEST.tsv`: one row per runnable profile.
- `EVIDENCE_MANIFEST.tsv`: one row per copied final evidence run.

## Directory Rule

Code and results are separated.

- To move and rerun on another Linux server, copy this whole directory.
- Do not copy old mixed `runs` directories into `xiangshan-v3/*/profiles/*/runs`.
- Keep new run output generated on the new server under fresh `runs` directories or set `RUNS_ROOT`.

## First Command On A Linux Server

```bash
cd kmhv3_portable_pocs_20260904
bash prepare_on_linux.sh
```

The prepare script restores executable bits for shell scripts and `runtime/kmhv3-emu/emu`, which may be lost after passing through Windows.

## Run Examples

```bash
./run_verified_pocs.sh --list
RUN_ID=test-v5-asid-sv39 ./run_verified_pocs.sh spectre-v5-asid-kmhv3/sv39
RUN_ID=test-v1-basic ./run_verified_pocs.sh spectre-v1-kmhv3/bare
```

If the new server has an older glibc than the emulator needs, use the same optional loader override pattern as hwfuzz:

```bash
export EMU_LD=/path/to/ld-linux-x86-64.so.2
export EMU_LD_LIBRARY_PATH=/path/to/glibc/lib:/path/to/glibc/lib64
```

## Evidence Boundary

- V1 basic/priv/asid/vmid and V2/V5 basic have six-byte evidence where listed.
- V1 hs/vs/vu sv48, V2 isolation/privilege, and V5 priv/isolation entries are one-byte smoke evidence unless the report says otherwise.
- Runner completion, `rc=143`, or a copied source tree alone is not a recovery claim. Use `status.json`, `result.json`, and `run.log`.
