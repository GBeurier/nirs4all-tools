# Workspace conversion runbook

This runbook converts a supported legacy nirs4all workspace into a separate
`nirs4all-workspace-v2` output. It uses only an installed console command; a
source checkout is not required.

The `nirs4all-tools` packages covered here are candidate artifacts and are
currently **unpublished**. Obtain the candidate wheel through the release
process. Do not substitute an unverified package-registry version.

## 1. Install the supplied candidate

Use an isolated Python 3.11 or newer environment. DuckDB workspace conversion
also needs the `duckdb` and `parquet` extras:

```bash
python -m venv /opt/nirs4all-tools-candidate
/opt/nirs4all-tools-candidate/bin/python -m pip install \
  "./nirs4all_tools-<candidate>-py3-none-any.whl[duckdb,parquet]"
/opt/nirs4all-tools-candidate/bin/nirs4all-tools --version
```

Verify the wheel by the signed-artifact procedure supplied with the release
before installation. No public download URL is defined by this runbook.

## 2. Inspect without changing the source

```bash
/opt/nirs4all-tools-candidate/bin/nirs4all-tools workspace inspect \
  /data/workspace --format text
```

Inspection is read-only. Record its output and exit code before continuing.
The runtime performs the same kind of read-only detection and raises
`ConversionRequired`; it never invokes this tool automatically.

## 3. Convert into a new directory

Choose an output outside and disjoint from the source. It must not already
contain data.

```bash
/opt/nirs4all-tools-candidate/bin/nirs4all-tools workspace convert \
  /data/workspace --output /data/workspace-r2 --verify
```

The source path, inode, and bytes remain intact. The command never renames the
source, never writes into it, and never creates a `.bak` copy. Keep the original
source and the new native output as separate assets.

The workspace conversion domain codes are:

| Code | Operator meaning |
|---:|---|
| `0` | Clean conversion; the output passed requested verification |
| `10` | Best-effort conversion completed, but unsupported content was preserved opaque; review the reports before use |
| `20` | Unsupported input or strict refusal; do not treat the output as converted |

Codes `30`, `40`, and `70` respectively identify verification failure, policy
refusal, and internal failure. Preserve the reports and stop rather than
treating any non-`0` result as unconditional success.

## 4. Verify again when needed

`workspace convert --verify` performs verification during conversion. To
verify the completed output later without reading the source, use the installed
historical verification command and the manifest emitted in the output:

```bash
/opt/nirs4all-tools-candidate/bin/nirs4all-tools legacy verify \
  /data/workspace-r2 \
  --manifest /data/workspace-r2/migration-manifest.json
```

## Runtime and rollback boundary

The explicit `engine="legacy"` runtime remains available for its supported
workflows until after R4. It does not open a DuckDB store through the current
workspace runtime and does not make conversion implicit.

There is no R2-to-R1 reverse conversion. To roll back:

1. Reinstall the signed R1 runtime artifact supplied by the release process.
2. Reopen the original, unchanged source workspace with that R1 runtime.
3. Retain the separately created R2-native output; do not replace the source
   with it and do not attempt to convert it backwards.

This procedure depends on preserving the source, so archive or retention policy
must cover both the original workspace and the new output.
