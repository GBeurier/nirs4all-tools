# Legacy input support SLA for V1

This is a version-based compatibility SLA for `nirs4all-tools` 0.x. Its
machine-readable authority is
[`contracts/legacy-support-matrix.v1.json`](contracts/legacy-support-matrix.v1.json).
The validator rejects missing detected input kinds, duplicate entries, a
shortened retention window, writable legacy sources, or undocumented rollback
requirements.

## Support window

R2 (`1.0.0-rc.1`) flips the product to the native backend. Existing Tools
legacy readers are guaranteed for both complete releases after that flip: R3
(`1.0.0-rc.2`) and R4 (`1.0.0`). End of support cannot occur during V1. Any
reader retirement requires a separately announced post-V1 governance decision
and migration notice; silence or publication of a newer package is not notice.

This guarantee preserves the reader and its existing bounded dispositions. It
does not turn opaque preservation into semantic conversion, broaden accepted
schemas, or promise execution of serialized code.

## Operation commitments

| Operation | V1 commitment |
|---|---|
| Read | `workspace inspect` and `legacy inspect` keep supported detection, structural inspection, and qualified readers available through end of R4. Optional format dependencies remain explicit. |
| Write | No command writes, renames, replaces, or creates `.bak` beside a legacy input. Writers create only a fresh, disjoint `nirs4all-workspace-v2` output and external reports explicitly requested by the operator. |
| Migrate | `workspace convert` and `legacy migrate` retain the matrix disposition: semantic lowering where qualified, otherwise explicit opaque preservation or refusal. Codes `0`, `10`, and `20` keep their documented meaning. No new conversion is promised by this SLA. |

The original source path, inode and bytes are checked before completion and
remain the rollback authority. There is no reverse native-to-legacy conversion.

## Rollback artifact retention

R1 `0.13.0`, R2 `1.0.0-rc.1`, and R3 `1.0.0-rc.2` are the required rollback
points for their successors. Their signed/versioned distributions and source
archives must remain reachable through the end of R4. A promotion gate must
record, in the release lock, the official versioned URL, SHA-256, and signature
or attestation for each applicable rollback release. A mutable `latest` URL is
not evidence.

`nirs4all-tools` 0.0.7 is published and is the supported Tools distribution for
this matrix. That component publication does not promote the nirs4all V1
product train: the final lock must still bind the rollback URLs, checksums and
signatures or attestations before the V1 promotion gate can close.

## Validate

From a source checkout:

```bash
/usr/bin/python3.11 scripts/validate_support_matrix.py
/usr/bin/python3.11 -m pytest -q tests/test_support_matrix.py
```
