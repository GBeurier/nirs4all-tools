# Tools contributor instructions

## Offline migration and safety

Tools owns offline one-way legacy readers/conversion, not live ingestion/autofallback; no automatic runtime invocation. Retain readers through R4; post-V1 retirement needs announced decision/notice under [SLA](docs/legacy-support-sla.md#support-window)/[matrix](docs/contracts/legacy-support-matrix.v1.json).
Source path/inode/bytes unchanged: no rename/.bak; require fresh/empty/disjoint output, refuse aliases/nesting. TMPDIR outside source AND output. POSIX no-follow staging/recheck is required; unsupported hosts fail closed. See [no-in-place](README.md#the-one-contract-no-in-place).
Untrusted input fails closed; never extract or deserialize `.n4a`. [SECURITY](SECURITY.md) requires bounded archive/manifest preflight, no secrets/network and benign private reporting.
Joblib requires explicit trusted-input consent `--trusted-load-joblib`, never auto-load. [CLI](README.md#cli) bounds fitted-PLS finite-affine PREDICT-only export/attestation; no arbitrary estimator/fabricated fitted workspace.
Exit 0 is not predict support: retain `converted_workspace_has_no_fitted_model`/[runbook conditions](docs/workspace-conversion-runbook.md#3-convert-into-a-new-directory), exact lowering/opaque/refusal profiles/extras, four [contracts](README.md#contracts) and [exit codes](README.md#exit-codes).
[Reservations/single-rename publication](README.md#cli) apply ONLY to `--copy-only`. Keep portable-name/external-contract limits and completed-output-only attested read-only resume, never partial recovery.

## Gates and rights

From checkout/package env the [gate](docs/maintenance/quality_gates.md#local-green-gate-matches-ci) needs `.[dev,parquet]`; each transform needs `--dry-run`, strict hash/schema preflight and parquet-present AND absent/adversarial tests. [CONTRIBUTING](CONTRIBUTING.md) retains CHANGELOG duties; [goldens](README.md#development) stay read-only.
[Validation](docs/legacy-support-sla.md#validate)/[rollback](docs/workspace-conversion-runbook.md#runtime-and-rollback-boundary) retain signed/versioned artifacts. Paths/0.0.7 are examples, not host requirements. No reverse conversion/product-gate closure by publication.
Versioning: versions are `X.Y.Z`. `Z` (patch) = fixes and purely additive, backward-compatible features (existing outputs, wire formats, schemas and ABI symbols unchanged); `Y` (minor) = any compatibility break (changed/removed API signature, ABI break or ABI version change, wire/byte/schema/fixture change, renamed ids, changed numerical results of existing operations); `X` = product version. The package that bumps classifies its change. Cross-repository dependencies accept one tested series, `>=X.Y[.Z],<X.(Y+1)` (patch floor only when a fix or feature from that patch is required); for 1.x packages never npm `^1.x` or Cargo `"1.x"` (they accept the next minor): use `~1.4.1`, `">=1.4.1, <1.5"`, `>=1.4.1,<1.5`. Exact pins only in lockfiles, wheel locks and product install lists; intra-repo lockstep may stay exact. See the [ecosystem version constraints](https://github.com/GBeurier/nirs4all-ecosystem/blob/main/docs/contracts/release/VERSION_CONSTRAINTS.md).
[LICENSE](LICENSE) retains `CeCILL-2.1 OR AGPL-3.0-or-later`, optional commercial terms/contact and canonical LICENSES notices in distributions.

## Working rules

Read applicable instructions first and preserve dirty work. If `../AGENTS.md` exists, read it within the current user scope; this file also works alone.
Use CodeGraph FIRST only with this checkout's own `.codegraph/` (exact projectPath or local CLI); never auto-index or use an ancestor index. Source, tests and builds are final authority.
Record actual commands, exits and skips. Keep secrets, private data and build output out of Git. Examples grant no install, network, science, publication, hosting, frontend or Git authority.
All project content, including UI text, docs, tests, reports, PRs and commits, is English; conversation may be French. Preserve names, identifiers, quotations and provenance.
