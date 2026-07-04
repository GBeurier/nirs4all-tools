# Codex Gate 3 — main diff review (nirs4all-tools)

**Reviewer:** Codex CLI 0.142.5 — `codex exec review --uncommitted`, 2026-07-04 (background).

## Verdict
> "The workflow SHA pinning itself appears syntactically fine, but the added maintenance/community docs
> contain materially wrong security scope and a local gate that does not match CI."

Two P2 findings — both from an **audit mischaracterization** of the repo, now corrected.

## Findings & disposition

| # | sev | finding | disposition |
|---|---|---|---|
| P2 | important | SECURITY.md used a copied "helper library, no file parsing" threat model, but `nirs4all-tools` is an **offline migration CLI** parsing SQLite / `.n4a` ZIP / JSON-YAML / Parquet legacy artifacts. | **Fixed** — SECURITY.md (and CITATION/CHANGELOG) rewritten to the real migration surface: untrusted-input parsing, zip-slip rejection, no-in-place safety, checksummed provenance. |
| P2 | important | CONTRIBUTING/quality_gates green gate omitted the `parquet` extra + `mypy` that CI runs (`pip install -e ".[dev,parquet]"`, `mypy`), so it wouldn't reproduce CI. | **Fixed** — gates now `pip install -e ".[dev,parquet]"` → ruff + mypy + pytest. |

## Root cause
The Phase-1 audit inferred "array/prediction validation helpers" from one commit subject; the repo is
actually the standalone home for legacy-artifact migration (lane L18 / LOCK-MIG). All community docs were
corrected against the README + package modules. Gate 4 consolidated into ecosystem Gate 5.
