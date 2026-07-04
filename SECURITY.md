# Security policy

`nirs4all-tools` is an **offline, one-way, no-in-place migration CLI** for legacy nirs4all artifacts.
It reads and parses potentially **untrusted legacy inputs** — SQLite workspaces, `.n4a` ZIP bundles,
loose prediction files, `runs/*/manifest.yaml`, and dag-ml native-results directories — and lowers
them into the runtime's `workspace-v2` format (`store.sqlite` + Parquet array sidecars).

Security-relevant properties:

- **Untrusted input surface.** SQLite / ZIP / JSON / YAML / Parquet parsing. A crafted artifact must
  fail **closed** with a clean error — never a path-traversal write, unbounded allocation, or code
  execution. `.n4a` ZIP extraction must reject zip-slip / absolute / symlink members.
- **No-in-place safety.** Migration never mutates the source; it writes a fresh output and preserves
  the raw legacy rows as **checksummed JSONL audit provenance**, after a strict hash/schema preflight.
- **No secrets, no network.** Purely local file transformation.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public GitHub issue. Email
**nirs4all-admin@cirad.fr** with the affected version, a description, and (ideally) a minimal crafted
reproducing artifact (a benign one — do not attach live malware). We aim to acknowledge within a few
working days and coordinate a fix and disclosure.
