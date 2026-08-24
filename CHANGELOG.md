# Changelog

All notable changes to this repository will be documented in this file.

## Unreleased

### Project

- Extracted the scanner and its sourceable libraries into the standalone
  Fathomtrace repository.
- Renamed the public executable to `fathomtrace` and retained
  `bash_simpleportscan.sh` as a compatibility wrapper.
- Added prefix-aware library discovery, an installer, development targets,
  architecture documentation, contribution guidance, and a security policy.

### Changed

- Fixed automatic color detection by no longer shadowing the standard
  `NO_COLOR` environment variable with a non-empty internal value.
- Added standard `NO_COLOR`, `CLICOLOR`, and `CLICOLOR_FORCE` handling while
  retaining explicit `--color auto|always|never` control.
- Added explicit `--show-secrets` output for operators who intentionally need
  unredacted credentials in console and artifact records.

- Refactored `bash_simpleportscan.sh` around sourceable CLI, presentation,
  validation, scan-profile, and artifact-storage layers while retaining the
  existing service-enumeration implementation.
- Added an explicit `scan` command while preserving positional target invocation,
  the localhost default, existing feature flags, `--option=value` syntax, and
  documented aliases.
- Added grouped help, stable exit codes, quiet/verbose/debug modes, automatic or
  forced color handling, and Unicode/ASCII icon selection.
- Added default, web, Active Directory, extended, and custom port selections,
  configurable worker counts, connection timeouts, and bounded retry limits.
- Replaced polling-based scan throttling and concurrent shared-file writes with a
  bounded worker pool, per-port result files, and deterministic parent-process
  aggregation.
- Made reverse DNS/tool preflight, anonymous/null-session checks, and guest checks
  independently skippable while retaining mandatory target/runtime/path checks.
- Corrected MSSQL enumeration gating to use `--check-mssql` rather than the
  unrelated BloodHound flag; `--mssql-brute` now also enables MSSQL enumeration.
- Removed an embedded development target and credential, and made MSSQL
  privilege escalation and `xp_cmdshell` configuration changes explicitly
  opt-in through `--mssql-privesc` and `--mssql-enable-cmdshell`.
- Masked supplied passwords in console guidance and redacted them from stored
  repeatable commands and captured-console artifacts.
- Ignored default `recon_*` session directories to reduce the chance of
  accidentally committing assessment data.

### Added

- Added bounded NetExec (`nxc rdp`/`netexec rdp`) credential validation when
  TCP/3389 is open and explicit credentials are supplied. The single-target
  command is recorded in command artifacts, the summary reports
  success/failure/skipped state, and successful authentication is mapped to
  MITRE ATT&CK T1021.001 in the attack-path engine.

### Fixed

- Added automatic NetBIOS node-status discovery with `nmblookup` and `nbtscan`
  fallback parsing for the target name, workgroup/domain, and reported MAC.
- Added SecLists-aware FFUF web-content enumeration with
  `raft-small-words.txt` as the default, a generated fallback list, and a
  `--web-wordlist FILE` override.
- Added SecLists-backed FFUF VHost enumeration with automatic calibration,
  validated result parsing, a `--vhost-wordlist FILE` override, and a
  wildcard-aware curl fallback.
- Text, JSON, and CSV console formats with schema-versioned machine summaries and
  diagnostics isolated on standard error.
- Unique per-run session directories with raw, parsed, evidence, sensitive loot,
  command, and report areas.
- Atomic index writes, restrictive permissions, SHA-256 checksums, hash-based
  deduplication, sensitivity labels, partial-failure records, and optional text,
  JSONL, CSV, or combined indexes.
- `--no-loot`, `--loot-dir`, `--overwrite`, `--index-format`, `--dry-run`,
  `--profile`, `--ports`, `--jobs`, `--connect-timeout`, `--retries`,
  `--skip-preflight`, `--skip-null-checks`, and `--skip-guest-checks`.
- Dependency-free Bash tests and golden help output covering the compatibility
  and refactor contracts.
- A pre-refactor architecture and behavior assessment in `docs/ASSESSMENT.md`.

### Fixed

- Restored the `bash_simpleportscan.sh` compatibility wrapper and made the
  installer continue with a warning if an incomplete source package omits it.

### Deprecated

- `--svc` remains accepted as an alias for `--service-detect`.
- `--check-cert` and `--check-ca` remain accepted as aliases for
  `--check-certs`.
