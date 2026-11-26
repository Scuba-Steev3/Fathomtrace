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

- Bumped Fathomtrace to 2.1.5 for evidence-based SSHole verdicts with optional
  Alpine host inventory, vendor backport evaluation, and structured finding status.

- Bumped Fathomtrace to 2.1.4. Scans report the SSH banner and protocol
  version on open TCP/22 and flag potential exposure to CVE-2026-123158.

- Bumped Fathomtrace to 2.1.3 for database version and OS hints in scans
  and hostname and OS metadata in authenticated database inventory. SQL Server scans also report instance and hostname when available.

- Raised the application version to 2.1.1 for BloodHound CE support and the
  optional DACL-audit bypass.
- Promoted successful IMAP authentication into both the Attack Path Decision
  Engine and Recon Summary, including the accepted user and TLS port.
- Added exported IMAP message findings to the Attack Path Decision Engine when
  the export count is greater than zero, including the protected loot path and
  targeted review and retention next steps.
- Grouped Service Exposure Checks into visually separated SMTP, POP3, IMAP,
  authenticated mailbox, and SNMP blocks with concise descriptions and
  per-endpoint subheaders matching the existing AD enumeration hierarchy.
- Kept the `Running Port Scan` phase limited to concurrent TCP reachability and
  concise open-port results. Protocol probes, mail banners and capabilities,
  TLS certificates, authentication checks, and enumeration now appear under a
  separate `Service Exposure Checks` phase.
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

- Added BloodHound CE support with `bloodhound-ce-python` preferred for `All`
  collection and legacy `bloodhound-python` retained as a `DCOnly` fallback.
- Added `--skip-dacl-audit` to bypass both the targeted Impacket DACL review and
  the directory-wide bloodyAD writable-object audit while keeping both enabled
  by default.
- Added profile-aware targeted UDP scanning, `--udp-ports` overrides, and a
  `--no-udp` opt-out. UDP results distinguish confirmed `open` listeners from
  inconclusive `open|filtered` candidates.
- Added SNMP/161 discovery with a bounded, read-only SNMPv2c `sysDescr.0`
  request using the common `public` community, device-description reporting,
  and targeted UDP Nmap service detection for discovered candidates.
- Added automatic certificate capture and parsing for SMTP, POP3, and IMAP over
  implicit TLS or advertised STARTTLS/STLS, including CN fallback when a
  certificate has no Subject Alternative Name extension.
- Added copy-ready OpenSSL connection guidance when IMAP STARTTLS or implicit
  TLS is confirmed, including SNI and safe interactive-session reminders.
- Added one-attempt IMAP credential validation using explicit `-u/-p` values,
  restricted to implicit TLS or confirmed STARTTLS with password-redacted
  evidence and no mailbox access.
- Added opt-in authenticated IMAP mailbox enumeration and bounded message
  export. The dump examines the preferred mailbox first, continues through all
  selectable `LIST` results while skipping `\Noselect` containers, and keeps a
  global message limit. Mailboxes are opened with `EXAMINE`, messages use
  `BODY.PEEK[]`, and exports are stored as sensitive artifacts without
  persisting passwords.
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
