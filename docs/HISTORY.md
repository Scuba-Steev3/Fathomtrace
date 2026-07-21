# Project history and original refactor assessment

Fathomtrace was extracted from `bash_simpleportscan.sh` in the Tooling repository.
The assessment below records the inherited architecture and the constraints that
shaped the first standalone release.

## Pre-refactor architecture

`bash_simpleportscan.sh` is a Bash 4+ monolith of roughly 7,800 lines. It declares
global scan state, parses arguments, creates temporary files, defines service
functions, and executes the scan in one file. The executable flow starts near the
middle of the file after all service helpers have been loaded.

The default workflow is:

1. Parse every argument with a permissive `case` loop; the first unrecognized
   argument becomes the target.
2. Default the target to `127.0.0.1` when none is supplied.
3. Print a legend and educational-use banner.
4. Resolve a hostname to IPv4.
5. Create `recon_<target>/{commands,evidence,loot,reports}` and truncate its
   index/report files.
6. Scan a fixed list of common TCP ports with `/dev/tcp`, `timeout`, and up to
   20 background workers.
7. Run service-specific discovery and optional credentialed modules based on
   open ports and feature flags.
8. Print a synopsis and attack-path suggestions, then remove temporary files.

The supported target forms are a single IPv4 address or a hostname resolving to
IPv4. The current public CLI has one implicit scan command and accepts the target
positionally. Existing flags include web/VHost, DNS, Kerberos, BloodHound, AD CS,
MSSQL, service-detection, authentication, and `--no-color` options. Several flags
have aliases, including `--svc`, `--check-cert`, `--check-ca`, `--username`,
`--password`, `-u=`, and `-p=`.

## Baseline behavior

There was no test directory, CI workflow, formatter, linter configuration, or
type-check configuration in the repository at assessment time. The documented
validation command, `bash -n ./*.sh`, succeeds for `bash_simpleportscan.sh`.

The original script does not implement `--help`. Passing it causes the parser to
treat `--help` as the target, print the legend and banner, attempt name
resolution, and fail. Unknown options are likewise accepted as a target or
silently ignored after a target has been set. The default target is localhost.

## Validation and preflight behavior

Target resolution is mandatory and happens before scanning. Other validation is
distributed across service functions. Many functions repeat checks for the same
credential, domain, executable, or file. Optional tools are generally checked at
the point of use, but some post-scan blocks perform unrelated discovery whenever
a port is open. There is no reusable validation cache and no user-facing way to
disable optional preflight, null-session, or guest checks.

## Output and loot behavior

Console output mixes direct `echo` calls, embedded ANSI sequences, Unicode icons,
diagnostics, credentials, findings, copy/paste commands, and summaries on standard
output. `--no-color` clears only part of the color palette. The legend is printed
for every invocation.

Artifact storage uses a stable `recon_<target>` directory, truncates files on
every run, and keeps a plain-text command list, attack-path report, and loot
index. Individual modules also write files in the current directory. There is no
session identifier, manifest, checksum, atomic write, deduplication, JSON/CSV
index, or consistent raw/parsed separation. Passwords can appear in normal
console output and repeatable-command artifacts.

## Performance bottlenecks

- The fixed scan profile and hard-coded two-second timeout cannot be tuned.
- Worker throttling repeatedly starts `jobs` and `wc` and sleeps in a polling
  loop.
- Concurrent workers write directly to shared files and the terminal, which can
  interleave output and duplicate evidence.
- Repeated domain, credential, tool, and file checks occur in several layers.
- Post-scan checks are spread through top-level code, making it difficult to skip
  an entire unrelated module before initialization.
- A stable artifact path is initialized and truncated on every run, even when the
  user only needs console output.

## Compatibility risks

- Existing users rely on `./bash_simpleportscan.sh TARGET [flags]` and the
  localhost default.
- Aliases and `--option=value` forms are documented and must continue to work.
- Service modules depend heavily on global variables and specific temporary-file
  names.
- Operators may consume legacy `nmap_service_<target>.txt` and module-specific
  filenames.
- Tightening unknown-option handling changes a previously permissive parser, so
  errors and migration guidance must be explicit.

## Refactoring plan

1. Add sourceable modules for CLI parsing, presentation, validation, scan
   profiles, and artifact storage while retaining the existing service functions.
2. Add an explicit `scan` command and keep the positional legacy invocation as a
   compatibility path.
3. Add deterministic help, exit codes, configurable profiles/jobs/timeouts,
   quiet/verbose/debug modes, safe color/Unicode fallbacks, and structured summary
   output.
4. Make optional preflight, null-session, and guest checks conditional without
   allowing mandatory target validation to be skipped.
5. Introduce per-session raw/parsed/report directories, atomic manifest/index
   writes, SHA-256 deduplication, secure permissions, and legacy artifact aliases
   where practical.
6. Preserve service-enumeration logic incrementally, move its orchestration behind
   gates, and cover the new boundaries with a dependency-free Bash test harness.
