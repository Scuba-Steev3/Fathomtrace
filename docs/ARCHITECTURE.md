# Architecture

Fathomtrace is a Bash 4+ TCP connect scanner and service-enumeration orchestrator.
The executable retains the mature service-specific implementation while its
cross-cutting boundaries are sourceable and independently testable.

## Components

- `fathomtrace` owns session state and service-specific orchestration.
- `lib/fathomtrace/cli.sh` parses commands and validates option values.
- `lib/fathomtrace/output.sh` owns presentation, redaction, and structured output.
- `lib/fathomtrace/validation.sh` validates targets and selected prerequisites.
- `lib/fathomtrace/scan.sh` expands profiles and runs the bounded worker pool.
- `lib/fathomtrace/loot.sh` owns secure session storage and manifests.

## Execution flow

1. Load the libraries from the repository or installed prefix.
2. Parse the CLI and initialize output behavior.
3. Validate mandatory runtime commands and the target.
4. Build a maintained or custom port set.
5. Probe ports concurrently and aggregate results in deterministic order.
6. Run service-relevant and explicitly selected modules.
7. Organize artifacts, finalize manifests, and emit the final summary.

Machine formats reserve standard output for one schema-versioned summary.
Diagnostics use standard error. Persistent sessions use unique directories,
restrictive permissions, atomic manifest updates, SHA-256 checksums, and
content-based deduplication.

## Compatibility boundary

`bash_simpleportscan.sh` is a wrapper for migrations from the original Tooling
repository. Internal `sps_` function prefixes remain intentionally stable while
the public command is `fathomtrace`.
