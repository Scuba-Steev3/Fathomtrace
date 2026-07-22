# Fathomtrace

Fathomtrace is a bounded-concurrency Bash port scanner and service-enumeration
orchestrator for authorized security assessments. Like the navigational charts
it is named after, it turns an unfamiliar target into a useful service map.

> [!WARNING]
> Use Fathomtrace only on systems you own or are explicitly authorized to test.
> Optional modules can attempt credentials, generate substantial traffic, and—
> only when separately enabled—change MSSQL configuration or privileges.

## Highlights

- Maintained default, web, Active Directory, and extended TCP port profiles.
- Custom ports and ranges with configurable jobs, timeouts, and retries.
- Deterministic worker aggregation instead of concurrent shared-file writes.
- Service-aware FTP, SMB, RPC, LDAP, Kerberos, DNS, web, MSSQL, NFS, Docker,
  Redis, Kubernetes, database, WinRM, RDP, AD CS, and BloodHound integrations.
- Text output for operators and stable JSON/CSV summaries for automation.
- Quiet, verbose, debug, color, ASCII, and Unicode presentation controls.
- Unique, private artifact sessions with manifests, checksums, deduplication,
  sensitivity labels, and partial-failure records.
- Credential redaction in guidance, diagnostics, structured summaries,
  repeatable commands, and captured-console artifacts.
- Compatibility with the original `bash_simpleportscan.sh` command name.

## Requirements

Fathomtrace requires Bash 4 or newer, `/dev/tcp`, `timeout`, and common Unix
utilities. Persistent artifact collection also uses standard file utilities such
as `find`, `cp`, `chmod`, and `wc`.

External utilities are optional. Their modules run only when their service and
feature prerequisites are satisfied. Examples include Nmap, curl, OpenSSL,
ffuf, DNS/LDAP/SMB clients, NetExec, Impacket, Certipy, and BloodHound tooling.

## Install

Run directly from a clone:

```bash
git clone https://github.com/Scuba-Steev3/Fathomtrace.git
cd Fathomtrace
./fathomtrace --help
```

Or install into `$HOME/.local`:

```bash
./install.sh
export PATH="$HOME/.local/bin:$PATH"
fathomtrace --version
```

Use a different prefix when needed:

```bash
./install.sh --prefix /usr/local
```

The installer places the executable under `PREFIX/bin` and its sourceable
libraries under `PREFIX/lib/fathomtrace`. Use `--no-legacy-wrapper` to omit the old
command name.

## Quick start

```bash
# Preferred explicit command
./fathomtrace scan 10.10.10.10

# Focused web profile
./fathomtrace scan app.example.test --profile web --jobs 32

# Custom ports and ranges
./fathomtrace scan 10.10.10.10 --ports 22,80,443,8000-8010

# Validate without connecting or writing persistent artifacts
./fathomtrace scan 127.0.0.1 --dry-run --no-loot --debug --ascii

# Stable machine-readable output
./fathomtrace scan 10.10.10.10 --format json --no-color > summary.json
```

The historical form remains valid:

```bash
./bash_simpleportscan.sh 10.10.10.10 --svc
```

## CLI overview

Run `fathomtrace --help` for the canonical reference.

| Group | Options |
|---|---|
| Commands | `scan`, `help`, `version` |
| Port selection | `--profile default\|web\|ad\|extended`, repeatable `--ports LIST` |
| Performance | `--jobs N`, `--connect-timeout SEC`, `--retries N` |
| Output | `--format text\|json\|csv`, `--quiet`, `--verbose`, `--debug`, `--color`, `--no-color`, `--ascii`, `--unicode`, `--show-secrets` |
| Artifacts | `--no-loot`, `--loot-dir PATH`, `--index-format text\|json\|csv\|all`, `--overwrite` |
| Optional checks | `--skip-preflight`, `--skip-null-checks`, `--skip-guest-checks` |
| Authentication | `--user USER`, `--pass PASS`, `--domain DOMAIN` |

Feature flags include `--vhost`, `--web-enum`, `--service-detect`,
`--kerb-enum`, `--kerberoast`, `--run-blood`, `--check-certs`,
`--check-mssql`, `--mssql-brute`, and DNS enumeration controls.

MSSQL enumeration does not attempt privilege escalation or enable
`xp_cmdshell` by default. Those actions require `--mssql-privesc` or
`--mssql-enable-cmdshell` plus valid credentials. Confirm that each action is
within the rules of engagement before selecting it.

### Color and credential display

Interactive text output uses a conventional CLI palette: green for success,
blue for information, cyan for findings, yellow for warnings, red for errors or
critical results, and gray for debug messages. `--color auto` is the default.
Fathomtrace also honors `NO_COLOR`, `CLICOLOR=0`, and `CLICOLOR_FORCE`.

Force colors when output is passing through a terminal wrapper or pager that
does not report TTY capability:

```bash
fathomtrace scan 10.10.10.10 --color always
```

Credentials remain redacted by default. To print and store their exact values:

```bash
fathomtrace scan 10.10.10.10 \
  --user analyst --pass 'REPLACE_ME' \
  --show-secrets --color always
```

`--show-secrets` can expose passwords in terminal scrollback, redirected logs,
repeatable-command files, manifests, and captured-console artifacts. Use it only
when those destinations are private and protected.

## Structured output

JSON and CSV modes reserve standard output for one final scan-summary record.
Diagnostics go to standard error. Schema version `1.0` reports:

- command status and exit code;
- requested and resolved targets;
- profile and open ports;
- duration and session ID;
- artifact root, manifest, and artifact count;
- the final error when the operation fails.

```json
{"schema_version":"1.0","command":"scan","status":"completed","exit_code":0,"target":"10.10.10.10","resolved_target":"10.10.10.10","profile":"default","open_ports":[22,80],"duration_seconds":3,"session_id":"20260719T210000Z_1a2b3c4d","artifact_root":"/work/recon_10.10.10.10/20260719T210000Z_1a2b3c4d","manifest":"reports/manifest.jsonl","artifact_count":8,"error":null}
```

## Artifact sessions

The default layout is:

```text
recon_<sanitized-target>/
└── <UTC-timestamp_random-suffix>/
    ├── commands/   # redacted repeatable commands
    ├── evidence/   # supporting evidence
    ├── raw/        # tool output and console transcript (redacted by default)
    ├── parsed/     # normalized JSON, CSV, and lists
    ├── loot/       # credentials, hashes, tickets, and keys
    └── reports/    # synopsis, attack paths, and indexes
```

Directories and files receive restrictive permissions where supported. Manifest
records include collection time, source, redacted command, module, byte size,
SHA-256, local path, status, sensitivity, duplicate source, and error details.

`--no-loot` routes legacy module output through a private temporary directory
and removes it at exit.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Requested operation completed |
| 2 | Command-line usage error |
| 3 | Invalid or unresolvable target |
| 4 | Mandatory runtime requirement unavailable |
| 5 | Scan or artifact orchestration failed |

## Development

```bash
make test
make lint
make format-check
```

The dependency-free Bash suite covers CLI behavior, redaction, output schemas,
worker determinism, artifact manifests, deduplication, partial failures, and
conditional module execution.

Project structure:

```text
fathomtrace                 Main executable and service orchestration
lib/fathomtrace/            Sourceable cross-cutting modules
tests/                      Test runner and golden help fixture
docs/ARCHITECTURE.md        Current architecture
docs/HISTORY.md             Original Tooling-repository assessment
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before
submitting changes or vulnerability reports.

## Name

Fathomtrace combines *fathom*—to measure or understand depth—with *trace*, the
evidence left by discovery. The name reflects the tool's role: map reachable
services, preserve the evidence, and leave the operator with practical paths to
inspect.

## License

Fathomtrace carries forward the source repository's GNU General Public License v3.0.
See [LICENSE](LICENSE).
