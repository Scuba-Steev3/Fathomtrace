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
- Profile-aware targeted UDP scanning with conservative `open` versus
  `open|filtered` reporting. SNMP/161 is included by default, with a bounded
  read-only `sysDescr.0` check for device identity and `public` community
  exposure.
- Read-only SMTP greeting, EHLO/HELO, HELP, capability, and hostname discovery
  on ports 25, 465, 587, and 2525. Port 465 uses OpenSSL when available.
- Read-only POP3 CAPA discovery on ports 110/995 and IMAP CAPABILITY discovery
  on ports 143/993, including TLS-upgrade and authentication advertisements.
- Automatic mail TLS certificate capture for implicit TLS and advertised
  STARTTLS/STLS services, with CN, SAN, issuer, validity, serial, and SHA-256
  fingerprint parsing. Concrete CN/SAN hostnames feed host discovery.
- Contextual IMAP OpenSSL connection commands for STARTTLS on port 143 and
  implicit TLS on port 993, plus tagged-command and credential-safety reminders.
- A single encrypted IMAP login validation when `-u/--user` and `-p/--pass`
  are supplied. Port 993 is preferred over STARTTLS/143, passwords are never
  retained in transcripts, and no mailbox or message command is issued.
- Optional Telnet-based greeting capture on cleartext SMTP, POP3, and IMAP
  ports when a local `telnet` client is available; no input is sent.
- A concise port-scan phase that reports listeners first, followed by a separate
  service-exposure phase for protocol probes, banners, certificates, and
  authenticated or opt-in enumeration.
- Service-exposure output grouped by protocol with descriptive service titles
  and separate endpoint blocks for clear terminal review.
- Deterministic worker aggregation instead of concurrent shared-file writes.
- Service-aware NetBIOS, FTP, SMB, RPC, LDAP, Kerberos, DNS, web, MSSQL, NFS, Docker,
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
ffuf, `nmblookup` or `nbtscan`, DNS/LDAP/SMB clients, NetExec,
Impacket, Certipy, and BloodHound tooling.

Targeted UDP scanning is enabled by default. The default profile checks UDP
53, 123, 137, 161, and 500; the web profile checks 53 and 161; the AD profile
checks 53, 88, 123, 137, 161, 389, and 464; and the extended profile adds
common TFTP, DHCP, IPMI, MSSQL Browser, SSDP, IPsec NAT-T, and mDNS ports.
Nmap classifies the selected set when available. Without Nmap, Fathomtrace can
still send its bounded SNMP/161 probe, but it does not guess the state of silent
UDP services.

Authenticated IMAP behavior is intentionally staged. Supplying `-u` and `-p`
performs one encrypted login validation and logs out without opening a mailbox.
`--imap-enum` additionally issues `LIST "" "*"`. Message export requires the
explicit `--imap-dump` flag. It examines `--imap-mailbox` (default `INBOX`)
first, then every other selectable mailbox returned by `LIST`; hierarchy nodes
marked `\Noselect` are skipped. Mailboxes are opened with read-only `EXAMINE`,
and at most `--imap-max-messages` newest messages total are retrieved with
`BODY.PEEK[]`. Empty or inaccessible mailboxes do not stop later mailbox checks.
Exports are treated as sensitive artifacts, so `--imap-dump` cannot be combined
with `--no-loot`.

NetBIOS identity detection runs automatically against the selected target. It
uses `nmblookup -A` when available and falls back to `nbtscan`. A valid unique
workstation or file-server name is displayed, retained with the raw node-status
evidence, and added to the `/etc/hosts` suggestions. On Kali, install either
provider with `sudo apt install samba-common-bin` or `sudo apt install nbtscan`.

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

# Override the profile's targeted UDP ports and run UDP service detection
./fathomtrace scan 10.10.10.10 --udp-ports 53,123,161,500 --service-detect

# TCP-only run
./fathomtrace scan 10.10.10.10 --no-udp

# Make one encrypted IMAP login attempt when IMAP is confirmed
./fathomtrace scan 10.10.10.10 --ports 143,993 -u analyst -p 'REPLACE_ME'

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

Database discovery fingerprints open TCP/1433 and TCP/3306 with Nmap and
Python 3 when both are available. It reports Microsoft SQL Server, MySQL, or
MariaDB and the version when identified. Generic protocol matches are reported
as MySQL-compatible. This probe does not log in or execute SQL. Use
`--skip-preflight` to disable it.

### Credentialed database inventory

Run the inventory command in an interactive terminal with a DNS hostname that
matches the server certificate. The native client prompts for the password.

```bash
fathomtrace db-inventory mysql mysql.example.org inventory_reader
fathomtrace db-inventory mariadb maria.example.org inventory_reader 3307
fathomtrace db-inventory mssql sql.example.org inventory_reader
```

On Kali, install `python3-pymssql` for SQL Server and `mariadb-client` for
MySQL and MariaDB. SQL Server also supports Microsoft's ODBC `sqlcmd`
(`mssql-tools18`) when pymssql is unavailable. For a private CA, set
`FATHOMTRACE_DB_CA_FILE` to its PEM CA bundle when using pymssql, MySQL, or
MariaDB. The inventory command can use either Kali's `mysql` compatibility
command or the `mariadb` executable. ODBC sqlcmd uses the system trust store.

For MySQL or MariaDB, append `--skip-ssl-verify-server-cert` to opt out of
certificate verification. Oracle MySQL still requires TLS. The MariaDB client
can fall back to an unencrypted connection with this flag.

The command prints database and base-table names visible to the supplied
account. SQL Server table inventory covers accessible online databases.
Client errors appear on the terminal and return a nonzero exit status.

| Group | Options |
|---|---|
| Commands | `scan`, `help`, `version` |
| Port selection | `--profile default\|web\|ad\|extended`, repeatable `--ports LIST`, `--udp-ports LIST`, `--no-udp` |
| Performance | `--jobs N`, `--connect-timeout SEC`, `--retries N` |
| Service detection | `--service-detect` |
| Output | `--format text\|json\|csv`, `--quiet`, `--verbose`, `--debug`, `--color`, `--no-color`, `--ascii`, `--unicode`, `--show-secrets` |
| Artifacts | `--no-loot`, `--loot-dir PATH`, `--index-format text\|json\|csv\|all`, `--overwrite` |
| Optional checks | `--skip-preflight`, `--skip-null-checks`, `--skip-guest-checks`, `--skip-dacl-audit` |
| Authentication | `--user USER`, `--pass PASS`, `--domain DOMAIN` |

When TCP/22 is open, Fathomtrace reads the SSH server identification string
and reports the advertised software and protocol version. OpenSSH versions
earlier than 10.6p2 produce a potential-exposure advisory for CVE-2026-123158.
`--service-detect` can also identify SSH on alternate ports selected for the
scan. The SSH version alone leaves libc, PAM, authentication settings, and
distribution backports unverified.

When TCP/3389 is open and both `--user` and `--pass` are supplied, Fathomtrace
uses `nxc rdp` or `netexec rdp` to validate exactly that single credential pair.
The command is wrapped in a 20-second outer timeout and recorded in the command
artifacts; screenshot, command-execution, and interactive-session options are
not enabled. The summary reports
`success`, `failure`, or `skipped`. A successful result is added to the Attack
Path Decision Engine as an authenticated RDP remote-service opportunity mapped
to MITRE ATT&CK T1021.001. Missing NetExec RDP support, timeouts, and transport or
protocol errors are reported as skipped/inconclusive rather than as bad
credentials.

DACL auditing remains enabled by default for authenticated LDAP scans. Use
`--skip-dacl-audit` to bypass both the targeted Impacket DACL review and the
directory-wide bloodyAD writable-object audit.

Feature flags include `--vhost`, `--web-enum`, `--service-detect`,
`--kerb-enum`, `--kerberoast`, `--run-blood`, `--check-certs`,
`--check-mssql`, `--mssql-brute`, and DNS enumeration controls.

`--run-blood` prefers `bloodhound-ce-python` and uses its `All` collection
method. When the CE collector is unavailable, Fathomtrace falls back to the
legacy `bloodhound-python` collector with `DCOnly` collection.

`--web-enum` uses FFUF for directory and file discovery. It prefers SecLists'
`/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt` and falls back
to a small built-in list when that file is unavailable. Use
`--web-wordlist FILE` to select another web-content list. FFUF uses 50 threads
by default; when `--jobs N` is explicitly supplied, FFUF uses `N` threads.
DNS brute forcing
continues to default to
`/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`; that list
contains subdomain labels and is not the directory-enumeration default.

`--vhost --vhost-domain DOMAIN` uses FFUF Host-header fuzzing with automatic
calibration and the same SecLists top-5000 subdomain list. Use
`--vhost-wordlist FILE` to override it. A missing list falls back to the
built-in VHost names. If FFUF is unavailable, fails, or its JSON results cannot
be parsed, Fathomtrace performs a smaller curl-based check and compares
candidates against two randomized wildcard-host baselines; unstable wildcard
responses are skipped rather than reported as likely false positives. FFUF uses
50 threads unless `--jobs N` was supplied.

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
- profile, confirmed TCP/UDP ports, and inconclusive UDP `open|filtered` candidates;
- duration and session ID;
- artifact root, manifest, and artifact count;
- the final error when the operation fails.

```json
{"schema_version":"1.0","command":"scan","status":"completed","exit_code":0,"target":"10.10.10.10","resolved_target":"10.10.10.10","profile":"default","open_ports":[22,80],"open_udp_ports":[161],"possible_udp_ports":[53],"duration_seconds":3,"session_id":"20260719T210000Z_1a2b3c4d","artifact_root":"/work/recon_10.10.10.10/20260719T210000Z_1a2b3c4d","manifest":"reports/manifest.jsonl","artifact_count":8,"error":null}
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
