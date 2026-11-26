#!/usr/bin/env bash
# shellcheck disable=SC2034 # Values are consumed by the sourcing entry point.

SPS_VERSION="2.1.5"

sps_cli_defaults() {
    COMMAND="scan"
    CLI_ACTION="run"
    CLI_ERROR=""
    TARGET_DEFAULTED=false
    SCAN_PROFILE="default"
    CUSTOM_PORTS=""
    ENABLE_UDP_SCAN=true
    CUSTOM_UDP_PORTS=""
    MAX_JOBS=20
    MAX_JOBS_EXPLICIT=false
    CONNECT_TIMEOUT=0.25
    RETRY_LIMIT=0
    OUTPUT_FORMAT="text"
    COLOR_MODE="auto"
    ICON_MODE="auto"
    QUIET=false
    VERBOSE=false
    DEBUG=false
    SHOW_SECRETS=false
    DRY_RUN=false
    SKIP_PREFLIGHT=false
    SSHOLE_EVIDENCE_FILE=""
    SKIP_NULL_CHECKS=false
    SKIP_GUEST_CHECKS=false
    SKIP_DACL_AUDIT=false
    VHOST_DOMAIN=""
    VHOST_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    ENABLE_IMAP_ENUM=false
    ENABLE_IMAP_DUMP=false
    IMAP_MAILBOX="INBOX"
    IMAP_MAILBOX_EXPLICIT=false
    IMAP_MAX_MESSAGES=25
    IMAP_MAX_MESSAGES_EXPLICIT=false
    LOOT_ENABLED=true
    LOOT_BASE_DIR=""
    OVERWRITE=false
    INDEX_FORMAT="json"
    declare -ga CLI_DEPRECATIONS=()
    declare -ga ORIGINAL_ARGS=("$@")
}

sps_cli_fail() {
    CLI_ERROR="$1"
    printf '[-] Error: %s\n' "$CLI_ERROR" >&2
    printf 'Try "%s --help" for usage.\n' "${0##*/}" >&2
    return 2
}

sps_require_value() {
    local option="$1"
    local value="${2:-}"
    [[ -n "$value" ]] || sps_cli_fail "$option requires a value."
}

sps_parse_args() {
    local positional_count=0
    local option value

    while (($#)); do
        option="$1"
        case "$option" in
            scan)
                if ((positional_count > 0)) || [[ "$COMMAND" != "scan" ]]; then
                    sps_cli_fail "Unexpected command: $option" || return $?
                fi
                COMMAND="scan"
                ;;
            help)
                CLI_ACTION="help"
                ;;
            version)
                CLI_ACTION="version"
                ;;
            -h | --help)
                CLI_ACTION="help"
                ;;
            --version)
                CLI_ACTION="version"
                ;;
            -q | --quiet)
                QUIET=true
                ;;
            -v | --verbose)
                VERBOSE=true
                ;;
            --debug)
                DEBUG=true
                VERBOSE=true
                ;;
            --no-color)
                COLOR_MODE="never"
                ;;
            --color=*)
                COLOR_MODE="${option#*=}"
                ;;
            --color)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                COLOR_MODE="$1"
                ;;
            --ascii)
                ICON_MODE="ascii"
                ;;
            --unicode)
                ICON_MODE="unicode"
                ;;
            --show-secrets)
                SHOW_SECRETS=true
                ;;
            --format=*)
                OUTPUT_FORMAT="${option#*=}"
                ;;
            --format)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                OUTPUT_FORMAT="$1"
                ;;
            --profile=*)
                SCAN_PROFILE="${option#*=}"
                ;;
            --profile)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                SCAN_PROFILE="$1"
                ;;
            --ports=*)
                value="${option#*=}"
                sps_require_value "--ports" "$value" || return $?
                CUSTOM_PORTS="${CUSTOM_PORTS:+$CUSTOM_PORTS,}$value"
                ;;
            --ports)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                CUSTOM_PORTS="${CUSTOM_PORTS:+$CUSTOM_PORTS,}$1"
                ;;
            --udp)
                ENABLE_UDP_SCAN=true
                ;;
            --no-udp)
                ENABLE_UDP_SCAN=false
                ;;
            --udp-ports=*)
                value="${option#*=}"
                sps_require_value "--udp-ports" "$value" || return $?
                CUSTOM_UDP_PORTS="${CUSTOM_UDP_PORTS:+$CUSTOM_UDP_PORTS,}$value"
                ENABLE_UDP_SCAN=true
                ;;
            --udp-ports)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                CUSTOM_UDP_PORTS="${CUSTOM_UDP_PORTS:+$CUSTOM_UDP_PORTS,}$1"
                ENABLE_UDP_SCAN=true
                ;;
            --jobs=*)
                MAX_JOBS="${option#*=}"
                MAX_JOBS_EXPLICIT=true
                ;;
            --jobs)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                MAX_JOBS="$1"
                MAX_JOBS_EXPLICIT=true
                ;;
            --connect-timeout=*)
                CONNECT_TIMEOUT="${option#*=}"
                ;;
            --connect-timeout)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                CONNECT_TIMEOUT="$1"
                ;;
            --retries=*)
                RETRY_LIMIT="${option#*=}"
                ;;
            --retries)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                RETRY_LIMIT="$1"
                ;;
            --dry-run)
                DRY_RUN=true
                ;;
            --no-loot)
                LOOT_ENABLED=false
                ;;
            --loot-dir=*)
                LOOT_BASE_DIR="${option#*=}"
                ;;
            --loot-dir)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                LOOT_BASE_DIR="$1"
                ;;
            --overwrite)
                OVERWRITE=true
                ;;
            --index-format=*)
                INDEX_FORMAT="${option#*=}"
                ;;
            --index-format)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                INDEX_FORMAT="$1"
                ;;
            --skip-preflight)
                SKIP_PREFLIGHT=true
                ;;
            --skip-null-checks)
                SKIP_NULL_CHECKS=true
                ;;
            --skip-guest-checks)
                SKIP_GUEST_CHECKS=true
                ;;
            --skip-dacl-audit)
                SKIP_DACL_AUDIT=true
                ;;
            --vhost)
                ENABLE_VHOST=true
                ;;
            --vhost-domain=*)
                VHOST_DOMAIN="${option#*=}"
                sps_require_value "--vhost-domain" "$VHOST_DOMAIN" || return $?
                ENABLE_VHOST=true
                ;;
            --vhost-domain)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                VHOST_DOMAIN="$1"
                ENABLE_VHOST=true
                ;;
            --vhost-wordlist=*)
                VHOST_WORDLIST="${option#*=}"
                sps_require_value "--vhost-wordlist" "$VHOST_WORDLIST" || return $?
                ENABLE_VHOST=true
                ;;
            --vhost-wordlist)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                VHOST_WORDLIST="$1"
                ENABLE_VHOST=true
                ;;
            --kerb-enum)
                ENABLE_KERB_ENUM=true
                ;;
            --web-enum)
                ENABLE_WEB_ENUM=true
                ;;
            --web-wordlist=*)
                WEB_WORDLIST="${option#*=}"
                sps_require_value "--web-wordlist" "$WEB_WORDLIST" || return $?
                ENABLE_WEB_ENUM=true
                ;;
            --web-wordlist)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                WEB_WORDLIST="$1"
                ENABLE_WEB_ENUM=true
                ;;
            --run-blood)
                ENABLE_BH_EXPORT=true
                ;;
            --kerberoast)
                ENABLE_KERBROAST=true
                ;;
            --check-certs)
                ENABLE_ADCS=true
                ;;
            --check-cert | --check-ca)
                ENABLE_ADCS=true
                CLI_DEPRECATIONS+=("$option is a compatibility alias; prefer --check-certs.")
                ;;
            --check-mssql)
                ENABLE_MSSQL_ENUM=true
                ;;
            --mssql-brute)
                ENABLE_MSSQL_BRUTE=true
                ENABLE_MSSQL_ENUM=true
                ;;
            --mssql-privesc)
                ENABLE_MSSQL_PRIVESC=true
                ENABLE_MSSQL_ENUM=true
                ;;
            --mssql-enable-cmdshell)
                ENABLE_MSSQL_CMDSHELL=true
                ENABLE_MSSQL_ENUM=true
                ;;
            --service-detect)
                ENABLE_SERVICE_DETECT=true
                ;;
            --sshole-evidence=*)
                SSHOLE_EVIDENCE_FILE="${option#*=}"
                sps_require_value "--sshole-evidence" "$SSHOLE_EVIDENCE_FILE" || return $?
                ;;
            --sshole-evidence)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                SSHOLE_EVIDENCE_FILE="$1"
                ;;
            --imap-enum)
                ENABLE_IMAP_ENUM=true
                ;;
            --imap-dump)
                ENABLE_IMAP_ENUM=true
                ENABLE_IMAP_DUMP=true
                ;;
            --imap-mailbox=*)
                IMAP_MAILBOX="${option#*=}"
                sps_require_value "--imap-mailbox" "$IMAP_MAILBOX" || return $?
                IMAP_MAILBOX_EXPLICIT=true
                ;;
            --imap-mailbox)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                IMAP_MAILBOX="$1"
                IMAP_MAILBOX_EXPLICIT=true
                ;;
            --imap-max-messages=*)
                IMAP_MAX_MESSAGES="${option#*=}"
                IMAP_MAX_MESSAGES_EXPLICIT=true
                ;;
            --imap-max-messages)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                IMAP_MAX_MESSAGES="$1"
                IMAP_MAX_MESSAGES_EXPLICIT=true
                ;;
            --svc)
                ENABLE_SERVICE_DETECT=true
                CLI_DEPRECATIONS+=("--svc is a compatibility alias; prefer --service-detect.")
                ;;
            --dns-enum)
                ENABLE_DNS_ENUM=true
                ;;
            --dns-brute)
                ENABLE_DNS_ENUM=true
                DNS_BRUTE=true
                ;;
            --dns-no-axfr)
                DNS_AXFR=false
                ;;
            --dns-domain=*)
                DNS_DOMAIN="${option#*=}"
                ENABLE_DNS_ENUM=true
                ;;
            --dns-domain)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                DNS_DOMAIN="$1"
                ENABLE_DNS_ENUM=true
                ;;
            --dns-wordlist=*)
                DNS_WORDLIST="${option#*=}"
                ENABLE_DNS_ENUM=true
                DNS_BRUTE=true
                ;;
            --dns-wordlist)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                DNS_WORDLIST="$1"
                ENABLE_DNS_ENUM=true
                DNS_BRUTE=true
                ;;
            --user=* | --username=* | -u=*)
                AUTH_USER="${option#*=}"
                ;;
            --user | --username | -u)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                AUTH_USER="$1"
                ;;
            --pass=* | --password=* | -p=*)
                AUTH_PASS="${option#*=}"
                ;;
            --pass | --password | -p)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                AUTH_PASS="$1"
                ;;
            --domain=*)
                AUTH_DOMAIN="${option#*=}"
                ;;
            --domain)
                shift
                sps_require_value "$option" "${1:-}" || return $?
                AUTH_DOMAIN="$1"
                ;;
            --)
                shift
                while (($#)); do
                    if [[ -n "$TARGET" ]]; then
                        sps_cli_fail "Only one target is supported; unexpected argument: $1" || return $?
                    fi
                    TARGET="$1"
                    positional_count=$((positional_count + 1))
                    shift
                done
                break
                ;;
            -*)
                sps_cli_fail "Unknown option: $option" || return $?
                ;;
            *)
                if [[ -n "$TARGET" ]]; then
                    sps_cli_fail "Only one target is supported; unexpected argument: $option" || return $?
                fi
                TARGET="$option"
                positional_count=$((positional_count + 1))
                ;;
        esac
        shift
    done

    case "$COLOR_MODE" in auto | always | never) ;; *) sps_cli_fail "--color must be auto, always, or never." || return $? ;; esac
    case "$ICON_MODE" in auto | ascii | unicode) ;; *) sps_cli_fail "Invalid icon mode: $ICON_MODE" || return $? ;; esac
    case "$OUTPUT_FORMAT" in text | json | csv) ;; *) sps_cli_fail "--format must be text, json, or csv." || return $? ;; esac
    case "$SCAN_PROFILE" in default | web | ad | extended) ;; *) sps_cli_fail "--profile must be default, web, ad, or extended." || return $? ;; esac
    case "$INDEX_FORMAT" in text | json | csv | all) ;; *) sps_cli_fail "--index-format must be text, json, csv, or all." || return $? ;; esac
    [[ "$MAX_JOBS" =~ ^[1-9][0-9]*$ ]] && ((MAX_JOBS <= 256)) || {
        sps_cli_fail "--jobs must be an integer from 1 through 256." || return $?
    }
    [[ "$CONNECT_TIMEOUT" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]] || {
        sps_cli_fail "--connect-timeout must be a positive number of seconds." || return $?
    }
    [[ "$CONNECT_TIMEOUT" != "0" && "$CONNECT_TIMEOUT" != "0.0" ]] || {
        sps_cli_fail "--connect-timeout must be greater than zero." || return $?
    }
    [[ "$RETRY_LIMIT" =~ ^[0-9]+$ ]] && ((RETRY_LIMIT <= 10)) || {
        sps_cli_fail "--retries must be an integer from 0 through 10." || return $?
    }
    [[ "$IMAP_MAX_MESSAGES" =~ ^[1-9][0-9]*$ ]] && ((IMAP_MAX_MESSAGES <= 100)) || {
        sps_cli_fail "--imap-max-messages must be an integer from 1 through 100." || return $?
    }
    if [[ "$IMAP_MAILBOX" =~ [[:cntrl:]] ]]; then
        sps_cli_fail "--imap-mailbox cannot contain control characters." || return $?
    fi
    if [[ -n "$SSHOLE_EVIDENCE_FILE" && ( ! -f "$SSHOLE_EVIDENCE_FILE" || ! -r "$SSHOLE_EVIDENCE_FILE" ) ]]; then
        sps_cli_fail "--sshole-evidence requires a readable inventory file." || return $?
    fi
    if [[ "$IMAP_MAILBOX_EXPLICIT" == true && "$ENABLE_IMAP_DUMP" != true ]]; then
        sps_cli_fail "--imap-mailbox requires --imap-dump." || return $?
    fi
    if [[ "$IMAP_MAX_MESSAGES_EXPLICIT" == true && "$ENABLE_IMAP_DUMP" != true ]]; then
        sps_cli_fail "--imap-max-messages requires --imap-dump." || return $?
    fi
    if [[ "$ENABLE_IMAP_ENUM" == true && ( -z "${AUTH_USER:-}" || -z "${AUTH_PASS:-}" ) ]]; then
        sps_cli_fail "--imap-enum and --imap-dump require both -u/--user and -p/--pass." || return $?
    fi
    if [[ "$ENABLE_IMAP_DUMP" == true && "$LOOT_ENABLED" != true ]]; then
        sps_cli_fail "--imap-dump cannot be combined with --no-loot because message exports are stored as protected artifacts." || return $?
    fi
    if [[ -n "$CUSTOM_PORTS" && ! "$CUSTOM_PORTS" =~ ^[0-9,-]+$ ]]; then
        sps_cli_fail "--ports accepts comma-separated ports and ranges only." || return $?
    fi
    if [[ -n "$CUSTOM_UDP_PORTS" && ! "$CUSTOM_UDP_PORTS" =~ ^[0-9,-]+$ ]]; then
        sps_cli_fail "--udp-ports accepts comma-separated ports and ranges only." || return $?
    fi
    if [[ -n "$VHOST_DOMAIN" ]]; then
        VHOST_DOMAIN="${VHOST_DOMAIN%.}"
        if [[ ! "$VHOST_DOMAIN" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)([.]([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+$ ]]; then
            sps_cli_fail "--vhost-domain requires a DNS domain such as example.test." || return $?
        fi
        VHOST_DOMAIN="${VHOST_DOMAIN,,}"
    fi

    if [[ -z "$TARGET" && "$CLI_ACTION" == "run" ]]; then
        TARGET="$DEFAULT_TARGET"
        TARGET_DEFAULTED=true
    fi
}

sps_print_version() {
    printf 'fathomtrace %s\n' "$SPS_VERSION"
}

sps_print_help() {
    cat << 'EOF'
Usage:
  fathomtrace [scan] [TARGET] [OPTIONS]
  fathomtrace db-inventory ENGINE HOST USER [PORT] [--skip-ssl-verify-server-cert]
  fathomtrace help | --help

Scan one IPv4 address or hostname with a bounded-concurrency TCP profile and a
small targeted UDP profile, then run relevant service-enumeration modules.
TARGET defaults to 127.0.0.1 for backward compatibility.

Global options:
  -h, --help                  Show this help and exit.
      --version               Show the version and exit.
  -q, --quiet                 Suppress routine text output and banners.
  -v, --verbose               Show optional validation and skip details.
      --debug                 Show debug details; implies --verbose.
      --color MODE            Color mode: auto (default), always, or never.
      --no-color              Compatibility alias for --color never.
      --ascii                 Force safe ASCII status icons.
      --unicode               Force Unicode status icons.
      --show-secrets          Print and store supplied credentials without
                              redaction. Unsafe for shared terminals or logs.

Scan command options:
      --profile NAME          Port profile: default (default), web, ad, or
                              extended. Last value wins.
      --ports LIST            Scan comma-separated ports/ranges instead of a
                              profile. May be repeated; values are merged.
      --udp                    Enable the targeted UDP scan (default).
      --no-udp                 Disable targeted UDP scanning.
      --udp-ports LIST        Scan selected UDP ports instead of profile
                              defaults; implies --udp and may be repeated.
      --dry-run               Validate and show the selected operation without
                              connecting to the target or creating loot.
      --vhost                 Enable virtual-host discovery when web ports open.
      --vhost-domain DOMAIN   Use DOMAIN as the VHost suffix; implies --vhost.
      --vhost-wordlist FILE   Use FILE for VHost labels; implies --vhost.
                              Defaults to SecLists top-5000 subdomains.
      --web-enum              Enable web content enumeration when applicable.
      --web-wordlist FILE     Use FILE for FFUF content discovery; implies
                              --web-enum. Defaults to SecLists raft-small-words.
      --service-detect        Run Nmap against discovered TCP and UDP ports.
      --sshole-evidence FILE  Assess SSHole using authorized host inventory.
      --imap-enum             After a successful encrypted login, list IMAP
                              mailboxes without selecting them.
      --imap-dump             Export messages read-only after login; implies
                              --imap-enum and requires persistent artifacts.
      --imap-mailbox NAME     Mailbox examined first by --imap-dump; default:
                              INBOX. Other selectable LIST results follow.
      --imap-max-messages N   Export at most the newest N messages total across
                              selectable mailboxes; default: 25, maximum: 100.
      --kerb-enum             Enable Kerberos user enumeration.
      --run-blood             Enable BloodHound collection, preferring
                              bloodhound-ce-python with legacy fallback.
      --kerberoast            Enable Kerberoast collection when prerequisites
                              and credentials are available.
      --check-certs           Enable AD CS checks when prerequisites exist.
      --check-mssql           Enable MSSQL enumeration when port 1433 is open.
      --mssql-brute           Enable the legacy MSSQL default-credential check.
      --mssql-privesc         Permit NetExec MSSQL privilege-escalation actions;
                              may alter SQL principal privileges.
      --mssql-enable-cmdshell Permit the authenticated MSSQL module to attempt
                              enabling xp_cmdshell; changes server configuration.
      --dns-enum              Enable DNS enumeration when port 53 is open.
      --dns-brute             Also enable DNS name brute forcing.
      --dns-domain DOMAIN     Set the DNS domain and enable DNS enumeration.
      --dns-wordlist FILE     Set the DNS wordlist and enable DNS brute force.
      --dns-no-axfr           Disable DNS zone-transfer attempts.

Authentication options:
  -u, --user USER             Username for selected authenticated modules.
      --username USER         Compatibility alias for --user.
  -p, --pass PASS             Password for selected authenticated modules.
      --password PASS         Compatibility alias for --pass.
      --domain DOMAIN         Authentication domain or Kerberos realm.
  Options also accept the legacy --name=value, -u=value, and -p=value forms.
  Authentication options are not repeatable; the last value wins.

Output and loot options:
      --format FORMAT         Console format: text (default), json, or csv.
                              JSON/CSV write only the stable summary to stdout.
      --no-loot               Do not create a session artifact directory.
      --loot-dir PATH         Store session artifacts below PATH instead of
                              recon_<sanitized-target>.
      --index-format FORMAT   Artifact index: json (default), text, csv, or all.
      --overwrite             Replace an explicitly colliding session directory.

Performance options:
      --jobs N                Concurrent TCP probes; default: 20, maximum: 256.
                              When supplied, N also sets FFUF threads; otherwise
                              FFUF defaults to 50 threads.
      --connect-timeout SEC   Per-attempt TCP timeout; default: 0.25 seconds.
      --retries N             Retry failed TCP probes N times; default: 0,
                              maximum: 10.

Validation options:
      --skip-preflight        Skip optional reverse DNS and discovery preflight.
                              Target syntax/resolution and safe paths remain
                              mandatory.
      --skip-null-checks      Skip optional anonymous/null-session checks.
      --skip-guest-checks     Skip optional guest-account checks.
      --skip-dacl-audit       Skip the Impacket and bloodyAD writable-object
                              audits. DACL auditing is enabled by default.

Examples:
  ./fathomtrace 10.10.10.10
  ./fathomtrace scan dc01.example.test --profile ad --jobs 32
  ./fathomtrace 10.10.10.10 --ports 22,80,443,8000-8010
  ./fathomtrace 10.10.10.10 --udp-ports 53,123,161,500 --service-detect
  ./fathomtrace dc01.example.test --domain example.test \
      --user analyst --pass 'REPLACE_ME' --kerb-enum --check-certs
  ./fathomtrace mail.example.test --ports 143,993 -u analyst \
      -p 'REPLACE_ME' --imap-dump --imap-mailbox INBOX
  ./fathomtrace 10.10.10.10 --format json --no-color --no-loot
  ./fathomtrace 127.0.0.1 --dry-run --debug --ascii

Exit codes:
  0  Requested operation completed.
  2  Command-line usage error.
  3  Invalid or unresolvable target.
  4  Mandatory local runtime requirement is unavailable.
  5  Scan orchestration failed.

Use only on systems you own or are explicitly authorized to test.
EOF
}
