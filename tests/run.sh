#!/usr/bin/env bash
# shellcheck disable=SC2034 # Test fixtures provide globals consumed by sourced modules.

set -uo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
SCRIPT="$ROOT_DIR/fathomtrace"
LEGACY_SCRIPT="$ROOT_DIR/bash_simpleportscan.sh"
TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/fathomtrace-tests.XXXXXX")"
PASS_COUNT=0
FAIL_COUNT=0

cleanup_tests() {
    [[ -d "$TEST_TMP" && "$TEST_TMP" == *fathomtrace-tests.* ]] && rm -rf -- "$TEST_TMP"
}
trap cleanup_tests EXIT

pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    printf '[PASS] %s\n' "$1"
}

fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf '[FAIL] %s\n' "$1" >&2
}

assert_eq() {
    local expected="$1" actual="$2" name="$3"
    [[ "$actual" == "$expected" ]] && pass "$name" || fail "$name (expected '$expected', got '$actual')"
}

assert_contains() {
    local file="$1" expected="$2" name="$3"
    grep -Fq -- "$expected" "$file" && pass "$name" || fail "$name (missing '$expected')"
}

assert_not_contains() {
    local file="$1" unexpected="$2" name="$3"
    if grep -Fq -- "$unexpected" "$file"; then
        fail "$name (found '$unexpected')"
    else
        pass "$name"
    fi
}

assert_file() {
    local file="$1" name="$2"
    [[ -f "$file" ]] && pass "$name" || fail "$name (missing $file)"
}

assert_no_file() {
    local file="$1" name="$2"
    [[ ! -e "$file" ]] && pass "$name" || fail "$name (unexpected $file)"
}

run_cli() {
    local name="$1"
    shift
    CLI_STDOUT="$TEST_TMP/$name.stdout"
    CLI_STDERR="$TEST_TMP/$name.stderr"
    "$SCRIPT" "$@" > "$CLI_STDOUT" 2> "$CLI_STDERR"
    CLI_RC=$?
}

run_cli help --help
assert_eq 0 "$CLI_RC" "help exits successfully"
if diff -u "$ROOT_DIR/tests/fixtures/help.txt" "$CLI_STDOUT" > "$TEST_TMP/help.diff"; then
    pass "help output matches golden file"
else
    fail "help output matches golden file"
    sed -n '1,80p' "$TEST_TMP/help.diff" >&2
fi

run_cli version --version
assert_eq 0 "$CLI_RC" "version exits successfully"
assert_contains "$CLI_STDOUT" "fathomtrace 2.1.0" "version is stable"

"$LEGACY_SCRIPT" --version > "$TEST_TMP/legacy.stdout" 2> "$TEST_TMP/legacy.stderr"
assert_eq 0 "$?" "legacy command wrapper exits successfully"
assert_contains "$TEST_TMP/legacy.stdout" "fathomtrace 2.1.0" "legacy command wrapper delegates to Fathomtrace"

"$ROOT_DIR/install.sh" --prefix "$TEST_TMP/install-prefix" --no-legacy-wrapper > "$TEST_TMP/install.stdout" 2> "$TEST_TMP/install.stderr"
assert_eq 0 "$?" "prefix installer exits successfully"
"$TEST_TMP/install-prefix/bin/fathomtrace" --version > "$TEST_TMP/installed.stdout" 2> "$TEST_TMP/installed.stderr"
assert_eq 0 "$?" "installed prefix layout resolves libraries"
assert_contains "$TEST_TMP/installed.stdout" "fathomtrace 2.1.0" "installed command reports the Fathomtrace version"
assert_no_file "$TEST_TMP/install-prefix/bin/bash_simpleportscan.sh" "installer can omit the legacy wrapper"

"$ROOT_DIR/install.sh" --prefix "$TEST_TMP/install-prefix-legacy" > "$TEST_TMP/install-legacy.stdout" 2> "$TEST_TMP/install-legacy.stderr"
assert_eq 0 "$?" "default installer exits successfully"
assert_file "$TEST_TMP/install-prefix-legacy/bin/bash_simpleportscan.sh" "default installer includes the legacy wrapper"
"$TEST_TMP/install-prefix-legacy/bin/bash_simpleportscan.sh" --version > "$TEST_TMP/installed-legacy.stdout" 2> "$TEST_TMP/installed-legacy.stderr"
assert_eq 0 "$?" "installed legacy wrapper exits successfully"
assert_contains "$TEST_TMP/installed-legacy.stdout" "fathomtrace 2.1.0" "installed legacy wrapper delegates to Fathomtrace"

run_cli unknown --definitely-unknown
assert_eq 2 "$CLI_RC" "unknown option uses CLI exit code"
assert_contains "$CLI_STDERR" "Unknown option" "unknown option is explained"

run_cli invalid-ports 127.0.0.1 --dry-run --no-loot --ports 0,70000
assert_eq 2 "$CLI_RC" "invalid ports use CLI exit code"
assert_contains "$CLI_STDERR" "selected port set" "invalid ports are explained"

run_cli invalid-jobs 127.0.0.1 --dry-run --no-loot --jobs 0
assert_eq 2 "$CLI_RC" "invalid worker count uses CLI exit code"
assert_contains "$CLI_STDERR" "--jobs must be" "invalid worker count is explained"

(
    TARGET=""
    source "$ROOT_DIR/lib/fathomtrace/cli.sh"
    sps_cli_defaults
    sps_parse_args scan 127.0.0.1 --jobs 37 --ports 80
    printf '%s:%s\n' "$MAX_JOBS" "$MAX_JOBS_EXPLICIT"
) > "$TEST_TMP/explicit-jobs.txt"
assert_contains "$TEST_TMP/explicit-jobs.txt" "37:true" "explicit --jobs is tracked for FFUF"

(
    TARGET="" AUTH_USER="" AUTH_PASS=""
    source "$ROOT_DIR/lib/fathomtrace/cli.sh"
    sps_cli_defaults
    sps_parse_args scan 192.0.2.143 -u robin -p robin --imap-dump \
        --imap-mailbox DEV.DEPARTMENT.INT --imap-max-messages 10
    printf '%s|%s|%s|%s|%s\n' "$AUTH_USER" "$ENABLE_IMAP_ENUM" "$ENABLE_IMAP_DUMP" \
        "$IMAP_MAILBOX" "$IMAP_MAX_MESSAGES"
) > "$TEST_TMP/imap-cli-options"
assert_eq "robin|true|true|DEV.DEPARTMENT.INT|10" "$(cat "$TEST_TMP/imap-cli-options")" "IMAP dump options parse with short credential flags"

(
    TARGET="" AUTH_USER="" AUTH_PASS=""
    source "$ROOT_DIR/lib/fathomtrace/cli.sh"
    sps_cli_defaults
    sps_parse_args scan 192.0.2.143 --imap-enum > /dev/null 2>&1
    printf '%s\n' "$?"
) > "$TEST_TMP/imap-cli-missing-creds"
assert_eq "2" "$(cat "$TEST_TMP/imap-cli-missing-creds")" "IMAP enumeration requires explicit credentials"

(
    TARGET="" AUTH_USER="" AUTH_PASS=""
    source "$ROOT_DIR/lib/fathomtrace/cli.sh"
    sps_cli_defaults
    sps_parse_args scan 192.0.2.143 -u robin -p robin --imap-dump --no-loot > /dev/null 2>&1
    printf '%s\n' "$?"
) > "$TEST_TMP/imap-cli-no-loot"
assert_eq "2" "$(cat "$TEST_TMP/imap-cli-no-loot")" "IMAP message dumping requires persistent protected artifacts"

(
    TARGET=""
    source "$ROOT_DIR/lib/fathomtrace/cli.sh"
    sps_cli_defaults
    printf '%s\n' "$CONNECT_TIMEOUT"
) > "$TEST_TMP/default-connect-timeout.txt"
assert_contains "$TEST_TMP/default-connect-timeout.txt" "0.25" "default port-scanning timeout is 250 ms"

(
    TARGET="" AUTH_USER="" AUTH_PASS=""
    source "$ROOT_DIR/lib/fathomtrace/cli.sh"
    source "$ROOT_DIR/lib/fathomtrace/scan.sh"
    source "$ROOT_DIR/lib/fathomtrace/udp.sh"
    sps_cli_defaults
    sps_parse_args scan 192.0.2.161 --udp-ports 53,161,500
    sps_configure_udp_ports
    printf '%s|%s|%s\n' "$ENABLE_UDP_SCAN" "$CUSTOM_UDP_PORTS" "${UDP_PORTS[*]}"
    TARGET=""
    sps_cli_defaults
    sps_parse_args scan 192.0.2.161 --no-udp
    sps_configure_udp_ports
    printf '%s|%s\n' "$ENABLE_UDP_SCAN" "${#UDP_PORTS[@]}"
) > "$TEST_TMP/udp-cli-options"
assert_contains "$TEST_TMP/udp-cli-options" "true|53,161,500|53 161 500" "custom UDP ports enable and configure targeted scanning"
assert_contains "$TEST_TMP/udp-cli-options" "false|0" "--no-udp disables targeted UDP scanning"

(
    source "$ROOT_DIR/lib/fathomtrace/cli.sh"
    source "$ROOT_DIR/lib/fathomtrace/scan.sh"
    source "$ROOT_DIR/lib/fathomtrace/udp.sh"
    sps_cli_defaults
    sps_configure_udp_ports
    printf '%s\n' "${UDP_PORTS[@]}"
) > "$TEST_TMP/default-udp-ports"
assert_contains "$TEST_TMP/default-udp-ports" "161" "default targeted UDP profile includes SNMP/161"

(
    source "$ROOT_DIR/lib/fathomtrace/cli.sh"
    source "$ROOT_DIR/lib/fathomtrace/scan.sh"
    sps_cli_defaults
    sps_configure_ports
    printf '%s\n' "${PORTS[@]}"
    SCAN_PROFILE=extended
    sps_configure_ports
    printf '%s\n' "${PORTS[@]}"
) > "$TEST_TMP/default-mail-ports.txt"
assert_contains "$TEST_TMP/default-mail-ports.txt" "25:SMTP:interesting" "default profile retains SMTP port 25"
assert_contains "$TEST_TMP/default-mail-ports.txt" "465:SMTPS:interesting" "default profile includes implicit TLS SMTP"
assert_contains "$TEST_TMP/default-mail-ports.txt" "587:SMTP Submission:interesting" "default profile includes SMTP submission"
assert_contains "$TEST_TMP/default-mail-ports.txt" "2525:SMTP-Alt:interesting" "extended profile includes alternate SMTP"
assert_contains "$TEST_TMP/default-mail-ports.txt" "993:IMAPS:interesting" "default profile retains implicit TLS IMAP"
assert_contains "$TEST_TMP/default-mail-ports.txt" "995:POP3S:interesting" "default profile includes implicit TLS POP3"

(
    source "$ROOT_DIR/lib/fathomtrace/smb.sh"
    args=()
    sps_build_netexec_smb_auth_args args hodor hodor NORTH
    (IFS='|'; printf '%s\n' "${args[*]}")
) > "$TEST_TMP/netexec-smb-domain-args.txt"
assert_contains "$TEST_TMP/netexec-smb-domain-args.txt" "-u|hodor|-p|hodor|-d|NORTH" "NetExec SMB authentication passes the supplied domain"

(
    source "$ROOT_DIR/lib/fathomtrace/smb.sh"
    args=()
    sps_build_netexec_smb_auth_args args hodor hodor ""
    (IFS='|'; printf '%s\n' "${args[*]}")
) > "$TEST_TMP/netexec-smb-no-domain-args.txt"
assert_contains "$TEST_TMP/netexec-smb-no-domain-args.txt" "-u|hodor|-p|hodor" "NetExec SMB authentication works without a domain"
assert_not_contains "$TEST_TMP/netexec-smb-no-domain-args.txt" "-d" "NetExec SMB authentication omits an empty domain"

(
    source "$ROOT_DIR/lib/fathomtrace/validation.sh"
    KERBEROS_AUTH_CHECKED=false
    kerberos_attempts=0
    kerberos_auth_check() {
        kerberos_attempts=$((kerberos_attempts + 1))
        return 1
    }

    sps_run_optional_kerberos_auth_check
    first_status=$?
    sps_run_optional_kerberos_auth_check
    second_status=$?
    printf 'first=%s second=%s attempts=%s checked=%s\n' \
        "$first_status" "$second_status" "$kerberos_attempts" "$KERBEROS_AUTH_CHECKED"
) > "$TEST_TMP/nonfatal-kerberos-auth.txt"
assert_contains "$TEST_TMP/nonfatal-kerberos-auth.txt" "first=0 second=0 attempts=1 checked=true" "failed optional Kerberos authentication is non-fatal and is not retried"

(
    source "$ROOT_DIR/lib/fathomtrace/smb.sh"
    cme_output='SMB         192.168.78.11   445    WINTERFELL       [-] Error enumerating domain users using dc ip 192.168.78.11: NTLM needs domain\username and a password
SMB         192.168.78.11   445    WINTERFELL       [*] Trying with SAMRPC protocol
SMB         192.168.78.11   445    WINTERFELL       [+] Enumerated domain user(s)
SMB         192.168.78.11   445    WINTERFELL       north.sevenkingdoms.local\Guest                          Built-in account for guest access to the computer/domain
SMB         192.168.78.11   445    WINTERFELL       north.sevenkingdoms.local\arya.stark                     Arya Stark
SMB         192.168.78.11   445    WINTERFELL       north.sevenkingdoms.local\sansa.stark                    Sansa Stark'
    parsed_users="$(sps_parse_cme_users <<< "$cme_output")"
    printf 'outcome=%s\n%s\n' \
        "$(sps_classify_cme_user_enum "$cme_output" 1 "$parsed_users")" \
        "$parsed_users"
) > "$TEST_TMP/cme-samrpc-fallback.txt"
assert_contains "$TEST_TMP/cme-samrpc-fallback.txt" "outcome=enumerated" "CME SAMRPC fallback overrides the initial domain-enumeration error"
assert_contains "$TEST_TMP/cme-samrpc-fallback.txt" "Guest|Built-in account" "CME parser preserves Guest as an enumerated account"
assert_contains "$TEST_TMP/cme-samrpc-fallback.txt" "arya.stark|Arya Stark" "CME parser preserves enumerated domain users"
assert_not_contains "$TEST_TMP/cme-samrpc-fallback.txt" "username|" "CME parser ignores NTLM domain\\username guidance"
assert_contains "$SCRIPT" "local dc_2025=false" "BadSuccessor evaluation initializes its Server 2025 state under nounset"
assert_contains "$SCRIPT" '"${dc_2025:-false}" == true' "BadSuccessor evaluation defensively reads its Server 2025 state"
assert_contains "$SCRIPT" "BADSUCCESSOR_CHECK_DONE=true" "completed BadSuccessor checks are recorded even without Server 2025"
assert_contains "$SCRIPT" "The required Server 2025 prerequisite is absent; no BadSuccessor attack path was added" "non-Server-2025 BadSuccessor results are a normal decision outcome"
assert_contains "$SCRIPT" "--format=krb5asrep asrep_hashes_\$TARGET_IPV4.txt" "AS-REP attack path includes a John cracking command"

(
    source "$ROOT_DIR/lib/fathomtrace/ldap.sh"
    sps_parse_netexec_dc_os <<'EOF'
LDAP                     192.168.78.11   389    WINTERFELL       [+] Response for object: CN=WINTERFELL,OU=Domain Controllers,DC=north,DC=sevenkingdoms,DC=local
LDAP                     192.168.78.11   389    WINTERFELL       operatingSystem      Windows Server 2019 Datacenter Evaluation
LDAP                     192.168.78.11   389    WINTERFELL       operatingSystemVersion 10.0 (17763)
LDAP                     192.168.78.11   389    WINTERFELL       dNSHostName          winterfell.north.sevenkingdoms.local
LDAP                     192.168.78.12   389    CASTLEBLACK      [+] Response for object: CN=CASTLEBLACK,OU=Domain Controllers,DC=north,DC=sevenkingdoms,DC=local
LDAP                     192.168.78.12   389    CASTLEBLACK      dNSHostName          castleblack.north.sevenkingdoms.local
LDAP                     192.168.78.12   389    CASTLEBLACK      operatingSystemVersion 10.0 (26100)
LDAP                     192.168.78.12   389    CASTLEBLACK      operatingSystem      Windows Server 2025 Datacenter
EOF
) > "$TEST_TMP/netexec-dc-os.txt"
assert_contains "$TEST_TMP/netexec-dc-os.txt" "CN=WINTERFELL,OU=Domain Controllers,DC=north,DC=sevenkingdoms,DC=local|winterfell.north.sevenkingdoms.local|Windows Server 2019 Datacenter Evaluation|10.0 (17763)" "NetExec parser extracts the Server 2019 DC record"
assert_contains "$TEST_TMP/netexec-dc-os.txt" "CN=CASTLEBLACK,OU=Domain Controllers,DC=north,DC=sevenkingdoms,DC=local|castleblack.north.sevenkingdoms.local|Windows Server 2025 Datacenter|10.0 (26100)" "NetExec parser handles arbitrary LDAP attribute order and multiple DCs"
assert_not_contains "$TEST_TMP/netexec-dc-os.txt" "Windows Server 2019 Datacenter Evaluation|Windows Server 2019 Datacenter Evaluation" "NetExec parser does not confuse operatingSystem with operatingSystemVersion"

(
    source "$ROOT_DIR/lib/fathomtrace/ad_acl.sh"
    sps_parse_bloodyad_writeowner <<'EOF'
distinguishedName: CN={8E9B87DA-1111-2222-3333-444444444444},CN=Policies,CN=System,DC=north,DC=sevenkingdoms,DC=local
OWNER: WRITE
description: Stark Wallpaper Policy

distinguishedName: CN=Unrelated,CN=Users,DC=north,DC=sevenkingdoms,DC=local
DACL: WRITE

distinguishedName: OU=Workstations,DC=north,DC=sevenkingdoms,DC=local
Right: WRITE_OWNER
EOF
) > "$TEST_TMP/writeowner-findings.txt"
assert_contains "$TEST_TMP/writeowner-findings.txt" "CN={8E9B87DA-1111-2222-3333-444444444444},CN=Policies,CN=System,DC=north,DC=sevenkingdoms,DC=local|GPO|WriteOwner" "WriteOwner parser detects an arbitrary writable GPO"
assert_contains "$TEST_TMP/writeowner-findings.txt" "OU=Workstations,DC=north,DC=sevenkingdoms,DC=local|OU|WriteOwner" "WriteOwner parser accepts explicit ACL right names"
assert_not_contains "$TEST_TMP/writeowner-findings.txt" "CN=Unrelated" "WriteOwner parser does not promote DACL-only findings"
assert_contains "$SCRIPT" "AD-ACL-WRITEOWNER" "WriteOwner findings are recorded in the structured report"
assert_contains "$SCRIPT" "Active Directory WriteOwner permission abuse candidate" "WriteOwner findings feed the attack-path report"
assert_contains "$SCRIPT" "SharpGPOAbuse.exe --AddComputerTask" "GPO WriteOwner attack path includes a concise impact-test reminder"

run_cli invalid-target 999.1.1.1 --dry-run --no-loot --skip-preflight --format json
assert_eq 3 "$CLI_RC" "invalid target uses target exit code"
assert_contains "$CLI_STDOUT" '"status":"failed"' "structured errors include status"
assert_contains "$CLI_STDOUT" '"exit_code":3' "structured errors include exit code"
assert_not_contains "$CLI_STDOUT" "Authorized Recon" "structured error stdout has no banner"

run_cli legacy-alias 127.0.0.1 --dry-run --no-loot --skip-preflight --svc --check-ca --ascii --no-color
assert_eq 0 "$CLI_RC" "legacy aliases remain accepted"
assert_contains "$CLI_STDERR" "compatibility alias" "legacy alias emits deprecation guidance"

run_cli vhost-domain 127.0.0.1 --dry-run --no-loot --skip-preflight --vhost-domain Example.Test --ports 3000,5000,9090,18080
assert_eq 0 "$CLI_RC" "--vhost-domain is accepted and implies --vhost"
run_cli vhost-wordlist 127.0.0.1 --dry-run --no-loot --skip-preflight --vhost-wordlist "$TEST_TMP/custom-vhosts.txt" --vhost-domain Example.Test --ports 80
assert_eq 0 "$CLI_RC" "--vhost-wordlist is accepted and implies --vhost"
run_cli missing-vhost-wordlist-value 127.0.0.1 --dry-run --no-loot --vhost-wordlist
assert_eq 2 "$CLI_RC" "missing --vhost-wordlist value uses CLI exit code"
assert_contains "$CLI_STDERR" "--vhost-wordlist requires a value" "missing VHost wordlist is explained"
run_cli invalid-vhost-domain 127.0.0.1 --dry-run --no-loot --skip-preflight --vhost-domain 'not a domain' --ports 80
assert_eq 2 "$CLI_RC" "invalid --vhost-domain uses CLI exit code"
assert_contains "$CLI_STDERR" "--vhost-domain requires" "invalid VHost domain is explained"

run_cli web-wordlist 127.0.0.1 --dry-run --no-loot --skip-preflight --web-wordlist "$TEST_TMP/custom-web-paths.txt" --ports 80
assert_eq 0 "$CLI_RC" "--web-wordlist is accepted and implies --web-enum"
run_cli missing-web-wordlist-value 127.0.0.1 --dry-run --no-loot --web-wordlist
assert_eq 2 "$CLI_RC" "missing --web-wordlist value uses CLI exit code"
assert_contains "$CLI_STDERR" "--web-wordlist requires a value" "missing web wordlist is explained"

run_cli mssql-safe-default 127.0.0.1 --dry-run --no-loot --skip-preflight --check-mssql --ports 1433
assert_eq 0 "$CLI_RC" "MSSQL enumeration dry run succeeds"
assert_not_contains "$CLI_STDOUT" "enable_cmdshell" "MSSQL enumeration does not enable xp_cmdshell by default"

run_cli mssql-explicit-actions 127.0.0.1 --dry-run --no-loot --skip-preflight --mssql-privesc --mssql-enable-cmdshell --ports 1433
assert_eq 0 "$CLI_RC" "explicit MSSQL action flags are accepted"

run_cli json 127.0.0.1 --dry-run --no-loot --skip-preflight --format json --ports 22,80 --user analyst --pass topsecret
assert_eq 0 "$CLI_RC" "JSON dry run succeeds"
assert_contains "$CLI_STDOUT" '"schema_version":"1.0"' "JSON schema version is present"
assert_contains "$CLI_STDOUT" '"open_ports":[]' "JSON open-port field is stable"
assert_not_contains "$CLI_STDOUT" "Legend" "JSON stdout has no legend"
assert_not_contains "$CLI_STDOUT" $'\033[' "JSON stdout has no ANSI sequences"
assert_not_contains "$CLI_STDOUT" "topsecret" "JSON stdout redacts passwords"
assert_not_contains "$CLI_STDERR" "topsecret" "JSON diagnostics redact passwords"

run_cli csv 127.0.0.1 --dry-run --no-loot --skip-preflight --format csv --ports 443
assert_eq 0 "$CLI_RC" "CSV dry run succeeds"
assert_contains "$CLI_STDOUT" "schema_version,command,status,exit_code" "CSV includes stable header"
assert_not_contains "$CLI_STDOUT" "Authorized Recon" "CSV stdout has no banner"

run_cli no-color 127.0.0.1 --dry-run --no-loot --skip-preflight --no-color --ascii --ports 80
assert_eq 0 "$CLI_RC" "no-color dry run succeeds"
assert_not_contains "$CLI_STDOUT" $'\033[' "no-color removes ANSI sequences"
assert_contains "$CLI_STDOUT" "Fathomtrace v2.1.0" "text startup banner includes the application version"
assert_contains "$CLI_STDOUT" "[*] Validating target" "ASCII information icon is used"

run_cli force-color 127.0.0.1 --dry-run --no-loot --skip-preflight --color always --ascii --ports 80
assert_eq 0 "$CLI_RC" "forced-color dry run succeeds"
assert_contains "$CLI_STDOUT" $'\033[' "--color always emits ANSI colors without a TTY"

CLICOLOR_FORCE=1 "$SCRIPT" 127.0.0.1 --dry-run --no-loot --skip-preflight --ascii --ports 80 > "$TEST_TMP/clicolor.stdout" 2> "$TEST_TMP/clicolor.stderr"
assert_eq 0 "$?" "CLICOLOR_FORCE dry run succeeds"
assert_contains "$TEST_TMP/clicolor.stdout" $'\033[' "CLICOLOR_FORCE enables ANSI colors"

NO_COLOR=1 "$SCRIPT" 127.0.0.1 --dry-run --no-loot --skip-preflight --ascii --ports 80 > "$TEST_TMP/no-color-env.stdout" 2> "$TEST_TMP/no-color-env.stderr"
assert_eq 0 "$?" "NO_COLOR dry run succeeds"
assert_not_contains "$TEST_TMP/no-color-env.stdout" $'\033[' "NO_COLOR disables ANSI colors"

run_cli show-secrets 127.0.0.1 --dry-run --no-loot --skip-preflight --no-color --user analyst --pass topsecret --show-secrets --ports 80
assert_eq 0 "$CLI_RC" "show-secrets dry run succeeds"
assert_contains "$CLI_STDOUT" "Password:  topsecret" "--show-secrets prints the supplied password"

run_cli unicode 127.0.0.1 --dry-run --no-loot --skip-preflight --unicode --ports 80
assert_eq 0 "$CLI_RC" "Unicode dry run succeeds"
assert_contains "$CLI_STDOUT" "ℹ Validating target" "Unicode information icon is used"

run_cli verbose 127.0.0.1 --dry-run --no-loot --skip-preflight --verbose --ascii --no-color --ports 80
assert_contains "$CLI_STDOUT" "Legend:" "verbose mode shows the legend"
run_cli debug 127.0.0.1 --dry-run --no-loot --skip-preflight --debug --ascii --no-color --ports 80
assert_contains "$CLI_STDERR" "[debug] Optional preflight disabled" "debug mode reports skipped preflight"

run_cli quiet 127.0.0.1 --dry-run --no-loot --skip-preflight --quiet --ascii --no-color --ports 80
assert_eq 0 "$CLI_RC" "quiet dry run succeeds"
[[ ! -s "$CLI_STDOUT" ]] && pass "quiet mode suppresses stdout" || fail "quiet mode suppresses stdout"

(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    printf 'left\0right\033[31mred\033[0m\n' | sps_clean_tool_stream > "$TEST_TMP/clean-tool-stream"
    if sps_tool_field_true 'SMBv1:False) (signing:True)' SMBv1; then
        printf 'true\n' > "$TEST_TMP/smbv1-field"
    else
        printf 'false\n' > "$TEST_TMP/smbv1-field"
    fi
    if sps_tool_field_true 'SMBv1:False) (signing:True)' signing; then
        printf 'true\n' > "$TEST_TMP/signing-field"
    else
        printf 'false\n' > "$TEST_TMP/signing-field"
    fi
)
assert_eq "leftrightred" "$(cat "$TEST_TMP/clean-tool-stream")" "tool output sanitizer removes NUL and ANSI bytes"
assert_eq "false" "$(cat "$TEST_TMP/smbv1-field")" "SMBv1 parser does not borrow a later true field"
assert_eq "true" "$(cat "$TEST_TMP/signing-field")" "SMB signing true field is detected exactly"

# Service-exposure blocks use the same visual hierarchy as the existing AD
# synopsis sections while remaining silent in quiet or structured modes.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    OUTPUT_FORMAT=text QUIET=false DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_PASS="" SMB_PASS=""
    sps_configure_output
    sps_service_heading "IMAP MAIL ACCESS" "Inspecting protocol capabilities and encrypted login access."
    sps_service_endpoint "IMAPS / TCP 993 - implicit TLS"
) > "$TEST_TMP/service-heading.txt"
assert_contains "$TEST_TMP/service-heading.txt" "IMAP MAIL ACCESS" "service block prints a prominent service title"
assert_contains "$TEST_TMP/service-heading.txt" "Inspecting protocol capabilities and encrypted login access." "service block explains the active discovery"
assert_contains "$TEST_TMP/service-heading.txt" "IMAPS / TCP 993 - implicit TLS" "service block separates individual endpoints"
assert_contains "$ROOT_DIR/lib/fathomtrace/pop3.sh" "POP3 MAIL RETRIEVAL" "POP3 discovery uses the service-block presentation"
assert_contains "$ROOT_DIR/lib/fathomtrace/smtp.sh" "SMTP MAIL TRANSFER" "SMTP discovery uses the service-block presentation"
assert_contains "$ROOT_DIR/lib/fathomtrace/udp.sh" "SNMP DEVICE DISCOVERY" "SNMP discovery uses the service-block presentation"

# Unit-test the deterministic scan worker without making network connections.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/validation.sh"
    source "$ROOT_DIR/lib/fathomtrace/scan.sh"
    OUTPUT_FORMAT=text QUIET=true DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_PASS="" SMB_PASS=""
    sps_configure_output
    RUNTIME_TMP_DIR="$TEST_TMP/scan-unit"
    mkdir -p "$RUNTIME_TMP_DIR"
    HINT_FILE="$RUNTIME_TMP_DIR/hints"
    HOSTS_FILE="$RUNTIME_TMP_DIR/hosts"
    DISCOVERED_HOSTS="$RUNTIME_TMP_DIR/discovered"
    REDIRECT_HOSTS="$RUNTIME_TMP_DIR/redirects"
    HTTP_MARKER="$RUNTIME_TMP_DIR/http"
    HTTPS_MARKER="$RUNTIME_TMP_DIR/https"
    SMB_MARKER="$RUNTIME_TMP_DIR/smb"
    KERB_MARKER="$RUNTIME_TMP_DIR/kerb"
    LDAP_MARKER="$RUNTIME_TMP_DIR/ldap"
    SMTP_MARKER="$RUNTIME_TMP_DIR/smtp"
    POP3_MARKER="$RUNTIME_TMP_DIR/pop3"
    IMAP_MARKER="$RUNTIME_TMP_DIR/imap"
    WEB_SERVICES_FILE="$RUNTIME_TMP_DIR/web-services"
    OPEN_PORTS_FILE="$RUNTIME_TMP_DIR/open"
    touch "$HINT_FILE" "$HOSTS_FILE" "$DISCOVERED_HOSTS" "$REDIRECT_HOSTS" "$HTTP_MARKER" "$HTTPS_MARKER" "$SMB_MARKER" "$KERB_MARKER" "$LDAP_MARKER" "$SMTP_MARKER" "$POP3_MARKER" "$IMAP_MARKER" "$WEB_SERVICES_FILE" "$OPEN_PORTS_FILE"
    MAX_JOBS=2 CONNECT_TIMEOUT=.1 RETRY_LIMIT=0 SKIP_PREFLIGHT=true
    WEB_PORT_OPEN=false WEB_SERVICE_CONFIRMED=false LDAP_PORT_OPEN=false KERBEROS_PORT_OPEN=false KERBEROS_SERVICE_CONFIRMED=false SMTP_PORT_OPEN=false POP3_PORT_OPEN=false IMAP_PORT_OPEN=false
    sps_record_finding() { :; }
    sps_tcp_probe() { [[ "$2" == 80 || "$2" == 443 ]]; }
    sps_probe_open_port() { printf '%s\n' "$1" >> "$RUNTIME_TMP_DIR/service-probes"; }
    run_port_scan 127.0.0.1 "80:HTTP:open" "22:SSH:open" "443:HTTPS:open" > /dev/null
    printf '%s\n' "${OPEN_PORTS[*]}" > "$TEST_TMP/scan-unit.result"
    [[ ! -e "$RUNTIME_TMP_DIR/service-probes" ]] && printf 'isolated\n' > "$TEST_TMP/scan-unit.phase"
    sps_run_service_probes "${OPEN_PORTS[@]}"
    sps_record_web_service http 3000 "unit protocol response"
    sps_classify_open_port 389
    sps_classify_open_port 25
    sps_classify_open_port 110
    sps_classify_open_port 143
)
assert_contains "$TEST_TMP/scan-unit.result" "80 443" "worker results are deterministic"
assert_contains "$TEST_TMP/scan-unit.phase" "isolated" "port scan does not run detailed service probes"
assert_contains "$TEST_TMP/scan-unit/service-probes" "80" "service exposure phase probes open ports"
assert_contains "$TEST_TMP/scan-unit/service-probes" "443" "service exposure phase probes every open port"
assert_contains "$TEST_TMP/scan-unit/http" "3000" "protocol-confirmed custom HTTP port is recorded"
assert_contains "$TEST_TMP/scan-unit/web-services" "http:3000" "web service evidence preserves scheme and custom port"
assert_contains "$TEST_TMP/scan-unit/ldap" "389" "LDAP open-port state is recorded"
assert_contains "$TEST_TMP/scan-unit/smtp" "25" "SMTP candidate port state is recorded"
assert_contains "$TEST_TMP/scan-unit/pop3" "110" "POP3 candidate port state is recorded"
assert_contains "$TEST_TMP/scan-unit/imap" "143" "IMAP candidate port state is recorded"
assert_not_contains "$TEST_TMP/scan-unit/hints" "KERBEROS" "LDAP does not imply Kerberos"

# Unit-test conservative Nmap UDP state parsing. OPEN is confirmed while
# OPEN|FILTERED remains a separate, inconclusive candidate.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/udp.sh"
    OUTPUT_FORMAT=text QUIET=true DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_PASS="" SMB_PASS=""
    sps_configure_output
    UDP_OPEN_PORTS_FILE="$TEST_TMP/udp-open"
    UDP_POSSIBLE_PORTS_FILE="$TEST_TMP/udp-possible"
    HINT_FILE="$TEST_TMP/udp-hints"
    : > "$UDP_OPEN_PORTS_FILE"
    : > "$UDP_POSSIBLE_PORTS_FILE"
    : > "$HINT_FILE"
    SNMP_PORT_OPEN=false SNMP_SERVICE_CONFIRMED=false
    printf '%s\n' 'Host: 192.0.2.161 ()  Ports: 53/open/udp//domain///, 161/open|filtered/udp//snmp///' > "$TEST_TMP/udp-scan.gnmap"
    sps_parse_udp_nmap_grepable "$TEST_TMP/udp-scan.gnmap"
    grep -qx 161 "$UDP_POSSIBLE_PORTS_FILE" && printf 'preserved\n' > "$TEST_TMP/udp-inconclusive-state"
    printf '%s\n' 'Host: 192.0.2.161 ()  Ports: 161/open/udp//snmp///' > "$TEST_TMP/udp-snmp.gnmap"
    sps_parse_udp_nmap_grepable "$TEST_TMP/udp-snmp.gnmap"
    printf '%s|%s\n' "$SNMP_PORT_OPEN" "$SNMP_SERVICE_CONFIRMED" > "$TEST_TMP/udp-snmp-state"
)
assert_contains "$TEST_TMP/udp-open" "53" "UDP parser records Nmap open state"
assert_contains "$TEST_TMP/udp-inconclusive-state" "preserved" "UDP parser preserves open-filtered as inconclusive"
assert_not_contains "$TEST_TMP/udp-possible" "161" "confirmed UDP response clears the inconclusive state"
assert_contains "$TEST_TMP/udp-snmp-state" "true|true" "UDP parser confirms Nmap-identified SNMP service"

# Unit-test SMTP transcript parsing and the read-only discovery integration.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/validation.sh"
    source "$ROOT_DIR/lib/fathomtrace/smtp.sh"
    OUTPUT_FORMAT=text QUIET=true DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_PASS="" SMB_PASS=""
    sps_configure_output
    cd "$TEST_TMP"
    SMTP_CONFIRMED_FILE="$TEST_TMP/smtp-confirmed"
    HOSTS_FILE="$TEST_TMP/smtp-hosts"
    DISCOVERED_HOSTS="$TEST_TMP/smtp-discovered"
    touch "$SMTP_CONFIRMED_FILE" "$HOSTS_FILE" "$DISCOVERED_HOSTS"
    SMTP_SERVICE_CONFIRMED=false
    TARGET_FQDN=""
    ORIGINAL_TARGET="192.0.2.25"
    sanitize_name() { printf '%s' "$1" | tr -c '[:alnum:]._' '_'; }
    record_loot() { printf '%s\n' "$1:$2:$3" > "$TEST_TMP/smtp-loot-record"; }
    record_module_status() { printf '%s\n' "$1:$2:$3" > "$TEST_TMP/smtp-module-status"; }
    sps_record_finding() { printf '%s\n' "$1" > "$TEST_TMP/smtp-finding"; }
    sps_run_mail_telnet_banner_check() { return 1; }
    sps_run_mail_certificate_check() { return 1; }
    sps_smtp_plain_session() {
        cat <<'EOF'
S: 220-mail.example.test ESMTP Postfix
S: 220 Ready
C: EHLO fathomtrace.invalid
S: 250-mail.example.test
S: 250-PIPELINING
S: 250-SIZE 10240000
S: 250-STARTTLS
S: 250-AUTH PLAIN LOGIN
S: 250 HELP
C: HELP
S: 214-Commands supported: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT HELP VRFY
S: 214 End
C: QUIT
S: 221 Bye
EOF
    }

    sps_run_smtp_discovery_port 192.0.2.25 25
    printf 'confirmed=%s hostname=%s\n' "$SMTP_SERVICE_CONFIRMED" "$SMTP_HOSTNAME" > "$TEST_TMP/smtp-state"
    sps_smtp_parse_capabilities smtp_192.0.2.25_25.txt > "$TEST_TMP/smtp-capabilities"
)
assert_contains "$TEST_TMP/smtp-state" "confirmed=true hostname=mail.example.test" "SMTP discovery confirms a greeting plus EHLO response"
assert_contains "$TEST_TMP/smtp-capabilities" "STARTTLS" "SMTP discovery parses STARTTLS capability"
assert_contains "$TEST_TMP/smtp-capabilities" "AUTH PLAIN LOGIN" "SMTP discovery parses authentication mechanisms"
assert_contains "$TEST_TMP/smtp-hosts" "192.0.2.25 mail.example.test" "SMTP discovery records a banner hostname"
assert_contains "$TEST_TMP/smtp-finding" "SMTP-SERVICE-25" "SMTP discovery records a structured finding"
assert_contains "$TEST_TMP/smtp-module-status" "smtp:25:executed:confirmed" "SMTP discovery records module status"
assert_not_contains "$ROOT_DIR/lib/fathomtrace/smtp.sh" "MAIL FROM" "SMTP discovery never begins a mail transaction"
assert_not_contains "$ROOT_DIR/lib/fathomtrace/smtp.sh" "RCPT TO" "SMTP discovery never submits a recipient"

# Unit-test POP3 capability parsing and read-only discovery integration.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/validation.sh"
    source "$ROOT_DIR/lib/fathomtrace/pop3.sh"
    OUTPUT_FORMAT=text QUIET=true DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_PASS="" SMB_PASS=""
    sps_configure_output
    cd "$TEST_TMP"
    POP3_CONFIRMED_FILE="$TEST_TMP/pop3-confirmed"
    HOSTS_FILE="$TEST_TMP/pop3-hosts"
    DISCOVERED_HOSTS="$TEST_TMP/pop3-discovered"
    touch "$POP3_CONFIRMED_FILE" "$HOSTS_FILE" "$DISCOVERED_HOSTS"
    POP3_SERVICE_CONFIRMED=false
    TARGET_FQDN=""
    ORIGINAL_TARGET="192.0.2.110"
    sanitize_name() { printf '%s' "$1" | tr -c '[:alnum:]._' '_'; }
    record_loot() { printf '%s\n' "$1:$2:$3" > "$TEST_TMP/pop3-loot-record"; }
    record_module_status() { printf '%s\n' "$1:$2:$3" > "$TEST_TMP/pop3-module-status"; }
    sps_record_finding() { printf '%s\n' "$1" > "$TEST_TMP/pop3-finding"; }
    sps_run_mail_telnet_banner_check() { return 1; }
    sps_run_mail_certificate_check() { return 1; }
    sps_pop3_plain_session() {
        cat <<'EOF'
S: +OK pop3.example.test Dovecot ready
C: CAPA
S: +OK Capability list follows
S: TOP
S: UIDL
S: SASL PLAIN LOGIN
S: STLS
S: .
C: QUIT
S: +OK Logging out
EOF
    }
    sps_run_pop3_discovery_port 192.0.2.110 110
    printf 'confirmed=%s hostname=%s\n' "$POP3_SERVICE_CONFIRMED" "$POP3_HOSTNAME" > "$TEST_TMP/pop3-state"
    sps_pop3_parse_capabilities pop3_192.0.2.110_110.txt > "$TEST_TMP/pop3-capabilities"
    printf '%s\n' 'S: +OK InFreight POP3 v9.188' > "$TEST_TMP/pop3-brand-banner"
    sps_pop3_extract_hostname "$TEST_TMP/pop3-brand-banner" > "$TEST_TMP/pop3-brand-hostname"
)
assert_contains "$TEST_TMP/pop3-state" "confirmed=true hostname=pop3.example.test" "POP3 discovery confirms greeting and CAPA response"
assert_contains "$TEST_TMP/pop3-capabilities" "STLS" "POP3 discovery parses STLS capability"
assert_contains "$TEST_TMP/pop3-capabilities" "SASL PLAIN LOGIN" "POP3 discovery parses SASL mechanisms"
assert_contains "$TEST_TMP/pop3-hosts" "192.0.2.110 pop3.example.test" "POP3 discovery records a banner hostname"
assert_eq "" "$(cat "$TEST_TMP/pop3-brand-hostname")" "POP3 discovery does not mistake a banner brand for an FQDN"
assert_contains "$TEST_TMP/pop3-finding" "POP3-SERVICE-110" "POP3 discovery records a structured finding"
assert_contains "$TEST_TMP/pop3-module-status" "pop3:110:executed:confirmed" "POP3 discovery records module status"
assert_not_contains "$ROOT_DIR/lib/fathomtrace/pop3.sh" "USER " "POP3 discovery never supplies a username"
assert_not_contains "$ROOT_DIR/lib/fathomtrace/pop3.sh" "PASS " "POP3 discovery never supplies a password"
assert_not_contains "$ROOT_DIR/lib/fathomtrace/pop3.sh" "RETR " "POP3 discovery never retrieves a message"

# Unit-test IMAP capability parsing and read-only discovery integration.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/validation.sh"
    source "$ROOT_DIR/lib/fathomtrace/imap.sh"
    OUTPUT_FORMAT=text QUIET=true DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_PASS="" SMB_PASS=""
    sps_configure_output
    cd "$TEST_TMP"
    IMAP_CONFIRMED_FILE="$TEST_TMP/imap-confirmed"
    HOSTS_FILE="$TEST_TMP/imap-hosts"
    DISCOVERED_HOSTS="$TEST_TMP/imap-discovered"
    touch "$IMAP_CONFIRMED_FILE" "$HOSTS_FILE" "$DISCOVERED_HOSTS"
    IMAP_SERVICE_CONFIRMED=false
    TARGET_FQDN=""
    ORIGINAL_TARGET="192.0.2.143"
    sanitize_name() { printf '%s' "$1" | tr -c '[:alnum:]._' '_'; }
    record_loot() { printf '%s\n' "$1:$2:$3" > "$TEST_TMP/imap-loot-record"; }
    record_module_status() { printf '%s\n' "$1:$2:$3" > "$TEST_TMP/imap-module-status"; }
    sps_record_finding() { printf '%s\n' "$1" > "$TEST_TMP/imap-finding"; }
    sps_run_mail_telnet_banner_check() { return 1; }
    sps_run_mail_certificate_check() { return 1; }
    sps_imap_plain_session() {
        cat <<'EOF'
S: * OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] imap.example.test ready
C: a001 CAPABILITY
S: * CAPABILITY IMAP4rev1 IDLE STARTTLS AUTH=PLAIN AUTH=LOGIN
S: a001 OK CAPABILITY completed
C: a002 LOGOUT
S: * BYE Logging out
S: a002 OK LOGOUT completed
EOF
    }
    sps_run_imap_discovery_port 192.0.2.143 143
    printf 'confirmed=%s hostname=%s\n' "$IMAP_SERVICE_CONFIRMED" "$IMAP_HOSTNAME" > "$TEST_TMP/imap-state"
    sps_imap_parse_capabilities imap_192.0.2.143_143.txt > "$TEST_TMP/imap-capabilities"
)
assert_contains "$TEST_TMP/imap-state" "confirmed=true hostname=imap.example.test" "IMAP discovery confirms greeting and CAPABILITY response"
assert_contains "$TEST_TMP/imap-capabilities" "STARTTLS" "IMAP discovery parses STARTTLS capability"
assert_contains "$TEST_TMP/imap-capabilities" "AUTH=PLAIN" "IMAP discovery parses authentication mechanisms"
assert_contains "$TEST_TMP/imap-hosts" "192.0.2.143 imap.example.test" "IMAP discovery records a banner hostname"
assert_contains "$TEST_TMP/imap-finding" "IMAP-SERVICE-143" "IMAP discovery records a structured finding"
assert_contains "$TEST_TMP/imap-module-status" "imap:143:executed:confirmed" "IMAP discovery records module status"
awk '
    /^sps_imap_plain_session\(\)/, /^}/ { print }
    /^sps_imap_tls_session\(\)/, /^}/ { print }
' "$ROOT_DIR/lib/fathomtrace/imap.sh" > "$TEST_TMP/imap-discovery-session-source"
assert_not_contains "$TEST_TMP/imap-discovery-session-source" " LOGIN " "unauthenticated IMAP discovery never issues LOGIN"
assert_not_contains "$ROOT_DIR/lib/fathomtrace/imap.sh" " SELECT " "IMAP discovery never selects a mailbox"
assert_not_contains "$TEST_TMP/imap-discovery-session-source" " FETCH " "unauthenticated IMAP discovery never fetches message data"

# Unit-test contextual IMAP OpenSSL connection guidance.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/validation.sh"
    source "$ROOT_DIR/lib/fathomtrace/imap.sh"
    OUTPUT_FORMAT=text QUIET=false DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_PASS="" SMB_PASS=""
    TARGET_FQDN=""
    ORIGINAL_TARGET="192.0.2.143"
    IMAP_HELP_REMINDERS_SHOWN=false
    sps_configure_output
    sps_imap_print_connection_help 192.0.2.143 143 true imap.example.test
    sps_imap_print_connection_help 192.0.2.143 993 false imap.example.test
) > "$TEST_TMP/imap-connection-help" 2>&1
assert_contains "$TEST_TMP/imap-connection-help" "openssl s_client -connect 192.0.2.143:143 -starttls imap -servername imap.example.test -crlf -quiet" "IMAP help prints the port 143 STARTTLS command"
assert_contains "$TEST_TMP/imap-connection-help" "openssl s_client -connect 192.0.2.143:993 -servername imap.example.test -crlf -quiet" "IMAP help prints the port 993 implicit-TLS command"
assert_contains "$TEST_TMP/imap-connection-help" "a001 CAPABILITY" "IMAP help explains tagged capability commands"
assert_contains "$TEST_TMP/imap-connection-help" "a002 LOGOUT" "IMAP help explains clean session termination"
assert_contains "$TEST_TMP/imap-connection-help" "Do not submit authentication credentials until TLS is active" "IMAP help warns against cleartext authentication"

# Unit-test one-attempt encrypted IMAP credential validation without a network
# connection and verify that the supplied password never reaches artifacts.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/validation.sh"
    source "$ROOT_DIR/lib/fathomtrace/imap.sh"
    OUTPUT_FORMAT=text QUIET=true DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_USER="alice" AUTH_PASS="supersecret" CREDS_PROVIDED=true
    AUTH_DOMAIN="" SMB_PASS="" SHOW_SECRETS=true
    TARGET_FQDN="" ORIGINAL_TARGET="192.0.2.143"
    IMAP_IMPLICIT_TLS_AVAILABLE=true IMAP_STARTTLS_AVAILABLE=true
    IMAP_AUTH_HOSTNAME="imap.example.test"
    sps_configure_output
    cd "$TEST_TMP"
    sanitize_name() { printf '%s' "$1" | tr -c '[:alnum:]._' '_'; }
    sps_command_available() { [[ "$1" == openssl ]]; }
    record_command_argv() { printf '%s\n' "$*" > "$TEST_TMP/imap-auth-command"; }
    record_loot() { printf '%s\n' "$1:$2:$3" > "$TEST_TMP/imap-auth-loot-record"; }
    record_module_status() { printf '%s\n' "$1:$2:$3" > "$TEST_TMP/imap-auth-module-status"; }
    sps_record_finding() { printf '%s\n' "$1:$4" > "$TEST_TMP/imap-auth-finding"; }
    sps_imap_login_session() {
        printf '%s\n' \
            'S: * OK IMAP ready' \
            'C: a001 LOGIN "alice" "[REDACTED]"' \
            'S: * OK diagnostic accidentally echoed supersecret' \
            'S: a001 OK Logged in' \
            'C: a002 LOGOUT' \
            'S: a002 OK Logout completed'
        printf '%s\n' "$*" > "$TEST_TMP/imap-auth-session-args"
    }

    sps_run_imap_auth_check 192.0.2.143
    printf '%s|%s|%s\n' "$IMAP_AUTH_STATUS" "$IMAP_AUTH_OK" "$IMAP_AUTH_REASON" \
        > "$TEST_TMP/imap-auth-state"
    sps_imap_auth_success_text > "$TEST_TMP/imap-auth-success-text"
)
assert_contains "$TEST_TMP/imap-auth-state" "success|true|IMAP accepted the supplied credentials" "IMAP auth classifies a tagged OK response as success"
assert_contains "$TEST_TMP/imap-auth-session-args" "192.0.2.143 993 implicit alice supersecret imap.example.test" "IMAP auth prefers one implicit-TLS attempt on port 993"
assert_contains "$TEST_TMP/imap-auth-command" "openssl s_client -quiet -crlf -connect 192.0.2.143:993 -servername imap.example.test" "IMAP auth records a password-free OpenSSL command"
assert_not_contains "$TEST_TMP/imap-auth-command" "supersecret" "IMAP auth command records never contain the password"
assert_contains "$TEST_TMP/imap_auth_192.0.2.143_993.txt" "[REDACTED]" "IMAP auth transcript contains a redaction marker"
assert_not_contains "$TEST_TMP/imap_auth_192.0.2.143_993.txt" "supersecret" "IMAP auth transcript forcibly removes the password even with show-secrets"
assert_contains "$TEST_TMP/imap-auth-finding" "IMAP-AUTHENTICATION" "successful IMAP auth records a structured finding"
assert_contains "$TEST_TMP/imap-auth-module-status" "imap-auth:executed:IMAP accepted" "successful IMAP auth records module status"
assert_eq "IMAP credentials accepted for alice on port 993" "$(cat "$TEST_TMP/imap-auth-success-text")" "IMAP success message preserves user and accepted port for final reports"
assert_eq "2" "$(grep -Fc 'success "$(sps_imap_auth_success_text)"' "$SCRIPT")" "IMAP success is promoted in both attack-path and recon-summary reports"
assert_contains "$SCRIPT" "AUTHENTICATED MAIL ACCESS" "attack-path report gives accepted IMAP credentials a dedicated section"

# Credentials must not trigger a cleartext IMAP login when neither encrypted
# transport was protocol-confirmed.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/validation.sh"
    source "$ROOT_DIR/lib/fathomtrace/imap.sh"
    OUTPUT_FORMAT=text QUIET=true DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_USER="alice" AUTH_PASS="supersecret" CREDS_PROVIDED=true AUTH_DOMAIN="" SMB_PASS=""
    IMAP_IMPLICIT_TLS_AVAILABLE=false IMAP_STARTTLS_AVAILABLE=false
    sps_configure_output
    sps_command_available() { return 0; }
    record_module_status() { printf '%s\n' "$1:$2:$3" > "$TEST_TMP/imap-auth-cleartext-status"; }
    sps_imap_login_session() { touch "$TEST_TMP/imap-auth-cleartext-attempted"; }
    sps_run_imap_auth_check 192.0.2.143
    printf '%s|%s\n' "$IMAP_AUTH_STATUS" "$IMAP_AUTH_REASON" > "$TEST_TMP/imap-auth-cleartext-state"
)
assert_contains "$TEST_TMP/imap-auth-cleartext-state" "skipped|no protocol-confirmed encrypted IMAP transport is available" "IMAP auth skips when only cleartext transport is available"
assert_no_file "$TEST_TMP/imap-auth-cleartext-attempted" "IMAP auth never submits credentials over cleartext"

# Unit-test opt-in mailbox listing and read-only message export parsing.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/validation.sh"
    source "$ROOT_DIR/lib/fathomtrace/imap.sh"
    OUTPUT_FORMAT=text QUIET=true DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_USER="robin" AUTH_PASS="robin" CREDS_PROVIDED=true AUTH_DOMAIN="" SMB_PASS=""
    ENABLE_IMAP_ENUM=true ENABLE_IMAP_DUMP=true IMAP_MAILBOX="DEV.DEPARTMENT.INT" IMAP_MAX_MESSAGES=5
    TARGET_FQDN="" ORIGINAL_TARGET="192.0.2.143"
    IMAP_IMPLICIT_TLS_AVAILABLE=true IMAP_STARTTLS_AVAILABLE=true
    IMAP_AUTH_HOSTNAME="dev.example.test"
    LOOT_DIR="$TEST_TMP/imap-sensitive"
    PARSED_DIR="$TEST_TMP/imap-parsed"
    mkdir -p "$LOOT_DIR" "$PARSED_DIR"
    sps_configure_output
    cd "$TEST_TMP"
    sanitize_name() { printf '%s' "$1" | tr -c '[:alnum:]._' '_'; }
    sps_command_available() { [[ "$1" == openssl ]]; }
    record_command_argv() { :; }
    record_loot() { printf '%s\n' "$1:$2:$3" >> "$TEST_TMP/imap-dump-loot-records"; }
    record_module_status() { printf '%s\n' "$1:$2:$3" >> "$TEST_TMP/imap-dump-module-statuses"; }
    sps_record_finding() { printf '%s\n' "$1" >> "$TEST_TMP/imap-dump-findings"; }
    sps_imap_login_session() {
        cat <<'EOF'
S: * OK IMAP ready
C: a001 LOGIN "robin" "[REDACTED]"
S: a001 OK Logged in
--- IMAP MAILBOX ENUMERATION ---
C: a002 LIST "" "*"
S: * LIST (\Noselect \HasChildren) "." DEV
S: * LIST (\Noselect \HasChildren) "." DEV.DEPARTMENT
S: * LIST (\HasNoChildren) "." DEV.DEPARTMENT.INT
S: * LIST (\HasNoChildren) "." INBOX
S: a002 OK List completed
--- IMAP READ-ONLY MESSAGE EXPORT: DEV.DEPARTMENT.INT ---
C: a003 EXAMINE "DEV.DEPARTMENT.INT"
S: * 1 EXISTS
S: a003 OK [READ-ONLY] Examine completed
C: a004 FETCH 1:1 (UID BODY.PEEK[])
S: * 1 FETCH (UID 1 BODY[] {42}
S: Subject: Test message
S:
S: Authorized test content
S: )
S: a004 OK Fetch completed
I: mailbox "DEV.DEPARTMENT.INT" examined read-only (1 message(s))
I: exported 1 message(s) from mailbox "DEV.DEPARTMENT.INT"
I: IMAP dump completed: mailboxes examined=1; mailboxes failed=0; messages exported=1; limit=5
C: a999 LOGOUT
S: a999 OK Logout completed
EOF
    }

    sps_run_imap_auth_check 192.0.2.143
    printf '%s|%s|%s|%s\n' \
        "$IMAP_DUMP_MAILBOXES_EXAMINED" "$IMAP_DUMP_MAILBOXES_FAILED" \
        "$IMAP_DUMP_MESSAGES_EXPORTED" "$IMAP_DUMP_LOOT_PATH" \
        > "$TEST_TMP/imap-dump-state"
)
assert_contains "$TEST_TMP/imap-parsed/imap_mailboxes_192.0.2.143_993.txt" $'\\HasNoChildren\tDEV.DEPARTMENT.INT' "IMAP enumeration parses a nested mailbox"
assert_contains "$TEST_TMP/imap-parsed/imap_mailboxes_192.0.2.143_993.txt" $'\\HasNoChildren\tINBOX' "IMAP enumeration parses INBOX"
assert_contains "$TEST_TMP/imap-sensitive/imap_mail_dump_192.0.2.143_993_DEV.DEPARTMENT.INT.txt" "Authorized test content" "IMAP dump stores message content in the protected loot path"
assert_not_contains "$TEST_TMP/imap-sensitive/imap_mail_dump_192.0.2.143_993_DEV.DEPARTMENT.INT.txt" 'C: a001 LOGIN "robin" "robin"' "IMAP dump never stores the supplied password"
assert_contains "$TEST_TMP/imap-dump-findings" "IMAP-MESSAGE-EXPORT" "IMAP dump records a structured finding"
assert_contains "$TEST_TMP/imap-dump-module-statuses" "imap-enum:executed:listed 4 mailbox(es)" "IMAP enumeration records module status"
assert_contains "$TEST_TMP/imap-dump-module-statuses" "imap-dump:executed:preferred-mailbox=DEV.DEPARTMENT.INT; mailboxes examined=1" "IMAP dump records multi-mailbox module status"
assert_contains "$TEST_TMP/imap-dump-state" "1|0|1|$TEST_TMP/imap-sensitive/imap_mail_dump_192.0.2.143_993_DEV.DEPARTMENT.INT.txt" "IMAP dump exposes counts and the protected loot path to final reports"
assert_contains "$ROOT_DIR/lib/fathomtrace/imap.sh" "EXAMINE" "IMAP dump opens the mailbox read-only"
assert_contains "$ROOT_DIR/lib/fathomtrace/imap.sh" "BODY.PEEK[]" "IMAP dump avoids setting the Seen flag"

# Attack-path export details are emitted only when at least one message was
# actually exported, and must name the protected artifact path.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/imap.sh"
    OUTPUT_FORMAT=text QUIET=false DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_PASS="" SMB_PASS=""
    ATTACK_PATHS=()
    sps_configure_output

    IMAP_DUMP_MESSAGES_EXPORTED=0
    IMAP_DUMP_SUMMARY="mailboxes examined=2; mailboxes failed=0; messages exported=0; limit=25"
    IMAP_DUMP_LOOT_PATH="$TEST_TMP/imap-sensitive/empty.txt"
    sps_imap_print_attack_path_details > "$TEST_TMP/imap-dump-attack-zero"

    IMAP_DUMP_MESSAGES_EXPORTED=1
    IMAP_DUMP_SUMMARY="mailboxes examined=2; mailboxes failed=0; messages exported=1; limit=25"
    IMAP_DUMP_LOOT_PATH="$TEST_TMP/imap-sensitive/messages.txt"
    sps_imap_print_attack_path_details > "$TEST_TMP/imap-dump-attack-positive"
    printf '%s\n' "${ATTACK_PATHS[@]}" > "$TEST_TMP/imap-dump-attack-paths"
)
assert_eq "0" "$(wc -c < "$TEST_TMP/imap-dump-attack-zero" | tr -d '[:space:]')" "zero-message IMAP dumps add no attack-path details"
assert_contains "$TEST_TMP/imap-dump-attack-positive" "messages exported=1" "positive IMAP dumps add their summary to the attack path"
assert_contains "$TEST_TMP/imap-dump-attack-positive" "$TEST_TMP/imap-sensitive/messages.txt" "positive IMAP dumps point to the protected loot path"
assert_contains "$TEST_TMP/imap-dump-attack-positive" "Next step: review the exported messages" "positive IMAP dumps include targeted review steps"
assert_contains "$TEST_TMP/imap-dump-attack-positive" "Handling reminder:" "positive IMAP dumps include sensitive-data cleanup guidance"
assert_contains "$TEST_TMP/imap-dump-attack-paths" "Authenticated IMAP message content exported (1 message(s))" "positive IMAP dumps register an attack-path finding"
assert_contains "$SCRIPT" "if sps_imap_dump_has_exported_messages; then" "Attack Path Decision Engine gates IMAP export details on a positive count"

# Exercise the live IMAP command loop with an empty INBOX and a message in a
# second selectable mailbox. Hierarchy-only \Noselect entries must be skipped.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/validation.sh"
    source "$ROOT_DIR/lib/fathomtrace/imap.sh"
    ENABLE_IMAP_ENUM=true ENABLE_IMAP_DUMP=true IMAP_MAILBOX="INBOX" IMAP_MAX_MESSAGES=5
    IMAP_AUTH_TIMEOUT=5
    timeout() {
        shift
        "$@"
    }
    openssl() {
        local command
        printf '%s\r\n' '* OK Test IMAP server ready'
        while IFS= read -r command; do
            command="${command%$'\r'}"
            case "$command" in
                'a001 LOGIN '* )
                    printf '%s\r\n' 'a001 OK Logged in'
                    ;;
                'a002 LIST "" "*"' )
                    printf '%s\r\n' \
                        '* LIST (\Noselect \HasChildren) "." DEV' \
                        '* LIST (\Noselect \HasChildren) "." DEV.DEPARTMENT' \
                        '* LIST (\HasNoChildren) "." DEV.DEPARTMENT.INT' \
                        '* LIST (\HasNoChildren) "." INBOX' \
                        'a002 OK List completed'
                    ;;
                'a003 EXAMINE "INBOX"' )
                    printf '%s\r\n' '* 0 EXISTS' 'a003 OK [READ-ONLY] Examine completed'
                    ;;
                'a004 EXAMINE "DEV.DEPARTMENT.INT"' )
                    printf '%s\r\n' '* 1 EXISTS' 'a004 OK [READ-ONLY] Examine completed'
                    ;;
                'a005 FETCH 1:1 (UID BODY.PEEK[])' )
                    printf '%s\r\n' '* 1 FETCH (UID 1 BODY[] {22}' 'Subject: Nested mailbox' ')' 'a005 OK Fetch completed'
                    ;;
                'a999 LOGOUT' )
                    printf '%s\r\n' '* BYE Logging out' 'a999 OK Logout completed'
                    break
                    ;;
            esac
        done
    }

    sps_imap_login_session 192.0.2.143 993 implicit robin robin > "$TEST_TMP/imap-multi-mailbox-session"
)
assert_contains "$TEST_TMP/imap-multi-mailbox-session" 'C: a003 EXAMINE "INBOX"' "IMAP dump examines the preferred mailbox first"
assert_contains "$TEST_TMP/imap-multi-mailbox-session" 'mailbox "INBOX" contains no messages; continuing' "IMAP dump continues after an empty preferred mailbox"
assert_contains "$TEST_TMP/imap-multi-mailbox-session" 'C: a004 EXAMINE "DEV.DEPARTMENT.INT"' "IMAP dump examines another selectable LIST mailbox"
assert_not_contains "$TEST_TMP/imap-multi-mailbox-session" 'EXAMINE "DEV"' "IMAP dump skips a top-level Noselect container"
assert_not_contains "$TEST_TMP/imap-multi-mailbox-session" 'EXAMINE "DEV.DEPARTMENT"' "IMAP dump skips a nested Noselect container"
assert_contains "$TEST_TMP/imap-multi-mailbox-session" 'C: a005 FETCH 1:1 (UID BODY.PEEK[])' "IMAP dump exports from a non-empty nested mailbox"
assert_contains "$TEST_TMP/imap-multi-mailbox-session" 'IMAP dump completed: mailboxes examined=2; mailboxes failed=0; messages exported=1; limit=5' "IMAP dump summarizes all examined mailboxes"

# Unit-test optional Telnet banner capture without opening a network socket.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/validation.sh"
    source "$ROOT_DIR/lib/fathomtrace/mail.sh"
    OUTPUT_FORMAT=text QUIET=true DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_PASS="" SMB_PASS=""
    sps_configure_output
    cd "$TEST_TMP"
    sanitize_name() { printf '%s' "$1" | tr -c '[:alnum:]._' '_'; }
    sps_command_available() { [[ "$1" == telnet ]]; }
    record_loot() { printf '%s\n' "$1:$2:$3" >> "$TEST_TMP/telnet-loot-records"; }
    record_module_status() { printf '%s\n' "$1:$2:$3" >> "$TEST_TMP/telnet-module-statuses"; }
    sps_record_finding() { printf '%s\n' "$1" >> "$TEST_TMP/telnet-findings"; }
    sps_mail_telnet_capture() {
        case "$2" in
            25) printf '%s\n' 'Trying 192.0.2.25...' 'Connected.' '220 mail.example.test ESMTP ready' ;;
            110) printf '%s\n' 'Trying 192.0.2.110...' 'Connected.' '+OK pop3.example.test ready' ;;
            143) printf '%s\n' 'Trying 192.0.2.143...' 'Connected.' '* OK imap.example.test ready' ;;
        esac
    }
    sps_run_mail_telnet_banner_check 192.0.2.25 25 smtp
    sps_run_mail_telnet_banner_check 192.0.2.110 110 pop3
    sps_run_mail_telnet_banner_check 192.0.2.143 143 imap
)
assert_contains "$TEST_TMP/telnet_smtp_192.0.2.25_25.txt" "220 mail.example.test" "Telnet SMTP banner is captured"
assert_contains "$TEST_TMP/telnet_pop3_192.0.2.110_110.txt" "+OK pop3.example.test" "Telnet POP3 banner is captured"
assert_contains "$TEST_TMP/telnet_imap_192.0.2.143_143.txt" "* OK imap.example.test" "Telnet IMAP banner is captured"
assert_contains "$TEST_TMP/telnet-findings" "TELNET-BANNER-SMTP-25" "Telnet SMTP banner records a finding"
assert_contains "$TEST_TMP/telnet-findings" "TELNET-BANNER-POP3-110" "Telnet POP3 banner records a finding"
assert_contains "$TEST_TMP/telnet-findings" "TELNET-BANNER-IMAP-143" "Telnet IMAP banner records a finding"
assert_not_contains "$ROOT_DIR/lib/fathomtrace/mail.sh" "AUTH " "Telnet banner capture sends no authentication command"
assert_not_contains "$ROOT_DIR/lib/fathomtrace/mail.sh" "CAPABILITY" "Telnet banner capture sends no IMAP command"
assert_not_contains "$ROOT_DIR/lib/fathomtrace/mail.sh" "CAPA" "Telnet banner capture sends no POP3 command"

# Unit-test mail TLS certificate parsing, CN fallback, and STARTTLS selection
# without opening a network socket.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/validation.sh"
    source "$ROOT_DIR/lib/fathomtrace/mail.sh"
    OUTPUT_FORMAT=text QUIET=true DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_PASS="" SMB_PASS=""
    sps_configure_output
    cd "$TEST_TMP"
    HOSTS_FILE="$TEST_TMP/certificate-hosts"
    DISCOVERED_HOSTS="$TEST_TMP/certificate-discovered"
    touch "$HOSTS_FILE" "$DISCOVERED_HOSTS"
    TARGET_FQDN=""
    ORIGINAL_TARGET="192.0.2.143"
    sanitize_name() { printf '%s' "$1" | tr -c '[:alnum:]._' '_'; }
    sps_command_available() { [[ "$1" == openssl ]]; }
    record_command_argv() { printf '%s\n' "$*" > "$TEST_TMP/certificate-command"; }
    record_loot() { printf '%s\n' "$1:$2:$3" >> "$TEST_TMP/certificate-loot-records"; }
    record_module_status() { printf '%s\n' "$1:$2:$3" >> "$TEST_TMP/certificate-module-statuses"; }
    sps_record_finding() { printf '%s\n' "$1" >> "$TEST_TMP/certificate-findings"; }
    sps_mail_fetch_leaf_certificate() {
        printf '%s\n' '-----BEGIN CERTIFICATE-----' 'TEST' '-----END CERTIFICATE-----'
        printf '%s\n' "$*" > "$TEST_TMP/certificate-fetch-args"
    }
    sps_mail_certificate_is_valid() { return 0; }
    cat > "$TEST_TMP/certificate-description.fixture" <<'EOF'
subject=emailAddress=cto.dev@dev.inlanefreight.htb,CN=dev.inlanefreight.htb,OU=DevOps Department,O=InlaneFreight Ltd,L=London,ST=London,C=UK
issuer=CN=InlaneFreight Test CA,O=InlaneFreight Ltd,C=UK
notBefore=Nov  8 23:10:05 2021 GMT
notAfter=Aug 23 23:10:05 2295 GMT
serial=01AB
sha256 Fingerprint=AA:BB:CC:DD
subjectAltName=none
EOF
    sps_mail_describe_certificate() { cat "$TEST_TMP/certificate-description.fixture"; }

    sps_run_mail_certificate_check 192.0.2.143 143 imap starttls
    printf 'cn=%s sans=%s hosts=%s issuer=%s\n' \
        "$MAIL_CERT_CN" "$MAIL_CERT_SANS" "$MAIL_CERT_HOSTNAMES" "$MAIL_CERT_ISSUER" \
        > "$TEST_TMP/certificate-state"
    cat > "$TEST_TMP/certificate-san.fixture" <<'EOF'
subject=CN=mail.example.test,O=Example
X509v3 Subject Alternative Name:
    DNS:imap.example.test, DNS:pop3.example.test, IP Address:192.0.2.143
EOF
    sps_mail_parse_certificate_metadata "$TEST_TMP/certificate-san.fixture"
    printf '%s\n' "$MAIL_CERT_SANS" > "$TEST_TMP/certificate-sans"
)
assert_contains "$TEST_TMP/certificate-state" "cn=dev.inlanefreight.htb sans= hosts=dev.inlanefreight.htb" "certificate parser falls back to the subject CN when SAN is absent"
assert_contains "$TEST_TMP/certificate-hosts" "192.0.2.143 dev.inlanefreight.htb" "certificate CN is added to host suggestions"
assert_contains "$TEST_TMP/certificate-discovered" "dev.inlanefreight.htb" "certificate CN is added to discovered hosts"
assert_contains "$TEST_TMP/certificate-fetch-args" "imap starttls" "certificate capture selects IMAP STARTTLS"
assert_contains "$TEST_TMP/certificate-command" "-starttls imap" "certificate capture records the STARTTLS command"
assert_contains "$TEST_TMP/certificate-findings" "TLS-CERTIFICATE-IMAP-143" "certificate capture records a structured finding"
assert_contains "$TEST_TMP/certificate-module-statuses" "certificate:imap:143:executed" "certificate capture records module status"
assert_eq "imap.example.test,pop3.example.test" "$(cat "$TEST_TMP/certificate-sans")" "certificate parser extracts and deduplicates DNS SANs"
assert_file "$TEST_TMP/tls_imap_192.0.2.143_143.pem" "certificate capture stores the leaf PEM"
assert_file "$TEST_TMP/tls_imap_192.0.2.143_143.txt" "certificate capture stores parsed metadata"

# Unit-test NetBIOS name-table parsing and tool fallback without network access.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/validation.sh"
    source "$ROOT_DIR/lib/fathomtrace/netbios.sh"
    OUTPUT_FORMAT=text QUIET=true DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_PASS="" SMB_PASS=""
    sps_configure_output
    mkdir -p "$TEST_TMP/netbios-unit/bin"
    cd "$TEST_TMP/netbios-unit"
    HOSTS_FILE="$TEST_TMP/netbios-unit/hosts"
    DISCOVERED_HOSTS="$TEST_TMP/netbios-unit/discovered"
    touch "$HOSTS_FILE" "$DISCOVERED_HOSTS"
    sanitize_name() { printf '%s' "$1" | tr -c '[:alnum:]._' '_'; }
    record_command_argv() { :; }
    record_loot() { :; }
    record_module_status() { :; }
    sps_record_finding() { :; }

    printf '%s\n' \
        'Looking up status of 192.0.2.20' \
        '        FILESRV         <00> -         B <ACTIVE>' \
        '        LAB             <00> - <GROUP> B <ACTIVE>' \
        '        FILESRV         <20> -         B <ACTIVE>' \
        '        MAC Address = 00:11:22:33:44:55' > nmblookup.fixture
    sps_parse_nmblookup_name nmblookup.fixture > "$TEST_TMP/netbios-nmb-name"
    sps_parse_nmblookup_workgroup nmblookup.fixture > "$TEST_TMP/netbios-nmb-workgroup"
    sps_parse_nmblookup_mac nmblookup.fixture > "$TEST_TMP/netbios-nmb-mac"

    printf '%s\n' \
        '192.0.2.20:LAB:00G' \
        '192.0.2.20:FALLBACK:20U' \
        '192.0.2.20:FALLBACK:00U' > nbtscan.fixture
    sps_parse_nbtscan_name nbtscan.fixture > "$TEST_TMP/netbios-nbtscan-name"
    sps_parse_nbtscan_workgroup nbtscan.fixture > "$TEST_TMP/netbios-nbtscan-workgroup"

    printf '%s\n' \
        '#!/usr/bin/env bash' \
        "printf '%s\\n' 'Looking up status of 192.0.2.20' '        FILESRV <00> - B <ACTIVE>' '        LAB <00> - <GROUP> B <ACTIVE>' '        FILESRV <20> - B <ACTIVE>' '        MAC Address = 00:11:22:33:44:55'" \
        > "$TEST_TMP/netbios-unit/bin/nmblookup"
    printf '%s\n' \
        '#!/usr/bin/env bash' \
        "printf '%s\\n' '192.0.2.20:LAB:00G' '192.0.2.20:FALLBACK:00U'" \
        > "$TEST_TMP/netbios-unit/bin/nbtscan"
    chmod +x "$TEST_TMP/netbios-unit/bin/nmblookup" "$TEST_TMP/netbios-unit/bin/nbtscan"
    PATH="$TEST_TMP/netbios-unit/bin:$PATH"
    SPS_VALIDATION_CACHE=()
    sps_run_netbios_scan 192.0.2.20
    printf '%s|%s|%s|%s\n' "$NETBIOS_NAME" "$NETBIOS_WORKGROUP" "$NETBIOS_MAC" "$NETBIOS_TOOL" \
        > "$TEST_TMP/netbios-primary-result"
    cp "$HOSTS_FILE" "$TEST_TMP/netbios-primary-hosts"

    printf '%s\n' '#!/usr/bin/env bash' 'exit 1' > "$TEST_TMP/netbios-unit/bin/nmblookup"
    chmod +x "$TEST_TMP/netbios-unit/bin/nmblookup"
    : > "$HOSTS_FILE"
    : > "$DISCOVERED_HOSTS"
    SPS_VALIDATION_CACHE=()
    sps_run_netbios_scan 192.0.2.20
    printf '%s|%s|%s\n' "$NETBIOS_NAME" "$NETBIOS_WORKGROUP" "$NETBIOS_TOOL" \
        > "$TEST_TMP/netbios-fallback-result"
)
assert_eq "FILESRV" "$(cat "$TEST_TMP/netbios-nmb-name")" "nmblookup parser selects the unique workstation name"
assert_eq "LAB" "$(cat "$TEST_TMP/netbios-nmb-workgroup")" "nmblookup parser selects the group name"
assert_eq "00:11:22:33:44:55" "$(cat "$TEST_TMP/netbios-nmb-mac")" "nmblookup parser selects the reported MAC"
assert_eq "FALLBACK" "$(cat "$TEST_TMP/netbios-nbtscan-name")" "nbtscan parser selects the unique workstation name"
assert_eq "LAB" "$(cat "$TEST_TMP/netbios-nbtscan-workgroup")" "nbtscan parser selects the group name"
assert_eq "FILESRV|LAB|00:11:22:33:44:55|nmblookup" "$(cat "$TEST_TMP/netbios-primary-result")" "NetBIOS scan records primary-tool identity fields"
assert_contains "$TEST_TMP/netbios-primary-hosts" "192.0.2.20 filesrv" "NetBIOS hostname is added to host suggestions"
assert_eq "FALLBACK|LAB|nbtscan" "$(cat "$TEST_TMP/netbios-fallback-result")" "NetBIOS scan falls back to nbtscan"

# Unit-test bounded NetExec RDP credential classification without a network connection.
rdp_fake_netexec() {
    if [[ "${1:-}" == rdp && "${2:-}" == --help ]]; then
        printf '%s\n' "usage: nxc rdp [-h] target"
        return 0
    fi
    printf '%s\n' "$@" > "$RDP_ARG_LOG"
    case "$RDP_FAKE_MODE" in
        success)
            printf '%s\n' 'RDP 192.0.2.25 3389 HOST [+] LAB\\analyst:********'
            ;;
        failure)
            printf '%s\n' 'RDP 192.0.2.25 3389 HOST [-] LAB\\analyst:******** (STATUS_LOGON_FAILURE)'
            return 1
            ;;
        *)
            printf '%s\n' 'RDP 192.0.2.25 3389 HOST [-] connection timed out'
            return 1
            ;;
    esac
}

(
    source "$ROOT_DIR/lib/fathomtrace/rdp.sh"
    info() { :; }
    success() { :; }
    warn() { :; }
    record_command_argv() { printf '%s\n' "$@" > "$TEST_TMP/rdp-command-log"; }
    record_module_status() { :; }
    sps_record_finding() { printf '%s\n' "$1" > "$TEST_TMP/rdp-finding"; }
    nxc() { rdp_fake_netexec "$@"; }
    timeout() {
        shift
        "$@"
    }
    RDP_FAKE_MODE=success RDP_ARG_LOG="$TEST_TMP/rdp-success.args"
    export RDP_FAKE_MODE RDP_ARG_LOG
    RDP_PORT_OPEN=true CREDS_PROVIDED=true AUTH_USER=analyst AUTH_PASS=topsecret AUTH_DOMAIN=LAB LDAP_DOMAIN=""
    sps_run_rdp_auth_check 192.0.2.25
    printf '%s|%s|%s|%s\n' "$RDP_AUTH_STATUS" "$RDP_AUTH_OK" "$RDP_AUTH_PROVIDER" "$RDP_AUTH_REASON" > "$TEST_TMP/rdp-success.result"
)
assert_contains "$TEST_TMP/rdp-success.result" "success|true|netexec|NetExec RDP accepted" "NetExec RDP success is classified"
assert_contains "$TEST_TMP/rdp-success.args" "rdp" "RDP validation uses the NetExec RDP protocol"
assert_contains "$TEST_TMP/rdp-success.args" "-d" "NetExec RDP validation passes the supplied domain"
assert_contains "$TEST_TMP/rdp-command-log" "Single-target credential validation via NetExec RDP" "NetExec RDP command is sent to the command artifact logger"
assert_contains "$TEST_TMP/rdp-command-log" "timeout" "logged NetExec RDP command includes its outer timeout"
assert_contains "$TEST_TMP/rdp-finding" "RDP-AUTH-T1021-001" "successful RDP authentication records the ATT&CK-mapped finding"

(
    source "$ROOT_DIR/lib/fathomtrace/rdp.sh"
    info() { :; }
    success() { :; }
    warn() { :; }
    record_command_argv() { :; }
    record_module_status() { :; }
    nxc() { rdp_fake_netexec "$@"; }
    timeout() {
        shift
        "$@"
    }
    RDP_FAKE_MODE=failure RDP_ARG_LOG="$TEST_TMP/rdp-failure.args"
    export RDP_FAKE_MODE RDP_ARG_LOG
    RDP_PORT_OPEN=true CREDS_PROVIDED=true AUTH_USER=analyst AUTH_PASS=wrong AUTH_DOMAIN="" LDAP_DOMAIN=""
    sps_run_rdp_auth_check 192.0.2.25
    printf '%s|%s|%s\n' "$RDP_AUTH_STATUS" "$RDP_AUTH_OK" "$RDP_AUTH_REASON" > "$TEST_TMP/rdp-failure.result"
)
assert_contains "$TEST_TMP/rdp-failure.result" "failure|false|NetExec RDP rejected" "RDP credential rejection is classified"

(
    source "$ROOT_DIR/lib/fathomtrace/rdp.sh"
    info() { :; }
    warn() { :; }
    record_module_status() { :; }
    timeout() {
        shift
        "$@"
    }
    RDP_ARG_LOG="$TEST_TMP/rdp-skipped.args"
    export RDP_ARG_LOG
    RDP_PORT_OPEN=true CREDS_PROVIDED=false AUTH_USER="" AUTH_PASS="" AUTH_DOMAIN="" LDAP_DOMAIN=""
    sps_run_rdp_auth_check 192.0.2.25
    printf '%s|%s|%s\n' "$RDP_AUTH_STATUS" "$RDP_AUTH_OK" "$RDP_AUTH_REASON" > "$TEST_TMP/rdp-skipped.result"
)
assert_contains "$TEST_TMP/rdp-skipped.result" "skipped|false|explicit credentials were not supplied" "RDP validation stays opt-in"
assert_no_file "$TEST_TMP/rdp-skipped.args" "skipped RDP validation does not invoke NetExec"

# Unit-test artifact sanitization, atomic manifests, deduplication, and failures.
(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    source "$ROOT_DIR/lib/fathomtrace/validation.sh"
    source "$ROOT_DIR/lib/fathomtrace/loot.sh"
    OUTPUT_FORMAT=text QUIET=true DEBUG=false VERBOSE=false COLOR_MODE=never ICON_MODE=ascii
    AUTH_PASS=topsecret SMB_PASS="" TARGET=127.0.0.1 TARGET_IPV4=127.0.0.1
    LOOT_ENABLED=true LOOT_BASE_DIR="$TEST_TMP/loot-unit" OVERWRITE=false INDEX_FORMAT=all
    RUNTIME_TMP_DIR="$TEST_TMP/loot-runtime" SPS_SESSION_ID=unit-session
    mkdir -p "$RUNTIME_TMP_DIR"
    sps_configure_output
    printf 'same evidence\n' > "$TEST_TMP/source-one.txt"
    printf 'same evidence\n' > "$TEST_TMP/source-two.txt"
    printf 'console secret: topsecret\n' > "$TEST_TMP/console.txt"
    MACHINE_CAPTURE_FILE="$TEST_TMP/console.txt"
    init_artifacts > /dev/null 2> /dev/null
    sps_store_artifact "$TEST_TMP/source-one.txt" web raw > "$TEST_TMP/first-path"
    sps_store_artifact "$TEST_TMP/source-two.txt" web raw > "$TEST_TMP/second-path"
    record_command Test Redaction "tool --password topsecret"
    record_module_status optional-module failed "simulated partial failure"
    sps_record_finding "TEST-001" high confirmed "unit evidence" "one|two" "three" active-read "evidence/path" "fix it" "clean it"
    printf 'user:topsecret\n' > credentials.txt
    sps_finalize_artifacts
    sps_restore_working_directory
    sanitize_name '../../unsafe target:name' > "$TEST_TMP/sanitized"
)
assert_eq "source-one.txt" "$(basename "$(cat "$TEST_TMP/first-path")")" "safe original filename is preserved"
assert_eq "$(cat "$TEST_TMP/first-path")" "$(cat "$TEST_TMP/second-path")" "identical artifacts are deduplicated by hash"
assert_contains "$TEST_TMP/sanitized" "unsafe_target_name" "filenames are sanitized"
MANIFEST="$TEST_TMP/loot-unit/unit-session/reports/manifest.jsonl"
MANIFEST_CSV="$TEST_TMP/loot-unit/unit-session/reports/manifest.csv"
FINDINGS="$TEST_TMP/loot-unit/unit-session/reports/findings.jsonl"
assert_file "$MANIFEST" "JSONL manifest is generated"
assert_file "$MANIFEST_CSV" "optional CSV manifest is generated"
assert_file "$FINDINGS" "structured findings JSONL is generated"
assert_contains "$MANIFEST" '"collection_time"' "manifest records collection time"
assert_contains "$MANIFEST" '"sha256"' "manifest records checksums"
assert_contains "$MANIFEST" '"status":"duplicate"' "manifest records deduplication"
assert_contains "$MANIFEST" '"status":"failed"' "partial module failure is preserved"
assert_contains "$MANIFEST" '"sensitive":true' "sensitive artifacts are labeled"
assert_contains "$FINDINGS" '"finding_id":"TEST-001"' "finding schema records the finding ID"
assert_contains "$FINDINGS" '"severity":"high"' "finding schema records severity"
assert_contains "$FINDINGS" '"confidence":"confirmed"' "finding schema records confidence"
assert_contains "$FINDINGS" '"evidence":"unit evidence"' "finding schema records evidence"
assert_contains "$FINDINGS" '"prerequisites":{"met":["one","two"],"missing":["three"]}' "finding schema records met and missing prerequisites"
assert_contains "$FINDINGS" '"action_class":"active-read"' "finding schema records action class"
assert_contains "$FINDINGS" '"artifact_paths":["evidence/path"]' "finding schema records artifact paths"
assert_contains "$FINDINGS" '"remediation":"fix it"' "finding schema records remediation"
assert_contains "$FINDINGS" '"cleanup_notes":"clean it"' "finding schema records cleanup notes"
assert_file "$TEST_TMP/loot-unit/unit-session/loot/credentials.txt" "sensitive root output moves to loot"
assert_not_contains "$TEST_TMP/loot-unit/unit-session/commands/repeatable_commands.txt" "topsecret" "command artifact redacts secrets"
assert_not_contains "$TEST_TMP/loot-unit/unit-session/raw/console-capture.txt" "topsecret" "captured console artifact redacts secrets"

(
    source "$ROOT_DIR/lib/fathomtrace/output.sh"
    SHOW_SECRETS=true AUTH_PASS=topsecret SMB_PASS=""
    sps_redact "tool --password topsecret" > "$TEST_TMP/show-secrets-unit"
)
assert_contains "$TEST_TMP/show-secrets-unit" "topsecret" "explicit show-secrets mode bypasses redaction"

# An anonymous rpcdump normally returns many UUIDs that are not in the small
# attack-path map. Unknown UUIDs must be ignored without tripping `set -u`.
RPC_FAKE_BIN="$TEST_TMP/rpc-fake-bin"
mkdir -p "$RPC_FAKE_BIN"
printf '#!/usr/bin/env bash\nexit 0\n' > "$RPC_FAKE_BIN/timeout"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "UUID : aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa v1.0"\n' > "$RPC_FAKE_BIN/rpcdump.py"
chmod +x "$RPC_FAKE_BIN/timeout" "$RPC_FAKE_BIN/rpcdump.py"
PATH="$RPC_FAKE_BIN:$PATH" \
    "$SCRIPT" 127.0.0.1 --ports 135 --connect-timeout .1 \
    --no-loot --skip-preflight --no-color --ascii \
    > "$TEST_TMP/rpc-unknown-uuid.stdout" 2> "$TEST_TMP/rpc-unknown-uuid.stderr"
assert_eq 0 "$?" "unknown rpcdump UUID does not abort the scan"
assert_contains "$TEST_TMP/rpc-unknown-uuid.stderr" "Anonymous MSRPC enumeration successful" "rpcdump fixture reaches UUID parsing"
assert_not_contains "$TEST_TMP/rpc-unknown-uuid.stderr" "unbound variable" "unknown rpcdump UUID is ignored under nounset"

# A bounded anonymous FTP probe may time out on a reachable but unresponsive
# service. The optional probe must report that result without aborting the scan.
FTP_FAKE_BIN="$TEST_TMP/ftp-fake-bin"
mkdir -p "$FTP_FAKE_BIN"
cat > "$FTP_FAKE_BIN/timeout" <<'EOF'
#!/usr/bin/env bash
shift
if [[ "${1:-}" == bash && "${2:-}" == -c ]]; then
    exit 0
fi
if [[ "${1:-}" == ftp ]]; then
    exit 124
fi
exec "$@"
EOF
printf '#!/usr/bin/env bash\nexit 0\n' > "$FTP_FAKE_BIN/ftp"
cat > "$FTP_FAKE_BIN/nxc" <<'EOF'
#!/usr/bin/env bash
printf '\0FTP 127.0.0.1 21 127.0.0.1 [+] anonymous:anonymous\0\n'
EOF
chmod +x "$FTP_FAKE_BIN/timeout" "$FTP_FAKE_BIN/ftp" "$FTP_FAKE_BIN/nxc"
PATH="$FTP_FAKE_BIN:$PATH" \
    "$SCRIPT" 127.0.0.1 --ports 21 --connect-timeout .1 \
    --no-loot --skip-preflight --no-color --ascii \
    > "$TEST_TMP/ftp-timeout.stdout" 2> "$TEST_TMP/ftp-timeout.stderr"
assert_eq 0 "$?" "anonymous FTP timeout does not abort the scan"
assert_contains "$TEST_TMP/ftp-timeout.stderr" "Anonymous FTP check timed out after 5 seconds" "anonymous FTP timeout is explained"
assert_contains "$TEST_TMP/ftp-timeout.stdout" "Testing anonymous FTP with NetExec (nxc)" "native FTP timeout falls back to the maintained NetExec CLI"
assert_contains "$TEST_TMP/ftp-timeout.stdout" "-u anonymous -p ''" "NetExec anonymous FTP fallback uses an empty password"
assert_contains "$TEST_TMP/ftp-timeout.stderr" "Anonymous FTP login allowed (confirmed by NetExec)" "NetExec anonymous FTP success is classified"
assert_not_contains "$TEST_TMP/ftp-timeout.stderr" "ignored null byte" "NetExec NUL bytes are removed before Bash capture"
assert_contains "$TEST_TMP/ftp-timeout.stdout" "Scan completed" "scan continues after anonymous FTP timeout"
assert_not_contains "$TEST_TMP/ftp-timeout.stderr" "Scan failed with exit code 124" "FTP timeout is not promoted to a scan failure"

# A selected but irrelevant module must not initialize or execute when its ports
# and prerequisites were not discovered.
FAKE_BIN="$TEST_TMP/fake-bin"
mkdir -p "$FAKE_BIN"
printf '#!/usr/bin/env bash\n: > "$SPS_MARKER"\n' > "$FAKE_BIN/bloodhound-python"
chmod +x "$FAKE_BIN/bloodhound-python"
SPS_MARKER="$TEST_TMP/bloodhound-ran" PATH="$FAKE_BIN:$PATH" \
    "$SCRIPT" 127.0.0.1 --ports 65534 --connect-timeout .1 --run-blood \
    --no-loot --skip-preflight --skip-null-checks --skip-guest-checks --quiet \
    > "$TEST_TMP/unrelated.stdout" 2> "$TEST_TMP/unrelated.stderr"
assert_eq 0 "$?" "closed-port scan completes successfully"
assert_no_file "$TEST_TMP/bloodhound-ran" "unrelated BloodHound module is not initialized"

printf '\n%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"
((FAIL_COUNT == 0))
