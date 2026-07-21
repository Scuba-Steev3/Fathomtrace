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
assert_contains "$CLI_STDOUT" "fathomtrace 2.0.0" "version is stable"

"$LEGACY_SCRIPT" --version > "$TEST_TMP/legacy.stdout" 2> "$TEST_TMP/legacy.stderr"
assert_eq 0 "$?" "legacy command wrapper exits successfully"
assert_contains "$TEST_TMP/legacy.stdout" "fathomtrace 2.0.0" "legacy command wrapper delegates to Fathomtrace"

"$ROOT_DIR/install.sh" --prefix "$TEST_TMP/install-prefix" --no-legacy-wrapper > "$TEST_TMP/install.stdout" 2> "$TEST_TMP/install.stderr"
assert_eq 0 "$?" "prefix installer exits successfully"
"$TEST_TMP/install-prefix/bin/fathomtrace" --version > "$TEST_TMP/installed.stdout" 2> "$TEST_TMP/installed.stderr"
assert_eq 0 "$?" "installed prefix layout resolves libraries"
assert_contains "$TEST_TMP/installed.stdout" "fathomtrace 2.0.0" "installed command reports the Fathomtrace version"
assert_no_file "$TEST_TMP/install-prefix/bin/bash_simpleportscan.sh" "installer can omit the legacy wrapper"

run_cli unknown --definitely-unknown
assert_eq 2 "$CLI_RC" "unknown option uses CLI exit code"
assert_contains "$CLI_STDERR" "Unknown option" "unknown option is explained"

run_cli invalid-ports 127.0.0.1 --dry-run --no-loot --ports 0,70000
assert_eq 2 "$CLI_RC" "invalid ports use CLI exit code"
assert_contains "$CLI_STDERR" "selected port set" "invalid ports are explained"

run_cli invalid-jobs 127.0.0.1 --dry-run --no-loot --jobs 0
assert_eq 2 "$CLI_RC" "invalid worker count uses CLI exit code"
assert_contains "$CLI_STDERR" "--jobs must be" "invalid worker count is explained"

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
run_cli invalid-vhost-domain 127.0.0.1 --dry-run --no-loot --skip-preflight --vhost-domain 'not a domain' --ports 80
assert_eq 2 "$CLI_RC" "invalid --vhost-domain uses CLI exit code"
assert_contains "$CLI_STDERR" "--vhost-domain requires" "invalid VHost domain is explained"

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
    WEB_SERVICES_FILE="$RUNTIME_TMP_DIR/web-services"
    OPEN_PORTS_FILE="$RUNTIME_TMP_DIR/open"
    touch "$HINT_FILE" "$HOSTS_FILE" "$DISCOVERED_HOSTS" "$REDIRECT_HOSTS" "$HTTP_MARKER" "$HTTPS_MARKER" "$SMB_MARKER" "$KERB_MARKER" "$LDAP_MARKER" "$WEB_SERVICES_FILE" "$OPEN_PORTS_FILE"
    MAX_JOBS=2 CONNECT_TIMEOUT=.1 RETRY_LIMIT=0 SKIP_PREFLIGHT=true
    WEB_PORT_OPEN=false WEB_SERVICE_CONFIRMED=false LDAP_PORT_OPEN=false KERBEROS_PORT_OPEN=false KERBEROS_SERVICE_CONFIRMED=false
    sps_record_finding() { :; }
    sps_tcp_probe() { [[ "$2" == 80 || "$2" == 443 ]]; }
    run_port_scan 127.0.0.1 "80:HTTP:open" "22:SSH:open" "443:HTTPS:open" > /dev/null
    printf '%s\n' "${OPEN_PORTS[*]}" > "$TEST_TMP/scan-unit.result"
    sps_record_web_service http 3000 "unit protocol response"
    sps_classify_open_port 389
)
assert_contains "$TEST_TMP/scan-unit.result" "80 443" "worker results are deterministic"
assert_contains "$TEST_TMP/scan-unit/http" "3000" "protocol-confirmed custom HTTP port is recorded"
assert_contains "$TEST_TMP/scan-unit/web-services" "http:3000" "web service evidence preserves scheme and custom port"
assert_contains "$TEST_TMP/scan-unit/ldap" "389" "LDAP open-port state is recorded"
assert_not_contains "$TEST_TMP/scan-unit/hints" "KERBEROS" "LDAP does not imply Kerberos"

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
