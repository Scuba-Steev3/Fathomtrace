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

sps_run_optional_preflight() {
    [[ "${SKIP_PREFLIGHT:-false}" == true ]] && {
        debug "Optional preflight disabled by --skip-preflight"
        return 0
    }

    [[ "${ENABLE_SERVICE_DETECT:-false}" == true ]] && sps_optional_tool_check "service detection" nmap || true
    [[ "${ENABLE_WEB_ENUM:-false}" == true ]] && sps_optional_tool_check "web enumeration" ffuf || true
    [[ "${ENABLE_VHOST:-false}" == true ]] && sps_optional_tool_check "VHost discovery" curl || true
    [[ "${ENABLE_DNS_ENUM:-false}" == true ]] && sps_optional_tool_check "DNS enumeration" dig || true
    [[ "${ENABLE_BH_EXPORT:-false}" == true ]] && sps_optional_tool_check "BloodHound" bloodhound-python bloodhound-ce-python || true
    [[ "${ENABLE_ADCS:-false}" == true ]] && sps_optional_tool_check "AD CS" certipy-ad || true
    [[ "${ENABLE_MSSQL_ENUM:-false}" == true || "${ENABLE_MSSQL_BRUTE:-false}" == true ]] &&
        sps_optional_tool_check "MSSQL" netexec crackmapexec || true
}

sps_validate_selected_features() {
    local missing_creds=false
    [[ -z "${AUTH_USER:-}" || -z "${AUTH_PASS:-}" ]] && missing_creds=true

    if [[ "$missing_creds" == true ]]; then
        if [[ "${ENABLE_BH_EXPORT:-false}" == true || "${ENABLE_KERBROAST:-false}" == true || "${ENABLE_ADCS:-false}" == true ||
            "${ENABLE_MSSQL_PRIVESC:-false}" == true || "${ENABLE_MSSQL_CMDSHELL:-false}" == true ]]; then
            warn "Credentials are absent; selected credentialed modules will be skipped when reached."
            debug "Credential-independent scan and discovery remain enabled"
        fi
    fi

    if [[ -n "${AUTH_USER:-}" && -z "${AUTH_PASS:-}" ]]; then
        debug "Username supplied without a password; authenticated modules remain disabled"
    elif [[ -z "${AUTH_USER:-}" && -n "${AUTH_PASS:-}" ]]; then
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
