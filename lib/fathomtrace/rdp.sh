#!/usr/bin/env bash

sps_set_rdp_auth_state() {
    RDP_AUTH_STATUS="$1"
    RDP_AUTH_REASON="$2"
    [[ "$RDP_AUTH_STATUS" == success ]] && RDP_AUTH_OK=true || RDP_AUTH_OK=false
}

sps_find_netexec_rdp_client() {
    local candidate
    for candidate in nxc netexec; do
        if command -v "$candidate" > /dev/null 2>&1; then
            command -v "$candidate"
            return 0
        fi
    done
    return 1
}

sps_netexec_supports_rdp() {
    local client="$1" help_output
    help_output="$("$client" rdp --help 2>&1 || true)"
    grep -Eqi '(^|[[:space:]])rdp([[:space:]]|$)|remote desktop' <<< "$help_output"
}

sps_rdp_output_is_auth_failure() {
    grep -Eqi \
        'ERRCONNECT_(AUTHENTICATION_FAILED|LOGON_FAILURE|PASSWORD_EXPIRED|ACCOUNT_DISABLED|ACCOUNT_RESTRICTION|ACCOUNT_LOCKED_OUT|ACCOUNT_EXPIRED|NO_OR_MISSING_CREDENTIALS)|STATUS_(LOGON_FAILURE|WRONG_PASSWORD|NO_SUCH_USER|ACCOUNT_DISABLED|ACCOUNT_RESTRICTION|ACCOUNT_LOCKED_OUT|ACCOUNT_EXPIRED|PASSWORD_EXPIRED|PASSWORD_MUST_CHANGE|LOGON_TYPE_NOT_GRANTED|INVALID_LOGON_HOURS|INVALID_WORKSTATION)|KDC_ERR_(PREAUTH_FAILED|CLIENT_REVOKED|C_PRINCIPAL_UNKNOWN)|authentication (failed|failure)|logon failure' \
        <<< "$1"
}

sps_netexec_rdp_output_is_auth_success() {
    grep -Fq '[+]' <<< "$1"
}

sps_run_rdp_auth_check() {
    local target="${1:-${TARGET_IPV4:-}}"
    local client="" domain="${AUTH_DOMAIN:-${LDAP_DOMAIN:-}}"
    local output="" rc=0
    local -a args=()

    RDP_AUTH_PROVIDER="none"
    sps_set_rdp_auth_state skipped "TCP/3389 is not open"
    [[ "${RDP_PORT_OPEN:-false}" == true ]] || return 0

    if [[ "${CREDS_PROVIDED:-false}" != true || -z "${AUTH_USER:-}" || -z "${AUTH_PASS:-}" ]]; then
        sps_set_rdp_auth_state skipped "explicit credentials were not supplied"
        declare -F info > /dev/null && info "RDP credential validation skipped: $RDP_AUTH_REASON"
        declare -F record_module_status > /dev/null &&
            record_module_status "rdp-auth" "skipped" "$RDP_AUTH_REASON"
        return 0
    fi

    if ! client="$(sps_find_netexec_rdp_client)" || ! sps_netexec_supports_rdp "$client"; then
        sps_set_rdp_auth_state skipped "nxc/netexec with RDP protocol support is unavailable"
        declare -F warn > /dev/null && warn "RDP credential validation skipped: $RDP_AUTH_REASON"
        declare -F record_module_status > /dev/null &&
            record_module_status "rdp-auth" "skipped" "$RDP_AUTH_REASON"
        return 0
    fi
    args=(rdp "$target" -u "${AUTH_USER:-}" -p "${AUTH_PASS:-}")
    if [[ -n "$domain" && "${AUTH_USER:-}" != *\\* && "${AUTH_USER:-}" != *@* ]]; then
        args+=(-d "$domain")
    fi

    # Consumed by the parent scanner's summary and attack-path engine.
    # shellcheck disable=SC2034
    RDP_AUTH_PROVIDER="netexec"

    declare -F info > /dev/null &&
        info "Trying RDP credentials with a bounded NetExec RDP authentication check"
    declare -F record_command_argv > /dev/null &&
        record_command_argv "RDP" "Single-target credential validation via NetExec RDP" \
            timeout 20s "$client" "${args[@]}"

    output="$(timeout 20s "$client" "${args[@]}" 2>&1)" || rc=$?

    if sps_rdp_output_is_auth_failure "$output"; then
        sps_set_rdp_auth_state failure "NetExec RDP rejected or restricted the supplied credentials"
        declare -F warn > /dev/null && warn "$RDP_AUTH_REASON"
        declare -F record_module_status > /dev/null &&
            record_module_status "rdp-auth" "executed" "$RDP_AUTH_REASON"
        return 0
    fi

    if sps_netexec_rdp_output_is_auth_success "$output"; then
        sps_set_rdp_auth_state success "NetExec RDP accepted the supplied credentials"
        declare -F success > /dev/null &&
            success "RDP credentials accepted (non-interactive NLA authentication)"
        declare -F record_module_status > /dev/null &&
            record_module_status "rdp-auth" "executed" "$RDP_AUTH_REASON"
        if declare -F sps_record_finding > /dev/null; then
            sps_record_finding \
                "RDP-AUTH-T1021-001" "high" "confirmed" \
                "NetExec RDP confirmed authentication for ${AUTH_USER} on ${target}:3389 (MITRE ATT&CK T1021.001)." \
                "TCP/3389 open|explicit credentials supplied|RDP/NLA authentication accepted" "" \
                "active-authentication" "" \
                "Restrict RDP exposure, require MFA or an RD Gateway where appropriate, and limit Remote Desktop logon rights." \
                "The check used one target and one explicitly supplied credential pair; no command, screenshot, or interactive-session option was requested."
        fi
        return 0
    fi

    if ((rc == 124)); then
        sps_set_rdp_auth_state skipped "RDP authentication timed out; credential validity is inconclusive"
    else
        sps_set_rdp_auth_state skipped "RDP authentication could not be completed; credential validity is inconclusive"
    fi
    declare -F warn > /dev/null && warn "$RDP_AUTH_REASON"
    declare -F record_module_status > /dev/null &&
        record_module_status "rdp-auth" "skipped" "$RDP_AUTH_REASON (NetExec RDP exit $rc)"
    return 0
}

sps_rdp_auth_summary() {
    printf '%s (%s)' "${RDP_AUTH_STATUS:-skipped}" "${RDP_AUTH_REASON:-not evaluated}"
}

sps_rdp_authenticated_remote_service() {
    [[ "${RDP_AUTH_STATUS:-skipped}" == success && "${RDP_AUTH_OK:-false}" == true ]]
}
