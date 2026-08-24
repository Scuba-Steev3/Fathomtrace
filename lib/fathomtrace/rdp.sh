#!/usr/bin/env bash

sps_set_rdp_auth_state() {
    RDP_AUTH_STATUS="$1"
    RDP_AUTH_REASON="$2"
    [[ "$RDP_AUTH_STATUS" == success ]] && RDP_AUTH_OK=true || RDP_AUTH_OK=false
}

sps_find_rdp_client() {
    local candidate
    for candidate in xfreerdp3 xfreerdp; do
        if command -v "$candidate" > /dev/null 2>&1; then
            command -v "$candidate"
            return 0
        fi
    done
    return 1
}

sps_rdp_client_supports_auth_only() {
    local client="$1" help_output
    help_output="$("$client" /help 2>&1 || true)"
    grep -Eq '(^|[[:space:]])/auth-only([[:space:]]|$)' <<< "$help_output"
}

sps_rdp_output_is_auth_failure() {
    grep -Eqi \
        'ERRCONNECT_(AUTHENTICATION_FAILED|LOGON_FAILURE|PASSWORD_EXPIRED|ACCOUNT_DISABLED|ACCOUNT_RESTRICTION|ACCOUNT_LOCKED_OUT|ACCOUNT_EXPIRED|NO_OR_MISSING_CREDENTIALS)|STATUS_(LOGON_FAILURE|WRONG_PASSWORD|NO_SUCH_USER|ACCOUNT_DISABLED|ACCOUNT_RESTRICTION|ACCOUNT_LOCKED_OUT|ACCOUNT_EXPIRED|PASSWORD_EXPIRED|PASSWORD_MUST_CHANGE)|authentication (failed|failure)|logon failure' \
        <<< "$1"
}

sps_run_rdp_auth_check() {
    local target="${1:-${TARGET_IPV4:-}}"
    local client="" domain="${AUTH_DOMAIN:-${LDAP_DOMAIN:-}}"
    local output="" rc=0
    local -a args=(
        /auth-only
        /cert:ignore
        /sec:nla
        "/v:${target}"
        "/u:${AUTH_USER:-}"
        "/p:${AUTH_PASS:-}"
        /timeout:10000
        /log-level:WARN
    )

    sps_set_rdp_auth_state skipped "TCP/3389 is not open"
    [[ "${RDP_PORT_OPEN:-false}" == true ]] || return 0

    if [[ "${CREDS_PROVIDED:-false}" != true || -z "${AUTH_USER:-}" || -z "${AUTH_PASS:-}" ]]; then
        sps_set_rdp_auth_state skipped "explicit credentials were not supplied"
        declare -F info > /dev/null && info "RDP credential validation skipped: $RDP_AUTH_REASON"
        declare -F record_module_status > /dev/null &&
            record_module_status "rdp-auth" "skipped" "$RDP_AUTH_REASON"
        return 0
    fi

    if ! client="$(sps_find_rdp_client)"; then
        sps_set_rdp_auth_state skipped "xfreerdp3/xfreerdp is unavailable"
        declare -F warn > /dev/null && warn "RDP credential validation skipped: $RDP_AUTH_REASON"
        declare -F record_module_status > /dev/null &&
            record_module_status "rdp-auth" "skipped" "$RDP_AUTH_REASON"
        return 0
    fi

    if ! sps_rdp_client_supports_auth_only "$client"; then
        sps_set_rdp_auth_state skipped "installed FreeRDP client does not support /auth-only"
        declare -F warn > /dev/null && warn "RDP credential validation skipped: $RDP_AUTH_REASON"
        declare -F record_module_status > /dev/null &&
            record_module_status "rdp-auth" "skipped" "$RDP_AUTH_REASON"
        return 0
    fi

    if [[ -n "$domain" && "${AUTH_USER:-}" != *\\* && "${AUTH_USER:-}" != *@* ]]; then
        args+=("/d:${domain}")
    fi

    declare -F info > /dev/null &&
        info "Trying RDP credentials with a non-interactive NLA authentication check"
    declare -F record_command_argv > /dev/null &&
        record_command_argv "RDP" "Non-interactive NLA credential validation" \
            timeout 15s "$client" "${args[@]}"

    output="$(timeout 15s "$client" "${args[@]}" 2>&1)" || rc=$?

    if sps_rdp_output_is_auth_failure "$output"; then
        sps_set_rdp_auth_state failure "RDP/NLA rejected the supplied credentials"
        declare -F warn > /dev/null && warn "$RDP_AUTH_REASON"
        declare -F record_module_status > /dev/null &&
            record_module_status "rdp-auth" "executed" "$RDP_AUTH_REASON"
        return 0
    fi

    if ((rc == 0)) || grep -Fqi 'Authentication only, exit status 0' <<< "$output"; then
        sps_set_rdp_auth_state success "RDP/NLA accepted the supplied credentials"
        declare -F success > /dev/null &&
            success "RDP credentials accepted (non-interactive NLA authentication)"
        declare -F record_module_status > /dev/null &&
            record_module_status "rdp-auth" "executed" "$RDP_AUTH_REASON"
        if declare -F sps_record_finding > /dev/null; then
            sps_record_finding \
                "RDP-AUTH-T1021-001" "high" "confirmed" \
                "FreeRDP /auth-only confirmed RDP/NLA authentication for ${AUTH_USER} on ${target}:3389 (MITRE ATT&CK T1021.001)." \
                "TCP/3389 open|explicit credentials supplied|RDP/NLA authentication accepted" "" \
                "active-authentication" "" \
                "Restrict RDP exposure, require MFA or an RD Gateway where appropriate, and limit Remote Desktop logon rights." \
                "The check used /auth-only and did not start an interactive desktop session."
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
        record_module_status "rdp-auth" "skipped" "$RDP_AUTH_REASON (FreeRDP exit $rc)"
    return 0
}

sps_rdp_auth_summary() {
    printf '%s (%s)' "${RDP_AUTH_STATUS:-skipped}" "${RDP_AUTH_REASON:-not evaluated}"
}

sps_rdp_authenticated_remote_service() {
    [[ "${RDP_AUTH_STATUS:-skipped}" == success && "${RDP_AUTH_OK:-false}" == true ]]
}
