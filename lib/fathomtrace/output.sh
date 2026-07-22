#!/usr/bin/env bash
# shellcheck disable=SC2034 # Compatibility colors/icons are used by the entry point.

sps_configure_output() {
    local use_color=false
    local use_unicode=false

    if [[ "${OUTPUT_FORMAT:-text}" != "text" ]]; then
        COLOR_MODE="never"
        ICON_MODE="ascii"
    fi

    case "${COLOR_MODE:-auto}" in
        always) use_color=true ;;
        auto)
            if [[ -n "${CLICOLOR_FORCE:-}" && "${CLICOLOR_FORCE:-0}" != "0" ]]; then
                use_color=true
            elif [[ -n "${NO_COLOR:-}" || "${CLICOLOR:-1}" == "0" ]]; then
                use_color=false
            elif [[ "${TERM:-dumb}" != "dumb" && (-t 1 || -t 2) ]]; then
                use_color=true
            fi
            ;;
    esac

    if [[ "$use_color" == true ]]; then
        RED=$'\033[0;31m'
        GREEN=$'\033[0;32m'
        YELLOW=$'\033[0;33m'
        BLUE=$'\033[0;34m'
        MAGENTA=$'\033[0;35m'
        CYAN=$'\033[0;36m'
        GRAY=$'\033[0;90m'
        BRED=$'\033[1;31m'
        BGREEN=$'\033[1;32m'
        BYELLOW=$'\033[1;33m'
        RESET=$'\033[0m'
    else
        RED=""
        GREEN=""
        YELLOW=""
        BLUE=""
        MAGENTA=""
        CYAN=""
        GRAY=""
        BRED=""
        BGREEN=""
        BYELLOW=""
        RESET=""
    fi

    case "${ICON_MODE:-auto}" in
        unicode) use_unicode=true ;;
        auto)
            [[ "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" =~ [Uu][Tt][Ff]-?8 ]] && use_unicode=true
            ;;
    esac

    if [[ "$use_unicode" == true ]]; then
        ICON_OK="✔"
        ICON_WARN="⚠"
        ICON_INFO="ℹ"
        ICON_FIND="◆"
        ICON_DEBUG="·"
        ICON_RISK="🔥"
        ICON_ALERT="🚨"
        ICON_CRIT="💥"
        ICON_SCAN="🔍"
        ICON_SHARE="📁"
        ICON_WEB="🌐"
        ICON_USER="👤"
        ICON_TIP="💡"
        ICON_PIN="📌"
    else
        ICON_OK="[+]"
        ICON_WARN="[!]"
        ICON_INFO="[*]"
        ICON_FIND="[>]"
        ICON_DEBUG="[debug]"
        ICON_RISK="[!!]"
        ICON_ALERT="[!]"
        ICON_CRIT="[!!!]"
        ICON_SCAN="[scan]"
        ICON_SHARE="[share]"
        ICON_WEB="[web]"
        ICON_USER="[user]"
        ICON_TIP="[tip]"
        ICON_PIN="[note]"
    fi

    MASKED_AUTH_PASS=""
    [[ -n "${AUTH_PASS:-}" ]] && MASKED_AUTH_PASS="$(sps_secret_value "$AUTH_PASS")"
    LAST_DIAGNOSTIC=""
    SPS_OUTPUT_CAPTURED=false
    SPS_OUTPUT_FINALIZED=false
    SPS_QUIET_CAPTURE=false
}

sps_secret_value() {
    local secret="${1:-}"
    if [[ "${SHOW_SECRETS:-false}" == true ]]; then
        #printf '%s' "$secret"
		printf "%s" "$secret"
    elif [[ -n "$secret" ]]; then
        printf "%s" "[REDACTED]"
    fi
}

sps_redact() {
    local text="${1:-}"
    local secret
    if [[ "${SHOW_SECRETS:-false}" == true ]]; then
        printf '%s' "$text"
        return 0
    fi
    for secret in "${AUTH_PASS:-}" "${SMB_PASS:-}"; do
        [[ -n "$secret" ]] && text="${text//"$secret"/[REDACTED]}"
    done
    printf '%s' "$text"
}

sps_redact_file() {
    local source="$1"
    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
        printf '%s\n' "$(sps_redact "$line")"
    done < "$source"
}

sps_emit() {
    local level="$1"
    shift
    local message
    message="$(sps_redact "$*")"
    local prefix color destination=1

    case "$level" in
        success)
            [[ "${QUIET:-false}" == true ]] && return 0
            prefix="$ICON_OK"
            color="$GREEN"
            ;;
        info)
            [[ "$message" == *"[DEBUG]"* && "${DEBUG:-false}" != true ]] && return 0
            [[ "${QUIET:-false}" == true ]] && return 0
            prefix="$ICON_INFO"
            color="$BLUE"
            ;;
        lightbulb)
            [[ "$message" == *"[DEBUG]"* && "${DEBUG:-false}" != true ]] && return 0
            [[ "${QUIET:-false}" == true ]] && return 0
			prefix="$ICON_TIP"
            color="$YELLOW"
            ;;
		finding)
            prefix="$ICON_FIND"
            color="$CYAN"
            ;;
        warning)
            prefix="$ICON_WARN"
            color="$YELLOW"
            destination=2
            LAST_DIAGNOSTIC="$message"
            ;;
        error)
            prefix="[-]"
            color="$RED"
            destination=2
            LAST_DIAGNOSTIC="$message"
            ;;
        debug)
            [[ "${DEBUG:-false}" == true ]] || return 0
            prefix="$ICON_DEBUG"
            color="$GRAY"
            destination=2
            ;;
        *)
            prefix="$ICON_INFO"
            color="$BLUE"
            ;;
    esac

    if [[ "${OUTPUT_FORMAT:-text}" != "text" ]]; then
        destination=2
    fi

    printf '%b%s%b %s\n' "$color" "$prefix" "$RESET" "$message" >&"$destination"
}

success() { sps_emit success "$*"; }
info() { sps_emit info "$*"; }
notify() { sps_emit warning "$*"; }
note() { sps_emit info "$*"; }
finding() { sps_emit finding "$*"; }
warn() { sps_emit warning "$*"; }
error() { sps_emit error "$*"; }
debug() { sps_emit debug "$*"; }
risk() { sps_emit warning "$*"; }
high_risk() { sps_emit warning "$*"; }
critical() { sps_emit error "$*"; }
danger() { sps_emit error "$*"; }
alert() { sps_emit warning "$*"; }
lightbulb() { sps_emit lightbulb "$*"; }

sps_section() {
    [[ "${QUIET:-false}" == true || "${OUTPUT_FORMAT:-text}" != "text" ]] && return 0
    local title="$1"
    printf '\n%b========================================%b\n' "$BLUE" "$RESET"
    printf '%b%s%b\n' "$BYELLOW" "$title" "$RESET"
    printf '%b========================================%b\n' "$BLUE" "$RESET"
}

sps_print_legend() {
    [[ "${QUIET:-false}" == true || "${OUTPUT_FORMAT:-text}" != "text" || "${VERBOSE:-false}" != true ]] && return 0
    cat << EOF

Legend:
  $ICON_OK  Success    $ICON_INFO  Information    $ICON_WARN  Warning
  $ICON_FIND  Finding    $ICON_DEBUG  Debug
EOF
}

sps_print_banner() {
    [[ "${QUIET:-false}" == true || "${OUTPUT_FORMAT:-text}" != "text" ]] && return 0
    sps_section "Authorized Recon and Service Enumeration"
    printf '  Use only in authorized environments. Intrusive modules remain opt-in.\n'
}

sps_show_deprecations() {
    local message
    for message in "${CLI_DEPRECATIONS[@]:-}"; do
        [[ -n "$message" ]] && warn "$message"
    done
    return 0
}

sps_begin_output_capture() {
    if [[ "${OUTPUT_FORMAT:-text}" != "text" ]]; then
        MACHINE_CAPTURE_FILE="${RUNTIME_TMP_DIR:?}/console.txt"
        exec 3>&1
        exec 1> "$MACHINE_CAPTURE_FILE"
        SPS_OUTPUT_CAPTURED=true
    elif [[ "${QUIET:-false}" == true ]]; then
        exec 3>&1
        exec 1> /dev/null
        SPS_OUTPUT_CAPTURED=true
        SPS_QUIET_CAPTURE=true
    fi
}

sps_json_escape() {
    local value="${1:-}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf '%s' "$value"
}

sps_csv_escape() {
    local value="${1:-}"
    value="${value//\"/\"\"}"
    printf '"%s"' "$value"
}

# Produce commands that remain safe to copy/paste even when a target, username,
# domain, path, or password contains shell metacharacters. Callers should pass
# one argument per command token instead of assembling command strings by hand.
sps_shell_join() {
    local rendered="" quoted argument
    for argument in "$@"; do
        printf -v quoted '%q' "$argument"
        rendered+="${rendered:+ }$quoted"
    done
    printf '%s' "$rendered"
}

sps_emit_structured_summary() {
    local exit_code="$1"
    local status="completed"
    local duration=0
    local artifact_root="${ARTIFACT_ROOT:-}"
    local manifest="${MANIFEST_FILE:-}"
    local findings="${FINDINGS_FILE:-}"
    local open_ports_json=""
    local open_ports_csv=""
    local port

    ((exit_code != 0)) && status="failed"
    [[ "${DRY_RUN:-false}" == true && "$exit_code" -eq 0 ]] && status="dry-run"
    [[ -n "${START_TIME:-}" ]] && duration=$(($(date +%s) - START_TIME))

    if declare -p OPEN_PORTS > /dev/null 2>&1; then
        for port in "${OPEN_PORTS[@]}"; do
            open_ports_json+="${open_ports_json:+,}$port"
            open_ports_csv+="${open_ports_csv:+;}$port"
        done
    fi

    case "$OUTPUT_FORMAT" in
        json)
            printf '{"schema_version":"1.0","command":"%s","status":"%s","exit_code":%d,' \
                "$(sps_json_escape "${COMMAND:-scan}")" "$status" "$exit_code"
            printf '"target":"%s","resolved_target":"%s","profile":"%s",' \
                "$(sps_json_escape "${ORIGINAL_TARGET:-${TARGET:-}}")" \
                "$(sps_json_escape "${TARGET_IPV4:-}")" \
                "$(sps_json_escape "${SCAN_PROFILE:-default}")"
            printf '"open_ports":[%s],"duration_seconds":%d,' "$open_ports_json" "$duration"
            printf '"session_id":"%s","artifact_root":' "$(sps_json_escape "${SESSION_ID:-}")"
            if [[ -n "$artifact_root" ]]; then
                printf '"%s"' "$(sps_json_escape "$artifact_root")"
            else
                printf 'null'
            fi
            printf ',"manifest":'
            if [[ -n "$manifest" ]]; then
                printf '"%s"' "$(sps_json_escape "$manifest")"
            else
                printf 'null'
            fi
            printf ',"findings":'
            if [[ -n "$findings" ]]; then
                printf '"%s"' "$(sps_json_escape "$findings")"
            else
                printf 'null'
            fi
            printf ',"artifact_count":%d,"finding_count":%d,"error":' \
                "${MANIFEST_ENTRY_COUNT:-0}" "${FINDING_ENTRY_COUNT:-0}"
            if ((exit_code != 0)); then
                printf '"%s"' "$(sps_json_escape "${LAST_DIAGNOSTIC:-operation failed}")"
            else
                printf 'null'
            fi
            printf '}\n'
            ;;
        csv)
            printf 'schema_version,command,status,exit_code,target,resolved_target,profile,open_ports,duration_seconds,session_id,artifact_root,manifest,findings,artifact_count,finding_count,error\n'
            printf '1.0,%s,%s,%d,%s,%s,%s,%s,%d,%s,%s,%s,%s,%d,%d,%s\n' \
                "$(sps_csv_escape "${COMMAND:-scan}")" \
                "$(sps_csv_escape "$status")" "$exit_code" \
                "$(sps_csv_escape "${ORIGINAL_TARGET:-${TARGET:-}}")" \
                "$(sps_csv_escape "${TARGET_IPV4:-}")" \
                "$(sps_csv_escape "${SCAN_PROFILE:-default}")" \
                "$(sps_csv_escape "$open_ports_csv")" "$duration" \
                "$(sps_csv_escape "${SESSION_ID:-}")" \
                "$(sps_csv_escape "$artifact_root")" \
                "$(sps_csv_escape "$manifest")" \
                "$(sps_csv_escape "$findings")" \
                "${MANIFEST_ENTRY_COUNT:-0}" \
                "${FINDING_ENTRY_COUNT:-0}" \
                "$(sps_csv_escape "$([[ "$exit_code" -ne 0 ]] && printf '%s' "${LAST_DIAGNOSTIC:-operation failed}")")"
            ;;
    esac
}

sps_finish_output() {
    local exit_code="${1:-0}"
    [[ "${SPS_OUTPUT_FINALIZED:-false}" == true ]] && return 0
    SPS_OUTPUT_FINALIZED=true

    if [[ "${SPS_OUTPUT_CAPTURED:-false}" == true ]]; then
        exec 1>&3
        exec 3>&-
        SPS_OUTPUT_CAPTURED=false
    fi

    if [[ "${OUTPUT_FORMAT:-text}" != "text" ]]; then
        sps_emit_structured_summary "$exit_code"
    elif [[ "${QUIET:-false}" != true ]]; then
        local duration=0
        local open_count=0
        [[ -n "${START_TIME:-}" ]] && duration=$(($(date +%s) - START_TIME))
        declare -p OPEN_PORTS > /dev/null 2>&1 && open_count="${#OPEN_PORTS[@]}"
        if ((exit_code == 0)); then
            success "Scan completed in ${duration}s; ${open_count} open port(s), ${MANIFEST_ENTRY_COUNT:-0} artifact record(s)."
        else
            error "Scan failed with exit code $exit_code${LAST_DIAGNOSTIC:+: $LAST_DIAGNOSTIC}"
        fi
    fi
}
