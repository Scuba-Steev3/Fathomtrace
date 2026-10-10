#!/usr/bin/env bash

# Read-only SMTP discovery. The module stops after greeting, capability, and
# HELP queries; it never begins a mail transaction or attempts authentication.

sps_smtp_plain_session() {
    local target="$1"
    local port="$2"
    local query_timeout="${SMTP_QUERY_TIMEOUT:-5}"

    timeout "$query_timeout" bash -c '
        target="$1"
        port="$2"
        ehlo_name="$3"

        exec 7<>"/dev/tcp/${target}/${port}" || exit 1

        smtp_read_reply() {
            local expected="$1" line code=""
            while IFS= read -r line <&7; do
                line="${line%$'\''\r'\''}"
                printf "S: %s\n" "$line"
                if [[ "$line" =~ ^([0-9]{3})[[:space:]] ]]; then
                    code="${BASH_REMATCH[1]}"
                    [[ -z "$expected" || "$code" == "$expected" ]]
                    return
                fi
            done
            return 1
        }

        smtp_read_reply 220 || exit 2

        printf "C: EHLO %s\n" "$ehlo_name"
        printf "EHLO %s\r\n" "$ehlo_name" >&7
        if ! smtp_read_reply 250; then
            printf "C: HELO %s\n" "$ehlo_name"
            printf "HELO %s\r\n" "$ehlo_name" >&7
            smtp_read_reply 250 || exit 3
        fi

        printf "C: HELP\n"
        printf "HELP\r\n" >&7
        smtp_read_reply "" || true

        printf "C: QUIT\n"
        printf "QUIT\r\n" >&7
        smtp_read_reply 221 || true
    ' _ "$target" "$port" "${SMTP_EHLO_NAME:-fathomtrace.invalid}"
}

sps_smtp_tls_session() {
    local target="$1"
    local port="$2"
    local query_timeout="${SMTP_QUERY_TIMEOUT:-5}"
    local ehlo_name="${SMTP_EHLO_NAME:-fathomtrace.invalid}"
    local sni_name=""

    if [[ -n "${TARGET_FQDN:-}" ]]; then
        sni_name="$TARGET_FQDN"
    elif ! sps_is_ipv4 "${ORIGINAL_TARGET:-$target}" && sps_is_hostname "${ORIGINAL_TARGET:-$target}"; then
        sni_name="${ORIGINAL_TARGET:-$target}"
    fi

    timeout "$query_timeout" bash -c '
        target="$1"
        port="$2"
        ehlo_name="$3"
        sni_name="$4"
        openssl_args=(s_client -quiet -crlf -connect "${target}:${port}")
        [[ -n "$sni_name" ]] && openssl_args+=(-servername "$sni_name")

        coproc SMTP_TLS { openssl "${openssl_args[@]}" 2> /dev/null; }
        exec 7<&"${SMTP_TLS[0]}"
        exec 8>&"${SMTP_TLS[1]}"

        smtp_read_reply() {
            local expected="$1" line code=""
            while IFS= read -r line <&7; do
                line="${line%$'\''\r'\''}"
                printf "S: %s\n" "$line"
                if [[ "$line" =~ ^([0-9]{3})[[:space:]] ]]; then
                    code="${BASH_REMATCH[1]}"
                    [[ -z "$expected" || "$code" == "$expected" ]]
                    return
                fi
            done
            return 1
        }

        smtp_read_reply 220 || exit 2

        printf "C: EHLO %s\n" "$ehlo_name"
        printf "EHLO %s\n" "$ehlo_name" >&8
        if ! smtp_read_reply 250; then
            printf "C: HELO %s\n" "$ehlo_name"
            printf "HELO %s\n" "$ehlo_name" >&8
            smtp_read_reply 250 || exit 3
        fi

        printf "C: HELP\n"
        printf "HELP\n" >&8
        smtp_read_reply "" || true

        printf "C: QUIT\n"
        printf "QUIT\n" >&8
        smtp_read_reply 221 || true
        exec 8>&-
        wait "$SMTP_TLS_PID" 2> /dev/null || true
    ' _ "$target" "$port" "$ehlo_name" "$sni_name"
}

sps_smtp_transcript_confirmed() {
    local source="$1"
    awk '
        /^S: 220[- ]/ { greeting=1 }
        /^S: 250[- ]/ { ehlo=1 }
        END { exit !(greeting && ehlo) }
    ' "$source"
}

sps_smtp_parse_banner() {
    local source="$1"
    sed -n 's/^S: 220[- ]//p' "$source" | head -n 1
}

sps_smtp_parse_capabilities() {
    local source="$1"
    sed -n -E 's/^S: 250[- ]//p' "$source" |
        sed -E '/^[[:space:]]*$/d' |
        awk 'NR > 1 && !seen[$0]++'
}

sps_smtp_parse_help() {
    local source="$1"
    sed -n -E 's/^S: 214[- ]//p' "$source" |
        sed -E '/^[[:space:]]*$/d' |
        awk '!seen[$0]++'
}

sps_smtp_extract_hostname() {
    local source="$1"
    local candidate=""
    candidate="$(sps_smtp_parse_banner "$source" | awk '{print $1}' | sed -E 's/^\[//; s/\]$//; s/[,:;]$//' | tr '[:upper:]' '[:lower:]')"
    case "$candidate" in
        ready | smtp | esmtp | service | mail) candidate="" ;;
    esac
    if [[ -z "$candidate" ]] || sps_is_ipv4 "$candidate" || ! sps_is_hostname "$candidate"; then
        candidate="$(sed -n -E 's/^S: 250[- ]([^[:space:]]+).*/\1/p' "$source" | head -n 1 | sed -E 's/^\[//; s/\]$//; s/[,:;]$//' | tr '[:upper:]' '[:lower:]')"
    fi
    if sps_is_ipv4 "$candidate" || ! sps_is_hostname "$candidate"; then
        candidate=""
    fi
    printf '%s' "$candidate"
}

sps_smtp_join_lines() {
    awk 'NF { if (out != "") out=out "; "; out=out $0 } END { print out }'
}

sps_run_smtp_discovery_port() {
    local target="$1"
    local port="$2"
    local safe_target output_file transcript="" rc=0
    local banner capabilities help_text auth_mechanisms smtp_hostname artifact="" telnet_artifact="" certificate_artifact="" certificate_hostname=""
    local starttls=false vrfy=false expn=false certificate_transport=""

    safe_target="$(sanitize_name "$target")"
    output_file="smtp_${safe_target}_${port}.txt"

    if [[ "$port" == 465 ]]; then
        if ! sps_command_available openssl; then
            warn "SMTP discovery on port 465 skipped: OpenSSL is required for implicit TLS"
            record_module_status "smtp:${port}" "skipped" "openssl unavailable for implicit TLS"
            return 1
        fi
        if transcript="$(sps_smtp_tls_session "$target" "$port")"; then
            rc=0
        else
            rc=$?
        fi
    else
        if transcript="$(sps_smtp_plain_session "$target" "$port")"; then
            rc=0
        else
            rc=$?
        fi
    fi

    printf '%s\n' "$transcript" | sps_clean_tool_stream > "$output_file"
    if [[ "$port" != 465 ]] && sps_run_mail_telnet_banner_check "$target" "$port" smtp; then
        telnet_artifact="$MAIL_TELNET_BANNER_FILE"
    fi
    if ! sps_smtp_transcript_confirmed "$output_file"; then
        debug "Port $port did not produce a confirmed SMTP greeting and EHLO/HELO response"
        [[ -s "$output_file" ]] && record_loot "smtp_unconfirmed_transcript" "$target:$port" "$output_file"
        record_module_status "smtp:${port}" "executed" "SMTP not confirmed; probe exit $rc"
        return 0
    fi

    SMTP_SERVICE_CONFIRMED=true
    grep -Fqx "$port" "$SMTP_CONFIRMED_FILE" 2> /dev/null || printf '%s\n' "$port" >> "$SMTP_CONFIRMED_FILE"
    banner="$(sps_smtp_parse_banner "$output_file")"
    capabilities="$(sps_smtp_parse_capabilities "$output_file" | sps_smtp_join_lines)"
    help_text="$(sps_smtp_parse_help "$output_file" | sps_smtp_join_lines)"
    auth_mechanisms="$(sps_smtp_parse_capabilities "$output_file" |
        sed -n -E 's/^AUTH[=[:space:]]+//Ip' | tr ' ' '\n' |
        awk 'NF && !seen[toupper($0)]++ { values[++count]=toupper($0) } END { for (i=1; i<=count; i++) printf "%s%s", (i > 1 ? "," : ""), values[i] }')"
    grep -Eqi '^S: 250[- ].*STARTTLS([[:space:]]|$)' "$output_file" && starttls=true
    grep -Eqi '(^|[[:space:]])VRFY([[:space:]]|$)' "$output_file" && vrfy=true
    grep -Eqi '(^|[[:space:]])EXPN([[:space:]]|$)' "$output_file" && expn=true
    smtp_hostname="$(sps_smtp_extract_hostname "$output_file")"

    if [[ "$port" == 465 ]]; then
        certificate_transport=implicit
    elif [[ "$starttls" == true ]]; then
        certificate_transport=starttls
    fi
    if [[ -n "$certificate_transport" ]] &&
        sps_run_mail_certificate_check "$target" "$port" smtp "$certificate_transport"; then
        certificate_artifact="$MAIL_CERT_PEM_FILE|$MAIL_CERT_METADATA_FILE"
        certificate_hostname="${MAIL_CERT_HOSTNAMES%%,*}"
        [[ -z "$smtp_hostname" && -n "$certificate_hostname" ]] && smtp_hostname="$certificate_hostname"
    fi

    if [[ -n "$smtp_hostname" ]]; then
        SMTP_HOSTNAME="$smtp_hostname"
        printf '%s %s\n' "$target" "$smtp_hostname" >> "$HOSTS_FILE"
        printf '%s\n' "$smtp_hostname" >> "$DISCOVERED_HOSTS"
        sort -u "$HOSTS_FILE" -o "$HOSTS_FILE"
        sort -u "$DISCOVERED_HOSTS" -o "$DISCOVERED_HOSTS"
    fi

    artifact="$output_file${telnet_artifact:+|$telnet_artifact}${certificate_artifact:+|$certificate_artifact}"
    record_loot "smtp_discovery" "$target:$port${smtp_hostname:+ hostname=$smtp_hostname}" "$output_file"
    success "SMTP confirmed on port $port${smtp_hostname:+ ($smtp_hostname)}"
    [[ -n "$banner" ]] && info "SMTP banner: $banner"
    [[ -n "$capabilities" ]] && info "SMTP EHLO capabilities: $capabilities"
    [[ -n "$auth_mechanisms" ]] && info "SMTP authentication mechanisms: $auth_mechanisms"
    info "SMTP STARTTLS advertised: $starttls; VRFY advertised/reported: $vrfy; EXPN advertised/reported: $expn"

    sps_record_finding \
        "SMTP-SERVICE-${port}" "informational" "high" \
        "SMTP protocol confirmed on ${target}:${port}; banner=${banner:-unavailable}; capabilities=${capabilities:-unavailable}; HELP=${help_text:-unavailable}; AUTH=${auth_mechanisms:-none advertised}; STARTTLS=$starttls; VRFY=$vrfy; EXPN=$expn" \
        "TCP port $port open|SMTP 220 greeting|SMTP 250 EHLO or HELO response" "" \
        "discovery" "$artifact" \
        "Restrict SMTP listeners and advertised extensions to the clients and functions that require them." \
        "Only greeting, EHLO/HELO, HELP, and QUIT were used; no authentication or mail transaction was attempted."
    record_module_status "smtp:${port}" "executed" \
        "confirmed; starttls=$starttls; auth=${auth_mechanisms:-none}; hostname=${smtp_hostname:-unknown}"
}

sps_run_smtp_discovery() {
    local target="$1"
    shift
    local port found=false

    for port in "$@"; do
        case "$port" in
            25 | 465 | 587 | 2525)
                if [[ "$found" != true ]]; then
                    sps_service_heading "SMTP MAIL TRANSFER" \
                        "Inspecting greetings, EHLO capabilities, TLS support, certificate identity, and advertised authentication."
                fi
                found=true
                case "$port" in
                    25) sps_service_endpoint "SMTP / TCP 25 - STARTTLS when advertised" ;;
                    465) sps_service_endpoint "SMTPS / TCP 465 - implicit TLS" ;;
                    587) sps_service_endpoint "SMTP SUBMISSION / TCP 587 - STARTTLS when advertised" ;;
                    2525) sps_service_endpoint "SMTP ALTERNATE / TCP 2525 - STARTTLS when advertised" ;;
                esac
                sps_run_smtp_discovery_port "$target" "$port" || true
                ;;
        esac
    done

    [[ "$found" == true ]] || debug "SMTP discovery skipped: no SMTP-family ports were open"
}
