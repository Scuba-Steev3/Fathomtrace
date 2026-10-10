#!/usr/bin/env bash

# Read-only POP3 discovery. Only the greeting, CAPA/NOOP, and QUIT commands are
# used; the module never supplies a username or accesses mailbox content.

sps_pop3_plain_session() {
    local target="$1" port="$2" query_timeout="${POP3_QUERY_TIMEOUT:-5}"

    timeout "$query_timeout" bash -c '
        target="$1"
        port="$2"
        exec 7<>"/dev/tcp/${target}/${port}" || exit 1

        pop3_read_line() {
            local line
            IFS= read -r line <&7 || return 1
            line="${line%$'\''\r'\''}"
            printf "S: %s\n" "$line"
            POP3_LAST_LINE="$line"
        }

        pop3_read_line || exit 2
        [[ "$POP3_LAST_LINE" == +OK* ]] || exit 2

        printf "C: CAPA\n"
        printf "CAPA\r\n" >&7
        pop3_read_line || exit 3
        if [[ "$POP3_LAST_LINE" == +OK* ]]; then
            while pop3_read_line; do
                [[ "$POP3_LAST_LINE" == "." ]] && break
            done
        else
            printf "C: NOOP\n"
            printf "NOOP\r\n" >&7
            pop3_read_line || exit 3
            [[ "$POP3_LAST_LINE" == +OK* ]] || exit 3
        fi

        printf "C: QUIT\n"
        printf "QUIT\r\n" >&7
        pop3_read_line || true
    ' _ "$target" "$port"
}

sps_pop3_tls_session() {
    local target="$1" port="$2" query_timeout="${POP3_QUERY_TIMEOUT:-5}" sni_name=""
    if [[ -n "${TARGET_FQDN:-}" ]]; then
        sni_name="$TARGET_FQDN"
    elif ! sps_is_ipv4 "${ORIGINAL_TARGET:-$target}" && sps_is_hostname "${ORIGINAL_TARGET:-$target}"; then
        sni_name="${ORIGINAL_TARGET:-$target}"
    fi

    timeout "$query_timeout" bash -c '
        target="$1"
        port="$2"
        sni_name="$3"
        openssl_args=(s_client -quiet -crlf -connect "${target}:${port}")
        [[ -n "$sni_name" ]] && openssl_args+=(-servername "$sni_name")
        coproc POP3_TLS { openssl "${openssl_args[@]}" 2> /dev/null; }
        exec 7<&"${POP3_TLS[0]}"
        exec 8>&"${POP3_TLS[1]}"

        pop3_read_line() {
            local line
            IFS= read -r line <&7 || return 1
            line="${line%$'\''\r'\''}"
            printf "S: %s\n" "$line"
            POP3_LAST_LINE="$line"
        }

        pop3_read_line || exit 2
        [[ "$POP3_LAST_LINE" == +OK* ]] || exit 2
        printf "C: CAPA\n"
        printf "CAPA\n" >&8
        pop3_read_line || exit 3
        if [[ "$POP3_LAST_LINE" == +OK* ]]; then
            while pop3_read_line; do
                [[ "$POP3_LAST_LINE" == "." ]] && break
            done
        else
            printf "C: NOOP\n"
            printf "NOOP\n" >&8
            pop3_read_line || exit 3
            [[ "$POP3_LAST_LINE" == +OK* ]] || exit 3
        fi
        printf "C: QUIT\n"
        printf "QUIT\n" >&8
        pop3_read_line || true
        exec 8>&-
        wait "$POP3_TLS_PID" 2> /dev/null || true
    ' _ "$target" "$port" "$sni_name"
}

sps_pop3_transcript_confirmed() {
    local source="$1"
    awk '
        /^S: [+]OK/ && !command { greeting=1 }
        /^C: (CAPA|NOOP)$/ { command=1; next }
        command && /^S: [+]OK/ { response=1 }
        END { exit !(greeting && response) }
    ' "$source"
}

sps_pop3_parse_banner() {
    sed -n 's/^S: [+]OK[[:space:]]*//p' "$1" | head -n 1
}

sps_pop3_parse_capabilities() {
    awk '
        /^C: CAPA$/ { in_capa=1; first=1; next }
        in_capa && /^C:/ { exit }
        in_capa && /^S: [+]OK/ && first { first=0; next }
        in_capa && /^S: -ERR/ { exit }
        in_capa && /^S: [.][[:space:]]*$/ { exit }
        in_capa && /^S: / { sub(/^S: /, ""); if (!seen[$0]++) print }
    ' "$1"
}

sps_pop3_extract_hostname() {
    local candidate
    candidate="$(sps_pop3_parse_banner "$1" | awk '{print $1}' | sed -E 's/^\[//; s/\]$//; s/[,:;]$//' | tr '[:upper:]' '[:lower:]')"
    case "$candidate" in ready | pop3 | service | mail) candidate="" ;; esac
    if [[ "$candidate" != *.* ]] || sps_is_ipv4 "$candidate" || ! sps_is_hostname "$candidate"; then candidate=""; fi
    printf '%s' "$candidate"
}

sps_pop3_join_lines() {
    awk 'NF { if (out != "") out=out "; "; out=out $0 } END { print out }'
}

sps_run_pop3_discovery_port() {
    local target="$1" port="$2" safe_target output_file transcript="" rc=0
    local banner capabilities auth_mechanisms pop3_hostname starttls=false artifact telnet_artifact="" certificate_artifact="" certificate_transport="" certificate_hostname=""
    safe_target="$(sanitize_name "$target")"
    output_file="pop3_${safe_target}_${port}.txt"

    if [[ "$port" == 995 ]]; then
        if ! sps_command_available openssl; then
            warn "POP3 discovery on port 995 skipped: OpenSSL is required for implicit TLS"
            record_module_status "pop3:${port}" "skipped" "openssl unavailable for implicit TLS"
            return 1
        fi
        if transcript="$(sps_pop3_tls_session "$target" "$port")"; then rc=0; else rc=$?; fi
    else
        if transcript="$(sps_pop3_plain_session "$target" "$port")"; then rc=0; else rc=$?; fi
    fi

    printf '%s\n' "$transcript" | sps_clean_tool_stream > "$output_file"
    if [[ "$port" != 995 ]] && sps_run_mail_telnet_banner_check "$target" "$port" pop3; then
        telnet_artifact="$MAIL_TELNET_BANNER_FILE"
    fi
    if ! sps_pop3_transcript_confirmed "$output_file"; then
        debug "Port $port did not produce a confirmed POP3 greeting and command response"
        [[ -s "$output_file" ]] && record_loot "pop3_unconfirmed_transcript" "$target:$port" "$output_file"
        record_module_status "pop3:${port}" "executed" "POP3 not confirmed; probe exit $rc"
        return 0
    fi

    POP3_SERVICE_CONFIRMED=true
    grep -Fqx "$port" "$POP3_CONFIRMED_FILE" 2> /dev/null || printf '%s\n' "$port" >> "$POP3_CONFIRMED_FILE"
    banner="$(sps_pop3_parse_banner "$output_file")"
    capabilities="$(sps_pop3_parse_capabilities "$output_file" | sps_pop3_join_lines)"
    auth_mechanisms="$(sps_pop3_parse_capabilities "$output_file" |
        awk 'toupper($1)=="SASL" { for (i=2; i<=NF; i++) if (!seen[toupper($i)]++) values[++n]=toupper($i) } END { for (i=1; i<=n; i++) printf "%s%s", (i>1 ? "," : ""), values[i] }')"
    grep -Eqi '^S: STLS([[:space:]]|$)' "$output_file" && starttls=true
    pop3_hostname="$(sps_pop3_extract_hostname "$output_file")"

    if [[ "$port" == 995 ]]; then
        certificate_transport=implicit
    elif [[ "$starttls" == true ]]; then
        certificate_transport=starttls
    fi
    if [[ -n "$certificate_transport" ]] &&
        sps_run_mail_certificate_check "$target" "$port" pop3 "$certificate_transport"; then
        certificate_artifact="$MAIL_CERT_PEM_FILE|$MAIL_CERT_METADATA_FILE"
        certificate_hostname="${MAIL_CERT_HOSTNAMES%%,*}"
        [[ -z "$pop3_hostname" && -n "$certificate_hostname" ]] && pop3_hostname="$certificate_hostname"
    fi

    if [[ -n "$pop3_hostname" ]]; then
        POP3_HOSTNAME="$pop3_hostname"
        printf '%s %s\n' "$target" "$pop3_hostname" >> "$HOSTS_FILE"
        printf '%s\n' "$pop3_hostname" >> "$DISCOVERED_HOSTS"
        sort -u "$HOSTS_FILE" -o "$HOSTS_FILE"
        sort -u "$DISCOVERED_HOSTS" -o "$DISCOVERED_HOSTS"
    fi

    artifact="$output_file${telnet_artifact:+|$telnet_artifact}${certificate_artifact:+|$certificate_artifact}"
    record_loot "pop3_discovery" "$target:$port${pop3_hostname:+ hostname=$pop3_hostname}" "$output_file"
    success "POP3 confirmed on port $port${pop3_hostname:+ ($pop3_hostname)}"
    [[ -n "$banner" ]] && info "POP3 banner: $banner"
    [[ -n "$capabilities" ]] && info "POP3 capabilities: $capabilities"
    [[ -n "$auth_mechanisms" ]] && info "POP3 SASL mechanisms: $auth_mechanisms"
    info "POP3 STLS advertised: $starttls"
    sps_record_finding \
        "POP3-SERVICE-${port}" "informational" "high" \
        "POP3 protocol confirmed on ${target}:${port}; banner=${banner:-unavailable}; capabilities=${capabilities:-unavailable}; SASL=${auth_mechanisms:-none advertised}; STLS=$starttls" \
        "TCP port $port open|POP3 +OK greeting|POP3 command response" "" \
        "discovery" "$artifact" \
        "Restrict POP3 listeners and advertised authentication methods to intended clients; prefer encrypted transport." \
        "Only greeting, CAPA/NOOP, and QUIT were used; no username, authentication, or mailbox command was attempted."
    record_module_status "pop3:${port}" "executed" \
        "confirmed; stls=$starttls; sasl=${auth_mechanisms:-none}; hostname=${pop3_hostname:-unknown}"
}

sps_run_pop3_discovery() {
    local target="$1" port found=false
    shift
    for port in "$@"; do
        case "$port" in
            110 | 995)
                if [[ "$found" != true ]]; then
                    sps_service_heading "POP3 MAIL RETRIEVAL" \
                        "Inspecting greetings, CAPA features, STLS support, certificate identity, and advertised authentication."
                fi
                found=true
                if [[ "$port" == 995 ]]; then
                    sps_service_endpoint "POP3S / TCP 995 - implicit TLS"
                else
                    sps_service_endpoint "POP3 / TCP 110 - STLS when advertised"
                fi
                sps_run_pop3_discovery_port "$target" "$port" || true
                ;;
        esac
    done
    [[ "$found" == true ]] || debug "POP3 discovery skipped: no POP3-family ports were open"
}
