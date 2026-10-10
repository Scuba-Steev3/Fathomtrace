#!/usr/bin/env bash

# Read-only IMAP discovery. Only CAPABILITY and LOGOUT are issued; the module
# never authenticates, selects a mailbox, or retrieves message metadata.

sps_imap_plain_session() {
    local target="$1" port="$2" query_timeout="${IMAP_QUERY_TIMEOUT:-5}"

    timeout "$query_timeout" bash -c '
        target="$1"
        port="$2"
        exec 7<>"/dev/tcp/${target}/${port}" || exit 1

        imap_read_line() {
            local line
            IFS= read -r line <&7 || return 1
            line="${line%$'\''\r'\''}"
            printf "S: %s\n" "$line"
            IMAP_LAST_LINE="$line"
        }

        imap_read_line || exit 2
        [[ "$IMAP_LAST_LINE" == "* OK"* || "$IMAP_LAST_LINE" == "* PREAUTH"* ]] || exit 2

        printf "C: a001 CAPABILITY\n"
        printf "a001 CAPABILITY\r\n" >&7
        while imap_read_line; do
            [[ "$IMAP_LAST_LINE" == "a001 OK"* ]] && break
            [[ "$IMAP_LAST_LINE" == "a001 NO"* || "$IMAP_LAST_LINE" == "a001 BAD"* ]] && exit 3
        done
        [[ "$IMAP_LAST_LINE" == "a001 OK"* ]] || exit 3

        printf "C: a002 LOGOUT\n"
        printf "a002 LOGOUT\r\n" >&7
        while imap_read_line; do
            [[ "$IMAP_LAST_LINE" == "a002 OK"* ]] && break
        done
    ' _ "$target" "$port"
}

sps_imap_tls_session() {
    local target="$1" port="$2" query_timeout="${IMAP_QUERY_TIMEOUT:-5}" sni_name=""
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
        coproc IMAP_TLS { openssl "${openssl_args[@]}" 2> /dev/null; }
        exec 7<&"${IMAP_TLS[0]}"
        exec 8>&"${IMAP_TLS[1]}"

        imap_read_line() {
            local line
            IFS= read -r line <&7 || return 1
            line="${line%$'\''\r'\''}"
            printf "S: %s\n" "$line"
            IMAP_LAST_LINE="$line"
        }

        imap_read_line || exit 2
        [[ "$IMAP_LAST_LINE" == "* OK"* || "$IMAP_LAST_LINE" == "* PREAUTH"* ]] || exit 2
        printf "C: a001 CAPABILITY\n"
        printf "a001 CAPABILITY\n" >&8
        while imap_read_line; do
            [[ "$IMAP_LAST_LINE" == "a001 OK"* ]] && break
            [[ "$IMAP_LAST_LINE" == "a001 NO"* || "$IMAP_LAST_LINE" == "a001 BAD"* ]] && exit 3
        done
        [[ "$IMAP_LAST_LINE" == "a001 OK"* ]] || exit 3
        printf "C: a002 LOGOUT\n"
        printf "a002 LOGOUT\n" >&8
        while imap_read_line; do
            [[ "$IMAP_LAST_LINE" == "a002 OK"* ]] && break
        done
        exec 8>&-
        wait "$IMAP_TLS_PID" 2> /dev/null || true
    ' _ "$target" "$port" "$sni_name"
}

sps_imap_transcript_confirmed() {
    local source="$1"
    awk '
        /^S: [*] (OK|PREAUTH)([[:space:]]|$)/ { greeting=1 }
        /^S: a001 OK([[:space:]]|$)/ { capability_ok=1 }
        END { exit !(greeting && capability_ok) }
    ' "$source"
}

sps_imap_parse_banner() {
    sed -n -E 's/^S: [*] (OK|PREAUTH)[[:space:]]*//p' "$1" | head -n 1
}

sps_imap_parse_capabilities() {
    local source="$1"
    {
        sed -n -E 's/^S: [*] CAPABILITY[[:space:]]+//p' "$source"
        sed -n -E 's/^S: [*] (OK|PREAUTH)[[:space:]]+\[CAPABILITY ([^]]+)\].*/\2/p' "$source"
    } | tr ' ' '\n' | awk 'NF && !seen[toupper($0)]++ {print toupper($0)}'
}

sps_imap_extract_hostname() {
    local source="$1" candidate=""
    candidate="$(sps_imap_parse_banner "$source" | tr ' ' '\n' |
        sed -E 's/^[[]//; s/[]].,:;]$//' |
        awk 'index($0, ".") && toupper($0) !~ /^IMAP[0-9]/ {print tolower($0); exit}')"
    if [[ -n "$candidate" ]] && { sps_is_ipv4 "$candidate" || ! sps_is_hostname "$candidate"; }; then candidate=""; fi
    printf '%s' "$candidate"
}

sps_imap_join_lines() {
    awk 'NF { if (out != "") out=out "; "; out=out $0 } END { print out }'
}

sps_imap_print_connection_help() {
    local target="$1" port="$2" starttls="$3" hostname="${4:-}"
    local sni_name="" display_command=""
    local -a command_args=(openssl s_client -connect "${target}:${port}")

    if [[ "$port" == 143 ]]; then
        if [[ "$starttls" != true ]]; then
            lightbulb "IMAP port 143 did not advertise STARTTLS; no OpenSSL upgrade command is suggested. Do not send credentials over cleartext."
            return 0
        fi
        command_args+=(-starttls imap)
    elif [[ "$port" != 993 ]]; then
        return 0
    fi

    if [[ -n "$hostname" && "$hostname" == *.* ]] && sps_is_hostname "$hostname"; then
        sni_name="$hostname"
    elif [[ -n "${TARGET_FQDN:-}" ]]; then
        sni_name="$TARGET_FQDN"
    elif ! sps_is_ipv4 "${ORIGINAL_TARGET:-$target}" && sps_is_hostname "${ORIGINAL_TARGET:-$target}"; then
        sni_name="${ORIGINAL_TARGET:-$target}"
    fi
    [[ -n "$sni_name" ]] && command_args+=(-servername "$sni_name")
    command_args+=(-crlf -quiet)
    display_command="${command_args[*]}"

    lightbulb "IMAP OpenSSL connection for port $port:"
    info "    $display_command"
    if [[ "${IMAP_HELP_REMINDERS_SHOWN:-false}" != true ]]; then
        lightbulb "IMAP commands require client tags; start with: a001 CAPABILITY"
        lightbulb "Close the session cleanly with: a002 LOGOUT"
        lightbulb "Do not submit authentication credentials until TLS is active, and avoid exposing passwords in recorded terminal sessions."
        lightbulb "For a self-signed certificate, compare the reported SHA-256 fingerprint and expected hostname before trusting the connection."
        IMAP_HELP_REMINDERS_SHOWN=true
    fi
}

sps_imap_quote_string() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '%s' "$value"
}

sps_imap_parse_list_line() {
    local line="$1" flags tail mailbox_name
    line="${line#S: }"
    [[ "$line" == '* LIST ('* ]] || return 1

    flags="${line#* LIST (}"
    [[ "$flags" == *') '* ]] || return 1
    flags="${flags%%)*}"
    tail="${line#*) }"
    [[ "$tail" == *' '* ]] || return 1
    mailbox_name="${tail#* }"
    if [[ "$mailbox_name" == \"*\" && ${#mailbox_name} -ge 2 ]]; then
        mailbox_name="${mailbox_name:1:${#mailbox_name}-2}"
        mailbox_name="${mailbox_name//\\\"/\"}"
        mailbox_name="${mailbox_name//\\\\/\\}"
    fi
    [[ -n "$mailbox_name" && ! "$mailbox_name" =~ [[:cntrl:]] ]] || return 1
    printf '%s\t%s\n' "$flags" "$mailbox_name"
}

sps_imap_mailbox_is_selectable() {
    local normalized_flags="${1//\\/}"
    [[ "${normalized_flags,,}" != *noselect* ]]
}

sps_imap_login_session() {
    local target="$1" port="$2" transport="$3" username="$4" password="$5" sni_name="${6:-}"
    local query_timeout="${IMAP_AUTH_TIMEOUT:-}" escaped_user escaped_password escaped_mailbox line="" parsed_list=""
    local response_seen=false login_succeeded=false mailbox_selected=false fetch_completed=false
    local tls_pid openssl_rc=0 exists=0 fetch_start=1 fetch_count=0 remaining_messages=0
    local tag_number=3 examine_tag="" fetch_tag="" listed_flags="" listed_mailbox="" current_mailbox="" existing_mailbox="" mailbox_known=false
    local mailboxes_examined=0 mailboxes_failed=0 messages_exported=0
    local enumerate="${ENABLE_IMAP_ENUM:-false}" dump="${ENABLE_IMAP_DUMP:-false}"
    local mailbox="${IMAP_MAILBOX:-INBOX}" max_messages="${IMAP_MAX_MESSAGES:-25}"
    local -a openssl_args=(s_client -quiet -crlf -connect "${target}:${port}")
    local -a mailbox_queue=()

    if [[ -z "$query_timeout" ]]; then
        [[ "$dump" == true ]] && query_timeout=60 || query_timeout=10
    fi
    [[ "$max_messages" =~ ^[0-9]+$ && "$max_messages" -gt 0 ]] || max_messages=25
    remaining_messages="$max_messages"
    [[ "$transport" == starttls ]] && openssl_args+=(-starttls imap)
    [[ -n "$sni_name" ]] && openssl_args+=(-servername "$sni_name")
    escaped_user="$(sps_imap_quote_string "$username")"
    escaped_password="$(sps_imap_quote_string "$password")"
    mailbox_queue+=("$mailbox")

    coproc IMAP_LOGIN_TLS { timeout "$query_timeout" openssl "${openssl_args[@]}" 2> /dev/null; }
    tls_pid="$IMAP_LOGIN_TLS_PID"
    exec 7<&"${IMAP_LOGIN_TLS[0]}"
    exec 8>&"${IMAP_LOGIN_TLS[1]}"

    printf 'C: a001 LOGIN "%s" "[REDACTED]"\n' "$escaped_user"
    printf 'a001 LOGIN "%s" "%s"\n' "$escaped_user" "$escaped_password" >&8
    while IFS= read -r line <&7; do
        line="${line%$'\r'}"
        printf 'S: %s\n' "$line"
        case "$line" in
            "a001 OK"*) response_seen=true; login_succeeded=true; break ;;
            "a001 NO"* | "a001 BAD"*) response_seen=true; break ;;
        esac
    done

    if [[ "$login_succeeded" == true && "$enumerate" == true ]]; then
        printf '%s\n' '--- IMAP MAILBOX ENUMERATION ---'
        printf 'C: a002 LIST "" "*"\n'
        printf 'a002 LIST "" "*"\n' >&8 2> /dev/null || true
        while IFS= read -r line <&7; do
            line="${line%$'\r'}"
            printf 'S: %s\n' "$line"
            if parsed_list="$(sps_imap_parse_list_line "$line" 2> /dev/null)"; then
                IFS=$'\t' read -r listed_flags listed_mailbox <<< "$parsed_list"
                if sps_imap_mailbox_is_selectable "$listed_flags"; then
                    mailbox_known=false
                    for existing_mailbox in "${mailbox_queue[@]}"; do
                        if [[ "$existing_mailbox" == "$listed_mailbox" ]]; then
                            mailbox_known=true
                            break
                        fi
                    done
                    if [[ "$mailbox_known" != true ]]; then
                        mailbox_queue+=("$listed_mailbox")
                    fi
                fi
            fi
            [[ "$line" == "a002 OK"* || "$line" == "a002 NO"* || "$line" == "a002 BAD"* ]] && break
        done
    fi

    if [[ "$login_succeeded" == true && "$dump" == true ]]; then
        for current_mailbox in "${mailbox_queue[@]}"; do
            mailbox_selected=false
            fetch_completed=false
            exists=0
            printf -v examine_tag 'a%03d' "$tag_number"
            tag_number=$((tag_number + 1))
            escaped_mailbox="$(sps_imap_quote_string "$current_mailbox")"
            printf '%s\n' "--- IMAP READ-ONLY MESSAGE EXPORT: $current_mailbox ---"
            printf 'C: %s EXAMINE "%s"\n' "$examine_tag" "$escaped_mailbox"
            printf '%s EXAMINE "%s"\n' "$examine_tag" "$escaped_mailbox" >&8 2> /dev/null || true
            while IFS= read -r line <&7; do
                line="${line%$'\r'}"
                printf 'S: %s\n' "$line"
                if [[ "$line" =~ ^\*[[:space:]]+([0-9]+)[[:space:]]+EXISTS ]]; then
                    exists="${BASH_REMATCH[1]}"
                fi
                case "$line" in
                    "$examine_tag OK"*) mailbox_selected=true; break ;;
                    "$examine_tag NO"* | "$examine_tag BAD"*) break ;;
                esac
            done

            if [[ "$mailbox_selected" != true ]]; then
                mailboxes_failed=$((mailboxes_failed + 1))
                printf 'I: mailbox "%s" could not be examined; continuing\n' "$current_mailbox"
                continue
            fi

            mailboxes_examined=$((mailboxes_examined + 1))
            printf 'I: mailbox "%s" examined read-only (%s message(s))\n' "$current_mailbox" "$exists"
            if ((exists == 0)); then
                printf 'I: mailbox "%s" contains no messages; continuing\n' "$current_mailbox"
                continue
            fi
            if ((remaining_messages == 0)); then
                printf 'I: global message export limit reached; mailbox "%s" was examined without fetching\n' "$current_mailbox"
                continue
            fi

            fetch_count="$exists"
            ((fetch_count > remaining_messages)) && fetch_count="$remaining_messages"
            fetch_start=$((exists - fetch_count + 1))
            printf -v fetch_tag 'a%03d' "$tag_number"
            tag_number=$((tag_number + 1))
            printf 'C: %s FETCH %s:%s (UID BODY.PEEK[])\n' "$fetch_tag" "$fetch_start" "$exists"
            printf '%s FETCH %s:%s (UID BODY.PEEK[])\n' "$fetch_tag" "$fetch_start" "$exists" >&8 2> /dev/null || true
            while IFS= read -r line <&7; do
                line="${line%$'\r'}"
                printf 'S: %s\n' "$line"
                case "$line" in
                    "$fetch_tag OK"*) fetch_completed=true; break ;;
                    "$fetch_tag NO"* | "$fetch_tag BAD"*) break ;;
                esac
            done
            if [[ "$fetch_completed" == true ]]; then
                messages_exported=$((messages_exported + fetch_count))
                remaining_messages=$((remaining_messages - fetch_count))
                printf 'I: exported %s message(s) from mailbox "%s"\n' "$fetch_count" "$current_mailbox"
            else
                printf 'I: message export failed for mailbox "%s"; continuing\n' "$current_mailbox"
            fi
        done

        if ((mailboxes_examined > 0)); then
            printf 'I: IMAP dump completed: mailboxes examined=%s; mailboxes failed=%s; messages exported=%s; limit=%s\n' \
                "$mailboxes_examined" "$mailboxes_failed" "$messages_exported" "$max_messages"
        else
            printf 'I: IMAP dump failed: no mailbox could be examined read-only\n'
        fi
    fi

    printf 'C: a999 LOGOUT\n'
    printf 'a999 LOGOUT\n' >&8 2> /dev/null || true
    while IFS= read -r line <&7; do
        line="${line%$'\r'}"
        printf 'S: %s\n' "$line"
        [[ "$line" == "a999 OK"* || "$line" == "a999 NO"* || "$line" == "a999 BAD"* ]] && break
    done
    exec 8>&-
    exec 7<&-
    wait "$tls_pid" 2> /dev/null || openssl_rc=$?
    [[ "$response_seen" == true ]] && return 0
    ((openssl_rc != 0)) && return "$openssl_rc"
    return 1
}

sps_imap_login_succeeded() {
    grep -Eq '^S: a001 OK([[:space:]]|$)' "$1"
}

sps_imap_login_rejected() {
    grep -Eq '^S: a001 (NO|BAD)([[:space:]]|$)' "$1"
}

sps_imap_parse_list_mailboxes() {
    local line parsed
    while IFS= read -r line; do
        if parsed="$(sps_imap_parse_list_line "$line" 2> /dev/null)"; then
            printf '%s\n' "$parsed"
        fi
    done < "$1"
}

sps_set_imap_auth_state() {
    IMAP_AUTH_STATUS="$1"
    IMAP_AUTH_REASON="$2"
    [[ "$IMAP_AUTH_STATUS" == success ]] && IMAP_AUTH_OK=true || IMAP_AUTH_OK=false
}

sps_imap_auth_success_text() {
    printf 'IMAP credentials accepted for %s on port %s' \
        "${AUTH_USER:-unknown}" "${IMAP_AUTH_PORT:-unknown}"
}

sps_imap_dump_has_exported_messages() {
    [[ "${IMAP_DUMP_MESSAGES_EXPORTED:-0}" =~ ^[0-9]+$ ]] &&
        ((IMAP_DUMP_MESSAGES_EXPORTED > 0))
}

sps_imap_print_attack_path_details() {
    local count="${IMAP_DUMP_MESSAGES_EXPORTED:-0}"
    local summary="${IMAP_DUMP_SUMMARY:-messages exported=$count}"
    local loot_path="${IMAP_DUMP_LOOT_PATH:-unavailable}"
    sps_imap_dump_has_exported_messages || return 0

    ATTACK_PATHS+=("Authenticated IMAP message content exported ($count message(s))")
    success "IMAP read-only multi-mailbox export completed: $summary"
    finding "Attack Path: Authenticated IMAP access exposed $count message(s) for offline review"
    note "Protected message loot: $loot_path"
    lightbulb "Next step: review the exported messages for sender and recipient identities, internal hostnames and domains, URLs, password-reset workflows, exposed secrets, and operational context that may identify additional authorized targets."
    lightbulb "Handling reminder: treat the export as sensitive, preserve its permissions and integrity, and securely delete it when the authorized retention period ends."
}

sps_run_imap_auth_check() {
    local target="$1" port="" transport="" hostname="${IMAP_AUTH_HOSTNAME:-${IMAP_HOSTNAME:-}}" sni_name=""
    local safe_target safe_mailbox output_file transcript="" rc=0 artifact_kind="imap_credential_validation"
    local mailbox_file="" mailbox_count=0 session_timeout="${IMAP_AUTH_TIMEOUT:-}" dump_summary=""
    local -a command_args=()

    IMAP_AUTH_PORT=""
    IMAP_AUTH_TRANSPORT=""
    IMAP_DUMP_MESSAGES_EXPORTED=0
    IMAP_DUMP_MAILBOXES_EXAMINED=0
    IMAP_DUMP_MAILBOXES_FAILED=0
    IMAP_DUMP_SUMMARY=""
    IMAP_DUMP_LOOT_PATH=""
    sps_set_imap_auth_state skipped "explicit credentials were not supplied"
    if [[ "${CREDS_PROVIDED:-false}" != true || -z "${AUTH_USER:-}" || -z "${AUTH_PASS:-}" ]]; then
        record_module_status "imap-auth" "skipped" "$IMAP_AUTH_REASON"
        return 0
    fi
    if [[ "$AUTH_USER" =~ [[:cntrl:]] || "$AUTH_PASS" =~ [[:cntrl:]] ]]; then
        sps_set_imap_auth_state skipped "credentials contain characters that cannot be safely encoded as an IMAP quoted string"
        warn "IMAP credential validation skipped: $IMAP_AUTH_REASON"
        record_module_status "imap-auth" "skipped" "$IMAP_AUTH_REASON"
        return 0
    fi
    if [[ "${ENABLE_IMAP_DUMP:-false}" == true && "${IMAP_MAILBOX:-INBOX}" =~ [[:cntrl:]] ]]; then
        sps_set_imap_auth_state skipped "the selected mailbox contains characters that cannot be safely encoded"
        warn "IMAP message export skipped: $IMAP_AUTH_REASON"
        record_module_status "imap-auth" "skipped" "$IMAP_AUTH_REASON"
        return 0
    fi
    if ! sps_command_available openssl; then
        sps_set_imap_auth_state skipped "OpenSSL is unavailable"
        warn "IMAP credential validation skipped: $IMAP_AUTH_REASON"
        record_module_status "imap-auth" "skipped" "$IMAP_AUTH_REASON"
        return 0
    fi

    if [[ "${IMAP_IMPLICIT_TLS_AVAILABLE:-false}" == true ]]; then
        port=993
        transport=implicit
    elif [[ "${IMAP_STARTTLS_AVAILABLE:-false}" == true ]]; then
        port=143
        transport=starttls
    else
        sps_set_imap_auth_state skipped "no protocol-confirmed encrypted IMAP transport is available"
        warn "IMAP credential validation skipped: $IMAP_AUTH_REASON"
        record_module_status "imap-auth" "skipped" "$IMAP_AUTH_REASON"
        return 0
    fi
    IMAP_AUTH_PORT="$port"
    IMAP_AUTH_TRANSPORT="$transport"

    if [[ -n "$hostname" && "$hostname" == *.* ]] && sps_is_hostname "$hostname"; then
        sni_name="$hostname"
    elif [[ -n "${TARGET_FQDN:-}" ]]; then
        sni_name="$TARGET_FQDN"
    elif ! sps_is_ipv4 "${ORIGINAL_TARGET:-$target}" && sps_is_hostname "${ORIGINAL_TARGET:-$target}"; then
        sni_name="${ORIGINAL_TARGET:-$target}"
    fi

    if [[ -z "$session_timeout" ]]; then
        [[ "${ENABLE_IMAP_DUMP:-false}" == true ]] && session_timeout=60 || session_timeout=10
    fi
    command_args=(timeout "$session_timeout" openssl s_client -quiet -crlf -connect "${target}:${port}")
    [[ "$transport" == starttls ]] && command_args+=(-starttls imap)
    [[ -n "$sni_name" ]] && command_args+=(-servername "$sni_name")
    if declare -F record_command_argv > /dev/null; then
        record_command_argv "IMAP" "Single encrypted IMAP credential validation; password supplied over the TLS session and not recorded" "${command_args[@]}"
    fi

    info "Testing one encrypted IMAP login for $AUTH_USER on port $port ($transport TLS); password is redacted"
    if transcript="$(sps_imap_login_session "$target" "$port" "$transport" "$AUTH_USER" "$AUTH_PASS" "$sni_name")"; then
        rc=0
    else
        rc=$?
    fi
    # Force password removal even when --show-secrets is enabled. Authentication
    # transcripts should never persist the supplied secret.
    transcript="${transcript//"$AUTH_PASS"/[REDACTED]}"
    safe_target="$(sanitize_name "$target")"
    if [[ "${ENABLE_IMAP_DUMP:-false}" == true ]]; then
        safe_mailbox="$(sanitize_name "${IMAP_MAILBOX:-INBOX}")"
        mkdir -p "${LOOT_DIR:-loot}"
        output_file="${LOOT_DIR:-loot}/imap_mail_dump_${safe_target}_${port}_${safe_mailbox}.txt"
        artifact_kind="imap_email_dump"
    elif [[ "${ENABLE_IMAP_ENUM:-false}" == true ]]; then
        output_file="imap_mailbox_enum_${safe_target}_${port}.txt"
        artifact_kind="imap_mailbox_enumeration"
    else
        output_file="imap_auth_${safe_target}_${port}.txt"
    fi
    printf '%s\n' "$transcript" | sps_clean_tool_stream > "$output_file"
    record_loot "$artifact_kind" "$target:$port user=$AUTH_USER transport=$transport" "$output_file"

    if sps_imap_login_succeeded "$output_file"; then
        sps_set_imap_auth_state success "IMAP accepted the supplied credentials"
        success "$(sps_imap_auth_success_text)"
        if [[ "${ENABLE_IMAP_ENUM:-false}" == true ]]; then
            mailbox_file="${PARSED_DIR:-.}/imap_mailboxes_${safe_target}_${port}.txt"
            sps_imap_parse_list_mailboxes "$output_file" > "$mailbox_file"
            mailbox_count="$(awk 'NF { count++ } END { print count+0 }' "$mailbox_file")"
            if grep -Eq '^S: a002 OK([[:space:]]|$)' "$output_file"; then
                success "IMAP mailbox enumeration completed: $mailbox_count mailbox(es)"
                while IFS=$'\t' read -r flags mailbox_name; do
                    [[ -n "$mailbox_name" ]] && info "IMAP mailbox: $mailbox_name${flags:+ ($flags)}"
                done < "$mailbox_file"
                record_loot "imap_mailbox_list" "$target:$port user=$AUTH_USER count=$mailbox_count" "$mailbox_file"
                record_module_status "imap-enum" "executed" "listed $mailbox_count mailbox(es)"
            else
                warn "IMAP login succeeded, but mailbox enumeration did not complete"
                record_module_status "imap-enum" "failed" "LIST command did not return tagged OK"
            fi
        fi
        if [[ "${ENABLE_IMAP_DUMP:-false}" == true ]]; then
            dump_summary="$(sed -n 's/^I: IMAP dump completed: //p' "$output_file" | tail -n 1)"
            if [[ -n "$dump_summary" ]]; then
                IMAP_DUMP_SUMMARY="$dump_summary"
                if [[ "$dump_summary" =~ mailboxes[[:space:]]examined=([0-9]+) ]]; then
                    IMAP_DUMP_MAILBOXES_EXAMINED="${BASH_REMATCH[1]}"
                fi
                if [[ "$dump_summary" =~ mailboxes[[:space:]]failed=([0-9]+) ]]; then
                    IMAP_DUMP_MAILBOXES_FAILED="${BASH_REMATCH[1]}"
                fi
                if [[ "$dump_summary" =~ messages[[:space:]]exported=([0-9]+) ]]; then
                    IMAP_DUMP_MESSAGES_EXPORTED="${BASH_REMATCH[1]}"
                fi
                if [[ "$output_file" == /* ]]; then
                    IMAP_DUMP_LOOT_PATH="$output_file"
                elif [[ -n "${ARTIFACT_ROOT:-}" ]]; then
                    IMAP_DUMP_LOOT_PATH="${ARTIFACT_ROOT%/}/$output_file"
                else
                    IMAP_DUMP_LOOT_PATH="${PWD%/}/$output_file"
                fi
                success "IMAP read-only multi-mailbox export completed: $dump_summary"
                sps_record_finding \
                    "IMAP-MESSAGE-EXPORT" "informational" "confirmed" \
                    "Read-only IMAP export examined selectable mailboxes on ${target}:${port}, starting with ${IMAP_MAILBOX:-INBOX}; ${dump_summary}. Messages were requested with BODY.PEEK[]." \
                    "Encrypted IMAP authentication accepted|explicit --imap-dump authorization|LIST results filtered for selectable mailboxes|mailboxes opened with EXAMINE" "" \
                    "authenticated-read" "$output_file" \
                    "Limit mailbox access to authorized users, enforce MFA or application-specific credentials where supported, and monitor bulk mail access." \
                    "EXAMINE and BODY.PEEK[] were used to avoid changing message flags; securely delete the protected export when retention ends."
                record_module_status "imap-dump" "executed" "preferred-mailbox=${IMAP_MAILBOX:-INBOX}; $dump_summary"
            else
                warn "IMAP login succeeded, but no listed mailbox could be examined read-only"
                record_module_status "imap-dump" "failed" "no mailbox returned a tagged OK response to EXAMINE"
            fi
        fi
        local auth_evidence="Encrypted IMAP authentication succeeded for ${AUTH_USER} on ${target}:${port}."
        local auth_cleanup="Exactly one login was performed and the session ended with LOGOUT."
        if [[ "${ENABLE_IMAP_DUMP:-false}" == true ]]; then
            auth_evidence+=" Explicit read-only mailbox export was requested; ${IMAP_MAILBOX:-INBOX} was examined first, followed by other selectable LIST results."
            auth_cleanup+=" EXAMINE and BODY.PEEK[] avoided mailbox and message-flag changes."
        elif [[ "${ENABLE_IMAP_ENUM:-false}" == true ]]; then
            auth_evidence+=" Mailboxes were listed, but none was selected."
        else
            auth_evidence+=" No mailbox was selected and no message content was accessed."
        fi
        sps_record_finding \
            "IMAP-AUTHENTICATION" "informational" "confirmed" \
            "$auth_evidence" \
            "Confirmed IMAP service|encrypted transport|explicit credentials supplied|tagged LOGIN accepted" "" \
            "active-authentication" "$output_file" \
            "Review whether the account requires IMAP access, enforce MFA or application-specific credentials where supported, and monitor mail authentication events." \
            "$auth_cleanup"
        record_module_status "imap-auth" "executed" "$IMAP_AUTH_REASON; port=$port; transport=$transport"
        return 0
    fi
    if sps_imap_login_rejected "$output_file"; then
        sps_set_imap_auth_state failure "IMAP rejected the supplied credentials"
        warn "$IMAP_AUTH_REASON for $AUTH_USER on port $port"
        record_module_status "imap-auth" "executed" "$IMAP_AUTH_REASON; port=$port; transport=$transport"
        return 0
    fi

    if ((rc == 124)); then
        sps_set_imap_auth_state skipped "IMAP authentication timed out; credential validity is inconclusive"
    else
        sps_set_imap_auth_state skipped "IMAP authentication could not be completed; credential validity is inconclusive"
    fi
    warn "$IMAP_AUTH_REASON"
    record_module_status "imap-auth" "skipped" "$IMAP_AUTH_REASON (session exit $rc)"
    return 0
}

sps_run_imap_discovery_port() {
    local target="$1" port="$2" safe_target output_file transcript="" rc=0
    local banner capabilities auth_mechanisms imap_hostname starttls=false artifact telnet_artifact="" certificate_artifact="" certificate_transport="" certificate_hostname=""
    safe_target="$(sanitize_name "$target")"
    output_file="imap_${safe_target}_${port}.txt"

    if [[ "$port" == 993 ]]; then
        if ! sps_command_available openssl; then
            warn "IMAP discovery on port 993 skipped: OpenSSL is required for implicit TLS"
            record_module_status "imap:${port}" "skipped" "openssl unavailable for implicit TLS"
            return 1
        fi
        if transcript="$(sps_imap_tls_session "$target" "$port")"; then rc=0; else rc=$?; fi
    else
        if transcript="$(sps_imap_plain_session "$target" "$port")"; then rc=0; else rc=$?; fi
    fi

    printf '%s\n' "$transcript" | sps_clean_tool_stream > "$output_file"
    if [[ "$port" != 993 ]] && sps_run_mail_telnet_banner_check "$target" "$port" imap; then
        telnet_artifact="$MAIL_TELNET_BANNER_FILE"
    fi
    if ! sps_imap_transcript_confirmed "$output_file"; then
        debug "Port $port did not produce a confirmed IMAP greeting and CAPABILITY response"
        [[ -s "$output_file" ]] && record_loot "imap_unconfirmed_transcript" "$target:$port" "$output_file"
        record_module_status "imap:${port}" "executed" "IMAP not confirmed; probe exit $rc"
        return 0
    fi

    IMAP_SERVICE_CONFIRMED=true
    grep -Fqx "$port" "$IMAP_CONFIRMED_FILE" 2> /dev/null || printf '%s\n' "$port" >> "$IMAP_CONFIRMED_FILE"
    banner="$(sps_imap_parse_banner "$output_file")"
    capabilities="$(sps_imap_parse_capabilities "$output_file" | sps_imap_join_lines)"
    auth_mechanisms="$(sps_imap_parse_capabilities "$output_file" |
        sed -n -E 's/^AUTH=//p' |
        awk 'NF && !seen[$0]++ { values[++n]=$0 } END { for (i=1; i<=n; i++) printf "%s%s", (i>1 ? "," : ""), values[i] }')"
    sps_imap_parse_capabilities "$output_file" | grep -Fqx STARTTLS && starttls=true
    imap_hostname="$(sps_imap_extract_hostname "$output_file")"

    if [[ "$port" == 993 ]]; then
        certificate_transport=implicit
    elif [[ "$starttls" == true ]]; then
        certificate_transport=starttls
    fi
    if [[ -n "$certificate_transport" ]] &&
        sps_run_mail_certificate_check "$target" "$port" imap "$certificate_transport"; then
        certificate_artifact="$MAIL_CERT_PEM_FILE|$MAIL_CERT_METADATA_FILE"
        certificate_hostname="${MAIL_CERT_HOSTNAMES%%,*}"
        [[ -z "$imap_hostname" && -n "$certificate_hostname" ]] && imap_hostname="$certificate_hostname"
    fi

    if [[ -n "$imap_hostname" ]]; then
        IMAP_HOSTNAME="$imap_hostname"
        IMAP_AUTH_HOSTNAME="$imap_hostname"
        printf '%s %s\n' "$target" "$imap_hostname" >> "$HOSTS_FILE"
        printf '%s\n' "$imap_hostname" >> "$DISCOVERED_HOSTS"
        sort -u "$HOSTS_FILE" -o "$HOSTS_FILE"
        sort -u "$DISCOVERED_HOSTS" -o "$DISCOVERED_HOSTS"
    fi

    [[ "$port" == 993 ]] && IMAP_IMPLICIT_TLS_AVAILABLE=true
    [[ "$port" == 143 && "$starttls" == true ]] && IMAP_STARTTLS_AVAILABLE=true

    artifact="$output_file${telnet_artifact:+|$telnet_artifact}${certificate_artifact:+|$certificate_artifact}"
    record_loot "imap_discovery" "$target:$port${imap_hostname:+ hostname=$imap_hostname}" "$output_file"
    success "IMAP confirmed on port $port${imap_hostname:+ ($imap_hostname)}"
    [[ -n "$banner" ]] && info "IMAP banner: $banner"
    [[ -n "$capabilities" ]] && info "IMAP capabilities: $capabilities"
    [[ -n "$auth_mechanisms" ]] && info "IMAP authentication mechanisms: $auth_mechanisms"
    info "IMAP STARTTLS advertised: $starttls"
    sps_imap_print_connection_help "$target" "$port" "$starttls" "$imap_hostname"
    sps_record_finding \
        "IMAP-SERVICE-${port}" "informational" "high" \
        "IMAP protocol confirmed on ${target}:${port}; banner=${banner:-unavailable}; capabilities=${capabilities:-unavailable}; AUTH=${auth_mechanisms:-none advertised}; STARTTLS=$starttls" \
        "TCP port $port open|IMAP OK/PREAUTH greeting|Tagged CAPABILITY success" "" \
        "discovery" "$artifact" \
        "Restrict IMAP listeners and advertised authentication methods to intended clients; prefer encrypted transport." \
        "Only greeting, CAPABILITY, and LOGOUT were used; no authentication, mailbox selection, or message command was attempted."
    record_module_status "imap:${port}" "executed" \
        "confirmed; starttls=$starttls; auth=${auth_mechanisms:-none}; hostname=${imap_hostname:-unknown}"
}

sps_run_imap_discovery() {
    local target="$1" port found=false
    shift
    IMAP_IMPLICIT_TLS_AVAILABLE=false
    IMAP_STARTTLS_AVAILABLE=false
    IMAP_AUTH_HOSTNAME=""
    for port in "$@"; do
        case "$port" in
            143 | 993)
                if [[ "$found" != true ]]; then
                    sps_service_heading "IMAP MAIL ACCESS" \
                        "Inspecting greetings, CAPABILITY features, TLS support, certificate identity, and encrypted login access."
                fi
                found=true
                if [[ "$port" == 993 ]]; then
                    sps_service_endpoint "IMAPS / TCP 993 - implicit TLS"
                else
                    sps_service_endpoint "IMAP / TCP 143 - STARTTLS when advertised"
                fi
                sps_run_imap_discovery_port "$target" "$port" || true
                ;;
        esac
    done
    if [[ "$found" == true ]]; then
        if [[ "${CREDS_PROVIDED:-false}" == true ]]; then
            sps_service_endpoint "IMAP AUTHENTICATION AND MAILBOX ACCESS"
        fi
        sps_run_imap_auth_check "$target"
    else
        debug "IMAP discovery skipped: no IMAP-family ports were open"
    fi
}
