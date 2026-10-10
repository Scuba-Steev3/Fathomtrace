#!/usr/bin/env bash

# Optional cleartext mail-service banner capture via the local telnet client.
# Keeping stdin open briefly allows the remote greeting to arrive; no protocol
# command, credential, or payload is sent on this connection.

sps_mail_certificate_sni_name() {
    local target="$1"
    if [[ -n "${TARGET_FQDN:-}" ]]; then
        printf '%s' "$TARGET_FQDN"
    elif ! sps_is_ipv4 "${ORIGINAL_TARGET:-$target}" && sps_is_hostname "${ORIGINAL_TARGET:-$target}"; then
        printf '%s' "${ORIGINAL_TARGET:-$target}"
    fi
}

sps_mail_fetch_leaf_certificate() {
    local target="$1" port="$2" protocol="${3,,}" transport="$4" sni_name="${5:-}"
    local timeout_seconds="${MAIL_CERT_TIMEOUT:-8}"
    local -a openssl_args=(s_client -connect "${target}:${port}" -showcerts)

    [[ "$transport" == starttls ]] && openssl_args+=(-starttls "$protocol")
    [[ -n "$sni_name" ]] && openssl_args+=(-servername "$sni_name")

    timeout "$timeout_seconds" openssl "${openssl_args[@]}" < /dev/null 2> /dev/null |
        awk '
            /-----BEGIN CERTIFICATE-----/ { capture=1 }
            capture { print }
            /-----END CERTIFICATE-----/ { exit }
        '
}

sps_mail_certificate_is_valid() {
    openssl x509 -in "$1" -noout > /dev/null 2>&1
}

sps_mail_describe_certificate() {
    local pem_file="$1" san_output=""
    openssl x509 -in "$pem_file" -noout -subject -issuer -nameopt RFC2253
    openssl x509 -in "$pem_file" -noout -dates -serial -fingerprint -sha256
    san_output="$(openssl x509 -in "$pem_file" -noout -ext subjectAltName 2> /dev/null || true)"
    if [[ -n "$san_output" && "$san_output" != *"No extensions in certificate"* ]]; then
        printf '%s\n' "$san_output"
    else
        printf 'subjectAltName=none\n'
    fi
}

sps_mail_parse_certificate_metadata() {
    local metadata_file="$1"

    MAIL_CERT_SUBJECT="$(sed -n 's/^subject=//p' "$metadata_file" | head -n 1)"
    MAIL_CERT_ISSUER="$(sed -n 's/^issuer=//p' "$metadata_file" | head -n 1)"
    MAIL_CERT_NOT_BEFORE="$(sed -n 's/^notBefore=//p' "$metadata_file" | head -n 1)"
    MAIL_CERT_NOT_AFTER="$(sed -n 's/^notAfter=//p' "$metadata_file" | head -n 1)"
    MAIL_CERT_SERIAL="$(sed -n 's/^serial=//p' "$metadata_file" | head -n 1)"
    MAIL_CERT_SHA256="$(sed -n -E 's/^(sha256|SHA256) Fingerprint=//p' "$metadata_file" | head -n 1)"
    MAIL_CERT_CN="$(printf '%s\n' "$MAIL_CERT_SUBJECT" | tr ',' '\n' |
        sed -n -E 's/^[[:space:]]*CN[[:space:]]*=[[:space:]]*//p' | head -n 1 | tr '[:upper:]' '[:lower:]')"
    MAIL_CERT_SANS="$({ grep -Eo 'DNS:[^,[:space:]]+' "$metadata_file" 2> /dev/null || true; } |
        sed 's/^DNS://' | tr '[:upper:]' '[:lower:]' | awk 'NF && !seen[$0]++ { values[++n]=$0 } END { for (i=1; i<=n; i++) printf "%s%s", (i>1 ? "," : ""), values[i] }')"
}

sps_mail_record_certificate_hostnames() {
    local target="$1" hostname
    local candidates=""

    if [[ -n "$MAIL_CERT_SANS" ]]; then
        candidates+="$(printf '%s\n' "$MAIL_CERT_SANS" | tr ',' '\n')"$'\n'
    fi
    [[ -n "$MAIL_CERT_CN" ]] && candidates+="$MAIL_CERT_CN"$'\n'

    MAIL_CERT_HOSTNAMES=""
    while IFS= read -r hostname; do
        [[ -n "$hostname" && "$hostname" == *.* && "$hostname" != \*.* ]] || continue
        sps_is_ipv4 "$hostname" && continue
        sps_is_hostname "$hostname" || continue
        printf '%s %s\n' "$target" "$hostname" >> "$HOSTS_FILE"
        printf '%s\n' "$hostname" >> "$DISCOVERED_HOSTS"
        if [[ ",${MAIL_CERT_HOSTNAMES}," != *",${hostname},"* ]]; then
            MAIL_CERT_HOSTNAMES="${MAIL_CERT_HOSTNAMES:+$MAIL_CERT_HOSTNAMES,}$hostname"
        fi
    done <<< "$candidates"

    sort -u "$HOSTS_FILE" -o "$HOSTS_FILE"
    sort -u "$DISCOVERED_HOSTS" -o "$DISCOVERED_HOSTS"
}

sps_run_mail_certificate_check() {
    local target="$1" port="$2" protocol="${3,,}" transport="$4"
    local protocol_upper safe_target sni_name evidence
    local -a command_args=(openssl s_client -connect "${target}:${port}" -showcerts)

    MAIL_CERT_PEM_FILE=""
    MAIL_CERT_METADATA_FILE=""
    MAIL_CERT_SUBJECT=""
    MAIL_CERT_ISSUER=""
    MAIL_CERT_CN=""
    MAIL_CERT_SANS=""
    MAIL_CERT_HOSTNAMES=""
    MAIL_CERT_NOT_BEFORE=""
    MAIL_CERT_NOT_AFTER=""
    MAIL_CERT_SERIAL=""
    MAIL_CERT_SHA256=""

    protocol_upper="${protocol^^}"
    case "$protocol:$transport" in
        smtp:implicit | smtp:starttls | pop3:implicit | pop3:starttls | imap:implicit | imap:starttls) ;;
        *)
            debug "Certificate capture skipped for unsupported mode $protocol:$transport"
            return 2
            ;;
    esac

    if ! sps_command_available openssl; then
        debug "$protocol_upper certificate capture skipped: OpenSSL unavailable"
        record_module_status "certificate:${protocol}:${port}" "skipped" "openssl unavailable"
        return 1
    fi

    safe_target="$(sanitize_name "$target")"
    MAIL_CERT_PEM_FILE="tls_${protocol}_${safe_target}_${port}.pem"
    MAIL_CERT_METADATA_FILE="tls_${protocol}_${safe_target}_${port}.txt"
    sni_name="$(sps_mail_certificate_sni_name "$target")"

    [[ "$transport" == starttls ]] && command_args+=(-starttls "$protocol")
    [[ -n "$sni_name" ]] && command_args+=(-servername "$sni_name")
    if declare -F record_command_argv > /dev/null; then
        record_command_argv "Discovery" "$protocol_upper TLS certificate capture" "${command_args[@]}"
    fi

    sps_mail_fetch_leaf_certificate "$target" "$port" "$protocol" "$transport" "$sni_name" > "$MAIL_CERT_PEM_FILE" || true
    if [[ ! -s "$MAIL_CERT_PEM_FILE" ]] || ! sps_mail_certificate_is_valid "$MAIL_CERT_PEM_FILE"; then
        warn "Could not retrieve a valid $protocol_upper TLS certificate from $target:$port"
        record_module_status "certificate:${protocol}:${port}" "failed" "no valid leaf certificate returned"
        return 1
    fi

    if ! sps_mail_describe_certificate "$MAIL_CERT_PEM_FILE" > "$MAIL_CERT_METADATA_FILE"; then
        warn "Captured the $protocol_upper certificate on port $port but could not parse it"
        record_loot "${protocol}_tls_certificate_pem" "$target:$port transport=$transport" "$MAIL_CERT_PEM_FILE"
        record_module_status "certificate:${protocol}:${port}" "failed" "certificate parsing failed"
        return 1
    fi

    sps_mail_parse_certificate_metadata "$MAIL_CERT_METADATA_FILE"
    sps_mail_record_certificate_hostnames "$target"
    evidence="$MAIL_CERT_PEM_FILE|$MAIL_CERT_METADATA_FILE"
    record_loot "${protocol}_tls_certificate_pem" "$target:$port transport=$transport" "$MAIL_CERT_PEM_FILE"
    record_loot "${protocol}_tls_certificate_metadata" "$target:$port cn=${MAIL_CERT_CN:-unavailable} sans=${MAIL_CERT_SANS:-none}" "$MAIL_CERT_METADATA_FILE"

    success "$protocol_upper TLS certificate captured on port $port"
    [[ -n "$MAIL_CERT_SUBJECT" ]] && info "$protocol_upper certificate subject: $MAIL_CERT_SUBJECT"
    [[ -n "$MAIL_CERT_CN" ]] && info "$protocol_upper certificate CN: $MAIL_CERT_CN"
    info "$protocol_upper certificate SANs: ${MAIL_CERT_SANS:-none}"
    [[ -n "$MAIL_CERT_ISSUER" ]] && info "$protocol_upper certificate issuer: $MAIL_CERT_ISSUER"
    [[ -n "$MAIL_CERT_NOT_BEFORE" || -n "$MAIL_CERT_NOT_AFTER" ]] &&
        info "$protocol_upper certificate validity: ${MAIL_CERT_NOT_BEFORE:-unknown} to ${MAIL_CERT_NOT_AFTER:-unknown}"
    [[ -n "$MAIL_CERT_SERIAL" ]] && info "$protocol_upper certificate serial: $MAIL_CERT_SERIAL"
    [[ -n "$MAIL_CERT_SHA256" ]] && info "$protocol_upper certificate SHA-256: $MAIL_CERT_SHA256"

    sps_record_finding \
        "TLS-CERTIFICATE-${protocol_upper}-${port}" "informational" "high" \
        "$protocol_upper TLS certificate on ${target}:${port}; subject=${MAIL_CERT_SUBJECT:-unavailable}; issuer=${MAIL_CERT_ISSUER:-unavailable}; CN=${MAIL_CERT_CN:-unavailable}; SAN=${MAIL_CERT_SANS:-none}; validity=${MAIL_CERT_NOT_BEFORE:-unknown} to ${MAIL_CERT_NOT_AFTER:-unknown}; SHA256=${MAIL_CERT_SHA256:-unavailable}" \
        "Confirmed $protocol_upper service|${transport} TLS handshake" "" \
        "discovery" "$evidence" \
        "Use a certificate whose CN or SANs match the intended mail-service names and rotate it before expiration." \
        "The TLS handshake retrieved only the public server certificate; no authentication or mailbox operation was attempted."
    record_module_status "certificate:${protocol}:${port}" "executed" \
        "transport=$transport; cn=${MAIL_CERT_CN:-unavailable}; sans=${MAIL_CERT_SANS:-none}"
    return 0
}

sps_mail_telnet_capture() {
    local target="$1" port="$2"
    local wait_seconds="${MAIL_TELNET_BANNER_WAIT:-1}"
    local timeout_seconds="${MAIL_TELNET_BANNER_TIMEOUT:-3}"
    { sleep "$wait_seconds"; } |
        timeout "$timeout_seconds" telnet "$target" "$port" 2>&1 || true
}

sps_mail_parse_telnet_banner() {
    local protocol="${1,,}" source="$2"
    case "$protocol" in
        smtp) sed -n -E '/^220[- ]/p' "$source" | head -n 1 ;;
        pop3) sed -n -E '/^[+]OK([[:space:]]|$)/p' "$source" | head -n 1 ;;
        imap) sed -n -E '/^[*] (OK|PREAUTH)([[:space:]]|$)/p' "$source" | head -n 1 ;;
        *) return 2 ;;
    esac
}

sps_run_mail_telnet_banner_check() {
    local target="$1" port="$2" protocol="${3,,}"
    local safe_target output_file raw_output="" banner="" protocol_upper

    MAIL_TELNET_BANNER=""
    MAIL_TELNET_BANNER_FILE=""
    protocol_upper="${protocol^^}"

    if ! sps_command_available telnet; then
        debug "$protocol_upper Telnet banner check skipped: telnet client unavailable"
        record_module_status "telnet-banner:${protocol}:${port}" "skipped" "telnet client unavailable"
        return 1
    fi

    safe_target="$(sanitize_name "$target")"
    output_file="telnet_${protocol}_${safe_target}_${port}.txt"
    if declare -F record_command_argv > /dev/null; then
        record_command_argv "Discovery" "$protocol_upper greeting capture via Telnet" telnet "$target" "$port"
    fi
    raw_output="$(sps_mail_telnet_capture "$target" "$port")"
    printf '%s\n' "$raw_output" | sps_clean_tool_stream > "$output_file"
    banner="$(sps_mail_parse_telnet_banner "$protocol" "$output_file")"

    if [[ -z "$banner" ]]; then
        [[ -s "$output_file" ]] && record_loot "${protocol}_telnet_unconfirmed" "$target:$port" "$output_file"
        record_module_status "telnet-banner:${protocol}:${port}" "executed" "expected greeting not observed"
        debug "$protocol_upper Telnet connection did not return an expected greeting on port $port"
        return 1
    fi

    MAIL_TELNET_BANNER="$banner"
    MAIL_TELNET_BANNER_FILE="$output_file"
    record_loot "${protocol}_telnet_banner" "$target:$port banner=$banner" "$output_file"
    success "$protocol_upper banner observed via Telnet on port $port: $banner"
    sps_record_finding \
        "TELNET-BANNER-${protocol_upper}-${port}" "informational" "high" \
        "$protocol_upper greeting observed through a read-only Telnet connection to ${target}:${port}: $banner" \
        "TCP port $port open|Expected $protocol_upper greeting format" "" \
        "discovery" "$output_file" \
        "Restrict the cleartext listener to intended clients and prefer encrypted transport where supported." \
        "The connection was held open only long enough to receive the greeting; no Telnet input or mail-protocol command was sent."
    record_module_status "telnet-banner:${protocol}:${port}" "executed" "expected greeting observed"
    return 0
}
