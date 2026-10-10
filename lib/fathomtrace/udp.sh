#!/usr/bin/env bash

sps_udp_service_name() {
    case "$1" in
        53) printf 'DNS' ;;
        67 | 68) printf 'DHCP' ;;
        69) printf 'TFTP' ;;
        88) printf 'Kerberos' ;;
        123) printf 'NTP' ;;
        137) printf 'NetBIOS Name Service' ;;
        161) printf 'SNMP' ;;
        389) printf 'CLDAP' ;;
        464) printf 'Kerberos Password' ;;
        500) printf 'IKE' ;;
        623) printf 'IPMI' ;;
        1434) printf 'MSSQL Browser' ;;
        1900) printf 'SSDP/UPnP' ;;
        4500) printf 'IPsec NAT-T' ;;
        5353) printf 'mDNS' ;;
        *) printf 'UDP service' ;;
    esac
}

sps_configure_udp_ports() {
    local -a port_numbers=()
    local port

    UDP_PORTS=()
    [[ "${ENABLE_UDP_SCAN:-true}" == true ]] || return 0

    if [[ -n "${CUSTOM_UDP_PORTS:-}" ]]; then
        mapfile -t port_numbers < <(sps_expand_custom_ports "$CUSTOM_UDP_PORTS") || {
            error "Invalid --udp-ports value: $CUSTOM_UDP_PORTS"
            return 2
        }
    else
        case "${SCAN_PROFILE:-default}" in
            default) port_numbers=(53 123 137 161 500) ;;
            web) port_numbers=(53 161) ;;
            ad) port_numbers=(53 88 123 137 161 389 464) ;;
            extended) port_numbers=(53 67 69 88 123 137 161 389 464 500 623 1434 1900 4500 5353) ;;
        esac
    fi

    for port in "${port_numbers[@]}"; do
        UDP_PORTS+=("$port")
    done
}

sps_udp_ports_csv() {
    local separator="" port
    for port in "$@"; do
        printf '%s%s' "$separator" "$port"
        separator=,
    done
}

sps_udp_port_selected() {
    local expected="$1" port
    for port in "${UDP_PORTS[@]:-}"; do
        [[ "$port" == "$expected" ]] && return 0
    done
    return 1
}

sps_snmp_raw_probe() {
    local target="$1" output_file="$2"
    local probe_timeout="${SNMP_PROBE_TIMEOUT:-2}"

    : > "$output_file"
    timeout "$probe_timeout" bash -c '
        exec 3<>"/dev/udp/$1/161" || exit 1
        printf "%b" "\x30\x29\x02\x01\x01\x04\x06public\xa0\x1c\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00" >&3
        IFS= read -r -n 1 response <&3 || exit 1
        printf "%s" "$response"
    ' _ "$target" > "$output_file" 2> /dev/null || true

    [[ -s "$output_file" ]]
}

sps_record_udp_open() {
    local port="$1"
    grep -qx "$port" "$UDP_OPEN_PORTS_FILE" 2> /dev/null || printf '%s\n' "$port" >> "$UDP_OPEN_PORTS_FILE"
    if [[ -s "${UDP_POSSIBLE_PORTS_FILE:-}" ]]; then
        awk -v confirmed="$port" '$0 != confirmed' "$UDP_POSSIBLE_PORTS_FILE" > "${UDP_POSSIBLE_PORTS_FILE}.tmp"
        mv -f -- "${UDP_POSSIBLE_PORTS_FILE}.tmp" "$UDP_POSSIBLE_PORTS_FILE"
    fi
    if [[ "$port" == 161 ]]; then
        SNMP_PORT_OPEN=true
        printf 'SNMP\n' >> "$HINT_FILE"
    fi
}

sps_parse_udp_nmap_grepable() {
    local input_file="$1" field port state protocol owner detected_service remainder label

    while IFS= read -r field; do
        field="${field#${field%%[![:space:]]*}}"
        IFS=/ read -r port state protocol owner detected_service remainder <<< "$field"
        [[ "$protocol" == udp && "$port" =~ ^[0-9]+$ ]] || continue
        label="${detected_service:-$(sps_udp_service_name "$port")}"
        [[ -n "$label" && "$label" != unknown ]] || label="$(sps_udp_service_name "$port")"
        case "$state" in
            open)
                sps_record_udp_open "$port"
                success "UDP port $port OPEN ($label)"
                if [[ "$port" == 161 && "${detected_service,,}" == *snmp* ]]; then
                    SNMP_SERVICE_CONFIRMED=true
                fi
                ;;
            open\|filtered)
                grep -qx "$port" "$UDP_POSSIBLE_PORTS_FILE" 2> /dev/null || printf '%s\n' "$port" >> "$UDP_POSSIBLE_PORTS_FILE"
                info "UDP port $port OPEN|FILTERED ($label; inconclusive)"
                ;;
        esac
    done < <(sed -n 's/^.*Ports: //p' "$input_file" | tr ',' '\n')
}

run_udp_scan() {
    local target="$1"
    shift
    local -a ports=("$@") nmap_args=()
    local ports_csv output_file nmap_rc=0 raw_response used_nmap=false

    UDP_OPEN_PORTS=()
    UDP_POSSIBLE_PORTS=()
    : > "$UDP_OPEN_PORTS_FILE"
    : > "$UDP_POSSIBLE_PORTS_FILE"
    ((${#ports[@]})) || {
        info "Targeted UDP scan disabled"
        return 0
    }

    info "Scanning ${#ports[@]} targeted UDP port(s); silence is never reported as confirmed open"
    ports_csv="$(sps_udp_ports_csv "${ports[@]}")"
    output_file="udp_scan_$(sanitize_name "$target").gnmap"

    if sps_command_available nmap; then
        used_nmap=true
        nmap_args=(-n -Pn -sU --open --max-retries "${UDP_RETRY_LIMIT:-0}" \
            --host-timeout "${UDP_HOST_TIMEOUT:-5s}" -p "$ports_csv" "$target" -oG "$output_file")
        record_command_argv "Discovery" "Fast targeted UDP port scan" nmap "${nmap_args[@]}"
        if nmap "${nmap_args[@]}" > /dev/null 2>&1; then
            nmap_rc=0
        else
            nmap_rc=$?
        fi
        if [[ -s "$output_file" ]]; then
            sps_parse_udp_nmap_grepable "$output_file"
            record_loot "udp_port_scan" "$target udp_ports=$ports_csv" "$output_file"
        fi
        if ((nmap_rc != 0)); then
            warn "Targeted UDP scan did not complete cleanly (nmap exit $nmap_rc)"
            record_module_status "udp-scan" "failed" "nmap exit $nmap_rc"
        else
            record_module_status "udp-scan" "executed" "targeted ports=$ports_csv"
        fi
    elif sps_udp_port_selected 161; then
        info "nmap is unavailable; using the bounded SNMP protocol probe for UDP/161"
        ((${#ports[@]} > 1)) && warn "nmap is unavailable; non-SNMP UDP ports were not classified"
    else
        warn "nmap is unavailable; targeted UDP ports could not be classified"
        record_module_status "udp-scan" "skipped" "nmap unavailable"
    fi

    if sps_udp_port_selected 161 &&
        ! grep -qx 161 "$UDP_OPEN_PORTS_FILE" 2> /dev/null &&
        ! grep -qx 161 "$UDP_POSSIBLE_PORTS_FILE" 2> /dev/null; then
        raw_response="$RUNTIME_TMP_DIR/snmp-fast-response.bin"
        if sps_snmp_raw_probe "$target" "$raw_response"; then
            sps_record_udp_open 161
            SNMP_SERVICE_CONFIRMED=true
            success "UDP port 161 OPEN (SNMP response)"
            [[ "$used_nmap" == false ]] && record_module_status "udp-scan" "executed" "SNMP/161 confirmed by protocol response; nmap unavailable"
        elif [[ "$used_nmap" == false ]]; then
            info "UDP port 161 did not answer the bounded SNMP probe; state remains unknown"
            record_module_status "udp-scan" "skipped" "nmap unavailable; SNMP probe received no response"
        fi
    fi

    if [[ -s "$UDP_OPEN_PORTS_FILE" ]]; then
        mapfile -t UDP_OPEN_PORTS < <(sort -nu "$UDP_OPEN_PORTS_FILE")
    fi
    if [[ -s "$UDP_POSSIBLE_PORTS_FILE" ]]; then
        mapfile -t UDP_POSSIBLE_PORTS < <(sort -nu "$UDP_POSSIBLE_PORTS_FILE")
    fi
}

sps_run_snmp_discovery() {
    local target="$1" output_file raw_response description="" rc=0

    sps_udp_port_selected 161 || return 0
    sps_service_heading "SNMP DEVICE DISCOVERY" \
        "Checking UDP/161 for a bounded SNMP response and read-only system identity using the public community."
    sps_service_endpoint "SNMP / UDP 161 - device identity and management exposure"
    output_file="snmp_$(sanitize_name "$target")_161.txt"

    if sps_command_available snmpget; then
        if timeout "${SNMP_PROBE_TIMEOUT:-2}" snmpget -v2c -c public -t "${SNMP_PROBE_TIMEOUT:-2}" -r 0 \
            -Oqv "$target" 1.3.6.1.2.1.1.1.0 > "$output_file" 2>&1; then
            rc=0
        else
            rc=$?
        fi
        if ((rc == 0)) && [[ -s "$output_file" ]]; then
            description="$(sps_clean_tool_stream < "$output_file" | sed -n '1p')"
            SNMP_PORT_OPEN=true
            SNMP_SERVICE_CONFIRMED=true
            SNMP_PUBLIC_ACCESS_CONFIRMED=true
            SNMP_SYS_DESCR="$description"
            sps_record_udp_open 161
            success "SNMP/161 responded to the public community query"
            [[ -n "$description" ]] && finding "SNMP sysDescr: $description"
            record_loot "snmp_sysdescr" "$target:161 community=public" "$output_file"
            sps_record_finding \
                "SNMP-PUBLIC-SYSDESCR" "informational" "confirmed" \
                "SNMPv2c community public returned sysDescr.0 on ${target}:161${description:+: $description}" \
                "UDP/161 protocol response|SNMP sysDescr query accepted" "" "active-read" "$output_file" \
                "Replace default community strings, prefer SNMPv3, and restrict UDP/161 to authorized management systems." \
                "One read-only sysDescr.0 request was sent; no configuration was changed."
            record_module_status "snmp:161" "executed" "public sysDescr query accepted"
            return 0
        fi
    fi

    raw_response="$RUNTIME_TMP_DIR/snmp-service-response.bin"
    if [[ -s "$RUNTIME_TMP_DIR/snmp-fast-response.bin" ]] || sps_snmp_raw_probe "$target" "$raw_response"; then
        [[ -s "$RUNTIME_TMP_DIR/snmp-fast-response.bin" ]] && raw_response="$RUNTIME_TMP_DIR/snmp-fast-response.bin"
        SNMP_PORT_OPEN=true
        SNMP_SERVICE_CONFIRMED=true
        SNMP_PUBLIC_ACCESS_CONFIRMED=true
        sps_record_udp_open 161
        success "SNMP/161 responded to the public community probe"
        record_loot "snmp_response" "$target:161 community=public" "$raw_response"
        sps_record_finding \
            "SNMP-PUBLIC-RESPONSE" "informational" "confirmed" \
            "UDP/161 returned an SNMP response to a read-only SNMPv2c request using community public." \
            "UDP/161 protocol response|SNMP request accepted" "" "active-read" "$raw_response" \
            "Replace default community strings, prefer SNMPv3, and restrict UDP/161 to authorized management systems." \
            "One read-only sysDescr.0 request was sent; no configuration was changed."
        record_module_status "snmp:161" "executed" "public SNMP response received"
    elif [[ "${SNMP_SERVICE_CONFIRMED:-false}" == true ]]; then
        success "SNMP service confirmed on UDP/161 by service detection"
        record_module_status "snmp:161" "executed" "confirmed by nmap service detection"
    else
        info "SNMP/161 was targeted but did not return a protocol response; closed versus filtered remains inconclusive"
        record_module_status "snmp:161" "skipped" "no protocol response"
    fi
}

sps_udp_service_version_detection() {
    local target="$1" candidates_file ports_csv output_file screen_file nmap_rc=0 port
    local -a nmap_args=()

    sps_command_available nmap || return 0
    candidates_file="$RUNTIME_TMP_DIR/udp-service-candidates"
    sort -nu "$UDP_OPEN_PORTS_FILE" "$UDP_POSSIBLE_PORTS_FILE" 2> /dev/null > "$candidates_file"
    [[ -s "$candidates_file" ]] || return 0
    ports_csv="$(awk 'NF { printf "%s%s", separator, $1; separator="," } END { print "" }' "$candidates_file")"
    output_file="nmap_udp_service_$(sanitize_name "$target").txt"
    screen_file="nmap_udp_service_$(sanitize_name "$target").screen.txt"
    nmap_args=(-n -Pn -sU -sV --version-light --max-retries 1 -p "$ports_csv" "$target" -oN "$output_file")

    sps_section "UDP Service Detection"
    info "Running targeted UDP service detection against open and open|filtered candidates"
    echo -e " ${YELLOW}$ICON_TIP Copy/Paste:${RESET}"
    echo -e " ${GREEN}$(sps_shell_join nmap "${nmap_args[@]}")${RESET}"
    record_command_argv "Discovery" "Targeted UDP service and version detection" nmap "${nmap_args[@]}"
    nmap "${nmap_args[@]}" 2> /dev/null | tee "$screen_file"
    nmap_rc=${PIPESTATUS[0]}
    if ((nmap_rc != 0)); then
        warn "Nmap UDP service detection failed (exit $nmap_rc)"
        record_module_status "udp-service-detect" "failed" "nmap exit $nmap_rc"
        return 1
    fi

    while read -r port; do
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        sps_record_udp_open "$port"
    done < <(awk '$1 ~ /^[0-9]+\/udp$/ && $2 == "open" { split($1, value, "/"); print value[1] }' "$output_file")
    if awk '$1 == "161/udp" && $2 == "open" && tolower($3) ~ /snmp/' "$output_file" | grep -q .; then
        SNMP_PORT_OPEN=true
        SNMP_SERVICE_CONFIRMED=true
    fi
    mapfile -t UDP_OPEN_PORTS < <(sort -nu "$UDP_OPEN_PORTS_FILE")
    record_loot "nmap_udp_service_detection" "$target udp_ports=$ports_csv" "$output_file"
    record_module_status "udp-service-detect" "executed" "ports=$ports_csv"
}
