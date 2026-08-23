#!/usr/bin/env bash

sps_netbios_name_valid() {
    local name="${1^^}"
    ((${#name} >= 1 && ${#name} <= 15)) || return 1
    [[ "$name" =~ ^[A-Z0-9]([A-Z0-9-]{0,13}[A-Z0-9])?$ ]]
}

sps_parse_nmblookup_name() {
    local source="$1"
    awk '
        $2 == "<20>" && $0 !~ /<GROUP>/ && server == "" { server=$1 }
        $2 == "<00>" && $0 !~ /<GROUP>/ {
            print $1
            found=1
            exit
        }
        END { if (!found && server != "") print server }
    ' "$source"
}

sps_parse_nmblookup_workgroup() {
    local source="$1"
    awk '$2 == "<00>" && /<GROUP>/ { print $1; exit }' "$source"
}

sps_parse_nmblookup_mac() {
    local source="$1"
    sed -n 's/^[[:space:]]*MAC Address[[:space:]]*=[[:space:]]*//p' "$source" | head -n 1 | tr '[:lower:]' '[:upper:]'
}

sps_parse_nbtscan_name() {
    local source="$1"
    awk -F: '
        $3 == "20U" && server == "" { server=$2 }
        $3 == "00U" { print $2; found=1; exit }
        END { if (!found && server != "") print server }
    ' "$source"
}

sps_parse_nbtscan_workgroup() {
    local source="$1"
    awk -F: '$3 == "00G" { print $2; exit }' "$source"
}

sps_netbios_clean_value() {
    local value="${1:-}"
    value="${value//$'\r'/}"
    value="${value//$'\n'/}"
    value="${value#${value%%[![:space:]]*}}"
    value="${value%${value##*[![:space:]]}}"
    printf '%s' "${value^^}"
}

sps_run_netbios_scan() {
    local target="$1"
    local output_file="netbios_$(sanitize_name "$target").txt"
    local tool_output="" candidate="" workgroup="" mac_address="" rc=0 attempted=0
    local query_timeout="${NETBIOS_QUERY_TIMEOUT:-5}"

    NETBIOS_DETECTED=false
    NETBIOS_NAME=""
    NETBIOS_WORKGROUP=""
    NETBIOS_MAC=""
    NETBIOS_TOOL=""
    NETBIOS_LOOT_FILE=""
    : > "$output_file"

    if sps_command_available nmblookup; then
        attempted=$((attempted + 1))
        NETBIOS_TOOL="nmblookup"
        record_command_argv "Discovery" "NetBIOS node-status query" nmblookup -A "$target"
        if tool_output="$(timeout "$query_timeout" nmblookup -A "$target" 2>&1)"; then
            rc=0
        else
            rc=$?
        fi
        {
            printf '### nmblookup -A %s (exit %d)\n' "$target" "$rc"
            printf '%s\n' "$tool_output"
        } >> "$output_file"
        candidate="$(sps_parse_nmblookup_name "$output_file")"
        workgroup="$(sps_parse_nmblookup_workgroup "$output_file")"
        mac_address="$(sps_parse_nmblookup_mac "$output_file")"
        candidate="$(sps_netbios_clean_value "$candidate")"
        sps_netbios_name_valid "$candidate" || candidate=""
    fi

    if [[ -z "$candidate" ]] && sps_command_available nbtscan; then
        attempted=$((attempted + 1))
        NETBIOS_TOOL="nbtscan"
        record_command_argv "Discovery" "NetBIOS name scan" nbtscan -v -s : -t 2000 "$target"
        if tool_output="$(timeout "$query_timeout" nbtscan -v -s : -t 2000 "$target" 2>&1)"; then
            rc=0
        else
            rc=$?
        fi
        {
            printf '\n### nbtscan -v -s : -t 2000 %s (exit %d)\n' "$target" "$rc"
            printf '%s\n' "$tool_output"
        } >> "$output_file"
        candidate="$(sps_parse_nbtscan_name "$output_file")"
        workgroup="$(sps_parse_nbtscan_workgroup "$output_file")"
    fi

    if ((attempted == 0)); then
        rm -f -- "$output_file"
        if [[ -n "${SMB_MARKER:-}" && -s "${SMB_MARKER:-}" ]]; then
            warn "NetBIOS discovery skipped: install samba-common-bin or nbtscan"
        else
            debug "NetBIOS discovery skipped: neither nmblookup nor nbtscan is available"
        fi
        record_module_status "netbios" "skipped" "nmblookup and nbtscan unavailable"
        return 1
    fi

    NETBIOS_LOOT_FILE="$output_file"
    record_loot "netbios_node_status" "$target" "$output_file"
    candidate="$(sps_netbios_clean_value "$candidate")"
    workgroup="$(sps_netbios_clean_value "$workgroup")"
    mac_address="$(sps_netbios_clean_value "$mac_address")"

    if ! sps_netbios_name_valid "$candidate"; then
        debug "NetBIOS query completed without a valid unique workstation or server name"
        record_module_status "netbios" "executed" "no valid unique name returned; attempted_tools=$attempted"
        return 0
    fi

    NETBIOS_DETECTED=true
    NETBIOS_NAME="$candidate"
    if sps_netbios_name_valid "$workgroup"; then
        NETBIOS_WORKGROUP="$workgroup"
    fi
    if [[ "$mac_address" =~ ^([0-9A-F]{2}:){5}[0-9A-F]{2}$ && "$mac_address" != "00:00:00:00:00:00" ]]; then
        NETBIOS_MAC="$mac_address"
    fi

    finding "NetBIOS target name: $NETBIOS_NAME"
    [[ -n "$NETBIOS_WORKGROUP" ]] && info "NetBIOS workgroup/domain: $NETBIOS_WORKGROUP"
    [[ -n "$NETBIOS_MAC" ]] && info "NetBIOS-reported MAC: $NETBIOS_MAC"

    if sps_is_hostname "${NETBIOS_NAME,,}"; then
        printf '%s %s\n' "$target" "${NETBIOS_NAME,,}" >> "$HOSTS_FILE"
        printf '%s\n' "${NETBIOS_NAME,,}" >> "$DISCOVERED_HOSTS"
        sort -u "$HOSTS_FILE" -o "$HOSTS_FILE"
        sort -u "$DISCOVERED_HOSTS" -o "$DISCOVERED_HOSTS"
    fi

    sps_record_finding \
        "NETBIOS-NAME-DISCLOSURE" "informational" "high" \
        "A NetBIOS node-status response identified $target as $NETBIOS_NAME${NETBIOS_WORKGROUP:+ in $NETBIOS_WORKGROUP}." \
        "NetBIOS node-status response|Unique workstation or file-server name" "" \
        "discovery" "$output_file" \
        "Disable NetBIOS over TCP/IP where legacy name resolution and SMB compatibility are not required." \
        "Only a NetBIOS node-status query was sent; no target-side changes were made."
    record_module_status "netbios" "executed" \
        "name=$NETBIOS_NAME; workgroup=${NETBIOS_WORKGROUP:-unknown}; tool=$NETBIOS_TOOL"
    return 0
}
