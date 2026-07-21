#!/usr/bin/env bash

sps_port_entry() {
    case "$1" in
        21) printf '21:FTP:interesting' ;;
        22) printf '22:SSH:open' ;;
        23) printf '23:Telnet:high' ;;
        25) printf '25:SMTP:interesting' ;;
        53) printf '53:DNS:open' ;;
        80) printf '80:HTTP:open' ;;
        88) printf '88:Kerberos:high' ;;
        110) printf '110:POP3:interesting' ;;
        111) printf '111:RPCBind:interesting' ;;
        135) printf '135:MSRPC:high' ;;
        139) printf '139:SMB:high' ;;
        143) printf '143:IMAP:interesting' ;;
        389) printf '389:LDAP:interesting' ;;
        443) printf '443:HTTPS:open' ;;
        445) printf '445:SMB:high' ;;
        464) printf '464:Kerberos password:interesting' ;;
        515) printf '515:PRINTER:open' ;;
        593) printf '593:RPC over HTTP:interesting' ;;
        631) printf '631:PRINTER:open' ;;
        636) printf '636:LDAPS:interesting' ;;
        993) printf '993:IMAPS:interesting' ;;
        1433) printf '1433:SQL Server:high' ;;
        2049) printf '2049:Network File System:high' ;;
        2375) printf '2375:Docker API:high' ;;
        2377) printf '2377:Docker Swarm:interesting' ;;
        3000) printf '3000:Web Dev:interesting' ;;
        3268) printf '3268:LDAP Global Catalog:interesting' ;;
        3269) printf '3269:LDAPS Global Catalog:interesting' ;;
        3306) printf '3306:MySQL:interesting' ;;
        3389) printf '3389:RDP:high' ;;
        5000) printf '5000:Web/Docker:interesting' ;;
        5432) printf '5432:PostgreSQL:interesting' ;;
        5900) printf '5900:VNC:interesting' ;;
        5985) printf '5985:WinRM:high' ;;
        5986) printf '5986:WinRM HTTPS:interesting' ;;
        6379) printf '6379:Redis:high' ;;
        6443) printf '6443:Kubernetes API:high' ;;
        8000) printf '8000:HTTP-Alt:interesting' ;;
        8008) printf '8008:HTTP-Alt:interesting' ;;
        8080) printf '8080:HTTP-Alt:interesting' ;;
        8443) printf '8443:HTTPS-Alt:interesting' ;;
        8888) printf '8888:HTTP-Alt:interesting' ;;
        9000) printf '9000:Web:interesting' ;;
        9090) printf '9090:Web:interesting' ;;
        9100) printf '9100:PRINTER:interesting' ;;
        9389) printf '9389:AD Web Services:interesting' ;;
        9443) printf '9443:HTTPS-Alt:interesting' ;;
        11211) printf '11211:Memcached:high' ;;
        27017) printf '27017:MongoDB:interesting' ;;
        54925) printf '54925:BROTHER_PRINTER:open' ;;
        *) printf '%s:Custom:open' "$1" ;;
    esac
}

sps_expand_custom_ports() {
    local specification="$1"
    local token start end port
    local -a selected=()
    IFS=, read -r -a tokens <<< "$specification"
    for token in "${tokens[@]}"; do
        if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start="${BASH_REMATCH[1]}"
            end="${BASH_REMATCH[2]}"
            ((start >= 1 && end <= 65535 && start <= end)) || return 2
            for ((port = start; port <= end; port++)); do selected+=("$port"); done
        elif [[ "$token" =~ ^[0-9]+$ ]]; then
            port="$token"
            ((port >= 1 && port <= 65535)) || return 2
            selected+=("$port")
        else
            return 2
        fi
    done
    printf '%s\n' "${selected[@]}" | sort -nu
}

sps_configure_ports() {
    local -a port_numbers=()
    local port
    if [[ -n "${CUSTOM_PORTS:-}" ]]; then
        mapfile -t port_numbers < <(sps_expand_custom_ports "$CUSTOM_PORTS") || {
            error "Invalid --ports value: $CUSTOM_PORTS"
            return 2
        }
    else
        case "${SCAN_PROFILE:-default}" in
            default)
                port_numbers=(21 22 23 25 53 80 88 110 111 135 139 143 389 443 445 515 631 636 993 1433 2049 2375 2377 3000 3306 3389 5000 5985 5986 6379 6443 8080 8443 9090 9100 27017 54925)
                ;;
            web)
                port_numbers=(80 443 3000 5000 8000 8008 8080 8443 8888 9000 9090 9443)
                ;;
            ad)
                port_numbers=(53 88 111 135 139 389 445 464 593 636 1433 2049 3268 3269 3389 5985 5986 9389)
                ;;
            extended)
                port_numbers=(21 22 23 25 53 80 88 110 111 135 139 143 389 443 445 464 515 593 631 636 993 1433 2049 2375 2377 3000 3268 3269 3306 3389 5000 5432 5900 5985 5986 6379 6443 8000 8008 8080 8443 8888 9000 9090 9100 9389 9443 11211 27017 54925)
                ;;
        esac
    fi

    PORTS=()
    for port in "${port_numbers[@]}"; do
        PORTS+=("$(sps_port_entry "$port")")
    done
    ((${#PORTS[@]})) || {
        error "The selected port set is empty."
        return 2
    }
}

sps_tcp_probe() {
    local target="$1"
    local port="$2"
    local attempts=$((RETRY_LIMIT + 1))
    local attempt
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if timeout "$CONNECT_TIMEOUT" bash -c 'exec 7<>"/dev/tcp/$1/$2"' _ "$target" "$port" 2> /dev/null; then
            return 0
        fi
    done
    return 1
}

sps_classify_open_port() {
    local port="$1"
    case "$port" in
        21) printf 'FTP\n' >> "$HINT_FILE" ;;
        53) printf 'DNS\n' >> "$HINT_FILE" ;;
        80 | 443 | 3000 | 5000 | 8000 | 8008 | 8080 | 8443 | 8888 | 9000 | 9090 | 9443)
            printf 'WEB\n' >> "$HINT_FILE"
            WEB_PORT_OPEN=true
            ;;
        88 | 464)
            printf 'KERBEROS\n' >> "$HINT_FILE"
            printf '%s\n' "$port" >> "$KERB_MARKER"
            KERBEROS_PORT_OPEN=true
            KERBEROS_SERVICE_CONFIRMED=true
            ;;
        111) printf 'NFS\n' >> "$HINT_FILE" ;;
        139 | 445)
            printf 'SMB\n' >> "$HINT_FILE"
            printf '%s\n' "$port" >> "$SMB_MARKER"
            SMB_PORT_OPEN=true
            ;;
        389 | 636 | 3268 | 3269)
            printf 'LDAP\n' >> "$HINT_FILE"
            printf '%s\n' "$port" >> "$LDAP_MARKER"
            LDAP_PORT_OPEN=true
            ;;
        1433 | 3306 | 5432 | 27017) printf 'DB\n' >> "$HINT_FILE" ;;
        2049) printf 'NFS\n' >> "$HINT_FILE" ;;
        2375) printf 'DOCKER\n' >> "$HINT_FILE" ;;
        3389) printf 'RDP\n' >> "$HINT_FILE" ;;
        5985 | 5986) printf 'WINRM\n' >> "$HINT_FILE" ;;
        6379) printf 'REDIS\n' >> "$HINT_FILE" ;;
        6443) printf 'K8S\n' >> "$HINT_FILE" ;;
    esac
}

sps_record_web_service() {
    local scheme="$1"
    local port="$2"
    local evidence="$3"
    local entry="${scheme}:${port}"
    grep -Fqx "$entry" "$WEB_SERVICES_FILE" 2> /dev/null || printf '%s\n' "$entry" >> "$WEB_SERVICES_FILE"
    [[ "$scheme" == https ]] && printf '%s\n' "$port" >> "$HTTPS_MARKER" || printf '%s\n' "$port" >> "$HTTP_MARKER"
    WEB_PORT_OPEN=true
    WEB_SERVICE_CONFIRMED=true
    sps_record_finding \
        "WEB-SERVICE-${port}-${scheme}" "informational" "high" \
        "$evidence" "TCP port $port open|HTTP response received" "" \
        "discovery" "" \
        "Restrict the listener and application routes to intended clients where appropriate." \
        "No target-side changes were made."
}

sps_probe_web_protocol() {
    local port="$1"
    local scheme code rc
    local -a schemes=(http https)
    case "$port" in
        443 | 636 | 8443 | 9443 | 5986 | 6443) schemes=(https http) ;;
    esac

    sps_command_available curl || return 1
    for scheme in "${schemes[@]}"; do
        if code="$(curl -k -sS -o /dev/null --max-time "$CONNECT_TIMEOUT" \
            -w '%{http_code}' "${scheme}://${TARGET_IPV4}:${port}/" 2> /dev/null)"; then
            rc=0
        else
            rc=$?
        fi
        if ((rc == 0)) && [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then
            sps_record_web_service "$scheme" "$port" \
                "${scheme}://${TARGET_IPV4}:${port}/ returned HTTP status $code"
            return 0
        fi
    done
    return 1
}

sps_probe_open_port() {
    local port="$1"
    local redirect host_name ldap_uri ldap_dn ldap_output ldap_rc=0 scheme

    # Selected web modules require protocol evidence even when generic optional
    # preflight discovery was disabled. Every open port is tested so custom
    # --ports values can be recognized as HTTP/HTTPS services.
    if [[ "${SKIP_PREFLIGHT:-false}" != true || "${ENABLE_WEB_ENUM:-false}" == true || "${ENABLE_VHOST:-false}" == true ]]; then
        sps_probe_web_protocol "$port" || true
    fi
    [[ "${SKIP_PREFLIGHT:-false}" == true ]] && return 0

    if grep -Eq ":${port}$" "$WEB_SERVICES_FILE" 2> /dev/null && sps_command_available curl; then
        scheme="$(awk -F: -v port="$port" '$2 == port {print $1; exit}' "$WEB_SERVICES_FILE")"
        redirect="$(curl -ksI --max-time "$CONNECT_TIMEOUT" "${scheme}://$TARGET_IPV4:$port" 2> /dev/null |
            awk -F': ' 'tolower($1)=="location"{print $2; exit}' | tr -d '\r')"
        if [[ "$redirect" =~ ^(https?:)?// ]]; then
            host_name="$(sed -E 's#^(https?:)?//([^/:]+).*#\2#' <<< "$redirect")"
            printf '%s %s\n' "$TARGET_IPV4" "$host_name" >> "$HOSTS_FILE"
            printf '%s\n' "$host_name" >> "$REDIRECT_HOSTS"
            finding "HTTP redirect on port $port: $redirect"
        fi
    fi

    if [[ "$port" =~ ^(389|636|3268|3269)$ ]] && sps_command_available ldapsearch; then
        [[ "$port" == 636 || "$port" == 3269 ]] && ldap_uri="ldaps://$TARGET_IPV4:$port" || ldap_uri="ldap://$TARGET_IPV4:$port"
        if ldap_output="$(timeout "$CONNECT_TIMEOUT" ldapsearch -x -H "$ldap_uri" -s base -b '' \
            defaultNamingContext supportedLDAPVersion 2> /dev/null)"; then
            ldap_rc=0
        else
            ldap_rc=$?
        fi
        ldap_dn="$(sed -n 's/^defaultNamingContext:[[:space:]]*//p' <<< "$ldap_output" | head -n 1)"
        if ((ldap_rc == 0)) || grep -qiE '^supportedLDAPVersion:|^defaultNamingContext:' <<< "$ldap_output"; then
            LDAP_SERVICE_CONFIRMED=true
            ((ldap_rc == 0)) && LDAP_ACCESS_CONFIRMED=true
        fi
        if [[ "$ldap_dn" =~ ^[Dd][Cc]= ]]; then
            LDAP_DOMAIN="$(sed -E 's/[Dd][Cc]=//g; s/,/./g' <<< "$ldap_dn" | tr '[:upper:]' '[:lower:]')"
            printf '%s %s\n' "$TARGET_IPV4" "$LDAP_DOMAIN" >> "$HOSTS_FILE"
            printf '%s\n' "$LDAP_DOMAIN" >> "$DISCOVERED_HOSTS"
            finding "LDAP domain discovered: $LDAP_DOMAIN"
            sps_record_finding \
                "LDAP-DOMAIN-DISCLOSURE-${port}" "informational" "high" \
                "Anonymous RootDSE on $ldap_uri returned defaultNamingContext=$ldap_dn" \
                "TCP port $port open|LDAP protocol response" "" "discovery" "" \
                "Limit anonymous directory metadata if it is not operationally required." \
                "No target-side changes were made."
        fi
    fi

    if [[ "$port" == 6379 ]] && sps_command_available redis-cli; then
        if timeout "$CONNECT_TIMEOUT" redis-cli -h "$TARGET_IPV4" ping 2> /dev/null | grep -qi PONG; then
            critical "Redis responded without authentication; validate exposure manually."
            REDIS_UNAUTH_CONFIRMED=true
            sps_record_finding \
                "REDIS-UNAUTHENTICATED" "critical" "high" \
                "redis-cli PING returned PONG without credentials on ${TARGET_IPV4}:6379" \
                "TCP port 6379 open|redis-cli available" "" "active-read" "" \
                "Require authentication, bind to trusted interfaces, and restrict network access." \
                "No data or configuration was changed."
        fi
    fi

    if [[ "$port" == 2375 ]] && sps_command_available curl; then
        if curl -s --max-time "$CONNECT_TIMEOUT" "http://$TARGET_IPV4:2375/containers/json" 2> /dev/null | grep -q '^\['; then
            critical "Docker API returned container data without authentication."
            DOCKER_UNAUTH_CONFIRMED=true
            sps_record_finding \
                "DOCKER-API-UNAUTHENTICATED" "critical" "high" \
                "GET /containers/json returned a JSON array without credentials on ${TARGET_IPV4}:2375" \
                "TCP port 2375 open|HTTP API response" "" "active-read" "" \
                "Disable the unauthenticated TCP API or protect it with mutual TLS and network controls." \
                "Only a read-only containers listing request was sent."
        fi
    fi
}

run_port_scan() {
    local target="$1"
    shift
    local -a entries=("$@")
    local -a pids=()
    local -a result_files=()
    local entry port service level result_file temporary pid
    local result_dir

    result_dir="$(mktemp -d "$RUNTIME_TMP_DIR/port-results.XXXXXX")"
    sps_section "Running Port Scan"
    info "Scanning ${#entries[@]} port(s) with ${MAX_JOBS} worker(s), ${CONNECT_TIMEOUT}s timeout, ${RETRY_LIMIT} retry/retries"

    for entry in "${entries[@]}"; do
        IFS=: read -r port service level <<< "$entry"
        result_file="$result_dir/$port.result"
        result_files+=("$result_file")
        (
            if sps_tcp_probe "$target" "$port"; then
                temporary="$result_file.$$"
                printf '%s:%s:%s\n' "$port" "$service" "$level" > "$temporary"
                mv -f -- "$temporary" "$result_file"
            fi
        ) &
        pids+=("$!")

        if ((${#pids[@]} >= MAX_JOBS)); then
            wait "${pids[0]}" || true
            pids=("${pids[@]:1}")
        fi
    done
    for pid in "${pids[@]}"; do wait "$pid" || true; done

    : > "$OPEN_PORTS_FILE"
    OPEN_PORTS=()
    for result_file in "${result_files[@]}"; do
        [[ -s "$result_file" ]] || continue
        IFS=: read -r port service level < "$result_file"
        OPEN_PORTS+=("$port")
        printf '%s\n' "$port" >> "$OPEN_PORTS_FILE"
        success "Port $port OPEN ($service)"
        sps_classify_open_port "$port"
    done

    for port in "${OPEN_PORTS[@]}"; do
        sps_probe_open_port "$port" || debug "Optional discovery probe failed for port $port"
    done
}

sps_print_dry_run() {
    local port_list=""
    local entry port
    for entry in "${PORTS[@]}"; do
        IFS=: read -r port _ <<< "$entry"
        port_list+="${port_list:+,}$port"
    done
    info "Dry run: command=$COMMAND target=${ORIGINAL_TARGET:-$TARGET} resolved=${TARGET_IPV4:-unresolved}"
    info "Dry run: profile=$SCAN_PROFILE ports=$port_list jobs=$MAX_JOBS timeout=$CONNECT_TIMEOUT retries=$RETRY_LIMIT"
    info "Dry run: loot=$LOOT_ENABLED format=$OUTPUT_FORMAT optional-preflight=$([[ "$SKIP_PREFLIGHT" == true ]] && printf disabled || printf enabled)"
}
