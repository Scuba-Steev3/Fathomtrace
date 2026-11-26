#!/usr/bin/env bash

sps_port_entry() {
    case "$1" in
        21) printf '21:FTP:interesting' ;;
        22) printf '22:SSH:open' ;;
        23) printf '23:Telnet:high' ;;
        25) printf '25:SMTP:interesting' ;;
        465) printf '465:SMTPS:interesting' ;;
        587) printf '587:SMTP Submission:interesting' ;;
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
        995) printf '995:POP3S:interesting' ;;
        1433) printf '1433:SQL Server:high' ;;
        2049) printf '2049:Network File System:high' ;;
        2375) printf '2375:Docker API:high' ;;
        2377) printf '2377:Docker Swarm:interesting' ;;
        2525) printf '2525:SMTP-Alt:interesting' ;;
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
                port_numbers=(21 22 23 25 53 80 88 110 111 135 139 143 389 443 445 465 515 587 631 636 993 995 1433 2049 2375 2377 3000 3306 3389 5000 5985 5986 6379 6443 8080 8443 9090 9100 27017 54925)
                ;;
            web)
                port_numbers=(80 443 3000 5000 8000 8008 8080 8443 8888 9000 9090 9443)
                ;;
            ad)
                port_numbers=(53 88 111 135 139 389 445 464 593 636 1433 2049 3268 3269 3389 5985 5986 9389)
                ;;
            extended)
                port_numbers=(21 22 23 25 53 80 88 110 111 135 139 143 389 443 445 464 465 515 587 593 631 636 993 995 1433 2049 2375 2377 2525 3000 3268 3269 3306 3389 5000 5432 5900 5985 5986 6379 6443 8000 8008 8080 8443 8888 9000 9090 9100 9389 9443 11211 27017 54925)
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
        25 | 465 | 587 | 2525)
            printf 'SMTP\n' >> "$HINT_FILE"
            printf '%s\n' "$port" >> "$SMTP_MARKER"
            SMTP_PORT_OPEN=true
            ;;
        110 | 995)
            printf 'POP3\n' >> "$HINT_FILE"
            printf '%s\n' "$port" >> "$POP3_MARKER"
            POP3_PORT_OPEN=true
            ;;
        143 | 993)
            printf 'IMAP\n' >> "$HINT_FILE"
            printf '%s\n' "$port" >> "$IMAP_MARKER"
            IMAP_PORT_OPEN=true
            ;;
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

sps_probe_database_protocol() {
    local port="$1"
    local xml metadata evidence

    sps_command_available nmap && sps_command_available python3 || return 1
    local -a script_args=()
    if [[ "$port" == 1433 ]]; then
        script_args=(--script ms-sql-info,ms-sql-ntlm-info
            --script-args "mssql.instance-port=$port,mssql.scanned-ports-only=true")
    fi
    xml="$(timeout --kill-after=2s 30s nmap -n -Pn -sT -sV --version-light \
        "${script_args[@]}" -p "$port" -oX - "$TARGET_IPV4" 2> /dev/null)" || return 1

    metadata="$(python3 -c '
import sys
import xml.etree.ElementTree as ET

try:
    root = ET.parse(sys.stdin).getroot()
except ET.ParseError:
    sys.exit(1)

port_id = int(sys.argv[1])
port = root.find(f"./host/ports/port[@protocol=\"tcp\"][@portid=\"{port_id}\"]")
if port is None or port.find("./state[@state=\"open\"]") is None:
    sys.exit(1)
service = port.find("./service[@method=\"probed\"]")
if service is None:
    sys.exit(1)

name = service.get("name", "")
product = service.get("product", "")
version = service.get("version", "")
if name == "ms-sql-s":
    engine = "Microsoft SQL Server"
elif name in ("mysql", "mariadb"):
    if name == "mariadb" or "mariadb" in f"{product} {version}".lower():
        engine = "MariaDB"
    elif product.lower() == "mysql":
        engine = "MySQL"
    else:
        engine = "MySQL-compatible server"
else:
    sys.exit(1)

def clean_metadata(value):
    return "".join(c for c in value[:160] if c.isascii() and c.isprintable()).strip()

os_hint = clean_metadata(service.get("ostype", ""))
if not os_hint:
    import re

    banner = " ".join((product, version, service.get("extrainfo", "")))
    match = re.search(r"(?<![A-Za-z])(Ubuntu|Debian|Windows|Linux|FreeBSD|Alpine|CentOS|Red Hat)(?![A-Za-z])", banner, re.IGNORECASE)
    if match:
        os_hint = match.group(1).title()

version = clean_metadata(version) or "unknown"
os_hint = os_hint or "unknown"
details = f"{engine} (version {version}; OS hint: {os_hint})"
if name == "ms-sql-s":
    fields = {}
    for script in port.findall("script"):
        if script.get("id") not in ("ms-sql-info", "ms-sql-ntlm-info"):
            continue
        for line in script.get("output", "").splitlines():
            key, separator, value = line.strip().partition(":")
            if separator and value.strip():
                fields[key] = clean_metadata(value.strip())
    hostname = fields.get("DNS_Computer_Name") or fields.get("NetBIOS_Computer_Name")
    for label, value in (("instance", fields.get("Instance name")), ("hostname", hostname),
                         ("SQL build", fields.get("number")), ("OS build", fields.get("Product_Version"))):
        if value:
            details += f"; {label}: {value}"
print(details)
' "$port" <<< "$xml")" || return 1

    evidence="$metadata confirmed by service probe on TCP/$port"
    finding "$evidence"
    sps_record_finding \
        "DB-SERVICE-$port" "informational" "high" \
        "$evidence" "TCP port $port open|Database protocol matched" "" \
        "discovery" "" \
        "Restrict the database listener to intended clients." \
        "No credentials or SQL statements were sent."
}

sps_probe_open_port() {
    local port="$1"
    local redirect host_name ldap_uri ldap_dn ldap_output ldap_rc=0 scheme

    if [[ "$port" == 22 ]]; then
        SSH_PORT_OPEN=true
        sps_probe_ssh_banner "$TARGET_IPV4" "$port" || debug "SSH identification unavailable on TCP/$port"
    fi

    # Selected web modules require protocol evidence even when generic optional
    # preflight discovery was disabled. Every open port is tested so custom
    # --ports values can be recognized as HTTP/HTTPS services.
    if [[ "${SKIP_PREFLIGHT:-false}" != true || "${ENABLE_WEB_ENUM:-false}" == true || "${ENABLE_VHOST:-false}" == true ]]; then
        sps_probe_web_protocol "$port" || true
    fi
    [[ "${SKIP_PREFLIGHT:-false}" == true ]] && return 0

    case "$port" in
        1433 | 3306) sps_probe_database_protocol "$port" || debug "Database fingerprint unavailable on TCP/$port" ;;
    esac

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

sps_probe_ssh_banner() {
    local target="$1" port="$2"
    local identification protocol software evidence
    local pattern='^SSH-([0-9]+\.[0-9]+)-([!-~]+)( [[:print:]]*)?$'
    local LC_ALL=C

    identification="$(LC_ALL=C timeout 2s bash -c '
        exec 7<>"/dev/tcp/$1/$2" || exit 1
        for ((line_count = 0; line_count < 8; line_count++)); do
            IFS= read -r -n 255 line <&7 || exit 1
            ((${#line} < 255)) || exit 1
            case "$line" in
                SSH-*) printf "%s\n" "$line"; exit 0 ;;
            esac
        done
        exit 1
    ' _ "$target" "$port" 2> /dev/null)" || return 1
    identification="${identification%$'\r'}"
    ((${#identification} <= 253)) || return 1
    [[ "$identification" =~ $pattern ]] || return 1
    protocol="${BASH_REMATCH[1]}"
    software="${BASH_REMATCH[2]}"

    SSH_SERVICE_CONFIRMED=true
    evidence="SSH confirmed on TCP/$port (protocol $protocol, advertised software $software)."
    info "$evidence"
    sps_record_finding "SSH-SERVICE-TCP-$port" "informational" "high" "$evidence" \
        "Open TCP port|SSH server identification received" "" "discovery"
    if [[ "$software" == OpenSSH_* ]]; then
        sps_report_openssh_version "$port" "${software#OpenSSH_}" "SSH banner"
    fi
}

declare -A SPS_OPENSSH_ADVISORY_PORTS=()
declare -A SPS_SSHOLE_INVENTORY=()
declare -a SPS_SSHOLE_REPORTED_PORTS=()
SPS_SSHOLE_INPUT_ERROR=""
SPS_SSHOLE_ALPINE_ADVISORY='https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/'

sps_load_sshole_inventory() {
    local file="$1" line key value observed now
    local line_count=0
    [[ -n "$file" ]] || return 0
    SPS_SSHOLE_INVENTORY=()
    SPS_SSHOLE_INPUT_ERROR=""

    while IFS= read -r -n 257 line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        ((++line_count <= 24 && ${#line} <= 256)) || return 1
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" =~ ^([a-z_]+)=([A-Za-z0-9._:+-]+)$ ]] || return 1
        key="${BASH_REMATCH[1]}" value="${BASH_REMATCH[2]}"
        case "$key:$value" in
            target:* | port:* | observed_at:* | context:* | alpine_branch:* | package_version:* | \
                running_package:verified | running_package:unknown | \
                libc:musl | libc:glibc | libc:unknown | \
                pam:active | pam:disabled | pam:not_built | pam:unknown | \
                password_auth:enabled | password_auth:disabled | password_auth:unknown | \
                account_conditions:present | account_conditions:absent | account_conditions:unknown | \
                conflict:yes | conflict:no) ;;
            *) return 1 ;;
        esac
        [[ -z "${SPS_SSHOLE_INVENTORY[$key]+x}" ]] || return 1
        SPS_SSHOLE_INVENTORY["$key"]="$value"
    done < "$file" || return 1

    [[ "${SPS_SSHOLE_INVENTORY[target]:-}" == "$TARGET_IPV4" &&
        "${SPS_SSHOLE_INVENTORY[port]:-}" =~ ^[1-9][0-9]{0,4}$ ]] || return 1
    ((${SPS_SSHOLE_INVENTORY[port]} <= 65535)) || return 1
    if [[ -z "${SPS_SSHOLE_INVENTORY[context]:-}" ]]; then
        SPS_SSHOLE_INPUT_ERROR='Inventory is missing the assessed SSH access context.'
        return 0
    fi

    observed="${SPS_SSHOLE_INVENTORY[observed_at]:-}"
    if [[ "$observed" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] &&
        observed="$(date -u -d "$observed" +%s 2> /dev/null)" && now="$(date -u +%s)" &&
        ((observed <= now && now - observed <= 86400)); then
        return 0
    fi
    SPS_SSHOLE_INPUT_ERROR="Inventory timestamp is missing, invalid, or outside the 24-hour window."
}

# These cutoffs apply to official Alpine packages. A package on disk is
# insufficient until inventory ties that build to the running listener.
sps_sshole_alpine_patch_status() {
    local branch="$1" version="$2" fixed index
    local pattern='^([0-9]{1,3})\.([0-9]{1,3})_p([0-9]{1,3})-r([0-9]{1,3})$'
    local -a installed_parts fixed_parts
    case "$branch" in
        edge) fixed=10.6_p2-r0 ;;
        3.24) fixed=10.3_p1-r2 ;;
        3.23) fixed=10.2_p1-r1 ;;
        3.22) fixed=10.0_p1-r11 ;;
        3.21) fixed=9.9_p2-r1 ;;
        3.20) fixed=9.7_p1-r6 ;;
        3.19) fixed=9.6_p1-r3 ;;
        3.18) fixed=9.3_p2-r4 ;;
        3.17) fixed=9.1_p1-r7 ;;
        3.16) fixed=9.0_p1-r6 ;;
        *) printf '%s' unknown; return ;;
    esac
    [[ "$version" =~ $pattern ]] || { printf '%s' unknown; return; }
    installed_parts=("${BASH_REMATCH[@]}")
    [[ "$fixed" =~ $pattern ]]
    fixed_parts=("${BASH_REMATCH[@]}")
    for index in 1 2 3 4; do
        if ((10#${installed_parts[index]} < 10#${fixed_parts[index]})); then
            printf '%s' unpatched
            return
        elif ((10#${installed_parts[index]} > 10#${fixed_parts[index]})); then
            break
        fi
    done
    printf '%s' patched
}

# Vendor backports and the server's libc, PAM, and authentication
# configuration require host-side verification.
sps_report_openssh_version() {
    local port="$1" version="$2" source="$3" artifact="${4:-}"
    local major minor patch evidence candidate=false comparable=false
    local pattern='^([0-9]{1,8})\.([0-9]{1,8})(p([0-9]{1,8}))?($|[-+])'
    local advisory='https://nvd.nist.gov/vuln/detail/CVE-2026-123158'
    local remediation='Apply the distribution fix or upgrade to OpenSSH 10.6p2 or later, then restart sshd.'
    local status confidence=low severity=high verify_note=""
    local met='Open TCP port|OpenSSH service identified' missing='Host-side package, libc, PAM, password policy and account verification'
    local branch package patch_status=unknown libc pam password accounts package_series banner_series

    [[ -z "${SPS_OPENSSH_ADVISORY_PORTS[$port]+x}" ]] || return 0
    [[ "$version" =~ ^[0-9A-Za-z._+-]{1,64}$ ]] || version=""
    if [[ "$version" =~ $pattern ]]; then
        major="${BASH_REMATCH[1]}" minor="${BASH_REMATCH[2]}" patch="${BASH_REMATCH[4]:-}"
        comparable=true
        if ((10#$major < 10 || (10#$major == 10 &&
            (10#$minor < 6 || (10#$minor == 6 && 10#${patch:-0} < 2))))); then
            candidate=true
        fi
    fi

    if [[ "${SPS_SSHOLE_INVENTORY[port]:-}" == "$port" ]]; then
        branch="${SPS_SSHOLE_INVENTORY[alpine_branch]:-unknown}"
        package="${SPS_SSHOLE_INVENTORY[package_version]:-unknown}"
        libc="${SPS_SSHOLE_INVENTORY[libc]:-unknown}" pam="${SPS_SSHOLE_INVENTORY[pam]:-unknown}"
        password="${SPS_SSHOLE_INVENTORY[password_auth]:-unknown}" accounts="${SPS_SSHOLE_INVENTORY[account_conditions]:-unknown}"
        verify_note="$SPS_SSHOLE_INPUT_ERROR"
        if [[ "${SPS_SSHOLE_INVENTORY[conflict]:-no}" == yes ]]; then
            verify_note='Host inventory contains conflicting evidence.'
        elif [[ "${SPS_SSHOLE_INVENTORY[running_package]:-unknown}" == verified ]]; then
            patch_status="$(sps_sshole_alpine_patch_status "$branch" "$package")"
            if [[ "$patch_status" != unknown && "$comparable" == true ]]; then
                package_series="${package%-r*}"
                banner_series="$major.$minor"
                [[ -z "$patch" ]] || banner_series+="_p$patch"
                if [[ -z "$patch" ]]; then
                    package_series="${package_series%_p*}"
                fi
                [[ "$package_series" == "$banner_series" ]] || verify_note='Running package conflicts with the SSH fingerprint.'
            fi
        fi

        met+='|Authorized inventory matched the target IP and TCP port'
        evidence="Host inventory observed ${SPS_SSHOLE_INVENTORY[observed_at]:-unknown}, context ${SPS_SSHOLE_INVENTORY[context]:-unknown}, Alpine $branch, package $package, patch $patch_status, libc $libc, PAM $pam, password policy $password, account conditions $accounts."
        if [[ -n "$verify_note" ]]; then
            status=INCONCLUSIVE
            missing='Fresh, consistent host-side evidence'
        elif [[ "$patch_status" == patched || "$libc" == glibc || "$pam" == active || "$password" == disabled || "$accounts" == absent ]]; then
            status=NOT_AFFECTED confidence=high severity=informational missing=""
        elif [[ "$patch_status" == unpatched && "$libc" == musl && "$password" == enabled ]]; then
            if [[ ( "$pam" == disabled || "$pam" == not_built ) && "$accounts" == present ]]; then
                status=VULNERABLE confidence=high missing=""
            else
                status=LIKELY_VULNERABLE confidence=medium missing='Effective PAM or account prerequisite verification'
            fi
        elif [[ "$candidate" == true ]]; then
            status=POTENTIALLY_VULNERABLE
        else
            status=INCONCLUSIVE
        fi
    elif [[ "$candidate" == true ]]; then
        status=POTENTIALLY_VULNERABLE
    else
        return 0
    fi

    SPS_OPENSSH_ADVISORY_PORTS["$port"]="$status"
    SPS_SSHOLE_REPORTED_PORTS+=("$port")
    evidence="CVE-2026-123158 (SSHole, CVSS 3.1 8.1) on TCP/$port: $status. $source identified OpenSSH ${version:-with no version}. ${evidence:-} $verify_note"
    if [[ "$status" == NOT_AFFECTED ]]; then
        info "$evidence"
        remediation=""
    else
        warn "$evidence"
        [[ -z "$missing" ]] || note "Evidence needed: $missing"
    fi
    sps_record_finding \
        "CVE-2026-123158-TCP-$port" "$severity" "$confidence" "$evidence" \
        "$met" "$missing" "discovery" "$artifact" "$remediation $advisory $SPS_SSHOLE_ALPINE_ADVISORY" "" "$status"
}

sps_finish_sshole_assessment() {
    local inventory_port="${SPS_SSHOLE_INVENTORY[port]:-}" port status
    if [[ -n "$inventory_port" && -z "${SPS_OPENSSH_ADVISORY_PORTS[$inventory_port]+x}" ]]; then
        status=SKIPPED
        SPS_OPENSSH_ADVISORY_PORTS["$inventory_port"]="$status"
        SPS_SSHOLE_REPORTED_PORTS+=("$inventory_port")
        info "CVE-2026-123158 (SSHole) on TCP/$inventory_port: $status. OpenSSH could not be identified on the inventory endpoint."
        sps_record_finding "CVE-2026-123158-TCP-$inventory_port" "informational" "low" \
            "OpenSSH could not be identified on the inventory endpoint." "" "OpenSSH service identification" \
            "discovery" "" "" "" "$status"
    fi
    if [[ -n "${ATTACK_PATH_REPORT:-}" ]]; then
        for port in "${SPS_SSHOLE_REPORTED_PORTS[@]}"; do
            status="${SPS_OPENSSH_ADVISORY_PORTS[$port]}"
            sps_atomic_append "$ATTACK_PATH_REPORT" "[Exposure context] CVE-2026-123158 TCP/$port: $status"
        done
    fi
}

sps_report_openssh_advisory() {
    local nmap_output="$1"
    local port product version

    while read -r port product version; do
        [[ "$port" == 22 ]] && SSH_SERVICE_CONFIRMED=true
        if [[ "$product" == OpenSSH ]]; then
            sps_report_openssh_version "$port" "$version" "Nmap" "$nmap_output"
        fi
    done < <(awk '
        $1 ~ /^[0-9]+\/tcp$/ && $2 == "open" && $3 == "ssh" {
            sub(/\/tcp$/, "", $1)
            print $1, $4, $5
        }
    ' "$nmap_output")
}

sps_run_service_probes() {
    local port
    for port in "$@"; do
        sps_probe_open_port "$port" || debug "Optional discovery probe failed for port $port"
    done
}

run_port_scan() {
    local target="$1"
    shift
    local -a entries=("$@")
    local -a pids=()
    local -a result_files=()
    local entry port service level result_file temporary pid
    local result_dir db_engine db_command

    result_dir="$(mktemp -d "$RUNTIME_TMP_DIR/port-results.XXXXXX")"
    sps_section "Running Port Scan"
    info "Scanning ${#entries[@]} TCP port(s) with ${MAX_JOBS} worker(s), ${CONNECT_TIMEOUT}s timeout, ${RETRY_LIMIT} retry/retries"

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
        case "$port" in
            1433) db_engine=mssql ;;
            3306) db_engine=mysql ;;
            *) continue ;;
        esac
        printf -v db_command 'fathomtrace db-inventory %s %q %q %s' \
            "$db_engine" "${TARGET:-$target}" "${AUTH_USER:-YOUR_DB_USER}" "$port"
        info "If this is a database listener, list visible databases and tables: $db_command"
    done

}

sps_print_dry_run() {
    local port_list=""
    local udp_port_list=""
    local entry port
    for entry in "${PORTS[@]}"; do
        IFS=: read -r port _ <<< "$entry"
        port_list+="${port_list:+,}$port"
    done
    if [[ "${ENABLE_UDP_SCAN:-true}" == true ]]; then
        for port in "${UDP_PORTS[@]:-}"; do
            [[ -n "$port" ]] && udp_port_list+="${udp_port_list:+,}$port"
        done
    else
        udp_port_list="disabled"
    fi
    info "Dry run: command=$COMMAND target=${ORIGINAL_TARGET:-$TARGET} resolved=${TARGET_IPV4:-unresolved}"
    info "Dry run: profile=$SCAN_PROFILE tcp-ports=$port_list udp-ports=${udp_port_list:-none} jobs=$MAX_JOBS timeout=$CONNECT_TIMEOUT retries=$RETRY_LIMIT"
    info "Dry run: loot=$LOOT_ENABLED format=$OUTPUT_FORMAT optional-preflight=$([[ "$SKIP_PREFLIGHT" == true ]] && printf disabled || printf enabled)"
}
