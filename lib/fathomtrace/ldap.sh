#!/usr/bin/env bash

# Parse NetExec LDAP --query output for domain-controller OS records.
# Output fields: distinguished name|DNS hostname|operating system|OS version
sps_parse_netexec_dc_os() {
    awk '
        function flush_record() {
            if (dn != "" || hostname != "" || os != "" || version != "") {
                print dn "|" hostname "|" os "|" version
            }

            dn=""
            hostname=""
            os=""
            version=""
        }

        /Response for object:/ {
            flush_record()
            dn=$0
            sub(/\r$/, "", dn)
            sub(/^.*Response for object:[[:space:]]*/, "", dn)
            next
        }

        {
            line=$0
            sub(/\r$/, "", line)
            sub(/^[[:space:]]*LDAP[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+[^[:space:]]+[[:space:]]+/, "", line)

            # Match the complete attribute name so operatingSystemVersion is
            # never consumed as operatingSystem. Attribute order is arbitrary.
            if (line ~ /^operatingSystemVersion[[:space:]]+/) {
                sub(/^operatingSystemVersion[[:space:]]+/, "", line)
                version=line
                next
            }

            if (line ~ /^operatingSystem[[:space:]]+/) {
                sub(/^operatingSystem[[:space:]]+/, "", line)
                os=line
                next
            }

            if (line ~ /^dNSHostName[[:space:]]+/) {
                sub(/^dNSHostName[[:space:]]+/, "", line)
                hostname=line
                next
            }
        }

        END {
            flush_record()
        }
    '
}
