#!/usr/bin/env bash

# Parse bloodyAD writable-object records and emit only explicit WriteOwner
# rights as distinguished-name|object-type|right tuples.
sps_parse_bloodyad_writeowner() {
    awk '
        function emit_record(upper_dn, object_type) {
            if (dn == "" || !write_owner) return
            upper_dn=toupper(dn)
            if (upper_dn ~ /^CN=\{[0-9A-F-]+\},CN=POLICIES,CN=SYSTEM,/) {
                object_type="GPO"
            } else if (upper_dn ~ /^OU=/) {
                object_type="OU"
            } else if (upper_dn ~ /^CN=/) {
                object_type="Object"
            } else {
                object_type="DirectoryObject"
            }
            print dn "|" object_type "|WriteOwner"
        }

        /^[[:space:]]*$/ {
            emit_record()
            dn=""
            write_owner=0
            next
        }

        /^[[:space:]]*[Dd]istinguished[Nn]ame:[[:space:]]*/ {
            line=$0
            sub(/^[[:space:]]*[Dd]istinguished[Nn]ame:[[:space:]]*/, "", line)
            dn=line
            next
        }

        {
            upper=toupper($0)
            if (upper ~ /OWNER:[[:space:]]*WRITE([[:space:]]|$)/ ||
                upper ~ /WRITE[_ -]OWNER([[:space:]]|$)/) {
                write_owner=1
            }
        }

        END { emit_record() }
    '
}

# Run both read-only writable-object audits unless the operator opts out.
sps_run_ad_dacl_audits() {
    if [[ "${LDAP_BIND_TYPE:-}" != "auth" ]]; then
        return 0
    fi

    if [[ "${SKIP_DACL_AUDIT:-false}" == true ]]; then
        info "Skipping Impacket and bloodyAD writable-object audits (--skip-dacl-audit)"
        return 0
    fi

    info "Checking Active Directory for writable objects and exploitable ACL permissions (Authenticated only)"
    note "Impacket checks selected high-value objects; bloodyAD searches directory-wide for effective write access"
    run_impacket_dacl_audit || true
    run_bloodyad_writable_audit || true
}
