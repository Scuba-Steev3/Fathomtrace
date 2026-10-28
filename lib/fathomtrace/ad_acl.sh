#!/usr/bin/env bash

# Normalize directory-wide effective WriteOwner results from bloodyAD output.
# Output fields: target DN|object type|right
sps_parse_bloodyad_writeowner() {
    awk '
        function classify_target(target, lower_target) {
            lower_target=tolower(target)

            if (lower_target ~ /,cn=policies,cn=system,/) return "GPO"
            if (lower_target ~ /^ou=/) return "OU"
            if (lower_target ~ /^dc=/) return "DOMAIN"
            if (lower_target ~ /^cn=/) return "DIRECTORY_OBJECT"
            return "UNKNOWN"
        }

        function emit_target() {
            if (target_dn != "" && write_owner) {
                print target_dn "|" classify_target(target_dn) "|WriteOwner"
            }

            target_dn=""
            write_owner=0
        }

        /^[[:space:]]*distinguishedName[[:space:]]*:/ {
            emit_target()
            target_dn=$0
            sub(/^[[:space:]]*distinguishedName[[:space:]]*:[[:space:]]*/, "", target_dn)
            sub(/\r$/, "", target_dn)
            next
        }

        {
            line=tolower($0)

            # bloodyAD get writable reports effective WRITE_OWNER as
            # "OWNER: WRITE". Also accept names emitted by ACL/BloodHound
            # tooling so the parser remains useful across supported versions.
            if (line ~ /^[[:space:]]*owner[[:space:]]*:[[:space:]]*write([[:space:]]|$)/ ||
                line ~ /write[_ -]?owner/ ||
                line ~ /right_write_owner/) {
                write_owner=1
            }
        }

        END {
            emit_target()
        }
    ' | sort -u
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
