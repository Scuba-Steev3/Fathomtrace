#!/usr/bin/env bash

sps_parse_cme_users() {
    awk '
        /^[A-Z]+[[:space:]]+[0-9.]+/ {
            user_field=0

            # Status lines can contain examples such as domain\\username.
            # Only account-result lines lack a CrackMapExec status marker.
            for (i=1; i<=NF; i++) {
                if ($i ~ /^\[[*+-]\]$/) next
                if ($i ~ /\\/) {
                    user_field=i
                    break
                }
            }

            if (user_field == 0) next

            split($user_field, account, "\\")
            user=account[length(account)]
            if (user == "") next

            desc=""
            for (i=user_field+1; i<=NF; i++) {
                desc=desc (desc == "" ? "" : " ") $i
            }
            sub(/^desc:[[:space:]]*/, "", desc)
            print user "|" desc
        }
    ' | sort -u
}

sps_classify_cme_user_enum() {
    local raw_output="$1"
    local command_status="$2"
    local parsed_users="$3"

    # A successful fallback wins over earlier errors in the same CME run.
    if [[ -n "$parsed_users" ]]; then
        printf 'enumerated\n'
    elif grep -qiE '\[-\].*(STATUS_LOGON_FAILURE|NT_STATUS_LOGON_FAILURE|ACCESS_DENIED)' <<< "$raw_output"; then
        printf 'auth_failed\n'
    elif grep -qiE 'Error enumerating domain users|NTLM needs domain\\\\username' <<< "$raw_output"; then
        printf 'enumeration_denied\n'
    elif [[ "$command_status" -ne 0 ]] && ! grep -q '\[+\]' <<< "$raw_output"; then
        printf 'command_failed\n'
    else
        printf 'no_users\n'
    fi
}
