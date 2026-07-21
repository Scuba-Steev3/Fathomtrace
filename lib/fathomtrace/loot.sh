#!/usr/bin/env bash

declare -gA SPS_HASH_PATHS=()
declare -gA SPS_FINDING_IDS=()
MANIFEST_ENTRY_COUNT=0
FINDING_ENTRY_COUNT=0

sanitize_name() {
    local value="${1:-target}"
    value="${value##*/}"
    value="${value//[^A-Za-z0-9_.-]/_}"
    while [[ "$value" == *..* ]]; do value="${value//../_}"; done
    while [[ "$value" == .* ]]; do value="${value#.}"; done
    while [[ "$value" == *. ]]; do value="${value%.}"; done
    printf '%.120s' "${value:-target}"
}

sps_sha256() {
    local path="$1"
    if sps_command_available sha256sum; then
        sha256sum "$path" | awk '{print $1}'
    elif sps_command_available shasum; then
        shasum -a 256 "$path" | awk '{print $1}'
    elif sps_command_available openssl; then
        openssl dgst -sha256 "$path" | awk '{print $NF}'
    else
        return 1
    fi
}

sps_atomic_write() {
    local destination="$1"
    local directory temporary
    directory="$(dirname -- "$destination")"
    mkdir -p -- "$directory"
    temporary="$(mktemp "$directory/.tmp.XXXXXX")"
    cat > "$temporary"
    chmod 600 "$temporary" 2> /dev/null || true
    mv -f -- "$temporary" "$destination"
}

sps_atomic_append() {
    local destination="$1"
    local line="$2"
    local directory temporary
    directory="$(dirname -- "$destination")"
    mkdir -p -- "$directory"
    temporary="$(mktemp "$directory/.tmp.XXXXXX")"
    [[ -f "$destination" ]] && cat -- "$destination" > "$temporary"
    printf '%s\n' "$line" >> "$temporary"
    chmod 600 "$temporary" 2> /dev/null || true
    mv -f -- "$temporary" "$destination"
}

sps_path_is_safe_session() {
    local path="$1"
    [[ -n "$path" && "$path" != "/" && "$path" != "." && "$path" != "$HOME" ]]
}

sps_make_session_id() {
    local suffix
    if [[ -n "${SPS_SESSION_ID:-}" ]]; then
        sanitize_name "$SPS_SESSION_ID"
        return
    fi
    printf -v suffix '%04x%04x' "$RANDOM" "$$"
    printf '%s_%s' "$(date -u +'%Y%m%dT%H%M%SZ')" "$suffix"
}

init_artifacts() {
    local safe_target requested_dir session_path
    safe_target="$(sanitize_name "${TARGET_IPV4:-$TARGET}")"
    SESSION_ID="$(sps_make_session_id)"
    ORIGINAL_WORKING_DIR="$PWD"

    if [[ -n "${DNS_WORDLIST:-}" && -f "${DNS_WORDLIST:-}" && "$DNS_WORDLIST" != /* ]]; then
        DNS_WORDLIST="$PWD/$DNS_WORDLIST"
    fi

    umask 077
    if [[ "${LOOT_ENABLED:-true}" != true ]]; then
        WORKING_ARTIFACT_DIR="$RUNTIME_TMP_DIR/session"
        mkdir -p "$WORKING_ARTIFACT_DIR"
        ARTIFACT_ROOT=""
        COMMANDS_DIR="$WORKING_ARTIFACT_DIR/commands"
        EVIDENCE_DIR="$WORKING_ARTIFACT_DIR/evidence"
        RAW_DIR="$WORKING_ARTIFACT_DIR/raw"
        PARSED_DIR="$WORKING_ARTIFACT_DIR/parsed"
        LOOT_DIR="$WORKING_ARTIFACT_DIR/loot"
        REPORTS_DIR="$WORKING_ARTIFACT_DIR/reports"
        MANIFEST_FILE=""
        MANIFEST_CSV_FILE=""
        LOOT_INDEX_FILE=""
        REPEATABLE_COMMANDS_FILE=""
        ATTACK_PATH_REPORT=""
        FINDINGS_FILE=""
        mkdir -p "$COMMANDS_DIR" "$EVIDENCE_DIR" "$RAW_DIR" "$PARSED_DIR" "$LOOT_DIR" "$REPORTS_DIR"
        cd "$WORKING_ARTIFACT_DIR" || return 5
        debug "Persistent artifact collection disabled; transient outputs use $WORKING_ARTIFACT_DIR"
        return 0
    fi

    requested_dir="${LOOT_BASE_DIR:-recon_${safe_target}}"
    mkdir -p -- "$requested_dir"
    session_path="$requested_dir/$SESSION_ID"

    if [[ -e "$session_path" ]]; then
        if [[ "${OVERWRITE:-false}" != true ]]; then
            error "Artifact session already exists: $session_path (use --overwrite to replace it)"
            return 5
        fi
        sps_path_is_safe_session "$session_path" || {
            error "Refusing unsafe artifact overwrite path: $session_path"
            return 5
        }
        rm -rf -- "$session_path"
    fi

    mkdir -p "$session_path"
    cd "$session_path" || return 5
    ARTIFACT_ROOT="$PWD"
    WORKING_ARTIFACT_DIR="."
    COMMANDS_DIR="commands"
    EVIDENCE_DIR="evidence"
    RAW_DIR="raw"
    PARSED_DIR="parsed"
    LOOT_DIR="loot"
    REPORTS_DIR="reports"
    mkdir -p "$COMMANDS_DIR" "$EVIDENCE_DIR" "$RAW_DIR" "$PARSED_DIR" "$LOOT_DIR" "$REPORTS_DIR"
    chmod 700 . "$COMMANDS_DIR" "$EVIDENCE_DIR" "$RAW_DIR" "$PARSED_DIR" "$LOOT_DIR" "$REPORTS_DIR" 2> /dev/null || true

    REPEATABLE_COMMANDS_FILE="$COMMANDS_DIR/repeatable_commands.txt"
    ATTACK_PATH_REPORT="$REPORTS_DIR/attack_path_engine.txt"
    LOOT_INDEX_FILE="$REPORTS_DIR/loot_index.txt"
    MANIFEST_FILE="$REPORTS_DIR/manifest.jsonl"
    MANIFEST_CSV_FILE="$REPORTS_DIR/manifest.csv"
    FINDINGS_FILE="$REPORTS_DIR/findings.jsonl"

    {
        printf '# Repeatable commands for report generation\n'
        printf '# Target: %s\n' "${TARGET_IPV4:-$TARGET}"
        printf '# Session: %s\n' "$SESSION_ID"
        printf '# Generated: %s\n\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    } | sps_atomic_write "$REPEATABLE_COMMANDS_FILE"
    {
        printf '# Attack Path Engine\n'
        printf '# Target: %s\n' "${TARGET_IPV4:-$TARGET}"
        printf '# Session: %s\n' "$SESSION_ID"
        printf '# Generated: %s\n\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    } | sps_atomic_write "$ATTACK_PATH_REPORT"
    : | sps_atomic_write "$LOOT_INDEX_FILE"
    : | sps_atomic_write "$MANIFEST_FILE"
    : | sps_atomic_write "$FINDINGS_FILE"
    printf 'collection_time,source,command,module,size,sha256,local_path,status,sensitive,duplicate_of,error\n' |
        sps_atomic_write "$MANIFEST_CSV_FILE"

    success "Artifact session initialized: $ARTIFACT_ROOT"
    warn "The artifact directory may contain credentials, hashes, tickets, or other sensitive assessment data."
}

sps_record_manifest() {
    [[ "${LOOT_ENABLED:-true}" == true && -n "${MANIFEST_FILE:-}" ]] || return 0
    local source="${1:-unknown}"
    local command_text="${2:-}"
    local module="${3:-general}"
    local size="${4:-0}"
    local checksum="${5:-}"
    local local_path="${6:-}"
    local status="${7:-collected}"
    local sensitive="${8:-false}"
    local duplicate_of="${9:-}"
    local failure="${10:-}"
    local collected_at json_line csv_line

    collected_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    [[ "${SHOW_SECRETS:-false}" == true ]] && sensitive=true
    command_text="$(sps_redact "$command_text")"
    source="$(sps_redact "$source")"
    failure="$(sps_redact "$failure")"

    printf -v json_line '{"collection_time":"%s","source":"%s","command":"%s","module":"%s","size":%s,"sha256":"%s","local_path":"%s","status":"%s","sensitive":%s,"duplicate_of":%s,"error":%s}' \
        "$(sps_json_escape "$collected_at")" "$(sps_json_escape "$source")" \
        "$(sps_json_escape "$command_text")" "$(sps_json_escape "$module")" "$size" \
        "$(sps_json_escape "$checksum")" "$(sps_json_escape "$local_path")" \
        "$(sps_json_escape "$status")" "$sensitive" \
        "$([[ -n "$duplicate_of" ]] && printf '"%s"' "$(sps_json_escape "$duplicate_of")" || printf 'null')" \
        "$([[ -n "$failure" ]] && printf '"%s"' "$(sps_json_escape "$failure")" || printf 'null')"
    sps_atomic_append "$MANIFEST_FILE" "$json_line"

    printf -v csv_line '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s' \
        "$(sps_csv_escape "$collected_at")" "$(sps_csv_escape "$source")" \
        "$(sps_csv_escape "$command_text")" "$(sps_csv_escape "$module")" "$size" \
        "$(sps_csv_escape "$checksum")" "$(sps_csv_escape "$local_path")" \
        "$(sps_csv_escape "$status")" "$sensitive" \
        "$(sps_csv_escape "$duplicate_of")" "$(sps_csv_escape "$failure")"
    sps_atomic_append "$MANIFEST_CSV_FILE" "$csv_line"
    MANIFEST_ENTRY_COUNT=$((MANIFEST_ENTRY_COUNT + 1))
}

record_command() {
    local section="${1:-General}"
    local description="${2:-Command}"
    local command_text="${3:-}"
    [[ -n "$command_text" && -n "${REPEATABLE_COMMANDS_FILE:-}" ]] || return 0
    command_text="$(sps_redact "$command_text")"
    local block
    printf -v block '## [%s] %s\n%s\n' "$section" "$description" "$command_text"
    sps_atomic_append "$REPEATABLE_COMMANDS_FILE" "$block"
}

record_command_argv() {
    local section="${1:-General}"
    local description="${2:-Command}"
    shift 2 || true
    record_command "$section" "$description" "$(sps_shell_join "$@")"
}

sps_json_array_from_delimited() {
    local value="${1:-}"
    local delimiter="${2:-|}"
    local item output=""
    local -a items=()
    [[ -n "$value" ]] || {
        printf '[]'
        return 0
    }
    IFS="$delimiter" read -r -a items <<< "$value"
    for item in "${items[@]}"; do
        [[ -n "$item" ]] || continue
        output+="${output:+,}\"$(sps_json_escape "$item")\""
    done
    printf '[%s]' "$output"
}

# Stable JSONL finding schema for reporting and downstream tooling. Delimited
# list arguments use a pipe so human-readable evidence may still contain commas.
sps_record_finding() {
    [[ "${LOOT_ENABLED:-true}" == true && -n "${FINDINGS_FILE:-}" ]] || return 0
    local finding_id="${1:?finding id required}"
    local severity="${2:-informational}"
    local confidence="${3:-low}"
    local evidence="${4:-}"
    local prerequisites_met="${5:-}"
    local prerequisites_missing="${6:-}"
    local action_class="${7:-discovery}"
    local artifact_paths="${8:-}"
    local remediation="${9:-}"
    local cleanup_notes="${10:-}"
    local observed_at json_line

    [[ -z "${SPS_FINDING_IDS[$finding_id]+x}" ]] || return 0
    SPS_FINDING_IDS["$finding_id"]=1
    observed_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    evidence="$(sps_redact "$evidence")"
    remediation="$(sps_redact "$remediation")"
    cleanup_notes="$(sps_redact "$cleanup_notes")"

    printf -v json_line '{"finding_id":"%s","severity":"%s","confidence":"%s","evidence":"%s","prerequisites":{"met":%s,"missing":%s},"action_class":"%s","artifact_paths":%s,"remediation":"%s","cleanup_notes":"%s","observed_at":"%s"}' \
        "$(sps_json_escape "$finding_id")" \
        "$(sps_json_escape "$severity")" \
        "$(sps_json_escape "$confidence")" \
        "$(sps_json_escape "$evidence")" \
        "$(sps_json_array_from_delimited "$prerequisites_met")" \
        "$(sps_json_array_from_delimited "$prerequisites_missing")" \
        "$(sps_json_escape "$action_class")" \
        "$(sps_json_array_from_delimited "$artifact_paths")" \
        "$(sps_json_escape "$remediation")" \
        "$(sps_json_escape "$cleanup_notes")" \
        "$(sps_json_escape "$observed_at")"
    sps_atomic_append "$FINDINGS_FILE" "$json_line"
    FINDING_ENTRY_COUNT=$((FINDING_ENTRY_COUNT + 1))
}

record_loot() {
    local kind="${1:-loot}"
    local value="${2:-}"
    local evidence="${3:-}"
    local sensitive=false size=0 checksum="" duplicate_of="" status="recorded"
    [[ "${LOOT_ENABLED:-true}" == true ]] || return 0
    [[ -n "$value" || -n "$evidence" ]] || return 0

    [[ "$kind $value $evidence" =~ [Cc]red|[Pp]ass|[Hh]ash|[Tt]oken|[Kk]ey|[Tt]icket|[Pp][Ff][Xx]|[Cc]cache ]] && sensitive=true
    if [[ -f "$evidence" ]]; then
        size="$(wc -c < "$evidence" | tr -d '[:space:]')"
        checksum="$(sps_sha256 "$evidence" 2> /dev/null || true)"
        status="collected"
        if [[ -n "$checksum" && -n "${SPS_HASH_PATHS[$checksum]+x}" ]]; then
            duplicate_of="${SPS_HASH_PATHS[$checksum]}"
            status="duplicate"
        elif [[ -n "$checksum" ]]; then
            SPS_HASH_PATHS["$checksum"]="$evidence"
        fi
    fi

    if [[ -n "${LOOT_INDEX_FILE:-}" ]]; then
        local index_line
        printf -v index_line '[%s] %s%s' "$kind" "$(sps_redact "$value")" \
            "$([[ -n "$evidence" ]] && printf ' | evidence: %s' "$evidence")"
        sps_atomic_append "$LOOT_INDEX_FILE" "$index_line"
    fi
    sps_record_manifest "$value" "${CURRENT_COMMAND:-}" "$kind" "$size" "$checksum" "$evidence" "$status" "$sensitive" "$duplicate_of" ""
}

sps_store_artifact() {
    local source="$1"
    local module="${2:-general}"
    local data_class="${3:-raw}"
    local source_label="${4:-$source}"
    local destination_dir destination basename safe_base checksum suffix temporary
    local sensitive=false
    [[ "${LOOT_ENABLED:-true}" == true ]] || return 0
    [[ -f "$source" ]] || {
        sps_record_manifest "$source_label" "" "$module" 0 "" "" "failed" false "" "source file not found"
        return 1
    }

    checksum="$(sps_sha256 "$source" 2> /dev/null || true)"
    [[ "$data_class $source_label $source" =~ [Ll]oot|[Cc]red|[Pp]ass|[Hh]ash|[Tt]oken|[Kk]ey|[Tt]icket|[Pp][Ff][Xx]|[Cc]cache ]] && sensitive=true
    if [[ -n "$checksum" && -n "${SPS_HASH_PATHS[$checksum]+x}" ]]; then
        printf '%s' "${SPS_HASH_PATHS[$checksum]}"
        sps_record_manifest "$source_label" "" "$module" "$(wc -c < "$source" | tr -d '[:space:]')" "$checksum" \
            "${SPS_HASH_PATHS[$checksum]}" "duplicate" "$sensitive" "${SPS_HASH_PATHS[$checksum]}" ""
        return 0
    fi

    case "$data_class" in
        raw) destination_dir="$RAW_DIR" ;;
        parsed) destination_dir="$PARSED_DIR" ;;
        loot) destination_dir="$LOOT_DIR" ;;
        *) destination_dir="$EVIDENCE_DIR" ;;
    esac
    basename="${source##*/}"
    safe_base="$(sanitize_name "$basename")"
    suffix="${checksum:0:12}"
    [[ -n "$suffix" ]] || printf -v suffix '%04x%04x' "$RANDOM" "$$"
    destination="$destination_dir/$safe_base"
    if [[ -e "$destination" && "$safe_base" == *.* ]]; then
        destination="$destination_dir/${safe_base%.*}_${suffix}.${safe_base##*.}"
    elif [[ -e "$destination" ]]; then
        destination="$destination_dir/${safe_base}_${suffix}"
    fi
    temporary="$(mktemp "$destination_dir/.artifact.XXXXXX")"
    cp -- "$source" "$temporary"
    chmod 600 "$temporary" 2> /dev/null || true
    mv -f -- "$temporary" "$destination"
    [[ -n "$checksum" ]] && SPS_HASH_PATHS["$checksum"]="$destination"
    sps_record_manifest "$source_label" "" "$module" "$(wc -c < "$destination" | tr -d '[:space:]')" "$checksum" "$destination" "collected" "$sensitive" "" ""
    printf '%s' "$destination"
}

record_module_status() {
    local module="$1"
    local status="$2"
    local reason="${3:-}"
    sps_record_manifest "$module" "" "$module" 0 "" "" "$status" false "" "$reason"
}

sps_organize_session_root() {
    [[ "${LOOT_ENABLED:-true}" == true && "${WORKING_ARTIFACT_DIR:-}" == "." ]] || return 0
    local source basename safe_base destination_dir destination checksum suffix
    local -a root_files=()
    mapfile -t root_files < <(find . -maxdepth 1 -type f -print | sort)
    for source in "${root_files[@]}"; do
        basename="${source#./}"
        safe_base="$(sanitize_name "$basename")"
        case "$safe_base" in
            *[Cc]red* | *[Pp]ass* | *[Hh]ash* | *[Tt]oken* | *[Kk]ey* | *[Tt]icket* | *.pfx | *.ccache)
                destination_dir="$LOOT_DIR"
                ;;
            *.csv | *.json | *.jsonl | users_* | groups_* | computers_* | *parsed*)
                destination_dir="$PARSED_DIR"
                ;;
            *)
                destination_dir="$RAW_DIR"
                ;;
        esac
        destination="$destination_dir/$safe_base"
        if [[ -e "$destination" ]]; then
            checksum="$(sps_sha256 "$source" 2> /dev/null || true)"
            suffix="${checksum:0:12}"
            [[ -n "$suffix" ]] || printf -v suffix '%04x%04x' "$RANDOM" "$$"
            if [[ "$safe_base" == *.* ]]; then
                destination="$destination_dir/${safe_base%.*}_${suffix}.${safe_base##*.}"
            else
                destination="$destination_dir/${safe_base}_${suffix}"
            fi
        fi
        mv -- "$source" "$destination"
        chmod 600 "$destination" 2> /dev/null || true
    done
}

sps_finalize_artifacts() {
    [[ "${LOOT_ENABLED:-true}" == true && -n "${ARTIFACT_ROOT:-}" && -n "${MANIFEST_FILE:-}" ]] || return 0
    local artifact kind console_capture capture_label
    local -a artifacts=()
    sps_organize_session_root
    if [[ -s "${MACHINE_CAPTURE_FILE:-}" ]]; then
        console_capture="$RUNTIME_TMP_DIR/console-capture.txt"
        capture_label="captured legacy console output (redacted)"
        [[ "${SHOW_SECRETS:-false}" == true ]] && capture_label="captured legacy console output (secrets visible)"
        sps_redact_file "$MACHINE_CAPTURE_FILE" | sps_atomic_write "$console_capture"
        sps_store_artifact "$console_capture" "console" "raw" "$capture_label" > /dev/null || true
    fi
    if sps_command_available find; then
        mapfile -t artifacts < <(find "$WORKING_ARTIFACT_DIR" -type f -print | sort)
        for artifact in "${artifacts[@]}"; do
            case "$artifact" in
                "$MANIFEST_FILE" | "./$MANIFEST_FILE" | "$MANIFEST_CSV_FILE" | "./$MANIFEST_CSV_FILE" | "$LOOT_INDEX_FILE" | "./$LOOT_INDEX_FILE") continue ;;
                "./$RAW_DIR"/* | "$RAW_DIR"/*) kind="raw" ;;
                "./$PARSED_DIR"/* | "$PARSED_DIR"/*) kind="parsed" ;;
                "./$REPORTS_DIR"/* | "$REPORTS_DIR"/* | "./$COMMANDS_DIR"/* | "$COMMANDS_DIR"/*) kind="report" ;;
                *) kind="artifact" ;;
            esac
            record_loot "$kind" "${artifact##*/}" "$artifact"
        done
    fi
    sps_record_manifest "${ORIGINAL_TARGET:-${TARGET:-}}" "${INVOCATION:-}" "scan" 0 "" "$ARTIFACT_ROOT" "completed" false "" ""
    case "${INDEX_FORMAT:-json}" in
        text)
            rm -f -- "$MANIFEST_FILE" "$MANIFEST_CSV_FILE"
            MANIFEST_FILE="$LOOT_INDEX_FILE"
            ;;
        json) rm -f -- "$MANIFEST_CSV_FILE" ;;
        csv)
            rm -f -- "$MANIFEST_FILE"
            MANIFEST_FILE="$MANIFEST_CSV_FILE"
            ;;
        all) ;;
    esac
}

sps_restore_working_directory() {
    [[ -n "${ORIGINAL_WORKING_DIR:-}" && -d "${ORIGINAL_WORKING_DIR:-}" ]] && cd "$ORIGINAL_WORKING_DIR" || true
}
