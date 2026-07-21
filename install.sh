#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PREFIX="${PREFIX:-${HOME:?}/.local}"
INSTALL_LEGACY_WRAPPER=true

usage() {
    cat << 'EOF'
Usage: ./install.sh [--prefix PATH] [--no-legacy-wrapper]

Install Fathomtrace under PATH/bin and PATH/lib/fathomtrace.
The default prefix is $HOME/.local.
EOF
}

while (($#)); do
    case "$1" in
        --prefix)
            shift
            [[ -n "${1:-}" ]] || {
                printf '%s\n' '[-] --prefix requires a path.' >&2
                exit 2
            }
            PREFIX="$1"
            ;;
        --prefix=*) PREFIX="${1#*=}" ;;
        --no-legacy-wrapper) INSTALL_LEGACY_WRAPPER=false ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            printf '[-] Unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

[[ -n "$PREFIX" && "$PREFIX" != "/" ]] || {
    printf '[-] Refusing unsafe installation prefix: %s\n' "$PREFIX" >&2
    exit 2
}

BIN_DIR="$PREFIX/bin"
LIB_DIR="$PREFIX/lib/fathomtrace"
mkdir -p -- "$BIN_DIR" "$LIB_DIR"
install -m 0755 "$SCRIPT_DIR/fathomtrace" "$BIN_DIR/fathomtrace"
install -m 0644 "$SCRIPT_DIR"/lib/fathomtrace/*.sh "$LIB_DIR/"
if [[ "$INSTALL_LEGACY_WRAPPER" == true ]]; then
    install -m 0755 "$SCRIPT_DIR/bash_simpleportscan.sh" "$BIN_DIR/bash_simpleportscan.sh"
fi

printf '[+] Installed Fathomtrace to %s\n' "$PREFIX"
printf '[*] Ensure %s is present in PATH.\n' "$BIN_DIR"
