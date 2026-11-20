#!/usr/bin/env bash

sps_db_inventory_usage() {
    cat << 'EOF'
Usage: fathomtrace db-inventory ENGINE HOST USER [PORT] [--skip-ssl-verify-server-cert]

ENGINE: mssql, mysql, or mariadb. HOST: DNS name or IPv4 address.
PORT defaults to 1433 for mssql and 3306 for mysql or mariadb.
The native client prompts for the password and verifies the server certificate.
Inventory also reports the OS or build platform advertised by the server.
MySQL and MariaDB accept the optional flag to skip certificate verification.
EOF
}

sps_db_inventory() {
    if [[ "$#" -eq 1 && ( "$1" == -h || "$1" == --help ) ]]; then
        sps_db_inventory_usage
        return 0
    fi
    if (( $# < 3 || $# > 5 )); then
        sps_db_inventory_usage >&2
        return 2
    fi

    local engine="$1" host="$2" user="$3" port query
    local ca_file client_name client_family mysql_help skip_verify=false
    local -a client tls_args
    case "$engine" in
        mssql) port=1433 ;;
        mysql | mariadb) port=3306 ;;
        *) sps_db_inventory_usage >&2; return 2 ;;
    esac

    shift 3
    if (( $# > 0 )) && [[ "$1" != --* ]]; then
        port="$1"
        shift
    fi
    if (( $# == 1 )) && [[ "$1" == --skip-ssl-verify-server-cert && "$engine" != mssql ]]; then
        skip_verify=true
        shift
    fi
    if (( $# > 0 )); then
        sps_db_inventory_usage >&2
        return 2
    fi
    if [[ ! "$host" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ || -z "$user" || "$user" == -* ||
        ! "$port" =~ ^[1-9][0-9]{0,4}$ ]] || (( port > 65535 )); then
        printf '%s\n' 'Invalid database host, username, or port.' >&2
        return 2
    fi
    if [[ ! -t 0 ]]; then
        printf '%s\n' 'Run db-inventory in an interactive terminal for the password prompt.' >&2
        return 2
    fi

    if [[ "$engine" == mssql ]]; then
        query="$(cat << 'SQL'
SET NOCOUNT ON;
SELECT CASE
    WHEN LOWER(@@VERSION) LIKE '% on linux%' THEN 'Linux'
    WHEN LOWER(@@VERSION) LIKE '% on windows%' THEN 'Windows'
    ELSE 'Unknown'
END AS server_os_hint;
SELECT name AS database_name FROM sys.databases ORDER BY name;

DECLARE @db sysname, @sql nvarchar(max), @failed bit = 0;
DECLARE inventory_databases CURSOR LOCAL FAST_FORWARD FOR
    SELECT name FROM sys.databases
    WHERE state = 0 AND HAS_DBACCESS(name) = 1
    ORDER BY name;

OPEN inventory_databases;
FETCH NEXT FROM inventory_databases INTO @db;
WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        SET @sql = N'USE ' + QUOTENAME(@db) + N';
            SELECT DB_NAME() AS database_name, SCHEMA_NAME(schema_id) AS schema_name, name AS table_name
            FROM sys.tables ORDER BY schema_name, table_name;';
        EXEC sys.sp_executesql @sql;
    END TRY
    BEGIN CATCH
        SET @failed = 1;
        DECLARE @error nvarchar(2048) = ERROR_MESSAGE();
        RAISERROR(N'Table inventory failed for %s: %s', 10, 1, @db, @error);
    END CATCH;
    FETCH NEXT FROM inventory_databases INTO @db;
END
CLOSE inventory_databases;
DEALLOCATE inventory_databases;
IF @failed = 1
    RAISERROR(N'Table inventory is incomplete.', 11, 1);
SQL
)"
        if command -v python3 > /dev/null 2>&1 && python3 -c 'import pymssql' 2> /dev/null; then
            sps_db_inventory_freetds "$host" "$port" "$user" "$query"
            return $?
        fi
        if ! command -v sqlcmd > /dev/null 2>&1; then
            printf '%s\n' 'Install python3-pymssql from Kali APT, or Microsoft ODBC sqlcmd (mssql-tools18).' >&2
            return 4
        fi
        env -u SQLCMDPASSWORD -u SQLCMDINI sqlcmd -S "tcp:$host,$port" -d master \
            -U "$user" -N -b -l 10 -t 30 -Q "$query"
        return $?
    fi

    if [[ "$engine" == mariadb ]] && command -v mariadb > /dev/null 2>&1; then
        client_name=mariadb
        client_family=mariadb
    elif command -v mysql > /dev/null 2>&1; then
        mysql_help="$(mysql --no-defaults --help 2> /dev/null)" || mysql_help=""
        case "$mysql_help" in
            *--ssl-mode*) client_name=mysql; client_family=mysql ;;
            *--ssl-verify-server-cert*) client_name=mysql; client_family=mariadb ;;
        esac
    fi
    if [[ -z "${client_name:-}" ]] && command -v mariadb > /dev/null 2>&1; then
        client_name=mariadb
        client_family=mariadb
    fi
    if [[ -z "${client_name:-}" ]]; then
        printf '%s\n' 'Install the MariaDB client or the Oracle MySQL client.' >&2
        return 4
    fi

    client=("$client_name" --no-defaults)
    if [[ "$skip_verify" == true ]]; then
        if [[ "$client_family" == mysql ]]; then
            tls_args=(--ssl-mode=REQUIRED)
        else
            tls_args=(--ssl --skip-ssl-verify-server-cert)
            printf '%s\n' 'MariaDB client certificate verification is disabled and the client may fall back to plaintext.' >&2
        fi
    else
        ca_file="${FATHOMTRACE_DB_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}"
        if [[ ! -f "$ca_file" || ! -r "$ca_file" ]]; then
            printf 'Database CA bundle is unavailable: %s\n' "$ca_file" >&2
            return 4
        fi
        if [[ "$client_family" == mysql ]]; then
            tls_args=(--ssl-mode=VERIFY_IDENTITY --ssl-ca="$ca_file")
        else
            tls_args=(--ssl --ssl-verify-server-cert --ssl-ca="$ca_file")
        fi
    fi

    query="$(cat << 'SQL'
SELECT @@version_compile_os AS server_build_os,
       @@version_comment AS server_version_comment;
SELECT SCHEMA_NAME AS database_name
FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME;
SELECT TABLE_SCHEMA AS database_name, TABLE_NAME AS table_name
FROM information_schema.TABLES WHERE TABLE_TYPE = 'BASE TABLE'
ORDER BY TABLE_SCHEMA, TABLE_NAME;
SQL
)"
    env -u MYSQL_PWD "${client[@]}" --protocol=TCP --connect-timeout=10 \
        --host="$host" --port="$port" --user="$user" --password "${tls_args[@]}" \
        --batch --execute="$query"
}

sps_db_inventory_freetds() {
    python3 - "$@" << 'PYTHON'
import os
import sys
from contextlib import closing
from getpass import getpass
from pathlib import Path
from tempfile import TemporaryDirectory

host, port, user, query = sys.argv[1:]
ca_file = os.environ.get("FATHOMTRACE_DB_CA_FILE", "system")
if ca_file != "system":
    ca_file = str(Path(ca_file).resolve())
    if any(character in ca_file for character in "\r\n;#") or not Path(ca_file).is_file():
        sys.exit("Invalid database CA bundle path.")

with TemporaryDirectory(prefix="fathomtrace-db-") as directory:
    config = Path(directory) / "freetds.conf"
    config.write_text(
        "[fathomtrace_inventory]\n"
        f"host = {host}\n"
        f"port = {port}\n"
        "tds version = 7.4\n"
        "encryption = require\n"
        f"ca file = {ca_file}\n"
        "check certificate hostname = yes\n"
        f"certificate hostname = {host}\n",
        encoding="utf-8",
    )
    for variable in ("TDSHOST", "TDSPORT", "TDSVER", "TDSENCRYPTION", "TDSDUMP", "TDSDUMPCONFIG"):
        os.environ.pop(variable, None)
    os.environ["FREETDSCONF"] = str(config)

    import pymssql

    try:
        with closing(pymssql.connect(
            server="fathomtrace_inventory",
            port=port,
            user=user,
            password=getpass("SQL Server password: "),
            database="master",
            login_timeout=10,
            timeout=30,
            autocommit=True,
        )) as connection, closing(connection.cursor()) as cursor:
            cursor.execute(query)
            while True:
                if cursor.description:
                    print("\t".join(column[0] for column in cursor.description))
                    for row in cursor:
                        print("\t".join(str(value) for value in row))
                if not cursor.nextset():
                    break
    except pymssql.Error as error:
        sys.exit(f"SQL Server inventory failed: {error}")
PYTHON
}
