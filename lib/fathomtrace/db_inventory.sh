#!/usr/bin/env bash

sps_db_inventory_usage() {
    cat << 'EOF'
Usage: fathomtrace db-inventory ENGINE HOST USER [PORT]

ENGINE: mssql, mysql, or mariadb. HOST: DNS name or IPv4 address.
PORT defaults to 1433 for mssql and 3306 for mysql or mariadb.
The native client prompts for the password and verifies the server certificate.
EOF
}

sps_db_inventory() {
    if [[ "$#" -eq 1 && ( "$1" == -h || "$1" == --help ) ]]; then
        sps_db_inventory_usage
        return 0
    fi
    if (( $# < 3 || $# > 4 )); then
        sps_db_inventory_usage >&2
        return 2
    fi

    local engine="$1" host="$2" user="$3" port query
    local ca_file
    local -a client
    case "$engine" in
        mssql) port=1433 ;;
        mysql | mariadb) port=3306 ;;
        *) sps_db_inventory_usage >&2; return 2 ;;
    esac

    if (( $# == 4 )); then
        port="$4"
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
        if ! command -v sqlcmd > /dev/null 2>&1; then
            printf '%s\n' 'Install Microsoft ODBC sqlcmd (mssql-tools18) to inventory SQL Server.' >&2
            return 4
        fi

        query="$(cat << 'SQL'
SET NOCOUNT ON;
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
        env -u SQLCMDPASSWORD -u SQLCMDINI sqlcmd -S "tcp:$host,$port" -d master \
            -U "$user" -N -b -l 10 -t 30 -Q "$query"
        return $?
    fi

    if [[ "$engine" == mariadb ]] && command -v mariadb > /dev/null 2>&1; then
        client=(mariadb --no-defaults --ssl --ssl-verify-server-cert)
    elif command -v mysql > /dev/null 2>&1 && mysql --no-defaults --help 2> /dev/null | grep -F -- '--ssl-mode' > /dev/null; then
        client=(mysql --no-defaults --ssl-mode=VERIFY_IDENTITY)
    elif command -v mariadb > /dev/null 2>&1; then
        client=(mariadb --no-defaults --ssl --ssl-verify-server-cert)
    else
        printf '%s\n' 'Install the MariaDB client or the Oracle MySQL client.' >&2
        return 4
    fi

    ca_file="${FATHOMTRACE_DB_CA_FILE:-/etc/ssl/certs/ca-certificates.crt}"
    if [[ ! -f "$ca_file" || ! -r "$ca_file" ]]; then
        printf 'Database CA bundle is unavailable: %s\n' "$ca_file" >&2
        return 4
    fi

    query="$(cat << 'SQL'
SELECT SCHEMA_NAME AS database_name
FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME;
SELECT TABLE_SCHEMA AS database_name, TABLE_NAME AS table_name
FROM information_schema.TABLES WHERE TABLE_TYPE = 'BASE TABLE'
ORDER BY TABLE_SCHEMA, TABLE_NAME;
SQL
)"
    env -u MYSQL_PWD "${client[@]}" --protocol=TCP --connect-timeout=10 \
        --host="$host" --port="$port" --user="$user" --password --ssl-ca="$ca_file" \
        --batch --execute="$query"
}
