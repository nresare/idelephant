#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dev_dir="$repo_dir/local-dev"
pid_file="$dev_dir/surreal.pid"
root_password_file="$dev_dir/root-password"
app_password_file="$dev_dir/idelephant-password"
config_file="$dev_dir/idelephant.toml"
endpoint="ws://127.0.0.1:8001"

usage() {
    echo "Usage: $0 {start|stop|status}" >&2
    exit 2
}

running_pid() {
    [[ -f "$pid_file" ]] || return 1
    local pid
    pid="$(cat "$pid_file")"
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    kill -0 "$pid" 2>/dev/null || return 1
    ps -p "$pid" -o command= | grep -Fq "surreal start"
}

stop_server() {
    if ! running_pid; then
        echo "No local idElephant database is running."
        return
    fi
    local pid
    pid="$(cat "$pid_file")"
    kill "$pid"
    rm -f "$pid_file"
    echo "Stopped local idElephant database. Data remains in $dev_dir."
}

start_server() {
    command -v surreal >/dev/null || { echo "Install the SurrealDB CLI first." >&2; exit 1; }
    command -v openssl >/dev/null || { echo "openssl is required to generate local passwords." >&2; exit 1; }
    if running_pid; then
        echo "Local idElephant database is already running at $endpoint."
        return
    fi
    if surreal is-ready --endpoint "$endpoint" >/dev/null 2>&1; then
        echo "$endpoint is already in use by another database. Stop it before running this script." >&2
        exit 1
    fi
    if [[ -d "$dev_dir/database" && ( ! -f "$root_password_file" || ! -f "$app_password_file" ) ]]; then
        echo "Existing local data has missing password files. Restore them or move local-dev aside." >&2
        exit 1
    fi
    umask 077
    mkdir -p "$dev_dir"
    [[ -f "$root_password_file" ]] || openssl rand -hex 32 > "$root_password_file"
    [[ -f "$app_password_file" ]] || openssl rand -hex 32 > "$app_password_file"

    local root_key root_password app_password
    root_key="$(sed -n 's/^root_key[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$repo_dir/idelephant.toml" | head -n 1)"
    [[ -n "$root_key" ]] || { echo "Could not find root_key in idelephant.toml." >&2; exit 1; }
    root_password="$(cat "$root_password_file")"
    app_password="$(cat "$app_password_file")"
    cat > "$config_file" <<CONFIG
root_key = "$root_key"
origin = "http://127.0.0.1:8080"

[email]
sender_email = "admin@example.test"
relay_host = "localhost"

[persistence]
uri = "$endpoint"
username = "idelephant"
password_file = "$app_password_file"
CONFIG

    SURREAL_USER=local_admin SURREAL_PASS="$root_password" \
        nohup surreal start --no-banner --bind 127.0.0.1:8001 \
        "surrealkv://$dev_dir/database" > "$dev_dir/surreal.log" 2>&1 &
    local pid=$!
    echo "$pid" > "$pid_file"
    cleanup_on_error() {
        kill "$pid" 2>/dev/null || true
        rm -f "$pid_file"
    }
    trap cleanup_on_error ERR

    local ready=false
    for _ in {1..50}; do
        if surreal is-ready --endpoint "$endpoint" >/dev/null 2>&1; then
            ready=true
            break
        fi
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        sleep 0.2
    done
    if [[ "$ready" != true ]]; then
        echo "Database did not start. See $dev_dir/surreal.log" >&2
        cleanup_on_error
        trap - ERR
        return 1
    fi

    # The SurrealDB REPL writes history.txt in its current directory.
    cd "$dev_dir"

    SURREAL_USER=local_admin SURREAL_PASS="$root_password" \
        surreal sql --endpoint "$endpoint" --hide-welcome >/dev/null <<SQL
DEFINE NAMESPACE IF NOT EXISTS default;
USE NS default;
DEFINE DATABASE IF NOT EXISTS idelephant;
USE NS default DB idelephant;
DEFINE USER IF NOT EXISTS idelephant ON DATABASE PASSWORD '$app_password' ROLES OWNER;
SQL
    SURREAL_USER=idelephant SURREAL_PASS="$app_password" \
        surreal sql --endpoint "$endpoint" --namespace default --database idelephant \
        --auth-level database --hide-welcome >/dev/null <<SQL
RETURN true;
SQL
    trap - ERR
    echo "Local database ready at $endpoint."
    echo "App config: $config_file"
    echo "Start idElephant: cargo run -- --bypass-authentication -c '$config_file'"
    echo "Admin login: http://127.0.0.1:8080/?user=root"
    echo "Database admin: local_admin (password in $root_password_file)"
}

case "${1:-}" in
    start) start_server ;;
    stop) stop_server ;;
    status)
        if running_pid; then echo "Local database is running at $endpoint.";
        else echo "Local database is stopped."; fi
        ;;
    *) usage ;;
esac
