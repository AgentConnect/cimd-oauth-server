#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
pg_bin="${POSTGRES_BIN_DIR:-/usr/lib/postgresql/14/bin}"
test_root="$(mktemp -d /tmp/cimd-pg.XXXXXXXX)"
cleanup() {
  "$pg_bin/pg_ctl" -D "$test_root/data" -m immediate -w stop >/dev/null 2>&1 || true
  rm -rf "$test_root"
}
trap cleanup EXIT INT TERM
mkdir -m 700 "$test_root/socket"
"$pg_bin/initdb" -D "$test_root/data" --auth=trust --no-locale -E UTF8 >/dev/null
"$pg_bin/pg_ctl" -D "$test_root/data" -l "$test_root/postgres.log" -o "-k $test_root/socket -h '' -F" -w start >/dev/null
"$pg_bin/createdb" -h "$test_root/socket" cimd_component
export DATABASE_URL="postgresql:///cimd_component?host=$test_root/socket"
export NODE_ENV=test
npm run migrate
./node_modules/.bin/tsx --test tests/postgres.component.ts
