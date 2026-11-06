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
if [[ "${1:-}" == "--dsh-native" ]]; then
  ./node_modules/.bin/tsx --tsconfig "${3:?Pass the Harness source root}/tsconfig.base.json" scripts/dsh-native-component.ts "${2:?Pass the ANP Identity source root}" "${3:?Pass the Harness source root}"
elif [[ "${1:-}" == "--independent-client" ]]; then
  ./node_modules/.bin/tsx --test tests/independent-client.component.ts
elif [[ "${1:-}" == "--cache-window" ]]; then
  ./node_modules/.bin/tsx --test tests/cache-window.component.ts
elif [[ "${1:-}" == "--identity-http" ]]; then
  ./node_modules/.bin/tsx --test tests/identity-http.component.ts
elif [[ "${1:-}" == "--process-recovery" ]]; then
  POSTGRES_BIN_DIR="$pg_bin" ./node_modules/.bin/tsx scripts/process-recovery-component.ts
elif [[ "${1:-}" == "--shared-protocol" ]]; then
  ./node_modules/.bin/tsx --tsconfig "${3:?Pass Harness source root}/tsconfig.base.json" scripts/shared-protocol-component.ts "${2:?Pass identity source root}" "${3}" "${4:?Pass PAP source root}"
elif [[ "${1:-}" == "--rotation-native" ]]; then
  ./node_modules/.bin/tsx --tsconfig "${3:?Pass Harness source root}/tsconfig.base.json" scripts/rotation-native-component.ts "${2:?Pass identity source root}" "${3}"
elif [[ "${1:-}" == "--mcp-product" ]]; then
  identity_root="${2:?Pass ANP Identity source root}"
  harness_root="${3:?Pass Harness source root}"
  product_config="${4:?Pass the explicit source Vitest configuration}"
  : "${DSH_IDENTITY_USER_SERVICE_SOURCE:?Pass the strict B source root in the environment}"
  : "${DSH_IDENTITY_PYTHON:?Pass the explicit B component Python in the environment}"
  product_test="$identity_root/packages/dsh-anp-identity/test/mcp-product-live.spec.ts"
  test -f "$product_test"
  test -f "$product_config"
  export DSH_MCP_PRODUCT_HARNESS_SOURCE="$harness_root"
  export DSH_MCP_PRODUCT_AS_SOURCE="$PWD"
  node "$identity_root/packages/dsh-anp-identity/node_modules/vitest/vitest.mjs" run "$product_test" --config "$product_config"
else
  ./node_modules/.bin/tsx --test tests/postgres.component.ts
fi
