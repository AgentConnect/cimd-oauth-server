#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export NODE_ENV=test
./node_modules/.bin/tsx --tsconfig "${2:?Pass the actual D source root}/tsconfig.base.json" scripts/independent-as-native.ts "${1:?Pass the native identity source root}" "${2}"
