#!/usr/bin/env bash
# Refuse to ship if a key, mnemonic or credential could be in the build output or the tracked files.
# Usage: scripts/check-secrets.sh [dist-dir]     (exit 1 on any hit; prints file names, never contents)
set -euo pipefail
cd "$(dirname "$0")/.."
dist="${1:-dist}"
fail=0
bad() { echo "check-secrets: $*" >&2; fail=1; }

# 1. Nothing secret-looking is tracked by git (key files, mnemonics, env files, wallet exports).
if git rev-parse --git-dir >/dev/null 2>&1; then
  hits=$(git ls-files | grep -i -E '(^|/)(keys?/|\.env$|.*\.mnemonic$|.*\.key$|secrets?(/|\.)|[^/]*\.secrets?([./]|$)|.*faucet-login|.*\.pem$|id_(rsa|ed25519))' | grep -v -E '^\.env\.example$' || true)
  [ -z "$hits" ] || bad "tracked secret-looking files: $hits"
fi

# 2. .env values that Vite would inline (VITE_*) must be public-only ids; nothing else may be set.
if [ -f .env ]; then
  extra=$(grep -E '^[A-Za-z_][A-Za-z0-9_]*=.+' .env | cut -d= -f1 | grep -v -x 'VITE_WALLETCONNECT_PROJECT_ID' || true)
  [ -z "$extra" ] || bad ".env sets unexpected variables (names only): $extra"
fi

# 3. The build output holds no key material or references to our key files.
if [ -d "$dist" ]; then
  pat='qday-testnet|\.mnemonic|faucet-login|keys/qday|BEGIN [A-Z ]*PRIVATE KEY|PRIVATE_KEY=|"mnemonic"[[:space:]]*:[[:space:]]*"[a-z]+( [a-z]+){11}'
  files=$(grep -r -l -E "$pat" "$dist" || true)
  [ -z "$files" ] || bad "suspicious strings in $dist: $files"
  # Any 12/24-word lowercase phrase inside a string literal is treated as a possible mnemonic.
  phrase=$(grep -r -l -o -E '"([a-z]{3,8} ){11}[a-z]{3,8}"|"([a-z]{3,8} ){23}[a-z]{3,8}"' "$dist" || true)
  [ -z "$phrase" ] || bad "12/24-word phrase literal in $dist (check it is not a mnemonic): $phrase"
  [ ! -e "$dist/.env" ] || bad "$dist/.env exists"
fi

[ "$fail" = 0 ] && echo "check-secrets: clean ($dist and tracked files)"
exit "$fail"
