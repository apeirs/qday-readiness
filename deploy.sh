#!/usr/bin/env bash
# One command to put the demo online as a Cloudflare Worker (static app + read-only chain gateway).
#   ./deploy.sh              test, build, secret check, deploy to https://qday-readiness.<account>.workers.dev
#   ./deploy.sh --dry-run    same, but only bundles the Worker (no Cloudflare login, nothing uploaded)
# Login: `npx wrangler login` once, or export CLOUDFLARE_API_TOKEN (Workers Scripts: Edit) and
# CLOUDFLARE_ACCOUNT_ID. Extra arguments go to `wrangler deploy`.
set -euo pipefail
cd "$(dirname "$0")"

dry=0
for a in "$@"; do [ "$a" = "--dry-run" ] && dry=1; done

[ -d node_modules ] || npm ci --no-audit --no-fund
npm test
nice -n 19 npm run build
scripts/check-secrets.sh dist

if [ "$dry" = 1 ]; then
  out=$(mktemp -d)
  npx wrangler deploy --dry-run --outdir "$out" "$@"
  echo "Dry run OK: Worker bundle in $out, assets from ./dist. Nothing was uploaded."
  exit 0
fi

if npx wrangler whoami 2>&1 | grep -q -i 'not authenticated'; then
  echo "Not logged in to Cloudflare: run 'npx wrangler login' or export CLOUDFLARE_API_TOKEN." >&2
  exit 1
fi
npx wrangler deploy "$@"
