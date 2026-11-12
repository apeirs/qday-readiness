# Q-Day Readiness Audit

Which QoreChain accounts would a quantum attacker take first? This tool scans any `qor1…` or `0x…` address on
QoreChain, scores how exposed it is, tells you the one thing to fix, and lets you prove your own account is
ready with a single hybrid-signed (secp256k1 + ML-DSA-87) transaction that anyone can verify.

It runs as a web app (scan, connect QoreX, attest, verify) and as a command-line tool (`qday`) for batch scans
and scripted attestations. Testnet (Diana, chain 9800) is the default; mainnet (Vladi) works for scans.

## Why it matters

QoreChain protects an account with a post-quantum key only after that key is registered. Until then the account
is guarded by ECDSA alone. Once its public key is on chain (after any transaction, or from an EVM signature), a
large enough quantum computer can derive the private key. And the first ML-DSA-87 key registered for an account
binds it: an attacker who has derived the ECDSA key could register their own post-quantum key first and lock
the owner out for good. The fix is cheap and one-time, but you have to know which of your accounts still need it.

## What it checks

| Check | Source | Effect on the score |
|---|---|---|
| ML-DSA-87 key registered | `qorechain/pqc/v1/account` | Missing on a funded account with a public ECDSA key: **critical** (-85) |
| Funded, key not yet published | `cosmos/auth`, `cosmos/bank`, `cosmos/staking` | **high** (-60) |
| Empty account without a PQC key | `cosmos/auth` | low (-25) |
| Proof of possession at registration | `possession_proven` | info (-3) |
| Open EVM authorisation window | `qorechain/pqc/v1/evm_window` | -5 if scoped to targets, -15 if not |
| EIP-7702 delegation | `eth_getCode` (`0xef0100…`) | -10 (-2 if the delegate has no code) |
| Extra authenticators on an abstract account | `qorechain/abstractaccount/v1` | -5 |
| Contracts and module accounts | `eth_getCode`, account type | not scored: no key to protect |

Readiness is 100 minus exposure. Grades: A ≥ 90, B ≥ 75, C ≥ 50, D ≥ 25, F below. Balances include the fest
tokens (fUSD, fETH, fBTC), which the chain keeps as `erc20:` bank denoms.

## The attestation

`Attest with QoreX` (web) or `qday attest` (CLI) sends 0.000001 QOR from the account to itself with a memo:

```
qday:v1;<qor1 address>;<grade>;<readiness>;<first 12 hex of the SHA-256 of the scan>
```

QoreChain requires every native transaction to carry an ML-DSA-87 signature next to the classical one, so the
transaction itself is the proof. If the key is not registered yet, QoreX (or the CLI, via `ensurePqcRegistered`)
registers it first. `Verify` and `qday verify <txhash>` check both signatures with
[`@qorechain/qoresign`](https://www.npmjs.com/package/@qorechain/qoresign) against the signer's registered key and
decode the memo. Share a result with `?tx=<hash>`; share a scan with `?a=<addr>,<addr>`.

Fees: about 0.15 QOR the first time (registration plus the attestation), about 0.06 QOR after that.

## Run the web app

```sh
npm install
npm run dev            # http://localhost:5173
npm run build && npm start   # production build served on http://127.0.0.1:8080 (PORT, HOST)
```

QoreChain's REST and Tendermint RPC endpoints send no CORS headers, so the app reads them through a small
read-only gateway (`gateway.mjs`) that the dev server and `server.mjs` both mount at `/chain/<network>/…`. It
forwards GET requests on an allowlist (`cosmos/auth|bank|staking|tx|upgrade`, `qorechain/pqc|abstractaccount`,
RPC `/tx` and `/status`), plus one write route: `POST /chain/testnet/rest/cosmos/tx/v1beta1/txs` for wallets that
broadcast through the page's REST endpoint. That route takes only a JSON body of at most 64 KB holding `tx_bytes`
and `mode: BROADCAST_MODE_SYNC`, relays it to testnet and passes the chain's answer back unchanged; the body is
never logged or stored. Every other write is refused (405). The EVM JSON-RPC allows CORS and is called directly.

## Deploy

The hosted demo is one Cloudflare Worker: Workers Static Assets serve the built app, and `worker/index.mjs`
runs the same gateway at `/chain/<network>/…` (same allowlist and broadcast checks as `gateway.mjs`, redirects
refused, 15 s upstream timeout). Nothing else is created: no KV, database or secrets.

```sh
npx wrangler login     # once (or export CLOUDFLARE_API_TOKEN with "Workers Scripts: Edit" + CLOUDFLARE_ACCOUNT_ID)
./deploy.sh            # tests, build, secret check, then `wrangler deploy` -> https://qday-readiness.<account>.workers.dev
./deploy.sh --dry-run  # same checks, bundles the Worker, uploads nothing
npm run cf:dev         # the Worker locally on http://127.0.0.1:8787 (after `npm run build`)
```

`scripts/check-secrets.sh` runs before every deploy and stops it if a key file, mnemonic or credential could be in
`dist/` or in the tracked files. Successful chain reads are cached at the edge for 15 s (account state) or a day
(committed transactions); errors and "not found" answers are never cached. Static files under `/assets/` are
content-hashed and cached for a year (`public/_headers`). To self-host instead, `npm run build && npm start` runs
the same app and gateway with Node and no dependencies.

## Command line

```sh
npm run qday -- scan qor1p2pkkdjkg3486c87skry656ys5wharvz9hwkxm 0xffc267ab318abc548a2d1c5c955a5daf9667eae5
npm run qday -- scan --file treasury.txt --json      # one address per line, # starts a comment
npm run qday -- verify F4ABC81D7A9C1B102A33F8CF7FAA41142AFEFCA070D9B8B80C1A2C5167733D68
npm run qday -- keygen --key ~/.qday/testnet.key     # new testnet key, file mode 0600, prints addresses only
npm run qday -- whoami --key ~/.qday/testnet.key
npm run qday -- attest --key ~/.qday/testnet.key --dry-run   # build and check the hybrid tx offline
npm run qday -- attest --key ~/.qday/testnet.key             # register if needed, then attest
```

`scan` exits 1 when any account has a critical finding, so it can gate a CI job or a treasury check.
`--network mainnet` scans mainnet; `attest` refuses to run without enough balance and says how much it needs.
Key files that other users can read are refused.

## Tests

```sh
npm test         # scoring, address parsing, memo format, gateway allowlist + Worker (path tricks, methods, broadcast route, cache)
npm run build    # type-check and production build
```

## Not the QoreX "Q-Day Scanner"

The QoreX mobile wallet has a built-in Q-Day Scanner for the wallet's own accounts. This tool is separate: it
scans any address, including ones you don't hold keys for (a treasury, a validator's operator account, a
contract's owner), works in batches from the command line, and records a verifiable on-chain attestation.

## Built with

The [create-qorechain-dapp](https://www.npmjs.com/package/create-qorechain-dapp) viem + wagmi template,
`@qorechain/sdk` (hybrid signing, PQC registration), `@qorechain/qoresign` (signature verification),
`@qorechain/qorex-types` and `@qorechain/qorex-rainbowkit` (QoreX), and `@qorechain/qorex-wallet-mock` for
browser tests.

## Licence

MIT
