/** Public QoreChain endpoints the scanner reads. Testnet first: the fest runs on Diana. */
export interface Network {
  name: "testnet" | "mainnet" | "localnet";
  chainId: string;
  evmChainId?: number;
  rest: string;
  rpc: string;
  evmRpc?: string;
  /** QDayRegistry (contracts/contracts/QDayRegistry.sol): the on-chain record of attestations. */
  registry?: string;
  /** The EVM transaction that deployed it. */
  registryDeployTx?: string;
  /** Explorer base for EVM pages: `${evmExplorer}/address/0x…` and `${evmExplorer}/tx/0x…`. */
  evmExplorer?: string;
  explorerTx: (hash: string) => string;
  /** The public explorer keeps its network in a cookie, not the URL: tell the reader which one to pick. */
  explorerNote?: string;
  /** Raw tx JSON from the chain's own REST API: always opens on the right network. */
  restTx: (hash: string) => string;
}

export const NETWORKS: Record<Network["name"], Network> = {
  testnet: {
    name: "testnet",
    chainId: "qorechain-diana",
    evmChainId: 9800,
    rest: "https://api-testnet.qore.host",
    rpc: "https://rpc-testnet.qore.host",
    evmRpc: "https://evm-testnet.qore.host",
    registry: "0xfcDd726E5cAeb40df793560F3FbbdBC669F0354A",
    registryDeployTx: "0xbf86da9725961930daad2c38e157071b7f746f13b4e3a64ca285312abe3ca999",
    evmExplorer: "https://explore.qore.network",
    explorerTx: (h) => `https://explore.qore.network/tx/${h}`,
    explorerNote: "switch the explorer's network to Testnet",
    restTx: (h) => `https://api-testnet.qore.host/cosmos/tx/v1beta1/txs/${h}`,
  },
  mainnet: {
    name: "mainnet",
    chainId: "qorechain-vladi",
    evmChainId: 9801,
    rest: "https://api.qore.host",
    rpc: "https://rpc.qore.host",
    evmRpc: "https://evm.qore.host",
    explorerTx: (h) => `https://explore.qore.network/tx/${h}`,
    restTx: (h) => `https://api.qore.host/cosmos/tx/v1beta1/txs/${h}`,
  },
  localnet: {
    name: "localnet",
    chainId: "qorechain-devnet",
    rest: "http://127.0.0.1:1317",
    rpc: "http://127.0.0.1:26657",
    explorerTx: (h) => `http://127.0.0.1:1317/cosmos/tx/v1beta1/txs/${h}`,
    restTx: (h) => `http://127.0.0.1:1317/cosmos/tx/v1beta1/txs/${h}`,
  },
};

export function networkByName(name: string | undefined): Network {
  const n = (name ?? "testnet").toLowerCase();
  if (n === "testnet" || n === "diana") return NETWORKS.testnet;
  if (n === "mainnet" || n === "vladi") return NETWORKS.mainnet;
  if (n === "localnet" || n === "devnet" || n === "local") return NETWORKS.localnet;
  throw new Error(`Unknown network "${name}". Use testnet, mainnet or localnet.`);
}

/** Same-origin gateway prefix used by the web app (vite.config.ts and server.mjs proxy it). */
export const GATEWAY_PREFIX = "/chain";

/**
 * The chain's REST and RPC endpoints send no CORS headers, so the browser reads
 * them through a small same-origin, GET-only gateway. The EVM JSON-RPC does send
 * CORS headers and is used directly.
 */
export function browserNetwork(name: Network["name"], origin: string): Network {
  const n = NETWORKS[name];
  return { ...n, rest: `${origin}${GATEWAY_PREFIX}/${name}/rest`, rpc: `${origin}${GATEWAY_PREFIX}/${name}/rpc` };
}
