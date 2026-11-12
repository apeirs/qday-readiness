/** Public QoreChain endpoints the scanner reads. Testnet first: the fest runs on Diana. */
export interface Network {
  name: "testnet" | "mainnet" | "localnet";
  chainId: string;
  evmChainId?: number;
  rest: string;
  rpc: string;
  evmRpc?: string;
  explorerTx: (hash: string) => string;
}

export const NETWORKS: Record<Network["name"], Network> = {
  testnet: {
    name: "testnet",
    chainId: "qorechain-diana",
    evmChainId: 9800,
    rest: "https://api-testnet.qore.host",
    rpc: "https://rpc-testnet.qore.host",
    evmRpc: "https://evm-testnet.qore.host",
    explorerTx: (h) => `https://explore.qore.network/tx/${h}`,
  },
  mainnet: {
    name: "mainnet",
    chainId: "qorechain-vladi",
    evmChainId: 9801,
    rest: "https://api.qore.host",
    rpc: "https://rpc.qore.host",
    evmRpc: "https://evm.qore.host",
    explorerTx: (h) => `https://explore.qore.network/tx/${h}`,
  },
  localnet: {
    name: "localnet",
    chainId: "qorechain-devnet",
    rest: "http://127.0.0.1:1317",
    rpc: "http://127.0.0.1:26657",
    explorerTx: (h) => `http://127.0.0.1:1317/cosmos/tx/v1beta1/txs/${h}`,
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
