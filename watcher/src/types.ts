// ─── Types ──────────────────────────────────────────────────────────────
// Shared types for the Taint Watcher service.
// The ChainWatcher interface is the adapter contract — each blockchain
// gets its own implementation, but they all emit the same PaymentEvent.

/**
 * Chain-agnostic payment event. Every chain watcher emits this same shape.
 * The scoring engine doesn't care which chain the payment came from.
 */
export interface PaymentEvent {
  /** Which blockchain (e.g. "stellar", "ethereum", "movement") */
  chain: string;
  /** Source address that sent the payment */
  sender: string;
  /** Destination address that received the payment */
  recipient: string;
  /** Human-readable amount (e.g. "50000.0000000") */
  amount: string;
  /** Asset identifier (e.g. "native", "USDC:GA5ZS...", "0x...") */
  asset: string;
  /** Transaction hash on the source chain */
  txHash: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** Bridge provider if this was a cross-chain transfer */
  bridgeProvider?: string;
  /** Source chain if this was a cross-chain transfer */
  originChain?: string;
  /** TX hash on the origin chain (for cross-chain transfers) */
  originTxHash?: string;
}

/**
 * Taint record — the output of the scoring engine.
 * Stored in Engram API and pushed to the Soroban contract.
 */
export interface TaintRecord {
  /** The address that is being tainted */
  taintedAddress: string;
  /** The address that directly caused the taint (the sender) */
  sourceAddress: string;
  /** The original sanctioned/flagged address at the root of the chain */
  originalSource: string;
  /** Why the original source was flagged */
  originalSourceType: "ofac_sdn" | "opensanctions" | "community_flagged" | "tainted";
  /** Taint score (0–100) */
  score: number;
  /** Hop depth from the original sanctioned address */
  hopDepth: number;
  /** Which blockchain */
  chain: string;
  /** Amount received */
  amount: string;
  /** Asset received */
  asset: string;
  /** Transaction hash */
  txHash: string;
  /** When the taint was detected */
  detectedAt: string;
  /** Risk status derived from score */
  status: TaintStatus;
}

export type TaintStatus = "clean" | "low_risk" | "elevated" | "high_risk" | "critical";

/**
 * A flagged address that the watcher should monitor.
 * Fetched from the Engram API or local sanctions data.
 */
export interface WatchedAddress {
  /** The address to monitor */
  address: string;
  /** Why this address is being watched */
  type: "sanctioned" | "community_flagged" | "tainted";
  /** Source of the flag (e.g. "ofac_sdn", "opensanctions", "agent_consensus") */
  source: string;
  /** Severity weight for scoring (1.0 for OFAC, 0.7 for community, 0.5 for tainted) */
  severity: number;
  /** Hop depth (0 for original sanctioned, 1+ for tainted) */
  hopDepth: number;
  /** Chain this address belongs to */
  chain: string;
}

/**
 * Chain watcher adapter interface.
 * Each blockchain implements this to feed PaymentEvents into the scoring engine.
 */
export interface ChainWatcher {
  /** Which chain this watcher monitors */
  readonly chain: string;

  /** Start monitoring an address for outbound payments */
  subscribe(address: string): void;

  /** Stop monitoring an address */
  unsubscribe(address: string): void;

  /** Register the callback for incoming payment events */
  onPayment(callback: (event: PaymentEvent) => void): void;

  /** Start the watcher (connect to data source) */
  start(): Promise<void>;

  /** Stop the watcher (disconnect) */
  stop(): void;

  /** Get the number of currently monitored addresses */
  watchCount(): number;
}

/**
 * Whitelist entry — addresses exempt from taint propagation.
 */
export interface WhitelistEntry {
  address: string;
  label: string;
  type: "exchange" | "custodial" | "bridge" | "protocol";
  chain: string;
}

/**
 * Watcher configuration.
 */
export interface WatcherConfig {
  horizonUrl: string;
  network: "testnet" | "mainnet";
  contractId: string;
  engramApiUrl: string;
  engramApiKey: string;
  operatorSecret: string;

  /** Minimum amount in XLM to trigger taint (default 100) */
  taintMinAmountXlm: number;
  /** Maximum hop depth (default 2) */
  taintMaxHops: number;
  /** Poll interval in ms for checking new flagged addresses (default 5000) */
  pollIntervalMs: number;

  /** NEAR Intents Explorer API JWT token */
  nearIntentsJwt: string;
  /** Enable NEAR Intents cross-chain bridge tracking */
  nearIntentsEnabled: boolean;
}
