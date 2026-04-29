// ─── NEAR Intents Bridge Watcher ────────────────────────────────────────
// Implements ChainWatcher for cross-chain bridge tracking via the
// NEAR Intents Explorer API. Polls for bridge transactions involving
// flagged addresses and emits PaymentEvents for cross-chain taint.
//
// Unlike the StellarWatcher (real-time SSE), this uses polling because
// the Explorer API is rate-limited (1 req / 5 seconds per partner).
//
// Flow:
//   1. Maintain a queue of flagged addresses to check
//   2. Every 6 seconds, search the Explorer API for one address
//   3. If we find a bridge tx with that address as sender, emit PaymentEvent
//   4. The orchestrator scores and propagates taint to the destination chain

import type { ChainWatcher, PaymentEvent } from "./types.js";

// ── NEAR Intents Explorer API types ─────────────────────────────────────

interface NearIntentsTx {
  originAsset: string;
  destinationAsset: string;
  depositAddress: string;
  depositMemo: string | null;
  recipient: string;
  status: "SUCCESS" | "FAILED" | "INCOMPLETE_DEPOSIT" | "PENDING_DEPOSIT" | "PROCESSING" | "REFUNDED";
  createdAt: string;
  createdAtTimestamp: number;
  intentHashes: string | null;
  referral: string | null;
  amountInFormatted: string;
  amountOutFormatted: string;
  nearTxHashes: string[];
  originChainTxHashes: string[];
  destinationChainTxHashes: string[];
  amountIn: string;
  amountInUsd: string;
  amountOut: string;
  amountOutUsd: string;
  refundTo: string;
  senders: string[];
  refundReason: string | null;
}

// ── Chain ID mapping ────────────────────────────────────────────────────
// Maps NEAR Intents chain IDs to our canonical chain names

const CHAIN_MAP: Record<string, string> = {
  near: "near",
  eth: "ethereum",
  base: "base",
  arb: "arbitrum",
  btc: "bitcoin",
  sol: "solana",
  ton: "ton",
  doge: "dogecoin",
  xrp: "xrp",
  bsc: "bsc",
  pol: "polygon",
  tron: "tron",
  sui: "sui",
  op: "optimism",
  avax: "avalanche",
  stellar: "stellar",
  aptos: "aptos",
  ltc: "litecoin",
  monad: "monad",
  bera: "berachain",
  gnosis: "gnosis",
  cardano: "cardano",
};

/**
 * Extract the chain ID from a NEAR Intents asset string.
 * Asset format: "nep141:eth-0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48.omft.near"
 * or: "nep245:v2_1.omni.hot.tg:1100_..."
 */
function extractChainFromAsset(asset: string): string | null {
  // Try to extract from known prefixes
  for (const [key, value] of Object.entries(CHAIN_MAP)) {
    if (asset.includes(`${key}-`) || asset.includes(`:${key}.`) || asset.includes(`/${key}/`)) {
      return value;
    }
  }

  // Check for specific patterns
  if (asset.includes(".omft.near")) {
    // Token format: "nep141:eth-0x...omft.near" — chain is the prefix before the dash
    const match = asset.match(/nep141:(\w+)-/);
    if (match && CHAIN_MAP[match[1]]) {
      return CHAIN_MAP[match[1]];
    }
  }

  return null;
}

/**
 * Determine the destination chain from a recipient address format.
 */
function detectChainFromAddress(address: string): string {
  if (address.startsWith("0x") && address.length === 42) return "ethereum"; // EVM
  if (address.startsWith("G") && address.length === 56) return "stellar";
  if (address.startsWith("bc1") || address.startsWith("1") || address.startsWith("3")) return "bitcoin";
  if (address.endsWith(".near")) return "near";
  if (address.length >= 32 && address.length <= 44 && /^[1-9A-HJ-NP-Za-km-z]+$/.test(address)) return "solana";
  if (address.startsWith("T") && address.length === 34) return "tron";
  if (address.startsWith("M") || address.startsWith("L") || address.startsWith("ltc1")) return "litecoin";
  if (address.startsWith("D") && address.length === 34) return "dogecoin";
  if (address.startsWith("r") && address.length >= 25 && address.length <= 35) return "xrp";
  return "unknown";
}

// ── Watcher ─────────────────────────────────────────────────────────────

export class NearIntentsWatcher implements ChainWatcher {
  readonly chain = "near_intents"; // Meta-chain: this watcher covers all chains

  private jwt: string;
  private watchedAddresses: Set<string> = new Set();
  private paymentCallback: ((event: PaymentEvent) => void) | null = null;
  private running = false;
  private pollHandle: ReturnType<typeof setInterval> | null = null;

  /** Queue of addresses to check — round-robin */
  private checkQueue: string[] = [];
  private queueIndex = 0;

  /** Track last-seen timestamp per address to avoid re-processing */
  private lastSeen: Map<string, number> = new Map();

  /** Track already-processed intent hashes to avoid duplicates */
  private processedIntents: Set<string> = new Set();

  /** API base URL */
  private readonly API_BASE = "https://explorer.near-intents.org/api/v0";

  /** Rate limit: 1 req / 5 seconds — we use 6s for safety */
  private readonly POLL_INTERVAL_MS = 6000;

  /** Max processed intents to keep in memory (prevent memory leak) */
  private readonly MAX_PROCESSED = 10000;

  constructor(jwt: string) {
    this.jwt = jwt;
  }

  onPayment(callback: (event: PaymentEvent) => void): void {
    this.paymentCallback = callback;
  }

  async start(): Promise<void> {
    if (!this.jwt) {
      console.warn("[NearIntentsWatcher] No JWT token — bridge tracking disabled");
      return;
    }

    this.running = true;
    this.rebuildQueue();

    console.log(
      `[NearIntentsWatcher] Started — monitoring ${this.watchedAddresses.size} addresses ` +
      `for cross-chain bridge activity`
    );

    // Start polling
    this.pollHandle = setInterval(() => this.pollNext(), this.POLL_INTERVAL_MS);
  }

  stop(): void {
    this.running = false;
    if (this.pollHandle) {
      clearInterval(this.pollHandle);
      this.pollHandle = null;
    }
    console.log("[NearIntentsWatcher] Stopped");
  }

  subscribe(address: string): void {
    if (this.watchedAddresses.has(address)) return;
    this.watchedAddresses.add(address);
    this.rebuildQueue();
  }

  unsubscribe(address: string): void {
    this.watchedAddresses.delete(address);
    this.lastSeen.delete(address);
    this.rebuildQueue();
  }

  watchCount(): number {
    return this.watchedAddresses.size;
  }

  // ── Private ───────────────────────────────────────────────────────────

  /**
   * Rebuild the round-robin queue from watched addresses.
   */
  private rebuildQueue(): void {
    this.checkQueue = [...this.watchedAddresses];
    if (this.queueIndex >= this.checkQueue.length) {
      this.queueIndex = 0;
    }
  }

  /**
   * Poll the next address in the queue.
   */
  private async pollNext(): Promise<void> {
    if (!this.running || this.checkQueue.length === 0) return;

    const address = this.checkQueue[this.queueIndex];
    this.queueIndex = (this.queueIndex + 1) % this.checkQueue.length;

    try {
      await this.checkAddress(address);
    } catch (err) {
      console.error(
        `[NearIntentsWatcher] Error checking ${address.substring(0, 8)}...:`,
        err instanceof Error ? err.message : err
      );
    }
  }

  /**
   * Search the Explorer API for bridge transactions involving this address.
   */
  private async checkAddress(address: string): Promise<void> {
    const url = new URL(`${this.API_BASE}/transactions`);
    url.searchParams.set("search", address);
    url.searchParams.set("numberOfTransactions", "20");
    url.searchParams.set("statuses", "SUCCESS");

    const response = await fetch(url.toString(), {
      headers: {
        Authorization: `Bearer ${this.jwt}`,
        Accept: "application/json",
      },
    });

    if (response.status === 429) {
      console.warn("[NearIntentsWatcher] Rate limited — backing off");
      return;
    }

    if (!response.ok) {
      console.error(`[NearIntentsWatcher] API ${response.status}: ${response.statusText}`);
      return;
    }

    const transactions: NearIntentsTx[] = await response.json();

    for (const tx of transactions) {
      this.processBridgeTx(address, tx);
    }
  }

  /**
   * Process a single bridge transaction.
   * Emit a PaymentEvent if:
   *   - The flagged address is the sender
   *   - The destination is a different chain
   *   - We haven't processed this intent before
   */
  private processBridgeTx(watchedAddress: string, tx: NearIntentsTx): void {
    if (!this.paymentCallback) return;
    if (tx.status !== "SUCCESS") return;

    // Check if any sender matches the watched address
    const isSender = tx.senders.some(
      (s) => s.toLowerCase() === watchedAddress.toLowerCase()
    );
    // Also check refundTo (another address format the sender might use)
    const isRefundTo = tx.refundTo?.toLowerCase() === watchedAddress.toLowerCase();

    if (!isSender && !isRefundTo) return;

    // Deduplicate by intent hash
    const intentKey = tx.intentHashes || `${tx.depositAddress}_${tx.createdAtTimestamp}`;
    if (this.processedIntents.has(intentKey)) return;

    // Check timestamp — only process new transactions
    const lastSeen = this.lastSeen.get(watchedAddress) || 0;
    if (tx.createdAtTimestamp <= lastSeen) return;

    // Mark as processed
    this.processedIntents.add(intentKey);
    this.lastSeen.set(watchedAddress, tx.createdAtTimestamp);

    // Cleanup old processed intents to prevent memory leak
    if (this.processedIntents.size > this.MAX_PROCESSED) {
      const entries = [...this.processedIntents];
      this.processedIntents = new Set(entries.slice(entries.length - this.MAX_PROCESSED / 2));
    }

    // Determine destination chain
    let destChain = extractChainFromAsset(tx.destinationAsset);
    if (!destChain) {
      destChain = detectChainFromAddress(tx.recipient);
    }

    // Skip if the destination is the same chain (not a cross-chain bridge)
    const originChain = extractChainFromAsset(tx.originAsset) || "stellar";
    if (destChain === originChain) return;

    // Get the tx hash on the destination chain
    const destTxHash = tx.destinationChainTxHashes?.[0] || intentKey;
    const originTxHash = tx.originChainTxHashes?.[0] || "";

    const event: PaymentEvent = {
      chain: destChain,
      sender: watchedAddress,
      recipient: tx.recipient,
      amount: tx.amountOutFormatted,
      asset: tx.destinationAsset,
      txHash: destTxHash,
      timestamp: tx.createdAt,
      bridgeProvider: "near_intents",
      originChain,
      originTxHash,
    };

    console.log(
      `[NearIntentsWatcher] 🌉 Bridge detected: ${watchedAddress.substring(0, 8)}... ` +
      `→ ${tx.recipient.substring(0, 12)}... | ${originChain} → ${destChain} | ` +
      `$${tx.amountInUsd} USD | via NEAR Intents`
    );

    this.paymentCallback(event);
  }
}
