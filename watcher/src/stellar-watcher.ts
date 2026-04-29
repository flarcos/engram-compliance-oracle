// ─── Stellar Watcher ────────────────────────────────────────────────────
// Implements ChainWatcher for Stellar using Horizon's server-sent events.
// Streams real-time payments for all watched addresses.

import { Horizon } from "@stellar/stellar-sdk";
import type { ChainWatcher, PaymentEvent } from "./types.js";

export class StellarWatcher implements ChainWatcher {
  readonly chain = "stellar";

  private server: Horizon.Server;
  private watchedAddresses: Set<string> = new Set();
  private activeStreams: Map<string, () => void> = new Map();
  private paymentCallback: ((event: PaymentEvent) => void) | null = null;
  private running = false;

  constructor(horizonUrl: string) {
    this.server = new Horizon.Server(horizonUrl);
  }

  /**
   * Register the callback for incoming payment events.
   */
  onPayment(callback: (event: PaymentEvent) => void): void {
    this.paymentCallback = callback;
  }

  /**
   * Start the watcher. Opens SSE streams for all currently watched addresses.
   */
  async start(): Promise<void> {
    this.running = true;
    console.log(`[StellarWatcher] Started — monitoring ${this.watchedAddresses.size} addresses`);

    // Open streams for all addresses that were subscribed before start
    for (const address of this.watchedAddresses) {
      this.openStream(address);
    }
  }

  /**
   * Stop the watcher. Closes all SSE streams.
   */
  stop(): void {
    this.running = false;
    for (const [address, close] of this.activeStreams) {
      close();
      console.log(`[StellarWatcher] Closed stream for ${address.substring(0, 8)}...`);
    }
    this.activeStreams.clear();
    console.log("[StellarWatcher] Stopped");
  }

  /**
   * Subscribe to payment monitoring for an address.
   */
  subscribe(address: string): void {
    if (this.watchedAddresses.has(address)) return;

    this.watchedAddresses.add(address);

    // If already running, immediately open a stream
    if (this.running) {
      this.openStream(address);
    }
  }

  /**
   * Stop monitoring an address.
   */
  unsubscribe(address: string): void {
    this.watchedAddresses.delete(address);

    const close = this.activeStreams.get(address);
    if (close) {
      close();
      this.activeStreams.delete(address);
    }
  }

  /**
   * Number of currently monitored addresses.
   */
  watchCount(): number {
    return this.watchedAddresses.size;
  }

  // ── Private ─────────────────────────────────────────────────────────

  /**
   * Open a Horizon SSE stream for an address's payment operations.
   * Only monitors outbound payments (sent FROM this address).
   */
  private openStream(address: string): void {
    if (this.activeStreams.has(address)) return;

    try {
      const close = this.server
        .payments()
        .forAccount(address)
        .cursor("now")
        .stream({
          onmessage: (record: Horizon.ServerApi.OperationRecord) => {
            this.handlePayment(address, record);
          },
          onerror: (error: unknown) => {
            console.error(
              `[StellarWatcher] Stream error for ${address.substring(0, 8)}...:`,
              error
            );
            // Auto-reconnect after 5 seconds
            this.activeStreams.delete(address);
            if (this.running && this.watchedAddresses.has(address)) {
              setTimeout(() => this.openStream(address), 5000);
            }
          },
        });

      this.activeStreams.set(address, close);
      console.log(`[StellarWatcher] Streaming payments for ${address.substring(0, 8)}...`);
    } catch (err) {
      console.error(`[StellarWatcher] Failed to open stream for ${address.substring(0, 8)}...:`, err);
    }
  }

  /**
   * Process a raw Horizon payment record into a PaymentEvent.
   * Only processes outbound payments (where the watched address is the sender).
   */
  private handlePayment(
    watchedAddress: string,
    record: Horizon.ServerApi.OperationRecord
  ): void {
    if (!this.paymentCallback) return;

    // We only care about "payment" and "path_payment_*" types
    const type = record.type;
    if (type !== "payment" && type !== "path_payment_strict_send" && type !== "path_payment_strict_receive") {
      return;
    }

    // Narrow to payment type
    const payment = record as Horizon.ServerApi.PaymentOperationRecord;

    // Only track outbound payments (FROM the watched address)
    const from = payment.from;
    if (from !== watchedAddress) return;

    // Extract payment details
    const to = payment.to;
    const amount = payment.amount;
    const asset = payment.asset_type === "native"
      ? "native"
      : `${payment.asset_code}:${payment.asset_issuer}`;
    const txHash = payment.transaction_hash;
    const timestamp = payment.created_at;

    const event: PaymentEvent = {
      chain: "stellar",
      sender: from,
      recipient: to,
      amount,
      asset,
      txHash,
      timestamp,
    };

    this.paymentCallback(event);
  }
}
