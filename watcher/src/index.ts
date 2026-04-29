// ─── Taint Watcher Orchestrator ──────────────────────────────────────────
// Main entry point. Connects the chain watcher, scoring engine, whitelist,
// and Engram API into a single pipeline.
//
// Flow:
//   1. Fetch all flagged/sanctioned addresses from Engram API
//   2. Subscribe to payment streams for each address
//   3. On payment: score → whitelist check → store taint → add recipient to watch list
//   4. Periodically poll for newly flagged addresses

import { loadConfig } from "./config.js";
import { StellarWatcher } from "./stellar-watcher.js";
import { ScoringEngine } from "./scoring.js";
import { Whitelist } from "./whitelist.js";
import type { PaymentEvent, TaintRecord, WatchedAddress, WatcherConfig } from "./types.js";

// ─── Rate Limiting ──────────────────────────────────────────────────────

/** Circuit breaker: max taint propagations per hour */
const MAX_TAINTS_PER_HOUR = 500;
/** Circuit breaker: max new watched addresses per hour */
const MAX_NEW_WATCHES_PER_HOUR = 200;
/** Taint storm detection: max taints from single source in 10 min */
const STORM_THRESHOLD = 50;
const STORM_WINDOW_MS = 10 * 60 * 1000;

// ─── Orchestrator ───────────────────────────────────────────────────────

class TaintOrchestrator {
  private config: WatcherConfig;
  private watcher: StellarWatcher;
  private scoring: ScoringEngine;
  private whitelist: Whitelist;

  /** Map of watched addresses → their metadata */
  private watchedMap: Map<string, WatchedAddress> = new Map();

  /** Taint records pending push to contract */
  private pendingTaints: TaintRecord[] = [];

  /** Rate limiting counters */
  private hourlyTaints = 0;
  private hourlyNewWatches = 0;
  private stormCounters: Map<string, { count: number; windowStart: number }> = new Map();

  /** Polling interval handle */
  private pollHandle: ReturnType<typeof setInterval> | null = null;
  private hourlyResetHandle: ReturnType<typeof setInterval> | null = null;

  constructor(config: WatcherConfig) {
    this.config = config;
    this.watcher = new StellarWatcher(config.horizonUrl);
    this.scoring = new ScoringEngine({
      minAmountXlm: config.taintMinAmountXlm,
      maxHops: config.taintMaxHops,
    });
    this.whitelist = new Whitelist();
  }

  /**
   * Start the orchestrator.
   */
  async start(): Promise<void> {
    console.log("╔═══════════════════════════════════════════════════════════╗");
    console.log("║     Engram Taint Watcher v0.6.0                         ║");
    console.log("║     Transaction Taint Propagation for Stellar           ║");
    console.log("╚═══════════════════════════════════════════════════════════╝");
    console.log();
    console.log(`  Horizon:    ${this.config.horizonUrl}`);
    console.log(`  Network:    ${this.config.network}`);
    console.log(`  Contract:   ${this.config.contractId}`);
    console.log(`  Min Amount: ${this.config.taintMinAmountXlm} XLM`);
    console.log(`  Max Hops:   ${this.config.taintMaxHops}`);
    console.log(`  Whitelist:  ${this.whitelist.size()} addresses`);
    console.log();

    // 1. Register payment handler
    this.watcher.onPayment((event) => this.handlePayment(event));

    // 2. Fetch initial flagged addresses
    await this.fetchFlaggedAddresses();
    console.log(`[Orchestrator] Watching ${this.watchedMap.size} addresses`);

    // 3. Start the Stellar watcher
    await this.watcher.start();

    // 4. Start polling for new flagged addresses
    this.pollHandle = setInterval(
      () => this.fetchFlaggedAddresses(),
      this.config.pollIntervalMs
    );

    // 5. Reset hourly counters
    this.hourlyResetHandle = setInterval(() => {
      this.hourlyTaints = 0;
      this.hourlyNewWatches = 0;
    }, 60 * 60 * 1000);

    console.log("[Orchestrator] Running. Press Ctrl+C to stop.");
  }

  /**
   * Stop the orchestrator.
   */
  stop(): void {
    if (this.pollHandle) clearInterval(this.pollHandle);
    if (this.hourlyResetHandle) clearInterval(this.hourlyResetHandle);
    this.watcher.stop();
    console.log("[Orchestrator] Stopped");
  }

  // ── Core Pipeline ───────────────────────────────────────────────────

  /**
   * Handle an incoming payment event from the chain watcher.
   */
  private handlePayment(event: PaymentEvent): void {
    const source = this.watchedMap.get(event.sender);
    if (!source) return; // Sender not in our watch list (shouldn't happen)

    // 1. Check whitelist — skip if recipient is whitelisted
    if (this.whitelist.isWhitelisted(event.recipient)) {
      console.log(
        `[Orchestrator] Payment to whitelisted address ${event.recipient.substring(0, 8)}... — skipped`
      );
      return;
    }

    // 2. Check rate limits
    if (!this.checkRateLimits(event.sender)) {
      return;
    }

    // 3. Score the payment
    const taint = this.scoring.evaluate(event, source);
    if (!taint) {
      // Below threshold — dust or too attenuated
      return;
    }

    // 4. Log the taint
    console.log(
      `[TAINT] ${event.sender.substring(0, 8)}... → ${event.recipient.substring(0, 8)}... | ` +
      `Score: ${taint.score} | Status: ${taint.status} | Hop: ${taint.hopDepth} | ` +
      `Amount: ${event.amount} ${event.asset} | TX: ${event.txHash.substring(0, 12)}...`
    );

    // 5. Store the taint record
    this.pendingTaints.push(taint);
    this.hourlyTaints++;

    // 6. Add recipient to watch list (recursive monitoring)
    if (taint.hopDepth < this.config.taintMaxHops) {
      this.addToWatchList({
        address: event.recipient,
        type: "tainted",
        source: `taint_from:${event.sender.substring(0, 12)}`,
        severity: 0.5,
        hopDepth: taint.hopDepth,
        chain: event.chain,
      });
    }

    // 7. Push to Engram API (async, non-blocking)
    this.pushTaintToEngram(taint).catch((err) => {
      console.error("[Orchestrator] Failed to push taint to Engram:", err);
    });
  }

  // ── Flagged Address Fetching ────────────────────────────────────────

  /**
   * Fetch currently flagged/sanctioned addresses from the Engram API.
   * Falls back to static seed addresses if API key is not configured.
   */
  private async fetchFlaggedAddresses(): Promise<void> {
    try {
      if (this.config.engramApiKey) {
        // ── Live: fetch from Engram API ──
        const response = await fetch(`${this.config.engramApiUrl}/v1/compliance/flagged?chain=stellar`, {
          headers: {
            Authorization: `Bearer ${this.config.engramApiKey}`,
            Accept: "application/json",
          },
        });

        if (response.ok) {
          const data = (await response.json()) as {
            sanctioned: Array<{
              address: string;
              type: string;
              source: string;
              severity: number;
            }>;
            tainted: Array<{
              address: string;
              type: string;
              source: string;
              severity: number;
              hopDepth: number;
              chain: string;
            }>;
            totalCount: number;
          };

          let newCount = 0;

          for (const entry of data.sanctioned) {
            if (!this.watchedMap.has(entry.address)) {
              this.addToWatchList({
                address: entry.address,
                type: entry.type as any,
                source: entry.source,
                severity: entry.severity,
                hopDepth: 0,
                chain: "stellar",
              });
              newCount++;
            }
          }

          for (const entry of data.tainted) {
            if (!this.watchedMap.has(entry.address) && entry.hopDepth < this.config.taintMaxHops) {
              this.addToWatchList({
                address: entry.address,
                type: entry.type as any,
                source: entry.source,
                severity: entry.severity,
                hopDepth: entry.hopDepth,
                chain: entry.chain || "stellar",
              });
              newCount++;
            }
          }

          if (newCount > 0) {
            console.log(
              `[Orchestrator] Fetched ${data.totalCount} flagged addresses from Engram API (+${newCount} new)`
            );
          }
          return;
        } else {
          console.warn(`[Orchestrator] Engram API returned ${response.status} — falling back to seed list`);
        }
      }

      // ── Fallback: static seed addresses ──
      const seedAddresses: WatchedAddress[] = [
        {
          address: "GA4ALNXXELASVP2S4FZXQFVXP3BPST7S2MZ5KBCSTR4PK3442NSQ5EQB",
          type: "community_flagged",
          source: "agent_consensus",
          severity: 0.7,
          hopDepth: 0,
          chain: "stellar",
        },
        {
          address: "GAZLTY5QNQQ4WBU6E3T3KKPZAREGARH6JQS4WF76QSWZ7GYTMGBDJZ5X",
          type: "community_flagged",
          source: "agent_consensus",
          severity: 0.7,
          hopDepth: 0,
          chain: "stellar",
        },
      ];

      for (const entry of seedAddresses) {
        this.addToWatchList(entry);
      }
    } catch (err) {
      console.error("[Orchestrator] Failed to fetch flagged addresses:", err);
    }
  }

  /**
   * Add an address to the watch list and subscribe to the watcher.
   */
  private addToWatchList(entry: WatchedAddress): void {
    if (this.watchedMap.has(entry.address)) return;

    // Rate limit new watches
    if (this.hourlyNewWatches >= MAX_NEW_WATCHES_PER_HOUR) {
      console.warn("[Orchestrator] Max new watches per hour reached — queuing");
      return;
    }

    this.watchedMap.set(entry.address, entry);
    this.watcher.subscribe(entry.address);
    this.hourlyNewWatches++;
  }

  // ── Rate Limiting ──────────────────────────────────────────────────

  /**
   * Check rate limits and circuit breakers.
   * Returns false if the payment should be skipped.
   */
  private checkRateLimits(sender: string): boolean {
    // Global hourly limit
    if (this.hourlyTaints >= MAX_TAINTS_PER_HOUR) {
      console.warn("[Orchestrator] ⚠ Hourly taint limit reached — pausing");
      return false;
    }

    // Per-source storm detection
    const now = Date.now();
    const counter = this.stormCounters.get(sender);

    if (counter) {
      if (now - counter.windowStart > STORM_WINDOW_MS) {
        // Reset window
        this.stormCounters.set(sender, { count: 1, windowStart: now });
      } else {
        counter.count++;
        if (counter.count > STORM_THRESHOLD) {
          console.warn(
            `[Orchestrator] ⚠ Taint storm detected from ${sender.substring(0, 8)}... ` +
            `(${counter.count} in ${Math.round((now - counter.windowStart) / 1000)}s) — ` +
            `requires manual review`
          );
          return false;
        }
      }
    } else {
      this.stormCounters.set(sender, { count: 1, windowStart: now });
    }

    return true;
  }

  // ── Engram API Integration ─────────────────────────────────────────

  /**
   * Push a taint record to the Engram API.
   */
  private async pushTaintToEngram(taint: TaintRecord): Promise<void> {
    if (!this.config.engramApiKey) {
      // No API key configured — log only
      return;
    }

    try {
      const response = await fetch(`${this.config.engramApiUrl}/v1/compliance/taint`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${this.config.engramApiKey}`,
        },
        body: JSON.stringify(taint),
      });

      if (!response.ok) {
        console.error(`[Engram API] Failed to push taint: ${response.status} ${response.statusText}`);
      }
    } catch (err) {
      console.error("[Engram API] Network error:", err);
    }
  }

  // ── Status ─────────────────────────────────────────────────────────

  /**
   * Get current orchestrator status.
   */
  status(): {
    watching: number;
    pendingTaints: number;
    hourlyTaints: number;
    whitelistSize: number;
  } {
    return {
      watching: this.watchedMap.size,
      pendingTaints: this.pendingTaints.length,
      hourlyTaints: this.hourlyTaints,
      whitelistSize: this.whitelist.size(),
    };
  }
}

// ─── Entry Point ────────────────────────────────────────────────────────

const config = loadConfig();
const orchestrator = new TaintOrchestrator(config);

// Graceful shutdown
process.on("SIGINT", () => {
  console.log("\n[Orchestrator] Shutting down...");
  orchestrator.stop();
  process.exit(0);
});

process.on("SIGTERM", () => {
  orchestrator.stop();
  process.exit(0);
});

// Start
orchestrator.start().catch((err) => {
  console.error("[Orchestrator] Fatal error:", err);
  process.exit(1);
});
