// ─── Taint Scoring Engine ────────────────────────────────────────────────
// Chain-agnostic scoring engine that processes PaymentEvents
// and produces TaintRecords based on configurable rules.

import type { PaymentEvent, TaintRecord, TaintStatus, WatchedAddress } from "./types.js";

/**
 * Scoring configuration thresholds.
 */
interface ScoringConfig {
  /** Minimum XLM-equivalent amount to trigger taint (below = ignored as dust) */
  minAmountXlm: number;
  /** Maximum hop depth to propagate taint */
  maxHops: number;
}

/**
 * Score thresholds → status mapping.
 *   < 10  = clean     (no action)
 *  10–29  = low_risk  (logged, no flag)
 *  30–59  = elevated  (API warning)
 *  60–89  = high_risk (auto-flagged on-chain)
 *  >= 90  = critical  (treated as sanctioned)
 */
function scoreToStatus(score: number): TaintStatus {
  if (score < 10) return "clean";
  if (score < 30) return "low_risk";
  if (score < 60) return "elevated";
  if (score < 90) return "high_risk";
  return "critical";
}

/**
 * Severity weight by source type.
 */
function baseSeverity(type: WatchedAddress["type"]): number {
  switch (type) {
    case "sanctioned":
      return 1.0;
    case "community_flagged":
      return 0.7;
    case "tainted":
      return 0.5;
    default:
      return 0.5;
  }
}

/**
 * The Taint Scoring Engine.
 *
 * Score formula:
 *   taint_score = base_severity × amount_factor × decay_factor × hop_penalty
 *
 * Where:
 *   base_severity: 1.0 (OFAC), 0.7 (community), 0.5 (inherited taint)
 *   amount_factor: min(1.0, received_amount / estimated_source_balance)
 *   decay_factor:  0.8 ^ hop_depth
 *   hop_penalty:   1.0 for hop 1, 0.6 for hop 2
 */
export class ScoringEngine {
  private config: ScoringConfig;

  constructor(config: ScoringConfig) {
    this.config = config;
  }

  /**
   * Process a payment event and determine if taint should be propagated.
   * Returns null if the payment doesn't meet taint criteria.
   */
  evaluate(
    event: PaymentEvent,
    source: WatchedAddress,
  ): TaintRecord | null {
    // 1. Check minimum amount (dust attack protection)
    const amount = parseFloat(event.amount);
    if (isNaN(amount) || amount < this.config.minAmountXlm) {
      return null;
    }

    // 2. Calculate hop depth for the recipient
    const recipientHop = source.hopDepth + 1;
    if (recipientHop > this.config.maxHops) {
      return null;
    }

    // 3. Calculate taint score
    const severity = source.severity ?? baseSeverity(source.type);
    const amountFactor = Math.min(1.0, amount / 10000); // Normalize against 10k XLM
    const decayFactor = Math.pow(0.8, recipientHop);
    const hopPenalty = recipientHop === 1 ? 1.0 : 0.6;

    const rawScore = severity * amountFactor * decayFactor * hopPenalty;
    const score = Math.round(rawScore * 100); // Convert to 0–100

    // 4. Determine status
    const status = scoreToStatus(score);

    // 5. Skip if clean
    if (status === "clean") {
      return null;
    }

    return {
      taintedAddress: event.recipient,
      sourceAddress: event.sender,
      originalSource: source.hopDepth === 0 ? source.address : source.address,
      originalSourceType: source.type === "sanctioned"
        ? (source.source as TaintRecord["originalSourceType"])
        : source.type === "community_flagged"
          ? "community_flagged"
          : "tainted",
      score,
      hopDepth: recipientHop,
      chain: event.chain,
      amount: event.amount,
      asset: event.asset,
      txHash: event.txHash,
      detectedAt: new Date().toISOString(),
      status,
    };
  }

  /**
   * Update scoring configuration.
   */
  updateConfig(config: Partial<ScoringConfig>): void {
    if (config.minAmountXlm !== undefined) this.config.minAmountXlm = config.minAmountXlm;
    if (config.maxHops !== undefined) this.config.maxHops = config.maxHops;
  }
}
