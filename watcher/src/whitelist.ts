// ─── Whitelist ───────────────────────────────────────────────────────────
// Manages the exchange/custodial address whitelist.
// Whitelisted addresses are never tainted and don't propagate taint downstream.

import type { WhitelistEntry } from "./types.js";

/**
 * Known Stellar exchange and custodial hot wallets.
 * These are seeded on startup and can be extended via the operator.
 *
 * Sources:
 * - Stellar Expert known accounts
 * - Public exchange documentation
 */
const SEED_WHITELIST: WhitelistEntry[] = [
  // ── Major Exchanges ──
  {
    address: "GCGNWKCJ3KHRLPM3TM6N7D3W5YKDJFL6A2YCXFXNMRTZ4Q66MEMZ4FI2",
    label: "Coinbase",
    type: "exchange",
    chain: "stellar",
  },
  {
    address: "GD6HBYBKJKLMQYNURTC2AQYAHKR2XNPXM3GZUKOQV6WUCE6OA7KDSUN",
    label: "Binance",
    type: "exchange",
    chain: "stellar",
  },
  {
    address: "GAHK7EEG2WWHVKDNT4CEQFZGKF2LGDSW2IVM4S5DP42RBW3K6BTODB4A",
    label: "Kraken",
    type: "exchange",
    chain: "stellar",
  },
  {
    address: "GB7GRJ5DTE3AA2TCVHQS2LAD3D7NFG7YLTOESJR65MFZLUQX33RQRRYG",
    label: "Lobstr",
    type: "exchange",
    chain: "stellar",
  },
  // ── Anchors ──
  {
    address: "GDUKMGUGDZQK6YHYA5Z6AY2G4XDSZPSZ3SW5UN3ARVMO6QSRDWP5YLEX",
    label: "StellarTerm",
    type: "protocol",
    chain: "stellar",
  },
];

export class Whitelist {
  private entries: Map<string, WhitelistEntry> = new Map();

  constructor() {
    // Seed with known addresses
    for (const entry of SEED_WHITELIST) {
      this.entries.set(entry.address, entry);
    }
  }

  /**
   * Check if an address is whitelisted.
   */
  isWhitelisted(address: string): boolean {
    return this.entries.has(address);
  }

  /**
   * Get the whitelist entry for an address.
   */
  get(address: string): WhitelistEntry | undefined {
    return this.entries.get(address);
  }

  /**
   * Add an address to the whitelist.
   */
  add(entry: WhitelistEntry): void {
    this.entries.set(entry.address, entry);
  }

  /**
   * Remove an address from the whitelist.
   */
  remove(address: string): void {
    this.entries.delete(address);
  }

  /**
   * Get all whitelist entries.
   */
  all(): WhitelistEntry[] {
    return Array.from(this.entries.values());
  }

  /**
   * Number of whitelisted addresses.
   */
  size(): number {
    return this.entries.size;
  }
}
