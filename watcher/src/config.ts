// ─── Config ─────────────────────────────────────────────────────────────
// Loads configuration from environment variables.

import { config as dotenvConfig } from "dotenv";
import type { WatcherConfig } from "./types.js";

dotenvConfig();

export function loadConfig(): WatcherConfig {
  return {
    horizonUrl: env("HORIZON_URL", "https://horizon-testnet.stellar.org"),
    network: env("STELLAR_NETWORK", "testnet") as "testnet" | "mainnet",
    contractId: env("CONTRACT_ID", "CCDAXPPXNXCM25QHYVEWDYBU3FJTNU6Z6BYCHTRRHJEXU6RGVD32PWQF"),
    engramApiUrl: env("ENGRAM_API_URL", "https://api.engram.sh"),
    engramApiKey: env("ENGRAM_API_KEY", ""),
    operatorSecret: env("OPERATOR_SECRET", ""),
    taintMinAmountXlm: Number(env("TAINT_MIN_AMOUNT_XLM", "100")),
    taintMaxHops: Number(env("TAINT_MAX_HOPS", "2")),
    pollIntervalMs: Number(env("POLL_INTERVAL_MS", "5000")),
  };
}

function env(key: string, fallback: string): string {
  return process.env[key] ?? fallback;
}
