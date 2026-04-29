# Engram Compliance Oracle

**Multi-layer on-chain compliance for Stellar/Soroban DeFi.**

A Soroban smart contract providing 4 layers of protection: Merkle-verified sanctions screening, agent consensus flagging, community reporting, and **automatic taint propagation** — all callable on-chain, in the same transaction.

🔗 **[Live Demo →](https://kytdemo.throbbing-cloud-0f8e.workers.dev/)**

## Architecture

```
Layer 1: Merkle Sanctions    → OFAC/OpenSanctions verified via on-chain Merkle proofs
Layer 2: Agent Consensus     → Multiple agents report → auto-flag at threshold
Layer 3: Community Reports   → On-chain reports with operator review
Layer 4: Taint Propagation   → Auto-flag recipients of flagged wallets (v0.6.0)
```

**Key behavior:** `is_flagged()` returns `true` for both consensus-flagged **and** tainted addresses. Any DeFi protocol already calling `is_flagged()` automatically gets taint protection — no code changes needed.

## Live on Testnet

**Contract:** [`CCDAXPPXNXCM25QHYVEWDYBU3FJTNU6Z6BYCHTRRHJEXU6RGVD32PWQF`](https://stellar.expert/explorer/testnet/contract/CCDAXPPXNXCM25QHYVEWDYBU3FJTNU6Z6BYCHTRRHJEXU6RGVD32PWQF)
**Version:** v0.6.0 — 38 exported functions
**WASM Hash:** `1a661658c3f6d8c9d2851e6b48cb62f701064ecde3456f08f3f2c96567a14770`

### Community Flagged Addresses (Testnet)

| Address | Status |
|---|---|
| `GA4ALNXXELASVP2S4FZXQFVXP3BPST7S2MZ5KBCSTR4PK3442NSQ5EQB` | 🚩 Flagged |
| `GAZLTY5QNQQ4WBU6E3T3KKPZAREGARH6JQS4WF76QSWZ7GYTMGBDJZ5X` | 🚩 Flagged |

### Whitelisted Addresses (Testnet)

| Address | Label |
|---|---|
| `GCGNWKCJ3KHRLPM3TM6N7D3W5YKDJFL6A2YCXFXNMRTZ4Q66MEMZ4FI2` | Coinbase |

## Quick Start

### For DeFi Integrators

```rust
let oracle = ComplianceOracleClient::new(&env, &oracle_contract_id);

// Single check — covers sanctions, consensus flags, AND taint
if oracle.is_flagged(&user_address) {
    panic!("Address is flagged — transaction blocked");
}

// Need to know WHY it's flagged?
let reason = oracle.flag_reason(&user_address);
// 0 = clean, 1 = consensus, 2 = tainted, 3 = both

// Check taint details
if oracle.is_tainted(&user_address) {
    let score = oracle.taint_score(&user_address);  // 0–100
    let source = oracle.taint_source(&user_address); // who sent funds
    let chain = oracle.taint_chain(&user_address);   // which blockchain
}

// Merkle proof verification (for sanctions list)
let verified = oracle.verify_merkle_proof(&address, &proof, &leaf_index);
```

### Build & Test

```bash
# Build
stellar contract build

# Test (40 tests)
cargo test

# Deploy to testnet
stellar contract deploy \
  --wasm target/wasm32v1-none/release/engram_compliance_oracle.wasm \
  --source <SECRET_KEY> \
  --network testnet
```

## CLI (compliance.sh)

```bash
# Full compliance check (flags, taint, whitelist, Merkle)
./compliance.sh check <address>

# Report a suspicious address
./compliance.sh report <address> "reason"

# Set taint for an address (operator)
./compliance.sh taint <address> <score> <source_addr> <hop> [chain]

# Clear taint (operator)
./compliance.sh clear-taint <address>

# Manage exchange whitelist
./compliance.sh whitelist add <address>
./compliance.sh whitelist remove <address>
./compliance.sh whitelist check <address>

# View taint configuration
./compliance.sh taint-config

# View contract status
./compliance.sh status
```

## Contract Interface

### Core Screening

| Function | Auth | Description |
|---|---|---|
| `is_flagged(addr)` | None | Returns true if flagged by consensus OR tainted |
| `flag_reason(addr)` | None | 0=clean, 1=consensus, 2=tainted, 3=both |
| `verify_merkle_proof(addr, proof, idx)` | None | Verify address against sanctions Merkle tree |
| `verify_batch_proofs(addrs, proofs, idxs)` | None | Batch verify multiple addresses |

### Taint Propagation (v0.6.0)

| Function | Auth | Description |
|---|---|---|
| `is_tainted(addr)` | None | Check if address is tainted |
| `taint_score(addr)` | None | Get taint score (0–100) |
| `taint_source(addr)` | None | Get the source address that caused taint |
| `taint_hop(addr)` | None | Get hop depth from original sanctioned |
| `taint_chain(addr)` | None | Get chain where taint originated |
| `set_taint(addr, score, src, hop, chain)` | Operator | Set taint for an address |
| `set_taint_batch(addrs, scores, srcs, hops, chains)` | Operator | Batch set (max 200) |
| `clear_taint(addr)` | Operator | Remove taint from an address |

### Whitelist (v0.6.0)

| Function | Auth | Description |
|---|---|---|
| `whitelist_address(addr)` | Operator | Exempt address from taint (exchanges, custodials) |
| `unwhitelist_address(addr)` | Operator | Remove exemption |
| `is_whitelisted(addr)` | None | Check whitelist status |

### Configuration

| Function | Auth | Description |
|---|---|---|
| `taint_config()` | None | Returns (min_amount, max_hops) |
| `set_taint_min_amount(amount)` | Operator | Set minimum taint amount (stroops) |
| `set_taint_max_hops(max_hops)` | Operator | Set max propagation depth |
| `set_report_threshold(n)` | Operator | Set auto-flag threshold |

### Community Reporting

| Function | Auth | Description |
|---|---|---|
| `report_address(reporter, target, reason)` | Reporter | Submit a community report |
| `reports_for(addr)` | None | Get report count for address |
| `get_report(id)` | None | Get report details |
| `review_report(id, accept)` | Operator | Accept/reject a report |

### Admin

| Function | Auth | Description |
|---|---|---|
| `initialize(owner, operator)` | None | One-time setup |
| `set_merkle_root(root, count, hash, src)` | Operator | Update sanctions Merkle tree |
| `set_operator(new_op)` | Owner | Change operator key |
| `transfer_owner(new_owner)` | Owner | Transfer ownership |
| `upgrade(new_wasm_hash)` | Owner | Upgrade contract code |

## Taint Watcher Service

The `watcher/` directory contains the Stellar Taint Watcher — an off-chain service that monitors Horizon payment streams from flagged addresses and automatically propagates taint to recipients.

```bash
cd watcher
cp .env.example .env   # Configure API keys
npm install
npm run dev             # Start watching
```

**Architecture:** Pluggable chain adapters — starting with Stellar (Horizon SSE), extensible to EVM and Movement chains.

**Safety features:**
- Dust attack protection (configurable minimum amount, default 100 XLM)
- Exchange whitelist (Coinbase, Binance, Kraken, Lobstr)
- Rate limiting (500 taints/hour)
- Storm detection (>50 from single source in 10 min → manual review)

## Data Sources

| Source | Type | Layer | Coverage |
|---|---|---|---|
| [OFAC SDN](https://sanctionslist.ofac.treas.gov/) | Government | 1 | US sanctions list |
| [OpenSanctions](https://opensanctions.org/) | Open data | 1 | Global sanctions & PEPs |
| Community Reports | Crowdsourced | 2–3 | User-submitted flagged addresses |
| Taint Propagation | Automated | 4 | Recipients of flagged wallets |

## License

MIT
