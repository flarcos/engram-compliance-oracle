# Compliant Swap — DeFi Integration Example

A minimal Soroban DEX contract demonstrating how to integrate the **Engram Compliance Oracle** for on-chain taint screening. All compliance checks happen on-chain, in the same transaction — no API keys, no off-chain lookups.

## 3 Integration Patterns

### Pattern 1: Simple Gate (`swap_simple`)

The recommended starting point. One cross-contract call blocks any flagged address — sanctions, consensus, or taint.

```rust
let oracle = oracle::Client::new(&env, &oracle_id);

if oracle.is_flagged(&sender_str) {
    return Err(SwapError::SenderFlagged);
}
```

**Best for:** Most protocols. Zero configuration. Covers all 4 layers.

### Pattern 2: Score-Based (`swap_scored`)

More nuanced — allows addresses with low taint scores (e.g. 2-hop indirect recipients) while blocking high-risk addresses.

```rust
let sender_score = oracle.taint_score(&sender_str);
if sender_score >= threshold {
    return Err(SwapError::SenderTaintTooHigh);
}
```

**Best for:** DEXs that want to avoid blocking innocent users who received funds indirectly from a tainted address.

### Pattern 3: Full Provenance (`swap_audited`)

Maximum visibility. Emits taint metadata as contract events even for clean addresses, giving indexers and frontends rich compliance context.

```rust
let sender_score = oracle.taint_score(&sender_str);
let sender_chain = oracle.taint_chain(&sender_str);
let sender_hop = oracle.taint_hop(&sender_str);

env.events().publish(
    (Symbol::new(&env, "compliance_check"),),
    (sender_str, sender_score, sender_hop, sender_chain),
);
```

**Best for:** Institutional DEXs needing full audit trails.

## Pre-Swap Compliance Check

For frontends — check if a swap would pass before submitting the transaction:

```rust
let (is_clean, score, reason) = compliant_swap.check_compliance(&user_address);
// is_clean: true if would pass
// score: 0–100 taint score  
// reason: 0=clean, 1=consensus, 2=tainted, 3=both
```

## Test Suite

The test suite runs against a **real oracle contract** — no mocks. Both contracts are deployed in the same Soroban test environment with real token contracts.

### Test Matrix

| Category | Tests | Description |
|---|---|---|
| **Simple Gate** | 4 | Clean swap, tainted sender/recipient, consensus-flagged |
| **Score-Based** | 3 | Below threshold, above threshold, consensus override |
| **Full Provenance** | 2 | Clean with events, blocked with events |
| **Compliance Check** | 4 | Clean, tainted, consensus, both flags |
| **Admin** | 3 | Initialize, set_oracle, set_threshold, double-init |
| **Edge Cases** | 4 | Zero amount, negative, multiple swaps, custom threshold |

### Run Tests

```bash
# Build the oracle WASM first (required for contractimport)
cargo build --target wasm32-unknown-unknown --release -p engram-compliance-oracle

# Run the compliant-swap tests
cargo test -p compliant-swap
```

## Build

```bash
# From the workspace root
cargo build --target wasm32-unknown-unknown --release -p compliant-swap
```

## Deploy

### Quick Deploy (Testnet)

```bash
cd examples/compliant-swap
./deploy.sh
```

The script will:
1. Build both the oracle and swap WASM
2. Deploy the swap contract to testnet
3. Initialize with the deployed oracle
4. Verify with a compliance check

### Manual Deploy

```bash
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/compliant_swap.wasm \
  --source <SECRET_KEY> \
  --network testnet

# Initialize with the oracle contract ID
stellar contract invoke \
  --id <SWAP_CONTRACT_ID> \
  --source <SECRET_KEY> \
  --network testnet \
  -- initialize \
  --admin <ADMIN_ADDRESS> \
  --oracle_id CCDAXPPXNXCM25QHYVEWDYBU3FJTNU6Z6BYCHTRRHJEXU6RGVD32PWQF \
  --block_threshold 60
```

### Configuration

| Env Var | Default | Description |
|---|---|---|
| `NETWORK` | `testnet` | Stellar network (`testnet` or `mainnet`) |
| `ORACLE_ID` | `CCDAXPP...` | Deployed oracle contract ID |
| `BLOCK_THRESHOLD` | `60` | Min taint score to block (0=all, 60=high-risk) |

## Frontend Integration

Check compliance before submitting a swap transaction:

```typescript
import { Contract, Server } from '@stellar/stellar-sdk';

const server = new Server('https://soroban-testnet.stellar.org');
const swap = new Contract('SWAP_CONTRACT_ID');

// Pre-check: will this address pass compliance?
const result = await server.simulateTransaction(
  swap.call('check_compliance', xdr.Address.fromString(userAddress))
);

const [isClean, taintScore, flagReason] = result.returnValue;

if (!isClean) {
  if (flagReason === 1) showWarning('Address flagged by community consensus');
  if (flagReason === 2) showWarning(`Address tainted (score: ${taintScore})`);
  if (flagReason === 3) showWarning('Address flagged by consensus AND tainted');
} else {
  // Safe to proceed with swap
  await submitSwap(sender, recipient, tokenIn, tokenOut, amount);
}
```

## Oracle Contract

The example connects to the deployed Engram Compliance Oracle:

**Testnet:** `CCDAXPPXNXCM25QHYVEWDYBU3FJTNU6Z6BYCHTRRHJEXU6RGVD32PWQF`

See the [main README](../../README.md) for the full contract interface.
