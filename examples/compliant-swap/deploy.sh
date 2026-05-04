#!/bin/bash
set -euo pipefail

# ─── Compliant Swap Deployment Script ────────────────────────────────
#
# Deploys the Compliant Swap example to Stellar testnet and runs
# a live integration test.
#
# Prerequisites:
#   - stellar CLI installed
#   - Funded testnet account
#   - Oracle contract already deployed
#
# Usage:
#   ./deploy.sh                          # Deploy + test
#   ./deploy.sh --oracle-only            # Just set the oracle address
#   NETWORK=mainnet ./deploy.sh          # Deploy to mainnet (careful!)
# ─────────────────────────────────────────────────────────────────────

NETWORK="${NETWORK:-testnet}"
ORACLE_ID="${ORACLE_ID:-CCDAXPPXNXCM25QHYVEWDYBU3FJTNU6Z6BYCHTRRHJEXU6RGVD32PWQF}"
BLOCK_THRESHOLD="${BLOCK_THRESHOLD:-60}"
WASM_PATH="../../target/wasm32-unknown-unknown/release/compliant_swap.wasm"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Engram Compliant Swap — Deploy & Test     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Build ────────────────────────────────────────────────────

echo -e "${YELLOW}[1/5]${NC} Building contracts..."

cd "$(dirname "$0")/../.."

# Build oracle first (needed for contractimport)
cargo build --target wasm32-unknown-unknown --release -p engram-compliance-oracle 2>&1 | tail -1

# Build swap contract
cargo build --target wasm32-unknown-unknown --release -p compliant-swap 2>&1 | tail -1

if [ ! -f "$WASM_PATH" ]; then
  echo -e "${RED}✗ Build failed — WASM not found at ${WASM_PATH}${NC}"
  exit 1
fi

WASM_SIZE=$(wc -c < "$WASM_PATH" | tr -d ' ')
echo -e "${GREEN}✓ Built successfully (${WASM_SIZE} bytes)${NC}"

# ── Step 2: Deploy ───────────────────────────────────────────────────

echo ""
echo -e "${YELLOW}[2/5]${NC} Deploying to ${NETWORK}..."

# Check if source identity exists
if ! stellar keys address deployer 2>/dev/null; then
  echo -e "${RED}✗ No 'deployer' identity found.${NC}"
  echo -e "  Create one with: ${CYAN}stellar keys generate deployer --network ${NETWORK}${NC}"
  exit 1
fi

DEPLOYER=$(stellar keys address deployer)
echo -e "  Deployer: ${CYAN}${DEPLOYER}${NC}"

SWAP_ID=$(stellar contract deploy \
  --wasm "$WASM_PATH" \
  --source deployer \
  --network "$NETWORK" \
  2>&1)

if [ $? -ne 0 ]; then
  echo -e "${RED}✗ Deploy failed:${NC}"
  echo "$SWAP_ID"
  exit 1
fi

echo -e "${GREEN}✓ Deployed:${NC} ${CYAN}${SWAP_ID}${NC}"

# ── Step 3: Initialize ──────────────────────────────────────────────

echo ""
echo -e "${YELLOW}[3/5]${NC} Initializing contract..."

stellar contract invoke \
  --id "$SWAP_ID" \
  --source deployer \
  --network "$NETWORK" \
  -- initialize \
  --admin "$DEPLOYER" \
  --oracle_id "$ORACLE_ID" \
  --block_threshold "$BLOCK_THRESHOLD"

echo -e "${GREEN}✓ Initialized${NC}"
echo -e "  Oracle:    ${CYAN}${ORACLE_ID}${NC}"
echo -e "  Threshold: ${CYAN}${BLOCK_THRESHOLD}${NC}"

# ── Step 4: Verify ───────────────────────────────────────────────────

echo ""
echo -e "${YELLOW}[4/5]${NC} Verifying deployment..."

SWAP_COUNT=$(stellar contract invoke \
  --id "$SWAP_ID" \
  --source deployer \
  --network "$NETWORK" \
  -- swap_count 2>&1)

echo -e "${GREEN}✓ swap_count = ${SWAP_COUNT}${NC}"

# ── Step 5: Test compliance check ────────────────────────────────────

echo ""
echo -e "${YELLOW}[5/5]${NC} Testing pre-swap compliance check..."

COMPLIANCE=$(stellar contract invoke \
  --id "$SWAP_ID" \
  --source deployer \
  --network "$NETWORK" \
  -- check_compliance \
  --addr "$DEPLOYER" 2>&1)

echo -e "${GREEN}✓ check_compliance(deployer) = ${COMPLIANCE}${NC}"

# ── Summary ──────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Deployment Complete                        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Network:    ${GREEN}${NETWORK}${NC}"
echo -e "  Swap ID:    ${GREEN}${SWAP_ID}${NC}"
echo -e "  Oracle ID:  ${GREEN}${ORACLE_ID}${NC}"
echo -e "  Threshold:  ${GREEN}${BLOCK_THRESHOLD}${NC}"
echo -e "  Deployer:   ${GREEN}${DEPLOYER}${NC}"
echo ""
echo -e "  ${YELLOW}Try a swap:${NC}"
echo -e "  stellar contract invoke --id ${SWAP_ID} --source deployer --network ${NETWORK} \\"
echo -e "    -- swap_simple --sender \$SENDER --recipient \$RECIPIENT \\"
echo -e "    --token_in \$TOKEN_A --token_out \$TOKEN_B --amount_in 1000000 --min_amount_out 900000"
echo ""
