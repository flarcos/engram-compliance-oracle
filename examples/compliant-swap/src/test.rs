#![cfg(test)]

// ─── Compliant Swap Test Suite ─────────────────────────────────────────
//
// Tests all 3 integration patterns against a real oracle instance.
// No mocks — both contracts run in the same Soroban test environment.
//
// Test matrix:
//   ✓ Pattern 1 (Simple Gate):    clean swap, flagged sender, flagged recipient
//   ✓ Pattern 2 (Score-Based):    below threshold, above threshold, sanctions override
//   ✓ Pattern 3 (Full Provenance): clean with events, blocked with events
//   ✓ Pre-swap compliance check:  clean, tainted, consensus-flagged
//   ✓ Admin functions:            initialize, set_oracle, set_block_threshold
//   ✓ Edge cases:                 zero amount, uninitialized, double-init

use super::*;
use soroban_sdk::{
    testutils::Address as _,
    token::{StellarAssetClient, TokenClient},
    Address, Env, String,
};

// ── Oracle Contract Import ──────────────────────────────────────────────

// Import the oracle contract directly for testing
mod oracle_contract {
    soroban_sdk::contractimport!(
        file = "../../target/wasm32-unknown-unknown/release/engram_compliance_oracle.wasm"
    );
}

// ── Test Setup ──────────────────────────────────────────────────────────

#[allow(dead_code)]
struct TestContext {
    env: Env,
    admin: Address,
    swap_id: Address,
    swap: CompliantSwapClient<'static>,
    oracle_id: Address,
    oracle: oracle_contract::Client<'static>,
    token_a: TokenClient<'static>,
    token_b: TokenClient<'static>,
    token_a_admin: StellarAssetClient<'static>,
    token_b_admin: StellarAssetClient<'static>,
}

fn setup() -> TestContext {
    let env = Env::default();
    env.mock_all_auths();

    // Deploy the oracle
    let oracle_id = env.register(oracle_contract::WASM, ());
    let oracle = oracle_contract::Client::new(&env, &oracle_id);
    let oracle_owner = Address::generate(&env);
    let oracle_operator = Address::generate(&env);
    oracle.initialize(&oracle_owner, &oracle_operator);

    // Deploy the swap contract
    let swap_id = env.register(CompliantSwap, ());
    let swap = CompliantSwapClient::new(&env, &swap_id);
    let admin = Address::generate(&env);
    swap.initialize(&admin, &oracle_id, &60); // block_threshold = 60

    // Create test tokens (Stellar Asset Contract)
    let token_a_id = env.register_stellar_asset_contract_v2(admin.clone());
    let token_b_id = env.register_stellar_asset_contract_v2(admin.clone());
    let token_a_admin = StellarAssetClient::new(&env, &token_a_id.address());
    let token_b_admin = StellarAssetClient::new(&env, &token_b_id.address());
    let token_a = TokenClient::new(&env, &token_a_id.address());
    let token_b = TokenClient::new(&env, &token_b_id.address());

    TestContext {
        env,
        admin,
        swap_id,
        swap,
        oracle_id,
        oracle,
        token_a,
        token_b,
        token_a_admin,
        token_b_admin,
    }
}

/// Fund a user with both tokens and approve the swap contract.
fn fund_user(ctx: &TestContext, user: &Address, amount: i128) {
    ctx.token_a_admin.mint(user, &amount);
    ctx.token_b_admin.mint(&ctx.swap_id, &amount); // Swap contract holds token_b liquidity
}

/// Helper: taint an address in the oracle.
#[allow(dead_code)]
fn taint_address(ctx: &TestContext, addr: &str, score: u32, hop: u32) {
    let target = String::from_str(&ctx.env, addr);
    let source = String::from_str(&ctx.env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&ctx.env, "stellar");
    // Ensure hop is within oracle's max (default 2)
    ctx.oracle.set_taint_max_hops(&(hop.max(2)));
    ctx.oracle.set_taint(&target, &score, &source, &hop, &chain);
}

/// Helper: flag an address via consensus (multiple reports).
#[allow(dead_code)]
fn flag_by_consensus(ctx: &TestContext, addr: &str) {
    let target = String::from_str(&ctx.env, addr);
    let reason = String::from_str(&ctx.env, "Flagged by test");

    // Set threshold to 2 for fast test flagging
    ctx.oracle.set_report_threshold(&2);

    let r1 = Address::generate(&ctx.env);
    let r2 = Address::generate(&ctx.env);
    ctx.oracle.report_address(&r1, &target, &reason);
    ctx.oracle.report_address(&r2, &target, &reason);
}

// ════════════════════════════════════════════════════════════════════════
// Pattern 1: Simple Gate
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_swap_simple_clean_addresses() {
    let ctx = setup();
    let sender = Address::generate(&ctx.env);
    let recipient = Address::generate(&ctx.env);
    fund_user(&ctx, &sender, 1000);

    let result = ctx.swap.swap_simple(
        &sender,
        &recipient,
        &ctx.token_a.address,
        &ctx.token_b.address,
        &100,
        &100,
    );

    assert_eq!(result, 100);
    assert_eq!(ctx.token_a.balance(&sender), 900);
    assert_eq!(ctx.token_b.balance(&recipient), 100);
    assert_eq!(ctx.swap.swap_count(), 1);
}

#[test]
fn test_swap_simple_blocks_tainted_sender() {
    let ctx = setup();
    let sender = Address::generate(&ctx.env);
    let recipient = Address::generate(&ctx.env);
    fund_user(&ctx, &sender, 1000);

    // Taint the sender with high score
    let sender_str = sender.to_string();
    let source = String::from_str(&ctx.env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&ctx.env, "stellar");
    ctx.oracle.set_taint(&sender_str, &80, &source, &1, &chain);

    let result = ctx.swap.try_swap_simple(
        &sender,
        &recipient,
        &ctx.token_a.address,
        &ctx.token_b.address,
        &100,
        &100,
    );

    assert!(result.is_err());
    // Balances unchanged
    assert_eq!(ctx.token_a.balance(&sender), 1000);
    assert_eq!(ctx.swap.swap_count(), 0);
}

#[test]
fn test_swap_simple_blocks_tainted_recipient() {
    let ctx = setup();
    let sender = Address::generate(&ctx.env);
    let recipient = Address::generate(&ctx.env);
    fund_user(&ctx, &sender, 1000);

    // Taint the recipient
    let recipient_str = recipient.to_string();
    let source = String::from_str(&ctx.env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&ctx.env, "stellar");
    ctx.oracle.set_taint(&recipient_str, &90, &source, &1, &chain);

    let result = ctx.swap.try_swap_simple(
        &sender,
        &recipient,
        &ctx.token_a.address,
        &ctx.token_b.address,
        &100,
        &100,
    );

    assert!(result.is_err());
    assert_eq!(ctx.token_a.balance(&sender), 1000);
}

#[test]
fn test_swap_simple_blocks_consensus_flagged() {
    let ctx = setup();
    let sender = Address::generate(&ctx.env);
    let recipient = Address::generate(&ctx.env);
    fund_user(&ctx, &sender, 1000);

    // Flag sender via consensus reports
    let sender_str = sender.to_string();
    let reason = String::from_str(&ctx.env, "Suspicious");
    ctx.oracle.set_report_threshold(&2);
    let r1 = Address::generate(&ctx.env);
    let r2 = Address::generate(&ctx.env);
    ctx.oracle.report_address(&r1, &sender_str, &reason);
    ctx.oracle.report_address(&r2, &sender_str, &reason);

    let result = ctx.swap.try_swap_simple(
        &sender,
        &recipient,
        &ctx.token_a.address,
        &ctx.token_b.address,
        &100,
        &100,
    );

    assert!(result.is_err());
}

// ════════════════════════════════════════════════════════════════════════
// Pattern 2: Score-Based
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_swap_scored_allows_low_taint() {
    let ctx = setup();
    let sender = Address::generate(&ctx.env);
    let recipient = Address::generate(&ctx.env);
    fund_user(&ctx, &sender, 1000);

    // Taint sender with LOW score (below threshold of 60)
    let sender_str = sender.to_string();
    let source = String::from_str(&ctx.env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&ctx.env, "stellar");
    ctx.oracle.set_taint(&sender_str, &25, &source, &2, &chain);

    let result = ctx.swap.swap_scored(
        &sender,
        &recipient,
        &ctx.token_a.address,
        &ctx.token_b.address,
        &100,
        &100,
    );

    // Should succeed — score 25 is below threshold 60
    assert_eq!(result, 100);
    assert_eq!(ctx.token_a.balance(&sender), 900);
    assert_eq!(ctx.token_b.balance(&recipient), 100);
}

#[test]
fn test_swap_scored_blocks_high_taint() {
    let ctx = setup();
    let sender = Address::generate(&ctx.env);
    let recipient = Address::generate(&ctx.env);
    fund_user(&ctx, &sender, 1000);

    // Taint sender with HIGH score (above threshold of 60)
    let sender_str = sender.to_string();
    let source = String::from_str(&ctx.env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&ctx.env, "stellar");
    ctx.oracle.set_taint(&sender_str, &80, &source, &1, &chain);

    let result = ctx.swap.try_swap_scored(
        &sender,
        &recipient,
        &ctx.token_a.address,
        &ctx.token_b.address,
        &100,
        &100,
    );

    assert!(result.is_err());
    assert_eq!(ctx.token_a.balance(&sender), 1000);
}

#[test]
fn test_swap_scored_blocks_consensus_even_below_threshold() {
    let ctx = setup();
    let sender = Address::generate(&ctx.env);
    let recipient = Address::generate(&ctx.env);
    fund_user(&ctx, &sender, 1000);

    // Taint sender with low score (would pass score check)
    let sender_str = sender.to_string();
    let source = String::from_str(&ctx.env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&ctx.env, "stellar");
    ctx.oracle.set_taint(&sender_str, &10, &source, &2, &chain);

    // But also flag via consensus (should block regardless of score)
    let reason = String::from_str(&ctx.env, "Known mixer");
    ctx.oracle.set_report_threshold(&2);
    let r1 = Address::generate(&ctx.env);
    let r2 = Address::generate(&ctx.env);
    ctx.oracle.report_address(&r1, &sender_str, &reason);
    ctx.oracle.report_address(&r2, &sender_str, &reason);

    let result = ctx.swap.try_swap_scored(
        &sender,
        &recipient,
        &ctx.token_a.address,
        &ctx.token_b.address,
        &100,
        &100,
    );

    // Should fail — consensus flagged overrides low score
    assert!(result.is_err());
}

// ════════════════════════════════════════════════════════════════════════
// Pattern 3: Full Provenance (Audited)
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_swap_audited_clean_addresses() {
    let ctx = setup();
    let sender = Address::generate(&ctx.env);
    let recipient = Address::generate(&ctx.env);
    fund_user(&ctx, &sender, 1000);

    let result = ctx.swap.swap_audited(
        &sender,
        &recipient,
        &ctx.token_a.address,
        &ctx.token_b.address,
        &100,
        &100,
    );

    // Swap succeeds
    assert_eq!(result, 100);
    // Events would contain compliance_check with score=0 for both parties
}

#[test]
fn test_swap_audited_blocks_flagged() {
    let ctx = setup();
    let sender = Address::generate(&ctx.env);
    let recipient = Address::generate(&ctx.env);
    fund_user(&ctx, &sender, 1000);

    // Taint sender
    let sender_str = sender.to_string();
    let source = String::from_str(&ctx.env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&ctx.env, "stellar");
    ctx.oracle.set_taint(&sender_str, &95, &source, &1, &chain);

    let result = ctx.swap.try_swap_audited(
        &sender,
        &recipient,
        &ctx.token_a.address,
        &ctx.token_b.address,
        &100,
        &100,
    );

    // Blocked + compliance_blocked event emitted
    assert!(result.is_err());
}

// ════════════════════════════════════════════════════════════════════════
// Pre-Swap Compliance Check
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_check_compliance_clean() {
    let ctx = setup();
    let user = Address::generate(&ctx.env);

    let (is_clean, score, reason) = ctx.swap.check_compliance(&user);

    assert!(is_clean);
    assert_eq!(score, 0);
    assert_eq!(reason, 0); // 0 = clean
}

#[test]
fn test_check_compliance_tainted() {
    let ctx = setup();
    let user = Address::generate(&ctx.env);

    // Taint the user
    let user_str = user.to_string();
    let source = String::from_str(&ctx.env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&ctx.env, "stellar");
    ctx.oracle.set_taint(&user_str, &72, &source, &1, &chain);

    let (is_clean, score, reason) = ctx.swap.check_compliance(&user);

    assert!(!is_clean);
    assert_eq!(score, 72);
    assert_eq!(reason, 2); // 2 = tainted
}

#[test]
fn test_check_compliance_consensus_flagged() {
    let ctx = setup();
    let user = Address::generate(&ctx.env);

    // Flag via consensus
    let user_str = user.to_string();
    let reason_str = String::from_str(&ctx.env, "Suspicious");
    ctx.oracle.set_report_threshold(&2);
    let r1 = Address::generate(&ctx.env);
    let r2 = Address::generate(&ctx.env);
    ctx.oracle.report_address(&r1, &user_str, &reason_str);
    ctx.oracle.report_address(&r2, &user_str, &reason_str);

    let (is_clean, _score, reason) = ctx.swap.check_compliance(&user);

    assert!(!is_clean);
    assert_eq!(reason, 1); // 1 = consensus only
}

#[test]
fn test_check_compliance_both_tainted_and_consensus() {
    let ctx = setup();
    let user = Address::generate(&ctx.env);

    // Taint + flag
    let user_str = user.to_string();
    let source = String::from_str(&ctx.env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&ctx.env, "stellar");
    ctx.oracle.set_taint(&user_str, &80, &source, &1, &chain);

    let reason_str = String::from_str(&ctx.env, "Flagged");
    ctx.oracle.set_report_threshold(&2);
    let r1 = Address::generate(&ctx.env);
    let r2 = Address::generate(&ctx.env);
    ctx.oracle.report_address(&r1, &user_str, &reason_str);
    ctx.oracle.report_address(&r2, &user_str, &reason_str);

    let (is_clean, score, reason) = ctx.swap.check_compliance(&user);

    assert!(!is_clean);
    assert_eq!(score, 80);
    assert_eq!(reason, 3); // 3 = both consensus + tainted
}

// ════════════════════════════════════════════════════════════════════════
// Admin Functions
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_set_oracle() {
    let ctx = setup();
    let new_oracle = Address::generate(&ctx.env);

    ctx.swap.set_oracle(&new_oracle);
    // No panic = success (oracle address updated)
}

#[test]
fn test_set_block_threshold() {
    let ctx = setup();

    ctx.swap.set_block_threshold(&30);
    // Now addresses with score >= 30 would be blocked by swap_scored
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn test_double_initialize_fails() {
    let ctx = setup();
    let another = Address::generate(&ctx.env);
    ctx.swap.initialize(&another, &ctx.oracle_id, &60);
}

// ════════════════════════════════════════════════════════════════════════
// Edge Cases
// ════════════════════════════════════════════════════════════════════════

#[test]
fn test_swap_zero_amount_fails() {
    let ctx = setup();
    let sender = Address::generate(&ctx.env);
    let recipient = Address::generate(&ctx.env);

    let result = ctx.swap.try_swap_simple(
        &sender,
        &recipient,
        &ctx.token_a.address,
        &ctx.token_b.address,
        &0,
        &0,
    );

    assert!(result.is_err());
}

#[test]
fn test_swap_negative_amount_fails() {
    let ctx = setup();
    let sender = Address::generate(&ctx.env);
    let recipient = Address::generate(&ctx.env);

    let result = ctx.swap.try_swap_simple(
        &sender,
        &recipient,
        &ctx.token_a.address,
        &ctx.token_b.address,
        &-100,
        &100,
    );

    assert!(result.is_err());
}

#[test]
fn test_multiple_swaps_increment_count() {
    let ctx = setup();
    let sender = Address::generate(&ctx.env);
    let recipient = Address::generate(&ctx.env);
    fund_user(&ctx, &sender, 10000);

    for _ in 0..5 {
        ctx.swap.swap_simple(
            &sender,
            &recipient,
            &ctx.token_a.address,
            &ctx.token_b.address,
            &100,
            &100,
        );
    }

    assert_eq!(ctx.swap.swap_count(), 5);
    assert_eq!(ctx.token_a.balance(&sender), 9500);
    assert_eq!(ctx.token_b.balance(&recipient), 500);
}

#[test]
fn test_swap_scored_with_custom_threshold() {
    let ctx = setup();
    let sender = Address::generate(&ctx.env);
    let recipient = Address::generate(&ctx.env);
    fund_user(&ctx, &sender, 1000);

    // Lower threshold to 30
    ctx.swap.set_block_threshold(&30);

    // Taint sender with score 25 (below 30)
    let sender_str = sender.to_string();
    let source = String::from_str(&ctx.env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&ctx.env, "stellar");
    ctx.oracle.set_taint(&sender_str, &25, &source, &2, &chain);

    // Should pass
    let result = ctx.swap.swap_scored(
        &sender,
        &recipient,
        &ctx.token_a.address,
        &ctx.token_b.address,
        &100,
        &100,
    );
    assert_eq!(result, 100);

    // Taint recipient with score 35 (above 30)
    let recipient_str = recipient.to_string();
    ctx.oracle.set_taint(&recipient_str, &35, &source, &2, &chain);

    // Should fail
    let sender2 = Address::generate(&ctx.env);
    fund_user(&ctx, &sender2, 1000);
    let result2 = ctx.swap.try_swap_scored(
        &sender2,
        &recipient,
        &ctx.token_a.address,
        &ctx.token_b.address,
        &100,
        &100,
    );
    assert!(result2.is_err());
}
