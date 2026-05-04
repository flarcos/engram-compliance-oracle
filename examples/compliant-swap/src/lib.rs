#![no_std]

// ─── Compliant Swap ────────────────────────────────────────────────────
//
// Example Soroban DEX contract demonstrating how to integrate the
// Engram Compliance Oracle for on-chain taint screening.
//
// This contract shows 3 integration patterns:
//
//   Pattern 1: Simple gate       — block flagged addresses entirely
//   Pattern 2: Score-based       — allow low-risk, block high-risk
//   Pattern 3: Full provenance   — check taint depth, source, and chain
//
// All patterns use cross-contract calls to the deployed oracle.
// No API keys, no off-chain lookups — everything on-chain, same tx.
//
// ────────────────────────────────────────────────────────────────────────

use soroban_sdk::{
    contract, contractimpl, contracttype, contracterror,
    Address, Env, String, Symbol,
    token,
};

// ─── Oracle Interface ───────────────────────────────────────────────────
//
// This mod_contract! generates a client for calling the compliance oracle.
// It only needs the function signatures you actually use.

mod oracle {
    soroban_sdk::contractimport!(
        file = "../../target/wasm32-unknown-unknown/release/engram_compliance_oracle.wasm"
    );
}

// ─── Storage ────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Address of the compliance oracle contract
    OracleId,
    /// Admin who can update the oracle address
    Admin,
    /// Minimum taint score to block (0 = block all tainted, 60 = only high risk)
    BlockThreshold,
    /// Total swap count (for demo purposes)
    SwapCount,
}

// ─── Errors ─────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum SwapError {
    /// Contract not initialized
    NotInitialized = 1,
    /// Already initialized
    AlreadyInitialized = 2,
    /// Caller is not the admin
    Unauthorized = 3,
    /// Sender address is flagged by the compliance oracle
    SenderFlagged = 4,
    /// Recipient address is flagged by the compliance oracle
    RecipientFlagged = 5,
    /// Sender taint score exceeds threshold
    SenderTaintTooHigh = 6,
    /// Recipient taint score exceeds threshold
    RecipientTaintTooHigh = 7,
    /// Invalid amount
    InvalidAmount = 8,
}

// ─── Contract ───────────────────────────────────────────────────────────

#[contract]
pub struct CompliantSwap;

#[contractimpl]
impl CompliantSwap {
    // ── Setup ───────────────────────────────────────────────────────────

    /// Initialize the swap contract with the oracle address and admin.
    ///
    /// # Arguments
    /// * `admin` — Can update oracle address and block threshold
    /// * `oracle_id` — Contract ID of the deployed Engram Compliance Oracle
    /// * `block_threshold` — Min taint score to block (0 = block all, 60 = high risk only)
    pub fn initialize(
        env: Env,
        admin: Address,
        oracle_id: Address,
        block_threshold: u32,
    ) -> Result<(), SwapError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(SwapError::AlreadyInitialized);
        }

        admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::OracleId, &oracle_id);
        env.storage().instance().set(&DataKey::BlockThreshold, &block_threshold);
        env.storage().instance().set(&DataKey::SwapCount, &0u64);

        env.events().publish(
            (Symbol::new(&env, "initialized"),),
            (admin, oracle_id, block_threshold),
        );

        Ok(())
    }

    /// Update the oracle contract address. Admin only.
    pub fn set_oracle(env: Env, oracle_id: Address) -> Result<(), SwapError> {
        let admin: Address = env.storage().instance()
            .get(&DataKey::Admin)
            .ok_or(SwapError::NotInitialized)?;
        admin.require_auth();

        env.storage().instance().set(&DataKey::OracleId, &oracle_id);

        env.events().publish(
            (Symbol::new(&env, "oracle_updated"),),
            oracle_id,
        );

        Ok(())
    }

    /// Update the block threshold. Admin only.
    /// 0 = block ALL tainted addresses. 60 = block only high_risk and critical.
    pub fn set_block_threshold(env: Env, threshold: u32) -> Result<(), SwapError> {
        let admin: Address = env.storage().instance()
            .get(&DataKey::Admin)
            .ok_or(SwapError::NotInitialized)?;
        admin.require_auth();

        env.storage().instance().set(&DataKey::BlockThreshold, &threshold);

        env.events().publish(
            (Symbol::new(&env, "threshold_updated"),),
            threshold,
        );

        Ok(())
    }

    // ── Pattern 1: Simple Gate ──────────────────────────────────────────
    //
    // The simplest integration. One line of compliance checking.
    // Block any flagged address (sanctions, consensus, or taint).

    /// Swap tokens with simple compliance gate.
    ///
    /// Checks `is_flagged()` on both sender and recipient.
    /// If either is flagged for ANY reason, the swap is rejected.
    ///
    /// **This is the recommended starting point for most protocols.**
    pub fn swap_simple(
        env: Env,
        sender: Address,
        recipient: Address,
        token_in: Address,
        token_out: Address,
        amount_in: i128,
        min_amount_out: i128,
    ) -> Result<i128, SwapError> {
        sender.require_auth();

        if amount_in <= 0 || min_amount_out <= 0 {
            return Err(SwapError::InvalidAmount);
        }

        // ── Compliance check: 1 cross-contract call per address ──
        let oracle_id: Address = env.storage().instance()
            .get(&DataKey::OracleId)
            .ok_or(SwapError::NotInitialized)?;
        let oracle = oracle::Client::new(&env, &oracle_id);

        let sender_str = Self::addr_to_string(&env, &sender);
        let recipient_str = Self::addr_to_string(&env, &recipient);

        // This single call covers sanctions + consensus + taint
        if oracle.is_flagged(&sender_str) {
            return Err(SwapError::SenderFlagged);
        }
        if oracle.is_flagged(&recipient_str) {
            return Err(SwapError::RecipientFlagged);
        }
        // ── End compliance check ──

        // Execute the swap (simplified — real DEX would have AMM logic)
        let amount_out = Self::calculate_output(amount_in, min_amount_out);

        token::Client::new(&env, &token_in).transfer(
            &sender, &env.current_contract_address(), &amount_in,
        );
        token::Client::new(&env, &token_out).transfer(
            &env.current_contract_address(), &recipient, &amount_out,
        );

        Self::increment_swap_count(&env);

        env.events().publish(
            (Symbol::new(&env, "swap"),),
            (sender, recipient, amount_in, amount_out),
        );

        Ok(amount_out)
    }

    // ── Pattern 2: Score-Based ──────────────────────────────────────────
    //
    // More nuanced. Low taint scores are allowed (e.g. 2-hop recipients),
    // only high-risk addresses are blocked.

    /// Swap tokens with score-based compliance.
    ///
    /// Allows addresses with low taint scores (configurable threshold).
    /// Only blocks addresses above the `block_threshold`.
    ///
    /// Use case: A DEX that wants to allow normal users who
    /// received funds from a tainted address indirectly (2+ hops).
    pub fn swap_scored(
        env: Env,
        sender: Address,
        recipient: Address,
        token_in: Address,
        token_out: Address,
        amount_in: i128,
        min_amount_out: i128,
    ) -> Result<i128, SwapError> {
        sender.require_auth();

        if amount_in <= 0 || min_amount_out <= 0 {
            return Err(SwapError::InvalidAmount);
        }

        let oracle_id: Address = env.storage().instance()
            .get(&DataKey::OracleId)
            .ok_or(SwapError::NotInitialized)?;
        let oracle = oracle::Client::new(&env, &oracle_id);
        let threshold: u32 = env.storage().instance()
            .get(&DataKey::BlockThreshold)
            .unwrap_or(60); // Default: block high_risk and above

        let sender_str = Self::addr_to_string(&env, &sender);
        let recipient_str = Self::addr_to_string(&env, &recipient);

        // ── Score-based compliance ──
        // Check taint score — allow if below threshold
        let sender_score = oracle.taint_score(&sender_str);
        if sender_score >= threshold {
            return Err(SwapError::SenderTaintTooHigh);
        }

        let recipient_score = oracle.taint_score(&recipient_str);
        if recipient_score >= threshold {
            return Err(SwapError::RecipientTaintTooHigh);
        }

        // Still check sanctions/consensus (those are always blocked)
        let sender_reason = oracle.flag_reason(&sender_str);
        if sender_reason == 1 || sender_reason == 3 {
            // 1 = consensus only, 3 = consensus + tainted
            return Err(SwapError::SenderFlagged);
        }

        let recipient_reason = oracle.flag_reason(&recipient_str);
        if recipient_reason == 1 || recipient_reason == 3 {
            return Err(SwapError::RecipientFlagged);
        }
        // ── End compliance ──

        // Execute swap
        let amount_out = Self::calculate_output(amount_in, min_amount_out);

        token::Client::new(&env, &token_in).transfer(
            &sender, &env.current_contract_address(), &amount_in,
        );
        token::Client::new(&env, &token_out).transfer(
            &env.current_contract_address(), &recipient, &amount_out,
        );

        Self::increment_swap_count(&env);

        env.events().publish(
            (Symbol::new(&env, "swap_scored"),),
            (sender, recipient, amount_in, amount_out),
        );

        Ok(amount_out)
    }

    // ── Pattern 3: Full Provenance ──────────────────────────────────────
    //
    // Maximum visibility. Emits the full taint context as an event,
    // giving indexers and frontends rich compliance data.

    /// Swap tokens with full provenance logging.
    ///
    /// Even if the swap is allowed, emits taint metadata as events
    /// so frontends and indexers can display risk context.
    ///
    /// Use case: Institutional DEX that needs full audit trails.
    pub fn swap_audited(
        env: Env,
        sender: Address,
        recipient: Address,
        token_in: Address,
        token_out: Address,
        amount_in: i128,
        min_amount_out: i128,
    ) -> Result<i128, SwapError> {
        sender.require_auth();

        if amount_in <= 0 || min_amount_out <= 0 {
            return Err(SwapError::InvalidAmount);
        }

        let oracle_id: Address = env.storage().instance()
            .get(&DataKey::OracleId)
            .ok_or(SwapError::NotInitialized)?;
        let oracle = oracle::Client::new(&env, &oracle_id);

        let sender_str = Self::addr_to_string(&env, &sender);
        let recipient_str = Self::addr_to_string(&env, &recipient);

        // ── Full provenance compliance check ──

        // Always block sanctioned / consensus-flagged
        if oracle.is_flagged(&sender_str) {
            let reason = oracle.flag_reason(&sender_str);
            env.events().publish(
                (Symbol::new(&env, "compliance_blocked"),),
                (sender_str.clone(), reason),
            );
            return Err(SwapError::SenderFlagged);
        }

        if oracle.is_flagged(&recipient_str) {
            let reason = oracle.flag_reason(&recipient_str);
            env.events().publish(
                (Symbol::new(&env, "compliance_blocked"),),
                (recipient_str.clone(), reason),
            );
            return Err(SwapError::RecipientFlagged);
        }

        // Emit taint context even for clean addresses (score will be 0)
        let sender_score = oracle.taint_score(&sender_str);
        let sender_chain = oracle.taint_chain(&sender_str);
        let sender_hop = oracle.taint_hop(&sender_str);

        env.events().publish(
            (Symbol::new(&env, "compliance_check"),),
            (sender_str, sender_score, sender_hop, sender_chain),
        );

        let recipient_score = oracle.taint_score(&recipient_str);
        let recipient_chain = oracle.taint_chain(&recipient_str);
        let recipient_hop = oracle.taint_hop(&recipient_str);

        env.events().publish(
            (Symbol::new(&env, "compliance_check"),),
            (recipient_str, recipient_score, recipient_hop, recipient_chain),
        );

        // ── End compliance ──

        // Execute swap
        let amount_out = Self::calculate_output(amount_in, min_amount_out);

        token::Client::new(&env, &token_in).transfer(
            &sender, &env.current_contract_address(), &amount_in,
        );
        token::Client::new(&env, &token_out).transfer(
            &env.current_contract_address(), &recipient, &amount_out,
        );

        Self::increment_swap_count(&env);

        env.events().publish(
            (Symbol::new(&env, "swap_audited"),),
            (sender, recipient, amount_in, amount_out),
        );

        Ok(amount_out)
    }

    // ── Read-Only ───────────────────────────────────────────────────────

    /// Check if an address would pass compliance screening.
    /// Returns (is_clean, taint_score, flag_reason).
    /// Useful for frontends to show warnings before submitting a tx.
    pub fn check_compliance(env: Env, addr: Address) -> (bool, u32, u32) {
        let oracle_id: Address = env.storage().instance()
            .get(&DataKey::OracleId)
            .unwrap_or(env.current_contract_address()); // Fallback for safety
        let oracle = oracle::Client::new(&env, &oracle_id);

        let addr_str = Self::addr_to_string(&env, &addr);

        let is_flagged = oracle.is_flagged(&addr_str);
        let score = oracle.taint_score(&addr_str);
        let reason = oracle.flag_reason(&addr_str);

        (!is_flagged, score, reason)
    }

    /// Get total swap count.
    pub fn swap_count(env: Env) -> u64 {
        env.storage().instance()
            .get(&DataKey::SwapCount)
            .unwrap_or(0u64)
    }

    // ── Internal ────────────────────────────────────────────────────────

    /// Convert an Address to a String for oracle calls.
    /// Uses the Soroban SDK's built-in string conversion.
    fn addr_to_string(_env: &Env, addr: &Address) -> String {
        addr.to_string()
    }

    /// Simplified swap calculation (1:1 for demo).
    /// Real DEX would use constant-product AMM or order book.
    fn calculate_output(amount_in: i128, min_amount_out: i128) -> i128 {
        // Demo: 1:1 ratio with no slippage
        let output = amount_in;
        if output < min_amount_out {
            min_amount_out
        } else {
            output
        }
    }

    fn increment_swap_count(env: &Env) {
        let count: u64 = env.storage().instance()
            .get(&DataKey::SwapCount)
            .unwrap_or(0u64);
        env.storage().instance().set(&DataKey::SwapCount, &(count + 1));
    }
}

mod test;
