#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, contracterror, Address, Bytes, BytesN, Env, String, Symbol, Vec};
use soroban_sdk::xdr::ToXdr;

// ─── Storage Keys ───────────────────────────────────────────────────────────
//
// IMPORTANT: New variants are appended at the end to preserve index ordering.
// Never insert or reorder variants — this would corrupt existing storage.

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    // ─── Indices 0–8: inherited from v0.4.0 ────────────────────────────
    /// The owner address — controls upgrades and role changes.
    Owner,               // index 0
    /// DEPRECATED in v0.5.0 — was Sanctioned(String). Slot preserved.
    _DeprecatedSanctioned(String), // index 1 (unused, preserves layout)
    /// Total number of sanctioned entities (set by operator from off-chain count)
    EntityCount,         // index 2
    /// Ledger timestamp of last update
    LastUpdated,         // index 3
    /// SHA-256 hash of the full off-chain dataset (for audit verification)
    DataHash,            // index 4
    /// Merkle root of the full sanctions dataset
    MerkleRoot,          // index 5
    /// Next report ID counter
    ReportCount,         // index 6
    /// Report detail: ReportData(id) → ReportEntry
    ReportData(u32),     // index 7
    /// The operator address — controls day-to-day operations
    Operator,            // index 8

    // ─── Indices 9+: new in v0.5.0 ─────────────────────────────────────
    /// Number of unique reporters for a given target address
    ReportsByTarget(String),         // index 9
    /// Whether a specific reporter has already flagged a specific target
    HasReported(Address, String),    // index 10
    /// Whether an address has been auto-flagged by agent consensus
    FlaggedByConsensus(String),      // index 11
    /// Configurable report threshold for auto-flagging
    ReportThreshold,                 // index 12

    // ─── Indices 13+: Taint Propagation (v0.6.0) ───────────────────────
    /// Whether an address has been auto-tainted by transaction tracking
    TaintedByPropagation(String),    // index 13
    /// Taint score for an address (0–100)
    TaintScore(String),              // index 14
    /// The source address that directly caused the taint
    TaintSource(String),             // index 15
    /// Hop depth from the original sanctioned address
    TaintHop(String),                // index 16
    /// Chain where the taint originated (e.g. "stellar", "ethereum")
    TaintChain(String),              // index 17
    /// Minimum amount (in stroops) to trigger taint propagation
    TaintMinAmount,                  // index 18
    /// Maximum hop depth for taint propagation
    TaintMaxHops,                    // index 19
    /// Whether an address is whitelisted (exempt from taint)
    WhitelistedAddress(String),      // index 20
}

/// Community report stored on-chain
#[contracttype]
#[derive(Clone)]
pub struct ReportEntry {
    pub reporter: Address,
    pub target: String,
    pub reason: String,
    pub timestamp: u64,
    pub status: u32, // 0=pending, 1=accepted, 2=rejected, 3=auto-flagged
}

// ─── Error Codes ────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Clone, Debug, PartialEq)]
#[repr(u32)]
pub enum OracleError {
    /// Contract has already been initialized
    AlreadyInitialized = 1,
    /// Contract has not been initialized yet
    NotInitialized = 2,
    /// Caller is not authorized for this operation
    Unauthorized = 3,
    /// Empty list provided
    EmptyList = 4,
    /// Batch size exceeds maximum
    BatchTooLarge = 5,
    /// Invalid Merkle proof provided
    InvalidProof = 6,
    /// Report not found
    ReportNotFound = 7,
    /// Report has already been reviewed
    AlreadyReviewed = 8,
    /// Maximum number of reports reached
    ReportLimitReached = 9,
    /// Address string is too short or too long
    InvalidAddressLength = 10,
    /// Reporter has already reported this address
    AlreadyReported = 11,
    /// Invalid threshold value
    InvalidThreshold = 12,
    /// Reason string is empty or too long
    InvalidReasonLength = 13,
    /// Batch array lengths do not match
    ArrayLengthMismatch = 14,
    /// Address is whitelisted and cannot be tainted
    AddressWhitelisted = 15,
    /// Taint score must be 0–100
    InvalidTaintScore = 16,
    /// Hop depth exceeds maximum configured hops
    InvalidHopDepth = 17,
}

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_BATCH_SIZE: u32 = 200;

/// Minimum address string length
const MIN_ADDR_LEN: u32 = 10;
/// Maximum address string length
const MAX_ADDR_LEN: u32 = 128;
/// Maximum reason string length (prevents storage bloat)
const MAX_REASON_LEN: u32 = 256;

/// Default number of unique agent reports before auto-flagging
const DEFAULT_REPORT_THRESHOLD: u32 = 10;

// Instance TTL: ~90 days
const INSTANCE_TTL_THRESHOLD: u32 = 518_400;
const INSTANCE_TTL_EXTEND_TO: u32 = 1_555_200;

// Report TTL: ~180 days
const REPORT_TTL_THRESHOLD: u32 = 518_400;
const REPORT_TTL_EXTEND_TO: u32 = 3_110_400;

// Consensus flag TTL: ~365 days (long-lived, important data)
const CONSENSUS_TTL_THRESHOLD: u32 = 1_555_200;
const CONSENSUS_TTL_EXTEND_TO: u32 = 6_307_200;

// ─── Taint Propagation Constants ────────────────────────────────────────

/// Default minimum amount to trigger taint (100 XLM = 1_000_000_000 stroops)
const DEFAULT_TAINT_MIN_AMOUNT: i128 = 1_000_000_000;
/// Default maximum hop depth for taint propagation
const DEFAULT_TAINT_MAX_HOPS: u32 = 2;

// Taint TTL: ~365 days (permanent intent — no expiry by design)
const TAINT_TTL_THRESHOLD: u32 = 1_555_200;
const TAINT_TTL_EXTEND_TO: u32 = 6_307_200;

// Whitelist TTL: ~365 days
const WHITELIST_TTL_THRESHOLD: u32 = 1_555_200;
const WHITELIST_TTL_EXTEND_TO: u32 = 6_307_200;

// ─── Contract ───────────────────────────────────────────────────────────────
//
// v0.6.0 — Taint Propagation + Agent Consensus + Merkle Verification
//
// Architecture:
//   - NO per-address storage for sanctions. All sanctions data lives off-chain.
//   - Merkle root on-chain: DeFi protocols verify proofs in-transaction.
//   - Agent consensus: when enough agents report an address, it auto-flags.
//   - Taint propagation: operator pushes taint data from off-chain watcher.
//   - is_flagged() returns true for BOTH consensus-flagged AND tainted addresses.
//   - Off-chain API (in Engram) ingests data, builds trees, serves proofs.
//
// Role separation:
//
//   OWNER (cold key / multi-sig)        OPERATOR (hot key)
//   ─────────────────────────           ──────────────────
//   initialize()                        set_merkle_root()
//   upgrade()                           set_entity_count()
//   transfer_owner()                    set_report_threshold()
//   set_operator()                      review_report()
//
//   ANYONE                              
//   ──────                              
//   verify_merkle_proof()               
//   verify_batch_proofs()               
//   report_address()                    
//   is_flagged()                        

#[contract]
pub struct ComplianceOracle;

#[contractimpl]
impl ComplianceOracle {
    // ── Owner / Lifecycle ───────────────────────────────────────────────

    /// Initialize the oracle with an owner and operator.
    pub fn initialize(env: Env, owner: Address, operator: Address) -> Result<(), OracleError> {
        if env.storage().instance().has(&DataKey::Owner) {
            return Err(OracleError::AlreadyInitialized);
        }
        owner.require_auth();

        env.storage().instance().set(&DataKey::Owner, &owner);
        env.storage().instance().set(&DataKey::Operator, &operator);
        env.storage().instance().set(&DataKey::EntityCount, &0u32);
        env.storage().instance().set(&DataKey::ReportCount, &0u32);
        env.storage().instance().set(&DataKey::ReportThreshold, &DEFAULT_REPORT_THRESHOLD);

        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "initialized"),),
            (owner, operator),
        );
        Ok(())
    }

    /// Transfer ownership. Both old and new owner must authorize.
    pub fn transfer_owner(env: Env, new_owner: Address) -> Result<(), OracleError> {
        let owner = Self::require_owner(&env)?;
        owner.require_auth();
        new_owner.require_auth();

        env.storage().instance().set(&DataKey::Owner, &new_owner);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "owner_transferred"),),
            new_owner,
        );
        Ok(())
    }

    /// Set a new operator. Owner only.
    pub fn set_operator(env: Env, new_operator: Address) -> Result<(), OracleError> {
        let owner = Self::require_owner(&env)?;
        owner.require_auth();

        env.storage().instance().set(&DataKey::Operator, &new_operator);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "operator_changed"),),
            new_operator,
        );
        Ok(())
    }

    /// Upgrade the contract WASM. Owner only.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), OracleError> {
        let owner = Self::require_owner(&env)?;
        owner.require_auth();

        env.deployer().update_current_contract_wasm(new_wasm_hash.clone());
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "upgraded"),),
            new_wasm_hash,
        );
        Ok(())
    }

    /// Returns the current owner.
    pub fn owner(env: Env) -> Result<Address, OracleError> {
        Self::require_owner(&env)
    }

    /// Returns the current operator.
    pub fn operator(env: Env) -> Result<Address, OracleError> {
        env.storage()
            .instance()
            .get(&DataKey::Operator)
            .ok_or(OracleError::NotInitialized)
    }

    // ── Merkle Verification (Free, Anyone) ──────────────────────────────

    /// Verify a Merkle proof that an address is in the sanctions dataset.
    ///
    /// **Leaf encoding**: `SHA-256(addr.to_xdr())` — includes XDR envelope.
    /// Off-chain provers must replicate this exact encoding.
    pub fn verify_merkle_proof(
        env: Env,
        addr: String,
        proof: Vec<BytesN<32>>,
        leaf_index: u32,
    ) -> Result<bool, OracleError> {
        let stored_root: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::MerkleRoot)
            .unwrap_or(BytesN::from_array(&env, &[0u8; 32]));

        let zero_root = BytesN::from_array(&env, &[0u8; 32]);
        if stored_root == zero_root {
            return Err(OracleError::InvalidProof);
        }

        let computed_root = Self::compute_merkle_root(&env, &addr, &proof, leaf_index);
        Ok(BytesN::from_array(&env, &computed_root.to_array()) == stored_root)
    }

    /// Verify multiple Merkle proofs in a single call. Returns a Vec<bool>.
    pub fn verify_batch_proofs(
        env: Env,
        addresses: Vec<String>,
        proofs: Vec<Vec<BytesN<32>>>,
        leaf_indices: Vec<u32>,
    ) -> Result<Vec<bool>, OracleError> {
        let count = addresses.len();
        if count == 0 {
            return Err(OracleError::EmptyList);
        }
        if count > MAX_BATCH_SIZE {
            return Err(OracleError::BatchTooLarge);
        }
        if count != proofs.len() || count != leaf_indices.len() {
            return Err(OracleError::ArrayLengthMismatch);
        }

        let stored_root: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::MerkleRoot)
            .unwrap_or(BytesN::from_array(&env, &[0u8; 32]));

        let zero_root = BytesN::from_array(&env, &[0u8; 32]);
        if stored_root == zero_root {
            return Err(OracleError::InvalidProof);
        }

        let mut results = Vec::new(&env);
        for i in 0..count {
            let addr = addresses.get(i).unwrap();
            let proof = proofs.get(i).unwrap();
            let idx = leaf_indices.get(i).unwrap();

            let computed_root = Self::compute_merkle_root(&env, &addr, &proof, idx);
            results.push_back(
                BytesN::from_array(&env, &computed_root.to_array()) == stored_root
            );
        }

        Ok(results)
    }

    /// Returns the current Merkle root.
    pub fn merkle_root(env: Env) -> BytesN<32> {
        env.storage()
            .instance()
            .get(&DataKey::MerkleRoot)
            .unwrap_or(BytesN::from_array(&env, &[0u8; 32]))
    }

    /// Returns the SHA-256 hash of the off-chain dataset.
    pub fn data_hash(env: Env) -> BytesN<32> {
        env.storage()
            .instance()
            .get(&DataKey::DataHash)
            .unwrap_or(BytesN::from_array(&env, &[0u8; 32]))
    }

    /// Returns the entity count (set by operator from off-chain).
    pub fn entity_count(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::EntityCount)
            .unwrap_or(0u32)
    }

    /// Returns the ledger timestamp of the last update.
    pub fn last_updated(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::LastUpdated)
            .unwrap_or(0u64)
    }

    // ── Operator Operations ─────────────────────────────────────────────

    /// Update the Merkle root and data hash. Operator only.
    /// Called by the off-chain API after rebuilding the tree.
    pub fn set_merkle_root(
        env: Env,
        root: BytesN<32>,
        data_hash: BytesN<32>,
        entity_count: u32,
    ) -> Result<(), OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        env.storage().instance().set(&DataKey::MerkleRoot, &root);
        env.storage().instance().set(&DataKey::DataHash, &data_hash);
        env.storage().instance().set(&DataKey::EntityCount, &entity_count);
        env.storage().instance().set(&DataKey::LastUpdated, &env.ledger().timestamp());

        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "merkle_root_updated"),),
            (root, entity_count),
        );
        Ok(())
    }

    /// Set the report threshold for agent consensus. Operator only.
    pub fn set_report_threshold(env: Env, threshold: u32) -> Result<(), OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        if threshold == 0 {
            return Err(OracleError::InvalidThreshold);
        }

        env.storage().instance().set(&DataKey::ReportThreshold, &threshold);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "threshold_changed"),),
            threshold,
        );
        Ok(())
    }

    /// Returns the current report threshold.
    pub fn report_threshold(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ReportThreshold)
            .unwrap_or(DEFAULT_REPORT_THRESHOLD)
    }

    // ── Agent Consensus Reporting ───────────────────────────────────────

    /// Any agent (or anyone) can report a suspicious address.
    /// Each reporter can only report a given target once.
    /// When the number of unique reporters reaches the threshold,
    /// the address is auto-flagged.
    pub fn report_address(
        env: Env,
        reporter: Address,
        target: String,
        reason: String,
    ) -> Result<u32, OracleError> {
        reporter.require_auth();

        // Validate target address length
        let len = target.len();
        if len < MIN_ADDR_LEN || len > MAX_ADDR_LEN {
            return Err(OracleError::InvalidAddressLength);
        }

        // Validate reason length (prevent storage bloat — H-1)
        let reason_len = reason.len();
        if reason_len == 0 || reason_len > MAX_REASON_LEN {
            return Err(OracleError::InvalidReasonLength);
        }

        // Prevent duplicate reports from the same reporter
        let has_reported_key = DataKey::HasReported(reporter.clone(), target.clone());
        if env.storage().persistent().has(&has_reported_key) {
            return Err(OracleError::AlreadyReported);
        }

        // Get report ID
        let report_id: u32 = env
            .storage()
            .instance()
            .get(&DataKey::ReportCount)
            .unwrap_or(0u32);
        let next_id = report_id.checked_add(1).ok_or(OracleError::ReportLimitReached)?;

        // Store the report
        let report = ReportEntry {
            reporter: reporter.clone(),
            target: target.clone(),
            reason,
            timestamp: env.ledger().timestamp(),
            status: 0,
        };

        env.storage().persistent().set(&DataKey::ReportData(report_id), &report);
        env.storage().persistent().extend_ttl(
            &DataKey::ReportData(report_id),
            REPORT_TTL_THRESHOLD,
            REPORT_TTL_EXTEND_TO,
        );

        // Mark this reporter as having reported this target
        env.storage().persistent().set(&has_reported_key, &true);
        env.storage().persistent().extend_ttl(
            &has_reported_key,
            REPORT_TTL_THRESHOLD,
            REPORT_TTL_EXTEND_TO,
        );

        // Increment unique reporter count for this target
        let reports_key = DataKey::ReportsByTarget(target.clone());
        let prev_reports: u32 = env.storage().persistent().get(&reports_key).unwrap_or(0);
        let new_reports = prev_reports.saturating_add(1);
        env.storage().persistent().set(&reports_key, &new_reports);
        env.storage().persistent().extend_ttl(
            &reports_key,
            REPORT_TTL_THRESHOLD,
            REPORT_TTL_EXTEND_TO,
        );

        // Update global report counter
        env.storage().instance().set(&DataKey::ReportCount, &next_id);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        // Check if threshold is reached → auto-flag
        let threshold: u32 = env
            .storage()
            .instance()
            .get(&DataKey::ReportThreshold)
            .unwrap_or(DEFAULT_REPORT_THRESHOLD);

        if new_reports >= threshold {
            let flagged_key = DataKey::FlaggedByConsensus(target.clone());
            if !env.storage().persistent().has(&flagged_key) {
                env.storage().persistent().set(&flagged_key, &true);
                env.storage().persistent().extend_ttl(
                    &flagged_key,
                    CONSENSUS_TTL_THRESHOLD,
                    CONSENSUS_TTL_EXTEND_TO,
                );

                env.events().publish(
                    (Symbol::new(&env, "auto_flagged"),),
                    (target.clone(), new_reports),
                );
            }
        }

        env.events().publish(
            (Symbol::new(&env, "address_reported"),),
            (report_id, reporter, target, new_reports),
        );

        Ok(report_id)
    }

    /// Check if an address is flagged — returns true for BOTH agent consensus
    /// flags AND taint propagation. Taint is nested under the main flagged status.
    pub fn is_flagged(env: Env, addr: String) -> bool {
        let consensus: bool = env.storage()
            .persistent()
            .get(&DataKey::FlaggedByConsensus(addr.clone()))
            .unwrap_or(false);
        let tainted: bool = env.storage()
            .persistent()
            .get(&DataKey::TaintedByPropagation(addr))
            .unwrap_or(false);
        consensus || tainted
    }

    /// Returns the reason an address is flagged:
    /// 0 = clean, 1 = consensus only, 2 = tainted only, 3 = both
    pub fn flag_reason(env: Env, addr: String) -> u32 {
        let consensus: bool = env.storage()
            .persistent()
            .get(&DataKey::FlaggedByConsensus(addr.clone()))
            .unwrap_or(false);
        let tainted: bool = env.storage()
            .persistent()
            .get(&DataKey::TaintedByPropagation(addr))
            .unwrap_or(false);
        match (consensus, tainted) {
            (false, false) => 0,
            (true, false) => 1,
            (false, true) => 2,
            (true, true) => 3,
        }
    }

    /// Get the number of unique reporters for a target address.
    pub fn reports_for(env: Env, addr: String) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ReportsByTarget(addr))
            .unwrap_or(0)
    }

    /// Remove a false-positive consensus flag. Operator only.
    /// Use when a flagged address is determined to be legitimate.
    pub fn unflag_address(env: Env, addr: String) -> Result<(), OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        let key = DataKey::FlaggedByConsensus(addr.clone());
        if env.storage().persistent().has(&key) {
            env.storage().persistent().remove(&key);
        }

        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "unflagged"),),
            addr,
        );
        Ok(())
    }

    /// Operator reviews a community report. Can only be reviewed once.
    /// In v0.5.0, acceptance emits an event but does NOT write to storage
    /// (no per-address sanctions list). The off-chain API picks up the event.
    pub fn review_report(
        env: Env,
        report_id: u32,
        accept: bool,
    ) -> Result<(), OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        let key = DataKey::ReportData(report_id);
        let mut report: ReportEntry = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(OracleError::ReportNotFound)?;

        if report.status != 0 {
            return Err(OracleError::AlreadyReviewed);
        }

        report.status = if accept { 1 } else { 2 };

        env.storage().persistent().set(&key, &report);
        env.storage().persistent().extend_ttl(
            &key,
            REPORT_TTL_THRESHOLD,
            REPORT_TTL_EXTEND_TO,
        );
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "report_reviewed"),),
            (report_id, accept, report.target),
        );
        Ok(())
    }

    /// Get a community report by ID.
    pub fn get_report(env: Env, report_id: u32) -> Result<ReportEntry, OracleError> {
        env.storage()
            .persistent()
            .get(&DataKey::ReportData(report_id))
            .ok_or(OracleError::ReportNotFound)
    }

    /// Get the total number of reports submitted.
    pub fn report_count(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ReportCount)
            .unwrap_or(0u32)
    }

    // ── Taint Propagation (v0.6.0) ───────────────────────────────────────

    /// Check if an address has been tainted by transaction propagation.
    pub fn is_tainted(env: Env, addr: String) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::TaintedByPropagation(addr))
            .unwrap_or(false)
    }

    /// Get the taint score (0–100) for an address.
    pub fn taint_score(env: Env, addr: String) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::TaintScore(addr))
            .unwrap_or(0)
    }

    /// Get the source address that directly caused the taint.
    pub fn taint_source(env: Env, addr: String) -> String {
        env.storage()
            .persistent()
            .get(&DataKey::TaintSource(addr))
            .unwrap_or(String::from_str(&env, ""))
    }

    /// Get the hop depth from the original sanctioned address.
    pub fn taint_hop(env: Env, addr: String) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::TaintHop(addr))
            .unwrap_or(0)
    }

    /// Get the chain where the taint originated.
    pub fn taint_chain(env: Env, addr: String) -> String {
        env.storage()
            .persistent()
            .get(&DataKey::TaintChain(addr))
            .unwrap_or(String::from_str(&env, ""))
    }

    /// Check if an address is whitelisted (exempt from taint).
    pub fn is_whitelisted(env: Env, addr: String) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::WhitelistedAddress(addr))
            .unwrap_or(false)
    }

    /// Returns the current taint configuration: (min_amount, max_hops).
    pub fn taint_config(env: Env) -> (i128, u32) {
        let min_amount: i128 = env.storage()
            .instance()
            .get(&DataKey::TaintMinAmount)
            .unwrap_or(DEFAULT_TAINT_MIN_AMOUNT);
        let max_hops: u32 = env.storage()
            .instance()
            .get(&DataKey::TaintMaxHops)
            .unwrap_or(DEFAULT_TAINT_MAX_HOPS);
        (min_amount, max_hops)
    }

    /// Set taint for a single address. Operator only.
    /// Called by the off-chain Taint Watcher service when a flagged address
    /// sends funds to a new wallet.
    pub fn set_taint(
        env: Env,
        addr: String,
        score: u32,
        source: String,
        hop: u32,
        chain: String,
    ) -> Result<(), OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        // Validate score range
        if score > 100 {
            return Err(OracleError::InvalidTaintScore);
        }

        // Validate address length
        let len = addr.len();
        if len < MIN_ADDR_LEN || len > MAX_ADDR_LEN {
            return Err(OracleError::InvalidAddressLength);
        }

        // Check whitelist
        if env.storage().persistent().get(&DataKey::WhitelistedAddress(addr.clone())).unwrap_or(false) {
            return Err(OracleError::AddressWhitelisted);
        }

        // Validate hop depth against max
        let max_hops: u32 = env.storage()
            .instance()
            .get(&DataKey::TaintMaxHops)
            .unwrap_or(DEFAULT_TAINT_MAX_HOPS);
        if hop > max_hops {
            return Err(OracleError::InvalidHopDepth);
        }

        Self::write_taint(&env, &addr, score, &source, hop, &chain);

        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "taint_set"),),
            (addr, score, source, hop, chain),
        );
        Ok(())
    }

    /// Batch set taint for multiple addresses. Operator only.
    /// All arrays must have the same length. Max 200 entries.
    pub fn set_taint_batch(
        env: Env,
        addresses: Vec<String>,
        scores: Vec<u32>,
        sources: Vec<String>,
        hops: Vec<u32>,
        chains: Vec<String>,
    ) -> Result<(), OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        let count = addresses.len();
        if count == 0 {
            return Err(OracleError::EmptyList);
        }
        if count > MAX_BATCH_SIZE {
            return Err(OracleError::BatchTooLarge);
        }
        if count != scores.len() || count != sources.len() || count != hops.len() || count != chains.len() {
            return Err(OracleError::ArrayLengthMismatch);
        }

        let max_hops: u32 = env.storage()
            .instance()
            .get(&DataKey::TaintMaxHops)
            .unwrap_or(DEFAULT_TAINT_MAX_HOPS);

        for i in 0..count {
            let addr = addresses.get(i).unwrap();
            let score = scores.get(i).unwrap();
            let source = sources.get(i).unwrap();
            let hop = hops.get(i).unwrap();
            let chain = chains.get(i).unwrap();

            // Skip whitelisted addresses
            if env.storage().persistent().get(&DataKey::WhitelistedAddress(addr.clone())).unwrap_or(false) {
                continue;
            }

            // Validate
            if score > 100 {
                return Err(OracleError::InvalidTaintScore);
            }
            if hop > max_hops {
                return Err(OracleError::InvalidHopDepth);
            }

            let len = addr.len();
            if len < MIN_ADDR_LEN || len > MAX_ADDR_LEN {
                return Err(OracleError::InvalidAddressLength);
            }

            Self::write_taint(&env, &addr, score, &source, hop, &chain);
        }

        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "taint_batch_set"),),
            count,
        );
        Ok(())
    }

    /// Remove taint from an address. Operator only.
    pub fn clear_taint(env: Env, addr: String) -> Result<(), OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        let keys = [
            DataKey::TaintedByPropagation(addr.clone()),
            DataKey::TaintScore(addr.clone()),
            DataKey::TaintSource(addr.clone()),
            DataKey::TaintHop(addr.clone()),
            DataKey::TaintChain(addr.clone()),
        ];

        for key in &keys {
            if env.storage().persistent().has(key) {
                env.storage().persistent().remove(key);
            }
        }

        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "taint_cleared"),),
            addr,
        );
        Ok(())
    }

    /// Whitelist an address — exempt from taint propagation. Operator only.
    /// Whitelisted addresses cannot be tainted via set_taint().
    pub fn whitelist_address(env: Env, addr: String) -> Result<(), OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        let key = DataKey::WhitelistedAddress(addr.clone());
        env.storage().persistent().set(&key, &true);
        env.storage().persistent().extend_ttl(
            &key,
            WHITELIST_TTL_THRESHOLD,
            WHITELIST_TTL_EXTEND_TO,
        );

        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "whitelisted"),),
            addr,
        );
        Ok(())
    }

    /// Remove an address from the whitelist. Operator only.
    pub fn unwhitelist_address(env: Env, addr: String) -> Result<(), OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        let key = DataKey::WhitelistedAddress(addr.clone());
        if env.storage().persistent().has(&key) {
            env.storage().persistent().remove(&key);
        }

        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "unwhitelisted"),),
            addr,
        );
        Ok(())
    }

    /// Set the minimum taint amount (in stroops). Operator only.
    pub fn set_taint_min_amount(env: Env, amount: i128) -> Result<(), OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        env.storage().instance().set(&DataKey::TaintMinAmount, &amount);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "taint_min_amt"),),
            amount,
        );
        Ok(())
    }

    /// Set the maximum hop depth for taint propagation. Operator only.
    pub fn set_taint_max_hops(env: Env, max_hops: u32) -> Result<(), OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        if max_hops == 0 {
            return Err(OracleError::InvalidHopDepth);
        }

        env.storage().instance().set(&DataKey::TaintMaxHops, &max_hops);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "taint_max_hops"),),
            max_hops,
        );
        Ok(())
    }

    // ── Internal Helpers ────────────────────────────────────────────────

    fn require_owner(env: &Env) -> Result<Address, OracleError> {
        env.storage()
            .instance()
            .get(&DataKey::Owner)
            .ok_or(OracleError::NotInitialized)
    }

    fn require_operator(env: &Env) -> Result<Address, OracleError> {
        env.storage()
            .instance()
            .get(&DataKey::Operator)
            .ok_or(OracleError::NotInitialized)
    }

    /// Write taint data for an address to persistent storage.
    fn write_taint(
        env: &Env,
        addr: &String,
        score: u32,
        source: &String,
        hop: u32,
        chain: &String,
    ) {
        // Set tainted flag
        let tainted_key = DataKey::TaintedByPropagation(addr.clone());
        env.storage().persistent().set(&tainted_key, &true);
        env.storage().persistent().extend_ttl(&tainted_key, TAINT_TTL_THRESHOLD, TAINT_TTL_EXTEND_TO);

        // Set score
        let score_key = DataKey::TaintScore(addr.clone());
        env.storage().persistent().set(&score_key, &score);
        env.storage().persistent().extend_ttl(&score_key, TAINT_TTL_THRESHOLD, TAINT_TTL_EXTEND_TO);

        // Set source
        let source_key = DataKey::TaintSource(addr.clone());
        env.storage().persistent().set(&source_key, source);
        env.storage().persistent().extend_ttl(&source_key, TAINT_TTL_THRESHOLD, TAINT_TTL_EXTEND_TO);

        // Set hop
        let hop_key = DataKey::TaintHop(addr.clone());
        env.storage().persistent().set(&hop_key, &hop);
        env.storage().persistent().extend_ttl(&hop_key, TAINT_TTL_THRESHOLD, TAINT_TTL_EXTEND_TO);

        // Set chain
        let chain_key = DataKey::TaintChain(addr.clone());
        env.storage().persistent().set(&chain_key, chain);
        env.storage().persistent().extend_ttl(&chain_key, TAINT_TTL_THRESHOLD, TAINT_TTL_EXTEND_TO);
    }

    /// Compute Merkle root from a leaf address and proof.
    fn compute_merkle_root(
        env: &Env,
        addr: &String,
        proof: &Vec<BytesN<32>>,
        leaf_index: u32,
    ) -> BytesN<32> {
        let addr_bytes = addr.clone().to_xdr(env);
        let hash = env.crypto().sha256(&addr_bytes);
        let mut current: BytesN<32> = hash.into();

        let mut idx = leaf_index;
        for sibling in proof.iter() {
            let sibling_bytes: BytesN<32> = sibling;
            if idx % 2 == 0 {
                let mut combined = Bytes::new(env);
                combined.append(&Bytes::from_slice(env, current.to_array().as_slice()));
                combined.append(&Bytes::from_slice(env, sibling_bytes.to_array().as_slice()));
                let h = env.crypto().sha256(&combined);
                current = h.into();
            } else {
                let mut combined = Bytes::new(env);
                combined.append(&Bytes::from_slice(env, sibling_bytes.to_array().as_slice()));
                combined.append(&Bytes::from_slice(env, current.to_array().as_slice()));
                let h = env.crypto().sha256(&combined);
                current = h.into();
            }
            idx /= 2;
        }

        current
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod test;
