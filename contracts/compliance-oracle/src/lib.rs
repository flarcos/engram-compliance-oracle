#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, contracterror, Address, Bytes, BytesN, Env, String, Symbol, Vec};
use soroban_sdk::xdr::ToXdr;

// ─── Storage Keys ───────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    // ─── IMPORTANT: Variant indices must match the original contract ───
    // Index 0: was Admin, now Owner (same storage slot, compatible)
    /// The owner address — controls upgrades and role changes.
    /// Should be a multi-sig account for production deployments.
    Owner,           // index 0 (was: Admin)
    // Index 1-8: unchanged from original contract
    /// Whether an address is sanctioned: DataKey::Sanctioned(addr_string) → bool
    ///
    /// addr_string is the raw address from any chain, **always lowercased**.
    /// Callers MUST lowercase addresses before querying `is_sanctioned`.
    Sanctioned(String),  // index 1 (unchanged)
    /// Total number of sanctioned entities currently on-chain
    EntityCount,         // index 2 (unchanged)
    /// Ledger timestamp of last sanctions list update
    LastUpdated,         // index 3 (unchanged)
    /// SHA-256 hash of the full off-chain dataset (for audit verification)
    DataHash,            // index 4 (unchanged)
    /// Merkle root of the full sanctions dataset (for proof verification)
    MerkleRoot,          // index 5 (unchanged)
    /// Next report ID
    ReportCount,         // index 6 (unchanged)
    /// Report detail: ReportData(id) → ReportEntry
    ReportData(u32),     // index 7 (unchanged)
    // ─── NEW: Added at the end to avoid index collision ────────────────
    /// The operator address — controls day-to-day data operations.
    /// (add/remove sanctions, review reports, set Merkle root, extend TTL)
    /// Can be a hot wallet since it cannot upgrade or change roles.
    Operator,            // index 8 (NEW)
}

/// Community report stored on-chain
#[contracttype]
#[derive(Clone)]
pub struct ReportEntry {
    pub reporter: Address,
    pub target: String,   // Any chain address as a string (lowercased)
    pub reason: String,
    pub timestamp: u64,
    pub status: u32, // 0=pending, 1=accepted, 2=rejected
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
    /// Empty address list provided
    EmptyList = 4,
    /// Batch size exceeds maximum (200)
    BatchTooLarge = 5,
    /// Invalid Merkle proof provided
    InvalidProof = 6,
    /// Report not found
    ReportNotFound = 7,
    /// Report has already been reviewed (accepted or rejected)
    AlreadyReviewed = 8,
    /// Maximum number of reports reached (u32::MAX)
    ReportLimitReached = 9,
    /// Address string is too short or too long
    InvalidAddressLength = 10,
}

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_BATCH_SIZE: u32 = 200;

/// Minimum address string length (e.g. shortest valid BTC addr ~26 chars)
const MIN_ADDR_LEN: u32 = 10;
/// Maximum address string length (prevents storage abuse)
const MAX_ADDR_LEN: u32 = 128;

// TTL: ~30 days in ledgers (1 ledger ≈ 5 seconds, 30 days ≈ 518400 ledgers)
const TTL_THRESHOLD: u32 = 259_200;   // Extend when below ~15 days
const TTL_EXTEND_TO: u32 = 518_400;   // Extend to ~30 days

// Instance TTL: ~90 days (contract code + instance storage)
const INSTANCE_TTL_THRESHOLD: u32 = 518_400;   // Extend when below ~30 days
const INSTANCE_TTL_EXTEND_TO: u32 = 1_555_200; // Extend to ~90 days

// Report TTL: ~180 days (longer to give admin time to review)
const REPORT_TTL_THRESHOLD: u32 = 518_400;     // Extend when below ~30 days
const REPORT_TTL_EXTEND_TO: u32 = 3_110_400;   // Extend to ~180 days

// ─── Contract ───────────────────────────────────────────────────────────────
//
// Role separation:
//
//   OWNER (cold key / multi-sig)        OPERATOR (hot key)
//   ─────────────────────────           ──────────────────
//   initialize()                        add_sanctioned()
//   upgrade()                           remove_sanctioned()
//   transfer_owner()                    set_merkle_root()
//   set_operator()                      review_report()
//                                       extend_ttl_batch()
//
//   If the operator key is compromised, the attacker CANNOT:
//     - Upgrade the contract binary
//     - Change the owner or operator
//     - Brick the contract
//
//   The owner can revoke the operator at any time via set_operator().

#[contract]
pub struct ComplianceOracle;

#[contractimpl]
impl ComplianceOracle {
    // ── Owner / Lifecycle ───────────────────────────────────────────────

    /// Initialize the oracle with an owner and operator address.
    /// Can only be called once.
    ///
    /// - `owner`: Controls upgrades and role changes. Should be a multi-sig.
    /// - `operator`: Controls data operations. Can be a hot wallet.
    ///
    /// For simple setups, pass the same address for both.
    pub fn initialize(env: Env, owner: Address, operator: Address) -> Result<(), OracleError> {
        if env.storage().instance().has(&DataKey::Owner) {
            return Err(OracleError::AlreadyInitialized);
        }
        owner.require_auth();
        env.storage().instance().set(&DataKey::Owner, &owner);
        env.storage().instance().set(&DataKey::Operator, &operator);
        env.storage().instance().set(&DataKey::EntityCount, &0u32);
        env.storage().instance().set(&DataKey::ReportCount, &0u32);

        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "initialized"),),
            (owner, operator),
        );
        Ok(())
    }

    /// Transfer ownership to a new address. Both old and new owner must authorize.
    /// This is the highest-privilege operation.
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

    /// One-time migration from v0.3.x → v0.4.0.
    /// Sets the Operator key (which didn't exist in previous versions).
    /// Can only be called once (idempotent — fails if Operator already set).
    /// Owner auth required.
    pub fn migrate_v4(env: Env, operator: Address) -> Result<(), OracleError> {
        let owner = Self::require_owner(&env)?;
        owner.require_auth();

        // Prevent double-migration
        if env.storage().instance().has(&DataKey::Operator) {
            return Err(OracleError::AlreadyInitialized);
        }

        env.storage().instance().set(&DataKey::Operator, &operator);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "migrated_v4"),),
            operator,
        );
        Ok(())
    }

    /// Set a new operator address. Owner only.
    /// Use this to rotate hot keys or revoke a compromised operator.
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

    /// Upgrade the contract to a new WASM binary. Owner only.
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

    /// Returns the current owner address.
    pub fn owner(env: Env) -> Result<Address, OracleError> {
        Self::require_owner(&env)
    }

    /// Returns the current operator address.
    pub fn operator(env: Env) -> Result<Address, OracleError> {
        env.storage()
            .instance()
            .get(&DataKey::Operator)
            .ok_or(OracleError::NotInitialized)
    }

    // ── Read (Free) ─────────────────────────────────────────────────────

    /// Check if an address from ANY chain is sanctioned.
    ///
    /// **Important**: The address string MUST be lowercased before calling.
    /// ETH addresses are case-insensitive (EIP-55 mixed-case is a checksum).
    /// The contract stores all addresses in lowercase.
    pub fn is_sanctioned(env: Env, addr: String) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Sanctioned(addr))
            .unwrap_or(false)
    }

    /// Returns the total number of sanctioned entities on-chain.
    pub fn entity_count(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::EntityCount)
            .unwrap_or(0u32)
    }

    /// Returns the ledger timestamp of the last sanctions list update.
    pub fn last_updated(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::LastUpdated)
            .unwrap_or(0u64)
    }

    /// Returns the SHA-256 hash of the off-chain dataset.
    pub fn data_hash(env: Env) -> BytesN<32> {
        env.storage()
            .instance()
            .get(&DataKey::DataHash)
            .unwrap_or(BytesN::from_array(&env, &[0u8; 32]))
    }

    /// Returns the Merkle root of the full sanctions dataset.
    pub fn merkle_root(env: Env) -> BytesN<32> {
        env.storage()
            .instance()
            .get(&DataKey::MerkleRoot)
            .unwrap_or(BytesN::from_array(&env, &[0u8; 32]))
    }

    /// Batch check multiple addresses at once (max 200).
    /// Returns a vector of booleans in the same order as the input.
    pub fn check_batch(env: Env, addresses: Vec<String>) -> Result<Vec<bool>, OracleError> {
        if addresses.len() > MAX_BATCH_SIZE {
            return Err(OracleError::BatchTooLarge);
        }

        let mut results = Vec::new(&env);
        for addr in addresses.iter() {
            let sanctioned = env
                .storage()
                .persistent()
                .get(&DataKey::Sanctioned(addr))
                .unwrap_or(false);
            results.push_back(sanctioned);
        }
        Ok(results)
    }

    // ── Write (Operator Only) ───────────────────────────────────────────

    /// Add addresses to the sanctions list. **Operator only.**
    ///
    /// All addresses should be **lowercased** before submission.
    ///
    /// - `addresses`: up to 200 address strings per call (10-128 chars each)
    /// - `data_hash`: SHA-256 of the full dataset snapshot
    /// - `data_source`: data source identifier (e.g. "ofac_sdn")
    pub fn add_sanctioned(
        env: Env,
        addresses: Vec<String>,
        data_hash: BytesN<32>,
        data_source: String,
    ) -> Result<u32, OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        let count = addresses.len();
        if count == 0 {
            return Err(OracleError::EmptyList);
        }
        if count > MAX_BATCH_SIZE {
            return Err(OracleError::BatchTooLarge);
        }

        let mut added: u32 = 0;
        for addr in addresses.iter() {
            let len = addr.len();
            if len < MIN_ADDR_LEN || len > MAX_ADDR_LEN {
                continue;
            }

            let key = DataKey::Sanctioned(addr.clone());
            if !env.storage().persistent().has(&key) {
                env.storage().persistent().set(&key, &true);
                env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND_TO);
                added += 1;
            } else {
                env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND_TO);
            }
        }

        let prev_count: u32 = env.storage().instance().get(&DataKey::EntityCount).unwrap_or(0);
        env.storage().instance().set(&DataKey::EntityCount, &prev_count.saturating_add(added));
        env.storage().instance().set(&DataKey::LastUpdated, &env.ledger().timestamp());
        env.storage().instance().set(&DataKey::DataHash, &data_hash);

        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "sanctioned_added"),),
            (added, data_source),
        );

        Ok(added)
    }

    /// Remove addresses from the sanctions list. **Operator only.**
    pub fn remove_sanctioned(
        env: Env,
        addresses: Vec<String>,
        data_hash: BytesN<32>,
        data_source: String,
    ) -> Result<u32, OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        let count = addresses.len();
        if count == 0 {
            return Err(OracleError::EmptyList);
        }
        if count > MAX_BATCH_SIZE {
            return Err(OracleError::BatchTooLarge);
        }

        let mut removed: u32 = 0;
        for addr in addresses.iter() {
            let key = DataKey::Sanctioned(addr.clone());
            if env.storage().persistent().has(&key) {
                env.storage().persistent().remove(&key);
                removed += 1;
            }
        }

        let prev_count: u32 = env.storage().instance().get(&DataKey::EntityCount).unwrap_or(0);
        let new_count = prev_count.saturating_sub(removed);
        env.storage().instance().set(&DataKey::EntityCount, &new_count);
        env.storage().instance().set(&DataKey::LastUpdated, &env.ledger().timestamp());
        env.storage().instance().set(&DataKey::DataHash, &data_hash);

        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "sanctioned_removed"),),
            (removed, data_source),
        );

        Ok(removed)
    }

    /// Update the Merkle root. **Operator only.**
    pub fn set_merkle_root(
        env: Env,
        root: BytesN<32>,
    ) -> Result<(), OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        env.storage().instance().set(&DataKey::MerkleRoot, &root);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "merkle_root_updated"),),
            root,
        );
        Ok(())
    }

    /// Verify a Merkle proof that an address string is in the sanctions dataset.
    ///
    /// **Leaf Encoding**: `SHA-256(addr.to_xdr())` — includes XDR envelope.
    /// Off-chain provers must use the same encoding.
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

        let addr_bytes = addr.clone().to_xdr(&env);
        let mut current_hash = env.crypto().sha256(&addr_bytes);

        let mut idx = leaf_index;
        for sibling in proof.iter() {
            let sibling_bytes: BytesN<32> = sibling;
            if idx % 2 == 0 {
                let mut combined = Bytes::new(&env);
                combined.append(&Bytes::from_slice(&env, current_hash.to_array().as_slice()));
                combined.append(&Bytes::from_slice(&env, sibling_bytes.to_array().as_slice()));
                current_hash = env.crypto().sha256(&combined);
            } else {
                let mut combined = Bytes::new(&env);
                combined.append(&Bytes::from_slice(&env, sibling_bytes.to_array().as_slice()));
                combined.append(&Bytes::from_slice(&env, current_hash.to_array().as_slice()));
                current_hash = env.crypto().sha256(&combined);
            }
            idx /= 2;
        }

        Ok(BytesN::from_array(&env, &current_hash.to_array()) == stored_root)
    }

    // ── Community Reporting ─────────────────────────────────────────────

    /// Anyone can report a suspicious address from any chain.
    pub fn report_address(
        env: Env,
        reporter: Address,
        target: String,
        reason: String,
    ) -> Result<u32, OracleError> {
        reporter.require_auth();

        let len = target.len();
        if len < MIN_ADDR_LEN || len > MAX_ADDR_LEN {
            return Err(OracleError::InvalidAddressLength);
        }

        let report_id: u32 = env
            .storage()
            .instance()
            .get(&DataKey::ReportCount)
            .unwrap_or(0u32);

        let next_id = report_id.checked_add(1).ok_or(OracleError::ReportLimitReached)?;

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

        env.storage().instance().set(&DataKey::ReportCount, &next_id);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "address_reported"),),
            (report_id, reporter, target),
        );

        Ok(report_id)
    }

    /// Operator reviews a community report. Can only be reviewed once.
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

        if accept {
            report.status = 1;

            let sanction_key = DataKey::Sanctioned(report.target.clone());
            if !env.storage().persistent().has(&sanction_key) {
                env.storage().persistent().set(&sanction_key, &true);
                env.storage().persistent().extend_ttl(&sanction_key, TTL_THRESHOLD, TTL_EXTEND_TO);

                let prev_count: u32 = env.storage().instance().get(&DataKey::EntityCount).unwrap_or(0);
                env.storage().instance().set(&DataKey::EntityCount, &prev_count.saturating_add(1));
            }
        } else {
            report.status = 2;
        }

        env.storage().persistent().set(&key, &report);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "report_reviewed"),),
            (report_id, accept),
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

    /// Get the total number of community reports.
    pub fn report_count(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ReportCount)
            .unwrap_or(0u32)
    }

    // ── TTL Management (Operator) ───────────────────────────────────────

    /// Batch extend TTL for sanctioned address entries. **Operator only.**
    pub fn extend_ttl_batch(
        env: Env,
        addresses: Vec<String>,
    ) -> Result<u32, OracleError> {
        let op = Self::require_operator(&env)?;
        op.require_auth();

        let count = addresses.len();
        if count > MAX_BATCH_SIZE {
            return Err(OracleError::BatchTooLarge);
        }

        let mut extended: u32 = 0;
        for addr in addresses.iter() {
            let key = DataKey::Sanctioned(addr);
            if env.storage().persistent().has(&key) {
                env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND_TO);
                extended += 1;
            }
        }

        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        Ok(extended)
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
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod test;
