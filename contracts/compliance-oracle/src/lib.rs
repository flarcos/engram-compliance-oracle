#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, contracterror, Address, Bytes, BytesN, Env, String, Symbol, Vec};
use soroban_sdk::xdr::ToXdr;

// ─── Storage Keys ───────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// The admin address (only entity that can update sanctions data)
    Admin,
    /// Whether an address is sanctioned: DataKey::Sanctioned(addr_string) → bool
    /// addr_string is the raw address from any chain (e.g. "0x...", "bc1...", "G...", "T...")
    Sanctioned(String),
    /// Total number of sanctioned entities currently on-chain
    EntityCount,
    /// Ledger timestamp of last sanctions list update
    LastUpdated,
    /// SHA-256 hash of the full off-chain dataset (for audit verification)
    DataHash,
    /// Merkle root of the full sanctions dataset (for proof verification)
    MerkleRoot,
    /// Next report ID
    ReportCount,
    /// Report detail: ReportData(id) → ReportEntry
    ReportData(u32),
}

/// Community report stored on-chain
#[contracttype]
#[derive(Clone)]
pub struct ReportEntry {
    pub reporter: Address,
    pub target: String,   // Any chain address as a string
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
    /// Caller is not the admin
    Unauthorized = 3,
    /// Empty address list provided
    EmptyList = 4,
    /// Batch size exceeds maximum (200)
    BatchTooLarge = 5,
    /// Invalid Merkle proof
    InvalidProof = 6,
    /// Report not found
    ReportNotFound = 7,
}

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_BATCH_SIZE: u32 = 200;

// TTL: ~30 days in ledgers (1 ledger ≈ 5 seconds, 30 days ≈ 518400 ledgers)
const TTL_THRESHOLD: u32 = 259_200;   // Extend when below ~15 days
const TTL_EXTEND_TO: u32 = 518_400;   // Extend to ~30 days

// Instance TTL: ~90 days (contract code + instance storage)
const INSTANCE_TTL_THRESHOLD: u32 = 518_400;   // Extend when below ~30 days
const INSTANCE_TTL_EXTEND_TO: u32 = 1_555_200; // Extend to ~90 days

// ─── Contract ───────────────────────────────────────────────────────────────

#[contract]
pub struct ComplianceOracle;

#[contractimpl]
impl ComplianceOracle {
    // ── Admin / Lifecycle ───────────────────────────────────────────────

    /// Initialize the oracle with an admin address.
    /// Can only be called once.
    pub fn initialize(env: Env, admin: Address) -> Result<(), OracleError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(OracleError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::EntityCount, &0u32);
        env.storage().instance().set(&DataKey::ReportCount, &0u32);

        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "initialized"),),
            admin,
        );
        Ok(())
    }

    /// Transfer admin to a new address. Both old and new admin must authorize.
    pub fn transfer_admin(env: Env, new_admin: Address) -> Result<(), OracleError> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();
        new_admin.require_auth();

        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "admin_transferred"),),
            new_admin,
        );
        Ok(())
    }

    /// Upgrade the contract to a new WASM binary. Admin only.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) -> Result<(), OracleError> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        env.deployer().update_current_contract_wasm(new_wasm_hash.clone());
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "upgraded"),),
            new_wasm_hash,
        );
        Ok(())
    }

    /// Returns the current admin address.
    pub fn admin(env: Env) -> Result<Address, OracleError> {
        Self::require_admin(&env)
    }

    // ── Read (Free) ─────────────────────────────────────────────────────

    /// Check if an address from ANY chain is sanctioned.
    /// Pass the raw address string: "0x1234..." (ETH), "bc1..." (BTC),
    /// "G..." (Stellar), "T..." (Tron), etc.
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

    /// Batch check multiple addresses at once.
    /// Returns a vector of booleans in the same order as the input.
    pub fn check_batch(env: Env, addresses: Vec<String>) -> Vec<bool> {
        let mut results = Vec::new(&env);
        for addr in addresses.iter() {
            let sanctioned = env
                .storage()
                .persistent()
                .get(&DataKey::Sanctioned(addr))
                .unwrap_or(false);
            results.push_back(sanctioned);
        }
        results
    }

    // ── Write (Admin Only) ──────────────────────────────────────────────

    /// Add addresses to the sanctions list. Accepts raw address strings
    /// from any blockchain (ETH, BTC, Stellar, Tron, etc.)
    ///
    /// - `addresses`: up to 200 address strings per call
    /// - `data_hash`: SHA-256 of the full dataset snapshot
    /// - `data_source`: data source identifier (e.g. "ofac_sdn")
    pub fn add_sanctioned(
        env: Env,
        addresses: Vec<String>,
        data_hash: BytesN<32>,
        data_source: String,
    ) -> Result<u32, OracleError> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        let count = addresses.len();
        if count == 0 {
            return Err(OracleError::EmptyList);
        }
        if count > MAX_BATCH_SIZE {
            return Err(OracleError::BatchTooLarge);
        }

        let mut added: u32 = 0;
        for addr in addresses.iter() {
            let key = DataKey::Sanctioned(addr.clone());
            if !env.storage().persistent().has(&key) {
                env.storage().persistent().set(&key, &true);
                env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND_TO);
                added += 1;
            } else {
                env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND_TO);
            }
        }

        // Update metadata
        let prev_count: u32 = env.storage().instance().get(&DataKey::EntityCount).unwrap_or(0);
        env.storage().instance().set(&DataKey::EntityCount, &(prev_count + added));
        env.storage().instance().set(&DataKey::LastUpdated, &env.ledger().timestamp());
        env.storage().instance().set(&DataKey::DataHash, &data_hash);

        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "sanctioned_added"),),
            (added, data_source),
        );

        Ok(added)
    }

    /// Remove addresses from the sanctions list.
    pub fn remove_sanctioned(
        env: Env,
        addresses: Vec<String>,
        data_hash: BytesN<32>,
        data_source: String,
    ) -> Result<u32, OracleError> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

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
        let new_count = if removed > prev_count { 0 } else { prev_count - removed };
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

    /// Update the Merkle root.
    pub fn set_merkle_root(
        env: Env,
        root: BytesN<32>,
    ) -> Result<(), OracleError> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        env.storage().instance().set(&DataKey::MerkleRoot, &root);
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "merkle_root_updated"),),
            root,
        );
        Ok(())
    }

    /// Verify a Merkle proof that an address string is in the sanctions dataset.
    pub fn verify_merkle_proof(
        env: Env,
        addr: String,
        proof: Vec<BytesN<32>>,
        leaf_index: u32,
    ) -> bool {
        let stored_root: BytesN<32> = env
            .storage()
            .instance()
            .get(&DataKey::MerkleRoot)
            .unwrap_or(BytesN::from_array(&env, &[0u8; 32]));

        let zero_root = BytesN::from_array(&env, &[0u8; 32]);
        if stored_root == zero_root {
            return false;
        }

        // Compute leaf hash: SHA-256(address_string_bytes)
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

        BytesN::from_array(&env, &current_hash.to_array()) == stored_root
    }

    // ── Community Reporting ─────────────────────────────────────────────

    /// Anyone can report a suspicious address from any chain.
    /// The target is a raw address string. Returns the report ID.
    pub fn report_address(
        env: Env,
        reporter: Address,
        target: String,
        reason: String,
    ) -> u32 {
        reporter.require_auth();

        let report_id: u32 = env
            .storage()
            .instance()
            .get(&DataKey::ReportCount)
            .unwrap_or(0u32);

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
            TTL_THRESHOLD,
            TTL_EXTEND_TO,
        );

        env.storage().instance().set(&DataKey::ReportCount, &(report_id + 1));
        env.storage().instance().extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        env.events().publish(
            (Symbol::new(&env, "address_reported"),),
            (report_id, reporter, target),
        );

        report_id
    }

    /// Admin reviews a community report.
    pub fn review_report(
        env: Env,
        report_id: u32,
        accept: bool,
    ) -> Result<(), OracleError> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

        let key = DataKey::ReportData(report_id);
        let mut report: ReportEntry = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(OracleError::ReportNotFound)?;

        if accept {
            report.status = 1;

            let sanction_key = DataKey::Sanctioned(report.target.clone());
            if !env.storage().persistent().has(&sanction_key) {
                env.storage().persistent().set(&sanction_key, &true);
                env.storage().persistent().extend_ttl(&sanction_key, TTL_THRESHOLD, TTL_EXTEND_TO);

                let prev_count: u32 = env.storage().instance().get(&DataKey::EntityCount).unwrap_or(0);
                env.storage().instance().set(&DataKey::EntityCount, &(prev_count + 1));
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

    // ── TTL Management (Admin) ──────────────────────────────────────────

    /// Batch extend TTL for sanctioned address entries.
    pub fn extend_ttl_batch(
        env: Env,
        addresses: Vec<String>,
    ) -> Result<u32, OracleError> {
        let admin = Self::require_admin(&env)?;
        admin.require_auth();

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

    fn require_admin(env: &Env) -> Result<Address, OracleError> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(OracleError::NotInitialized)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod test;
