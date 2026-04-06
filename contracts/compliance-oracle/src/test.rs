#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, String, Vec};
use soroban_sdk::xdr::ToXdr;

fn setup_env() -> (Env, Address, ComplianceOracleClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(ComplianceOracle, ());
    let client = ComplianceOracleClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.initialize(&admin);

    (env, admin, client)
}

fn mock_data_hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ])
}

// ─── Initialization ─────────────────────────────────────────────────────

#[test]
fn test_initialize() {
    let (_env, admin, client) = setup_env();
    assert_eq!(client.admin(), admin);
    assert_eq!(client.entity_count(), 0);
    assert_eq!(client.last_updated(), 0);
    assert_eq!(client.report_count(), 0);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn test_double_initialize_fails() {
    let (env, _admin, client) = setup_env();
    let another = Address::generate(&env);
    client.initialize(&another);
}

// ─── Add Sanctioned ─────────────────────────────────────────────────────

#[test]
fn test_add_sanctioned() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let data_source = String::from_str(&env, "ofac_sdn");

    let addr1 = Address::generate(&env);
    let addr2 = Address::generate(&env);

    let mut addresses = Vec::new(&env);
    addresses.push_back(addr1.clone());
    addresses.push_back(addr2.clone());

    let added = client.add_sanctioned(&addresses, &hash, &data_source);
    assert_eq!(added, 2);
    assert_eq!(client.entity_count(), 2);
    assert!(client.is_sanctioned(&addr1));
    assert!(client.is_sanctioned(&addr2));
}

#[test]
fn test_add_duplicate_does_not_double_count() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let data_source = String::from_str(&env, "ofac_sdn");

    let addr1 = Address::generate(&env);
    let mut addresses = Vec::new(&env);
    addresses.push_back(addr1.clone());

    client.add_sanctioned(&addresses, &hash, &data_source);
    assert_eq!(client.entity_count(), 1);

    // Add same address again
    let added = client.add_sanctioned(&addresses, &hash, &data_source);
    assert_eq!(added, 0);
    assert_eq!(client.entity_count(), 1);
}

// ─── Remove Sanctioned ──────────────────────────────────────────────────

#[test]
fn test_remove_sanctioned() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let data_source = String::from_str(&env, "ofac_sdn");

    let addr1 = Address::generate(&env);
    let addr2 = Address::generate(&env);

    let mut addresses = Vec::new(&env);
    addresses.push_back(addr1.clone());
    addresses.push_back(addr2.clone());

    client.add_sanctioned(&addresses, &hash, &data_source);
    assert_eq!(client.entity_count(), 2);

    let mut to_remove = Vec::new(&env);
    to_remove.push_back(addr1.clone());

    let removed = client.remove_sanctioned(&to_remove, &hash, &data_source);
    assert_eq!(removed, 1);
    assert_eq!(client.entity_count(), 1);
    assert!(!client.is_sanctioned(&addr1));
    assert!(client.is_sanctioned(&addr2));
}

#[test]
fn test_remove_nonexistent_is_noop() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let data_source = String::from_str(&env, "ofac_sdn");

    let addr1 = Address::generate(&env);
    let mut addresses = Vec::new(&env);
    addresses.push_back(addr1.clone());

    let removed = client.remove_sanctioned(&addresses, &hash, &data_source);
    assert_eq!(removed, 0);
    assert_eq!(client.entity_count(), 0);
}

// ─── is_sanctioned ──────────────────────────────────────────────────────

#[test]
fn test_unknown_address_is_clean() {
    let (env, _admin, client) = setup_env();
    let unknown = Address::generate(&env);
    assert!(!client.is_sanctioned(&unknown));
}

// ─── Batch Check ────────────────────────────────────────────────────────

#[test]
fn test_batch_check() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let data_source = String::from_str(&env, "ofac_sdn");

    let sanctioned = Address::generate(&env);
    let clean = Address::generate(&env);

    let mut to_add = Vec::new(&env);
    to_add.push_back(sanctioned.clone());
    client.add_sanctioned(&to_add, &hash, &data_source);

    let mut to_check = Vec::new(&env);
    to_check.push_back(sanctioned.clone());
    to_check.push_back(clean.clone());

    let results = client.check_batch(&to_check);
    assert_eq!(results.get(0).unwrap(), true);
    assert_eq!(results.get(1).unwrap(), false);
}

// ─── Admin Transfer ─────────────────────────────────────────────────────

#[test]
fn test_transfer_admin() {
    let (env, _admin, client) = setup_env();
    let new_admin = Address::generate(&env);

    client.transfer_admin(&new_admin);
    assert_eq!(client.admin(), new_admin);
}

// ─── Data Hash / Audit ──────────────────────────────────────────────────

#[test]
fn test_data_hash_updated_on_add() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let data_source = String::from_str(&env, "ofac_sdn");

    let addr = Address::generate(&env);
    let mut addresses = Vec::new(&env);
    addresses.push_back(addr);

    client.add_sanctioned(&addresses, &hash, &data_source);
    assert_eq!(client.data_hash(), hash);
}

// ─── Merkle Root ────────────────────────────────────────────────────────

#[test]
fn test_set_merkle_root() {
    let (env, _admin, client) = setup_env();
    let root = mock_data_hash(&env); // reuse as a mock root

    client.set_merkle_root(&root);
    assert_eq!(client.merkle_root(), root);
}

#[test]
fn test_verify_merkle_proof_no_root_returns_false() {
    let (env, _admin, client) = setup_env();
    let addr = Address::generate(&env);
    let proof: Vec<BytesN<32>> = Vec::new(&env);

    // No Merkle root set — should return false
    assert!(!client.verify_merkle_proof(&addr, &proof, &0));
}

#[test]
fn test_verify_merkle_proof_single_leaf() {
    let (env, _admin, client) = setup_env();

    // Build a simple 1-leaf Merkle tree:
    // root = SHA-256(leaf)
    let addr = Address::generate(&env);
    let addr_bytes = addr.clone().to_xdr(&env);
    let leaf_hash = env.crypto().sha256(&addr_bytes);

    // For a single leaf, the root IS the leaf hash
    let root = BytesN::from_array(&env, &leaf_hash.to_array());
    client.set_merkle_root(&root);

    // Empty proof — the leaf itself should equal the root
    let proof: Vec<BytesN<32>> = Vec::new(&env);
    assert!(client.verify_merkle_proof(&addr, &proof, &0));
}

#[test]
fn test_verify_merkle_proof_two_leaves() {
    let (env, _admin, client) = setup_env();

    let addr0 = Address::generate(&env);
    let addr1 = Address::generate(&env);

    // Compute leaf hashes
    let leaf0 = env.crypto().sha256(&addr0.clone().to_xdr(&env));
    let leaf1 = env.crypto().sha256(&addr1.clone().to_xdr(&env));

    // Compute root = SHA-256(leaf0 || leaf1)
    let mut combined = Bytes::new(&env);
    combined.append(&Bytes::from_slice(&env, leaf0.to_array().as_slice()));
    combined.append(&Bytes::from_slice(&env, leaf1.to_array().as_slice()));
    let root_hash = env.crypto().sha256(&combined);
    let root = BytesN::from_array(&env, &root_hash.to_array());

    client.set_merkle_root(&root);

    // Verify addr0 with proof [leaf1], index 0 (left child)
    let mut proof = Vec::new(&env);
    proof.push_back(BytesN::from_array(&env, &leaf1.to_array()));
    assert!(client.verify_merkle_proof(&addr0, &proof, &0));

    // Verify addr1 with proof [leaf0], index 1 (right child)
    let mut proof1 = Vec::new(&env);
    proof1.push_back(BytesN::from_array(&env, &leaf0.to_array()));
    assert!(client.verify_merkle_proof(&addr1, &proof1, &1));

    // Wrong address should fail
    let wrong = Address::generate(&env);
    assert!(!client.verify_merkle_proof(&wrong, &proof, &0));
}

// ─── Community Reporting ────────────────────────────────────────────────

#[test]
fn test_report_address() {
    let (env, _admin, client) = setup_env();

    let reporter = Address::generate(&env);
    let target = Address::generate(&env);
    let reason = String::from_str(&env, "Suspected sanctions evasion");

    let report_id = client.report_address(&reporter, &target, &reason);
    assert_eq!(report_id, 0);
    assert_eq!(client.report_count(), 1);

    let report = client.get_report(&0);
    assert_eq!(report.reporter, reporter);
    assert_eq!(report.target, target);
    assert_eq!(report.status, 0); // pending
}

#[test]
fn test_review_report_accept() {
    let (env, _admin, client) = setup_env();
    let _hash = mock_data_hash(&env);

    let reporter = Address::generate(&env);
    let target = Address::generate(&env);
    let reason = String::from_str(&env, "OFAC match");

    client.report_address(&reporter, &target, &reason);

    // Admin accepts the report
    client.review_report(&0, &true);

    let report = client.get_report(&0);
    assert_eq!(report.status, 1); // accepted

    // Target should now be sanctioned
    assert!(client.is_sanctioned(&target));
    assert_eq!(client.entity_count(), 1);
}

#[test]
fn test_review_report_reject() {
    let (env, _admin, client) = setup_env();

    let reporter = Address::generate(&env);
    let target = Address::generate(&env);
    let reason = String::from_str(&env, "False positive");

    client.report_address(&reporter, &target, &reason);
    client.review_report(&0, &false);

    let report = client.get_report(&0);
    assert_eq!(report.status, 2); // rejected

    // Target should NOT be sanctioned
    assert!(!client.is_sanctioned(&target));
}

#[test]
#[should_panic(expected = "Error(Contract, #7)")]
fn test_review_nonexistent_report_fails() {
    let (_env, _admin, client) = setup_env();
    client.review_report(&999, &true);
}

// ─── TTL Management ─────────────────────────────────────────────────────

#[test]
fn test_extend_ttl_batch() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let data_source = String::from_str(&env, "ofac_sdn");

    let addr1 = Address::generate(&env);
    let addr2 = Address::generate(&env);

    let mut to_add = Vec::new(&env);
    to_add.push_back(addr1.clone());
    to_add.push_back(addr2.clone());

    client.add_sanctioned(&to_add, &hash, &data_source);

    // Extend TTL — should succeed and return count
    let extended = client.extend_ttl_batch(&to_add);
    assert_eq!(extended, 2);
}

// ─── Edge Cases ─────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn test_add_empty_list_fails() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let data_source = String::from_str(&env, "ofac_sdn");
    let empty: Vec<Address> = Vec::new(&env);

    client.add_sanctioned(&empty, &hash, &data_source);
}
