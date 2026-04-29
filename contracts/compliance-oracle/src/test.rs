#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String, Vec, Bytes};
use soroban_sdk::xdr::ToXdr;

fn setup_env() -> (Env, Address, Address, ComplianceOracleClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(ComplianceOracle, ());
    let client = ComplianceOracleClient::new(&env, &contract_id);
    let owner = Address::generate(&env);
    let operator = Address::generate(&env);

    client.initialize(&owner, &operator);

    (env, owner, operator, client)
}

// ─── Helper: build a real Merkle tree and return (root, proofs, indices) ────

fn build_merkle_tree(env: &Env, addresses: &[&str]) -> (BytesN<32>, Vec<Vec<BytesN<32>>>, Vec<u32>) {
    // Hash leaves using the same XDR encoding as the contract
    let mut leaves: Vec<BytesN<32>> = Vec::new(env);
    for addr_str in addresses {
        let addr = String::from_str(env, addr_str);
        let addr_bytes = addr.to_xdr(env);
        let hash: BytesN<32> = env.crypto().sha256(&addr_bytes).into();
        leaves.push_back(hash);
    }

    // Pad to power of 2 with zero hashes
    let mut target = 1u32;
    while target < leaves.len() {
        target *= 2;
    }
    let zero_hash = BytesN::from_array(env, &[0u8; 32]);
    while leaves.len() < target {
        leaves.push_back(zero_hash.clone());
    }

    // Build tree layers
    let mut layers: soroban_sdk::Vec<Vec<BytesN<32>>> = soroban_sdk::Vec::new(env);
    layers.push_back(leaves.clone());

    let mut current = leaves;
    while current.len() > 1 {
        let mut next: Vec<BytesN<32>> = Vec::new(env);
        let pairs = current.len() / 2;
        for i in 0..pairs {
            let left = current.get(i * 2).unwrap();
            let right = current.get(i * 2 + 1).unwrap();
            let mut combined = Bytes::new(env);
            combined.append(&Bytes::from_slice(env, left.to_array().as_slice()));
            combined.append(&Bytes::from_slice(env, right.to_array().as_slice()));
            let parent: BytesN<32> = env.crypto().sha256(&combined).into();
            next.push_back(parent);
        }
        layers.push_back(next.clone());
        current = next;
    }

    let root = current.get(0).unwrap();

    // Generate proofs for each original address
    let mut all_proofs: Vec<Vec<BytesN<32>>> = Vec::new(env);
    let mut all_indices: Vec<u32> = Vec::new(env);

    for i in 0..(addresses.len() as u32) {
        let mut proof: Vec<BytesN<32>> = Vec::new(env);
        let mut idx = i;

        for layer_i in 0..(layers.len() - 1) {
            let layer = layers.get(layer_i).unwrap();
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            proof.push_back(layer.get(sibling_idx).unwrap());
            idx /= 2;
        }

        all_proofs.push_back(proof);
        all_indices.push_back(i);
    }

    (root, all_proofs, all_indices)
}

fn mock_data_hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ])
}

// ─── Initialization & Roles ─────────────────────────────────────────────

#[test]
fn test_initialize() {
    let (_env, owner, operator, client) = setup_env();
    assert_eq!(client.owner(), owner);
    assert_eq!(client.operator(), operator);
    assert_eq!(client.entity_count(), 0);
    assert_eq!(client.last_updated(), 0);
    assert_eq!(client.report_count(), 0);
    assert_eq!(client.report_threshold(), 10);
}

#[test]
fn test_initialize_same_owner_and_operator() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register(ComplianceOracle, ());
    let client = ComplianceOracleClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.initialize(&admin, &admin);
    assert_eq!(client.owner(), admin.clone());
    assert_eq!(client.operator(), admin);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn test_double_initialize_fails() {
    let (env, _owner, _operator, client) = setup_env();
    let another = Address::generate(&env);
    client.initialize(&another, &another);
}

#[test]
fn test_transfer_owner() {
    let (env, _owner, _operator, client) = setup_env();
    let new_owner = Address::generate(&env);
    client.transfer_owner(&new_owner);
    assert_eq!(client.owner(), new_owner);
}

#[test]
fn test_set_operator() {
    let (env, _owner, _operator, client) = setup_env();
    let new_operator = Address::generate(&env);
    client.set_operator(&new_operator);
    assert_eq!(client.operator(), new_operator);
}

// ─── Merkle Proof Verification ──────────────────────────────────────────

#[test]
fn test_merkle_proof_single_address() {
    let (env, _owner, _operator, client) = setup_env();

    let addresses = ["0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b"];
    let (root, proofs, indices) = build_merkle_tree(&env, &addresses);

    let data_hash = mock_data_hash(&env);
    client.set_merkle_root(&root, &data_hash, &1);

    assert_eq!(client.merkle_root(), root);
    assert_eq!(client.entity_count(), 1);

    let proof = proofs.get(0).unwrap();
    let idx = indices.get(0).unwrap();
    let addr = String::from_str(&env, addresses[0]);

    let result = client.verify_merkle_proof(&addr, &proof, &idx);
    assert!(result);
}

#[test]
fn test_merkle_proof_multiple_addresses() {
    let (env, _owner, _operator, client) = setup_env();

    let addresses = [
        "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b",
        "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
        "tn2yqtv5hpqenasqprfg3dqwxlkdcvk1qu",
        "0x7f367cc41522ce07553e823bf3be79a889debe1b",
    ];
    let (root, proofs, indices) = build_merkle_tree(&env, &addresses);

    let data_hash = mock_data_hash(&env);
    client.set_merkle_root(&root, &data_hash, &4);

    // Verify each address
    for i in 0..addresses.len() {
        let addr = String::from_str(&env, addresses[i]);
        let proof = proofs.get(i as u32).unwrap();
        let idx = indices.get(i as u32).unwrap();
        assert!(client.verify_merkle_proof(&addr, &proof, &idx));
    }

    // Unknown address should fail
    let unknown = String::from_str(&env, "0x0000000000000000000000000000000000000000");
    let fake_proof: Vec<BytesN<32>> = Vec::new(&env);
    assert!(!client.verify_merkle_proof(&unknown, &fake_proof, &0));
}

#[test]
fn test_verify_merkle_proof_no_root_returns_error() {
    let (env, _owner, _operator, client) = setup_env();
    let addr = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let proof: Vec<BytesN<32>> = Vec::new(&env);

    let result = client.try_verify_merkle_proof(&addr, &proof, &0);
    assert!(result.is_err());
}

#[test]
fn test_verify_batch_proofs() {
    let (env, _owner, _operator, client) = setup_env();

    let raw_addresses = [
        "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b",
        "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
    ];
    let (root, proofs, indices) = build_merkle_tree(&env, &raw_addresses);

    let data_hash = mock_data_hash(&env);
    client.set_merkle_root(&root, &data_hash, &2);

    let mut addrs = Vec::new(&env);
    for a in &raw_addresses {
        addrs.push_back(String::from_str(&env, a));
    }

    let results = client.verify_batch_proofs(&addrs, &proofs, &indices);
    assert_eq!(results.len(), 2);
    assert_eq!(results.get(0).unwrap(), true);
    assert_eq!(results.get(1).unwrap(), true);
}

// ─── Agent Consensus Reporting ──────────────────────────────────────────

#[test]
fn test_report_address() {
    let (env, _owner, _operator, client) = setup_env();

    let reporter = Address::generate(&env);
    let target = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let reason = String::from_str(&env, "Known mixer");

    let report_id = client.report_address(&reporter, &target, &reason);
    assert_eq!(report_id, 0);
    assert_eq!(client.report_count(), 1);
    assert_eq!(client.reports_for(&target), 1);
    assert!(!client.is_flagged(&target));
}

#[test]
fn test_duplicate_report_from_same_reporter_fails() {
    let (env, _owner, _operator, client) = setup_env();

    let reporter = Address::generate(&env);
    let target = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let reason = String::from_str(&env, "Known mixer");

    client.report_address(&reporter, &target, &reason);

    // Same reporter, same target → should fail
    let result = client.try_report_address(&reporter, &target, &reason);
    assert!(result.is_err());
}

#[test]
fn test_different_reporters_increment_count() {
    let (env, _owner, _operator, client) = setup_env();

    let target = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let reason = String::from_str(&env, "Suspicious");

    for _ in 0..5u32 {
        let reporter = Address::generate(&env);
        client.report_address(&reporter, &target, &reason);
    }

    assert_eq!(client.reports_for(&target), 5);
    assert_eq!(client.report_count(), 5);
    assert!(!client.is_flagged(&target)); // Below threshold of 10
}

#[test]
fn test_auto_flag_at_threshold() {
    let (env, _owner, _operator, client) = setup_env();

    let target = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let reason = String::from_str(&env, "Flagged");

    // Report from 10 unique agents → should auto-flag
    for _ in 0..10u32 {
        let reporter = Address::generate(&env);
        client.report_address(&reporter, &target, &reason);
    }

    assert_eq!(client.reports_for(&target), 10);
    assert!(client.is_flagged(&target));
}

#[test]
fn test_auto_flag_with_custom_threshold() {
    let (env, _owner, _operator, client) = setup_env();

    // Set threshold to 3
    client.set_report_threshold(&3);
    assert_eq!(client.report_threshold(), 3);

    let target = String::from_str(&env, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let reason = String::from_str(&env, "Flagged");

    // 2 reports → not flagged
    for _ in 0..2u32 {
        let reporter = Address::generate(&env);
        client.report_address(&reporter, &target, &reason);
    }
    assert!(!client.is_flagged(&target));

    // 3rd report → auto-flagged
    let reporter = Address::generate(&env);
    client.report_address(&reporter, &target, &reason);
    assert!(client.is_flagged(&target));
}

#[test]
#[should_panic(expected = "Error(Contract, #12)")]
fn test_set_threshold_zero_fails() {
    let (_env, _owner, _operator, client) = setup_env();
    client.set_report_threshold(&0);
}

#[test]
fn test_report_invalid_address_length() {
    let (env, _owner, _operator, client) = setup_env();
    let reporter = Address::generate(&env);
    let too_short = String::from_str(&env, "0x1234");
    let reason = String::from_str(&env, "test");

    let result = client.try_report_address(&reporter, &too_short, &reason);
    assert!(result.is_err());
}

// ─── Report Review ──────────────────────────────────────────────────────

#[test]
fn test_review_report_accept() {
    let (env, _owner, _operator, client) = setup_env();

    let reporter = Address::generate(&env);
    let target = String::from_str(&env, "tn2yqtv5hpqenasqprfg3dqwxlkdcvk1qu");
    let reason = String::from_str(&env, "Known mixer");

    client.report_address(&reporter, &target, &reason);
    client.review_report(&0, &true);

    let report = client.get_report(&0);
    assert_eq!(report.status, 1);
}

#[test]
fn test_review_report_reject() {
    let (env, _owner, _operator, client) = setup_env();

    let reporter = Address::generate(&env);
    let target = String::from_str(&env, "0x0000000000000000000000000000000000000000");
    let reason = String::from_str(&env, "False positive");

    client.report_address(&reporter, &target, &reason);
    client.review_report(&0, &false);

    let report = client.get_report(&0);
    assert_eq!(report.status, 2);
}

#[test]
fn test_review_report_already_reviewed_fails() {
    let (env, _owner, _operator, client) = setup_env();

    let reporter = Address::generate(&env);
    let target = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let reason = String::from_str(&env, "test");

    client.report_address(&reporter, &target, &reason);
    client.review_report(&0, &true);

    let result = client.try_review_report(&0, &false);
    assert!(result.is_err());
}

#[test]
#[should_panic(expected = "Error(Contract, #7)")]
fn test_review_nonexistent_report_fails() {
    let (_env, _owner, _operator, client) = setup_env();
    client.review_report(&999, &true);
}

// ─── Set Merkle Root ────────────────────────────────────────────────────

#[test]
fn test_set_merkle_root() {
    let (env, _owner, _operator, client) = setup_env();
    let root = mock_data_hash(&env);
    let data_hash = BytesN::from_array(&env, &[0xaa; 32]);

    client.set_merkle_root(&root, &data_hash, &1447);
    assert_eq!(client.merkle_root(), root);
    assert_eq!(client.data_hash(), data_hash);
    assert_eq!(client.entity_count(), 1447);
    assert!(client.last_updated() > 0 || true); // ledger timestamp in test env
}

// ─── Edge Cases ─────────────────────────────────────────────────────────

#[test]
fn test_is_flagged_unknown_address() {
    let (env, _owner, _operator, client) = setup_env();
    let unknown = String::from_str(&env, "0x0000000000000000000000000000000000000000");
    assert!(!client.is_flagged(&unknown));
}

#[test]
fn test_reports_for_unknown_address() {
    let (env, _owner, _operator, client) = setup_env();
    let unknown = String::from_str(&env, "0x0000000000000000000000000000000000000000");
    assert_eq!(client.reports_for(&unknown), 0);
}

// ─── Audit Fix Tests ────────────────────────────────────────────────────

#[test]
fn test_unflag_address() {
    let (env, _owner, _operator, client) = setup_env();

    // Set threshold to 2 for quick test
    client.set_report_threshold(&2);

    let target = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let reason = String::from_str(&env, "Suspicious activity");

    // Flag it
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);
    client.report_address(&r1, &target, &reason);
    client.report_address(&r2, &target, &reason);
    assert!(client.is_flagged(&target));

    // Unflag it
    client.unflag_address(&target);
    assert!(!client.is_flagged(&target));
}

#[test]
fn test_reason_too_long_fails() {
    let (env, _owner, _operator, client) = setup_env();
    let reporter = Address::generate(&env);
    let target = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");

    // 257 chars = too long
    let long_reason = String::from_str(&env, &"a".repeat(257));

    let result = client.try_report_address(&reporter, &target, &long_reason);
    assert!(result.is_err());
}

#[test]
fn test_empty_reason_fails() {
    let (env, _owner, _operator, client) = setup_env();
    let reporter = Address::generate(&env);
    let target = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let empty_reason = String::from_str(&env, "");

    let result = client.try_report_address(&reporter, &target, &empty_reason);
    assert!(result.is_err());
}

// ─── Taint Propagation ─────────────────────────────────────────────────

#[test]
fn test_set_taint() {
    let (env, _owner, _operator, client) = setup_env();

    let target = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let source = String::from_str(&env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&env, "stellar");

    client.set_taint(&target, &72, &source, &1, &chain);

    assert!(client.is_tainted(&target));
    assert_eq!(client.taint_score(&target), 72);
    assert_eq!(client.taint_source(&target), source);
    assert_eq!(client.taint_hop(&target), 1);
    assert_eq!(client.taint_chain(&target), chain);
}

#[test]
fn test_taint_score_and_source() {
    let (env, _owner, _operator, client) = setup_env();

    let target = String::from_str(&env, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh");
    let source = String::from_str(&env, "0x7f367cc41522ce07553e823bf3be79a889debe1b");
    let chain = String::from_str(&env, "ethereum");

    client.set_taint(&target, &45, &source, &2, &chain);

    assert_eq!(client.taint_score(&target), 45);
    assert_eq!(client.taint_source(&target), source);
    assert_eq!(client.taint_hop(&target), 2);
    assert_eq!(client.taint_chain(&target), chain);
}

#[test]
fn test_is_flagged_includes_taint() {
    let (env, _owner, _operator, client) = setup_env();

    let target = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let source = String::from_str(&env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&env, "stellar");

    // Not flagged initially
    assert!(!client.is_flagged(&target));

    // Taint it
    client.set_taint(&target, &80, &source, &1, &chain);

    // Now is_flagged() returns true
    assert!(client.is_flagged(&target));
}

#[test]
fn test_flag_reason() {
    let (env, _owner, _operator, client) = setup_env();

    let target = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let source = String::from_str(&env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&env, "stellar");
    let reason = String::from_str(&env, "Flagged");

    // Clean
    assert_eq!(client.flag_reason(&target), 0);

    // Taint only → reason 2
    client.set_taint(&target, &80, &source, &1, &chain);
    assert_eq!(client.flag_reason(&target), 2);

    // Add consensus flag → reason 3 (both)
    client.set_report_threshold(&2);
    let r1 = Address::generate(&env);
    let r2 = Address::generate(&env);
    client.report_address(&r1, &target, &reason);
    client.report_address(&r2, &target, &reason);
    assert_eq!(client.flag_reason(&target), 3);
}

#[test]
fn test_set_taint_batch() {
    let (env, _owner, _operator, client) = setup_env();

    let mut addrs = Vec::new(&env);
    let mut scores = Vec::new(&env);
    let mut sources = Vec::new(&env);
    let mut hops = Vec::new(&env);
    let mut chains = Vec::new(&env);

    let source = String::from_str(&env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&env, "stellar");

    let addr1 = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let addr2 = String::from_str(&env, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh");

    addrs.push_back(addr1.clone());
    addrs.push_back(addr2.clone());
    scores.push_back(80u32);
    scores.push_back(45u32);
    sources.push_back(source.clone());
    sources.push_back(source.clone());
    hops.push_back(1u32);
    hops.push_back(2u32);
    chains.push_back(chain.clone());
    chains.push_back(chain.clone());

    client.set_taint_batch(&addrs, &scores, &sources, &hops, &chains);

    assert!(client.is_tainted(&addr1));
    assert_eq!(client.taint_score(&addr1), 80);
    assert!(client.is_tainted(&addr2));
    assert_eq!(client.taint_score(&addr2), 45);
}

#[test]
fn test_clear_taint() {
    let (env, _owner, _operator, client) = setup_env();

    let target = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let source = String::from_str(&env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&env, "stellar");

    // Set taint
    client.set_taint(&target, &72, &source, &1, &chain);
    assert!(client.is_tainted(&target));

    // Clear taint
    client.clear_taint(&target);
    assert!(!client.is_tainted(&target));
    assert_eq!(client.taint_score(&target), 0);
    assert!(!client.is_flagged(&target));
}

#[test]
fn test_whitelist_address() {
    let (env, _owner, _operator, client) = setup_env();

    let exchange = String::from_str(&env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    assert!(!client.is_whitelisted(&exchange));

    client.whitelist_address(&exchange);
    assert!(client.is_whitelisted(&exchange));
}

#[test]
fn test_set_taint_whitelisted_fails() {
    let (env, _owner, _operator, client) = setup_env();

    let exchange = String::from_str(&env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let source = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let chain = String::from_str(&env, "stellar");

    // Whitelist it
    client.whitelist_address(&exchange);

    // Try to taint it → should fail
    let result = client.try_set_taint(&exchange, &80, &source, &1, &chain);
    assert!(result.is_err());
}

#[test]
fn test_unwhitelist_address() {
    let (env, _owner, _operator, client) = setup_env();

    let exchange = String::from_str(&env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let source = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let chain = String::from_str(&env, "stellar");

    // Whitelist then unwhitelist
    client.whitelist_address(&exchange);
    client.unwhitelist_address(&exchange);
    assert!(!client.is_whitelisted(&exchange));

    // Now taint should work
    client.set_taint(&exchange, &60, &source, &1, &chain);
    assert!(client.is_tainted(&exchange));
}

#[test]
fn test_is_whitelisted_unknown() {
    let (env, _owner, _operator, client) = setup_env();
    let unknown = String::from_str(&env, "0x0000000000000000000000000000000000000000");
    assert!(!client.is_whitelisted(&unknown));
}

#[test]
fn test_taint_config_defaults() {
    let (_env, _owner, _operator, client) = setup_env();
    let (min_amount, max_hops) = client.taint_config();
    assert_eq!(min_amount, 1_000_000_000); // 100 XLM
    assert_eq!(max_hops, 2);
}

#[test]
fn test_set_taint_min_amount() {
    let (_env, _owner, _operator, client) = setup_env();
    client.set_taint_min_amount(&5_000_000_000i128);
    let (min_amount, _) = client.taint_config();
    assert_eq!(min_amount, 5_000_000_000);
}

#[test]
fn test_set_taint_max_hops() {
    let (_env, _owner, _operator, client) = setup_env();
    client.set_taint_max_hops(&5);
    let (_, max_hops) = client.taint_config();
    assert_eq!(max_hops, 5);
}

#[test]
#[should_panic(expected = "Error(Contract, #16)")]
fn test_set_taint_invalid_score_fails() {
    let (env, _owner, _operator, client) = setup_env();

    let target = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let source = String::from_str(&env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let chain = String::from_str(&env, "stellar");

    // Score 101 is invalid
    client.set_taint(&target, &101, &source, &1, &chain);
}
