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

// ─── Multi-Chain Add Sanctioned ─────────────────────────────────────────

#[test]
fn test_add_eth_addresses() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");

    let eth1 = String::from_str(&env, "0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b");
    let eth2 = String::from_str(&env, "0x7F367cC41522cE07553e823bf3be79A889DEbe1B");

    let mut addresses = Vec::new(&env);
    addresses.push_back(eth1.clone());
    addresses.push_back(eth2.clone());

    let added = client.add_sanctioned(&addresses, &hash, &source);
    assert_eq!(added, 2);
    assert_eq!(client.entity_count(), 2);
    assert!(client.is_sanctioned(&eth1));
    assert!(client.is_sanctioned(&eth2));
}

#[test]
fn test_add_btc_addresses() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");

    let btc = String::from_str(&env, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh");

    let mut addresses = Vec::new(&env);
    addresses.push_back(btc.clone());

    let added = client.add_sanctioned(&addresses, &hash, &source);
    assert_eq!(added, 1);
    assert!(client.is_sanctioned(&btc));
}

#[test]
fn test_add_tron_addresses() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "opensanctions");

    let tron = String::from_str(&env, "TN2YqTv5HpqENAsQPRFG3dqWxLkDCVk1qU");

    let mut addresses = Vec::new(&env);
    addresses.push_back(tron.clone());

    let added = client.add_sanctioned(&addresses, &hash, &source);
    assert_eq!(added, 1);
    assert!(client.is_sanctioned(&tron));
}

#[test]
fn test_add_mixed_chain_addresses() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");

    let eth = String::from_str(&env, "0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b");
    let btc = String::from_str(&env, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh");
    let tron = String::from_str(&env, "TN2YqTv5HpqENAsQPRFG3dqWxLkDCVk1qU");
    let stellar = String::from_str(&env, "GBJRL4C72VICL7SD7BXA4KSA5VZD5YBVWIVUM47PX457EIMDCPNQI3QJ");

    let mut addresses = Vec::new(&env);
    addresses.push_back(eth.clone());
    addresses.push_back(btc.clone());
    addresses.push_back(tron.clone());
    addresses.push_back(stellar.clone());

    let added = client.add_sanctioned(&addresses, &hash, &source);
    assert_eq!(added, 4);
    assert_eq!(client.entity_count(), 4);

    // All are sanctioned
    assert!(client.is_sanctioned(&eth));
    assert!(client.is_sanctioned(&btc));
    assert!(client.is_sanctioned(&tron));
    assert!(client.is_sanctioned(&stellar));

    // Unknown address is clean
    let unknown = String::from_str(&env, "0x0000000000000000000000000000000000000000");
    assert!(!client.is_sanctioned(&unknown));
}

#[test]
fn test_add_duplicate_does_not_double_count() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");

    let addr = String::from_str(&env, "0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b");
    let mut addresses = Vec::new(&env);
    addresses.push_back(addr.clone());

    client.add_sanctioned(&addresses, &hash, &source);
    assert_eq!(client.entity_count(), 1);

    let added = client.add_sanctioned(&addresses, &hash, &source);
    assert_eq!(added, 0);
    assert_eq!(client.entity_count(), 1);
}

// ─── Remove Sanctioned ──────────────────────────────────────────────────

#[test]
fn test_remove_sanctioned() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");

    let addr1 = String::from_str(&env, "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let addr2 = String::from_str(&env, "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");

    let mut addresses = Vec::new(&env);
    addresses.push_back(addr1.clone());
    addresses.push_back(addr2.clone());

    client.add_sanctioned(&addresses, &hash, &source);
    assert_eq!(client.entity_count(), 2);

    let mut to_remove = Vec::new(&env);
    to_remove.push_back(addr1.clone());

    let removed = client.remove_sanctioned(&to_remove, &hash, &source);
    assert_eq!(removed, 1);
    assert_eq!(client.entity_count(), 1);
    assert!(!client.is_sanctioned(&addr1));
    assert!(client.is_sanctioned(&addr2));
}

// ─── Batch Check ────────────────────────────────────────────────────────

#[test]
fn test_batch_check() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");

    let sanctioned = String::from_str(&env, "0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b");
    let clean = String::from_str(&env, "0x0000000000000000000000000000000000000000");

    let mut to_add = Vec::new(&env);
    to_add.push_back(sanctioned.clone());
    client.add_sanctioned(&to_add, &hash, &source);

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

// ─── Merkle Root ────────────────────────────────────────────────────────

#[test]
fn test_set_merkle_root() {
    let (env, _admin, client) = setup_env();
    let root = mock_data_hash(&env);

    client.set_merkle_root(&root);
    assert_eq!(client.merkle_root(), root);
}

#[test]
fn test_verify_merkle_proof_no_root_returns_false() {
    let (env, _admin, client) = setup_env();
    let addr = String::from_str(&env, "0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b");
    let proof: Vec<BytesN<32>> = Vec::new(&env);

    assert!(!client.verify_merkle_proof(&addr, &proof, &0));
}

// ─── Community Reporting ────────────────────────────────────────────────

#[test]
fn test_report_eth_address() {
    let (env, _admin, client) = setup_env();

    let reporter = Address::generate(&env);
    let target = String::from_str(&env, "0xd882cFc20F52f2599D84b8e8D58C7FB62cfE344b");
    let reason = String::from_str(&env, "OFAC SDN match");

    let report_id = client.report_address(&reporter, &target, &reason);
    assert_eq!(report_id, 0);
    assert_eq!(client.report_count(), 1);

    let report = client.get_report(&0);
    assert_eq!(report.reporter, reporter);
    assert_eq!(report.target, target);
    assert_eq!(report.status, 0);
}

#[test]
fn test_review_report_accept() {
    let (env, _admin, client) = setup_env();

    let reporter = Address::generate(&env);
    let target = String::from_str(&env, "TN2YqTv5HpqENAsQPRFG3dqWxLkDCVk1qU");
    let reason = String::from_str(&env, "Known mixer");

    client.report_address(&reporter, &target, &reason);
    client.review_report(&0, &true);

    let report = client.get_report(&0);
    assert_eq!(report.status, 1);

    assert!(client.is_sanctioned(&target));
    assert_eq!(client.entity_count(), 1);
}

#[test]
fn test_review_report_reject() {
    let (env, _admin, client) = setup_env();

    let reporter = Address::generate(&env);
    let target = String::from_str(&env, "0x0000000000000000000000000000000000000000");
    let reason = String::from_str(&env, "False positive");

    client.report_address(&reporter, &target, &reason);
    client.review_report(&0, &false);

    let report = client.get_report(&0);
    assert_eq!(report.status, 2);
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
    let source = String::from_str(&env, "ofac_sdn");

    let addr1 = String::from_str(&env, "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let addr2 = String::from_str(&env, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh");

    let mut to_add = Vec::new(&env);
    to_add.push_back(addr1.clone());
    to_add.push_back(addr2.clone());

    client.add_sanctioned(&to_add, &hash, &source);

    let extended = client.extend_ttl_batch(&to_add);
    assert_eq!(extended, 2);
}

// ─── Edge Cases ─────────────────────────────────────────────────────────

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn test_add_empty_list_fails() {
    let (env, _admin, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");
    let empty: Vec<String> = Vec::new(&env);

    client.add_sanctioned(&empty, &hash, &source);
}
