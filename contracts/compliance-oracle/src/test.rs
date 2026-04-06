#![cfg(test)]

use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String, Vec};

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

// ─── Multi-Chain Add Sanctioned ─────────────────────────────────────────

#[test]
fn test_add_eth_addresses() {
    let (env, _owner, _operator, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");

    let eth1 = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let eth2 = String::from_str(&env, "0x7f367cc41522ce07553e823bf3be79a889debe1b");

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
    let (env, _owner, _operator, client) = setup_env();
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
    let (env, _owner, _operator, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "opensanctions");

    let tron = String::from_str(&env, "tn2yqtv5hpqenasqprfg3dqwxlkdcvk1qu");

    let mut addresses = Vec::new(&env);
    addresses.push_back(tron.clone());

    let added = client.add_sanctioned(&addresses, &hash, &source);
    assert_eq!(added, 1);
    assert!(client.is_sanctioned(&tron));
}

#[test]
fn test_add_mixed_chain_addresses() {
    let (env, _owner, _operator, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");

    let eth = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let btc = String::from_str(&env, "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh");
    let tron = String::from_str(&env, "tn2yqtv5hpqenasqprfg3dqwxlkdcvk1qu");
    let stellar = String::from_str(&env, "gbjrl4c72vicl7sd7bxa4ksa5vzd5ybvwivum47px457eimdcpnqi3qj");

    let mut addresses = Vec::new(&env);
    addresses.push_back(eth.clone());
    addresses.push_back(btc.clone());
    addresses.push_back(tron.clone());
    addresses.push_back(stellar.clone());

    let added = client.add_sanctioned(&addresses, &hash, &source);
    assert_eq!(added, 4);
    assert_eq!(client.entity_count(), 4);

    assert!(client.is_sanctioned(&eth));
    assert!(client.is_sanctioned(&btc));
    assert!(client.is_sanctioned(&tron));
    assert!(client.is_sanctioned(&stellar));

    let unknown = String::from_str(&env, "0x0000000000000000000000000000000000000000");
    assert!(!client.is_sanctioned(&unknown));
}

#[test]
fn test_add_duplicate_does_not_double_count() {
    let (env, _owner, _operator, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");

    let addr = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let mut addresses = Vec::new(&env);
    addresses.push_back(addr.clone());

    client.add_sanctioned(&addresses, &hash, &source);
    assert_eq!(client.entity_count(), 1);

    let added = client.add_sanctioned(&addresses, &hash, &source);
    assert_eq!(added, 0);
    assert_eq!(client.entity_count(), 1);
}

#[test]
fn test_add_skips_invalid_length_addresses() {
    let (env, _owner, _operator, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");

    let too_short = String::from_str(&env, "0x1234");
    let valid = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");

    let mut addresses = Vec::new(&env);
    addresses.push_back(too_short.clone());
    addresses.push_back(valid.clone());

    let added = client.add_sanctioned(&addresses, &hash, &source);
    assert_eq!(added, 1);
    assert!(!client.is_sanctioned(&too_short));
    assert!(client.is_sanctioned(&valid));
}

// ─── Remove Sanctioned ──────────────────────────────────────────────────

#[test]
fn test_remove_sanctioned() {
    let (env, _owner, _operator, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");

    let addr1 = String::from_str(&env, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let addr2 = String::from_str(&env, "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

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
    let (env, _owner, _operator, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");

    let sanctioned = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
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

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn test_batch_check_too_large() {
    let (env, _owner, _operator, client) = setup_env();
    let mut addresses = Vec::new(&env);
    let addr = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    for _ in 0..201u32 {
        addresses.push_back(addr.clone());
    }
    client.check_batch(&addresses);
}

// ─── Merkle Root ────────────────────────────────────────────────────────

#[test]
fn test_set_merkle_root() {
    let (env, _owner, _operator, client) = setup_env();
    let root = mock_data_hash(&env);

    client.set_merkle_root(&root);
    assert_eq!(client.merkle_root(), root);
}

#[test]
fn test_verify_merkle_proof_no_root_returns_error() {
    let (env, _owner, _operator, client) = setup_env();
    let addr = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let proof: Vec<BytesN<32>> = Vec::new(&env);

    let result = client.try_verify_merkle_proof(&addr, &proof, &0);
    assert!(result.is_err());
}

// ─── Community Reporting ────────────────────────────────────────────────

#[test]
fn test_report_eth_address() {
    let (env, _owner, _operator, client) = setup_env();

    let reporter = Address::generate(&env);
    let target = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
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
fn test_report_invalid_address_length() {
    let (env, _owner, _operator, client) = setup_env();
    let reporter = Address::generate(&env);
    let too_short = String::from_str(&env, "0x1234");
    let reason = String::from_str(&env, "test");

    let result = client.try_report_address(&reporter, &too_short, &reason);
    assert!(result.is_err());
}

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

    assert!(client.is_sanctioned(&target));
    assert_eq!(client.entity_count(), 1);
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
    assert!(!client.is_sanctioned(&target));
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

// ─── TTL Management ─────────────────────────────────────────────────────

#[test]
fn test_extend_ttl_batch() {
    let (env, _owner, _operator, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");

    let addr1 = String::from_str(&env, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
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
    let (env, _owner, _operator, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");
    let empty: Vec<String> = Vec::new(&env);

    client.add_sanctioned(&empty, &hash, &source);
}

#[test]
fn test_remove_more_than_count_saturates_to_zero() {
    let (env, _owner, _operator, client) = setup_env();
    let hash = mock_data_hash(&env);
    let source = String::from_str(&env, "ofac_sdn");

    let addr = String::from_str(&env, "0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b");
    let mut addresses = Vec::new(&env);
    addresses.push_back(addr.clone());

    client.add_sanctioned(&addresses, &hash, &source);
    assert_eq!(client.entity_count(), 1);

    client.remove_sanctioned(&addresses, &hash, &source);
    assert_eq!(client.entity_count(), 0);

    client.remove_sanctioned(&addresses, &hash, &source);
    assert_eq!(client.entity_count(), 0);
}
