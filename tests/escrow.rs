use nagi::{Beacon, ClaimVerdict, Custodian, Escrow, Identity, Plan, Recovery, RecoveryClaim};

const SECRET: &[u8] = b"vault-master-key-do-not-lose";

#[test]
fn owner_unlock_recovery_roundtrip() {
    let owner = Identity::generate();
    let plan = Plan::owner_unlock(3, 5);
    let shards = Escrow::seal(&owner, SECRET, &plan).unwrap();
    assert_eq!(shards.len(), 5);

    // Custodians accept shards, then release against an owner claim.
    let custodians: Vec<Custodian> = shards
        .iter()
        .take(3)
        .cloned()
        .map(|s| Custodian::accept(s, &plan).unwrap())
        .collect();
    let claim = RecoveryClaim::owner_claim(&owner, &shards[0].ceremony_id);
    let released: Vec<_> = custodians
        .iter()
        .filter_map(|c| match c.judge(&claim, nagi_now()) {
            (ClaimVerdict::Release, Some(s)) => Some(s),
            _ => None,
        })
        .collect();
    assert_eq!(released.len(), 3);

    let (secret, cert) = Recovery::assemble(&owner, &released).unwrap();
    assert_eq!(secret, SECRET);
    assert!(cert.verify());
    assert_eq!(cert.shard_indices.len(), 3);
}

#[test]
fn dead_man_releases_only_after_staleness() {
    let owner = Identity::generate();
    let heir = Identity::generate();
    let plan = Plan::dead_man(2, 3, 86_400, heir.public_key());
    let shards = Escrow::seal(&owner, SECRET, &plan).unwrap();
    let ceremony = shards[0].ceremony_id.clone();

    let custodian = Custodian::accept(shards[0].clone(), &plan).unwrap();

    // Fresh beacon: claim denied as not-yet.
    let beacon = Beacon::sign(&owner, &ceremony);
    assert!(beacon.verify());
    let claim = RecoveryClaim::dead_man_claim(&heir, &ceremony, beacon.ts);
    match custodian.judge(&claim, beacon.ts + 100) {
        (ClaimVerdict::NotYet(_), None) => {}
        other => panic!("expected NotYet, got {other:?}"),
    }

    // Stale beacon: release.
    match custodian.judge(&claim, beacon.ts + 90_000) {
        (ClaimVerdict::Release, Some(_)) => {}
        other => panic!("expected Release, got {other:?}"),
    }
}

#[test]
fn wrong_claimant_denied() {
    let owner = Identity::generate();
    let heir = Identity::generate();
    let stranger = Identity::generate();
    let plan = Plan::dead_man(2, 3, 100, heir.public_key());
    let shards = Escrow::seal(&owner, SECRET, &plan).unwrap();
    let custodian = Custodian::accept(shards[0].clone(), &plan).unwrap();

    let claim = RecoveryClaim::dead_man_claim(&stranger, &shards[0].ceremony_id, 0);
    match custodian.judge(&claim, u64::MAX) {
        (ClaimVerdict::Deny(_), None) => {}
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[test]
fn forged_shard_fails_recovery() {
    let owner = Identity::generate();
    let plan = Plan::owner_unlock(2, 3);
    let mut shards = Escrow::seal(&owner, SECRET, &plan).unwrap();

    // Tamper with shard 0's share bytes — the owner signature no longer
    // covers the payload and the shard is dropped at assembly.
    let tampered = hex::decode(&shards[0].share)
        .unwrap()
        .into_iter()
        .map(|b| b ^ 0xff)
        .collect::<Vec<u8>>();
    shards[0].share = hex::encode(tampered);

    // Threshold is 2 but only one shard verifies — assembly must fail.
    let result = Recovery::assemble(&owner, &shards[..2]);
    assert!(result.is_err());
}

#[test]
fn recombined_secret_verified_against_digest() {
    let owner = Identity::generate();
    let plan = Plan::owner_unlock(2, 3);
    let shards = Escrow::seal(&owner, SECRET, &plan).unwrap();
    // Take shares 1 and 3 — any k of n works.
    let (secret, cert) =
        Recovery::assemble(&owner, &[shards[0].clone(), shards[2].clone()]).unwrap();
    assert_eq!(secret, SECRET);
    assert_eq!(cert.secret_digest.len(), 64);
}

fn nagi_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
