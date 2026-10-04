use nagi::{Beacon, ClaimVerdict, Custodian, Escrow, Identity, Plan, Recovery, RecoveryClaim};

fn main() {
    // The organism's memory vault master key, escrowed across three
    // custodian machines, recoverable by the owner — or by a successor
    // key if the heartbeat dies.
    let owner = Identity::generate();
    let heir = Identity::generate(); // successor key on a second machine
    let plan = Plan::dead_man(2, 3, 86_400 * 30, heir.public_key());

    let shards = Escrow::seal(&owner, b"memory-vault-master-key", &plan).unwrap();
    let ceremony = shards[0].ceremony_id.clone();
    println!(
        "ceremony {} — {} shards, threshold {}",
        &ceremony[..12],
        shards.len(),
        plan.threshold
    );

    // Custodians verify before holding.
    let custodians: Vec<Custodian> = shards
        .into_iter()
        .map(|s| Custodian::accept(s, &plan).unwrap())
        .collect();
    println!("3 custodians holding signed shards");

    // While the owner lives: heartbeat.
    let beacon = Beacon::sign(&owner, &ceremony);
    let claim = RecoveryClaim::dead_man_claim(&heir, &ceremony, beacon.ts);
    let (verdict, _) = custodians[0].judge(&claim, beacon.ts + 60);
    println!("fresh heartbeat → {verdict:?}");

    // The machine dies. Thirty days pass. The heir claims the mind.
    let future = beacon.ts + 86_400 * 31;
    let mut released = Vec::new();
    for c in &custodians[..2] {
        if let (ClaimVerdict::Release, Some(s)) = c.judge(&claim, future) {
            released.push(s);
        }
    }
    let (secret, cert) = Recovery::assemble(&heir, &released).unwrap();
    println!(
        "heir recovered {} bytes; certificate signed: {}",
        secret.len(),
        cert.verify()
    );
}
