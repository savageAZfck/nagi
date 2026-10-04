use nagi::{Escrow, Identity, Plan, Recovery};

fn main() {
    let owner = Identity::generate();
    let plan = Plan::owner_unlock(3, 5);
    let secret = vec![7u8; 64];
    let t = std::time::Instant::now();
    for _ in 0..100 {
        let _ = Escrow::seal(&owner, &secret, &plan).unwrap();
    }
    println!("seal 3-of-5 x100: {:?}", t.elapsed());

    let shards = Escrow::seal(&owner, &secret, &plan).unwrap();
    let t = std::time::Instant::now();
    for _ in 0..100 {
        let _ = Recovery::assemble(&owner, &shards[..3]).unwrap();
    }
    println!("assemble + sign cert x100: {:?}", t.elapsed());
}
