# nagi

Dead-man memory escrow for sovereign organisms. Named for the Lakota *nagi* — the spirit that survives the body.

The question: what happens to a mind when its machine dies? `nagi` splits a memory vault's master key into `n` signed shards (GF(256) Shamir, k-of-n) and hands them to custodians the owner controls. Recovery happens two ways:

- **Owner unlock** — the owner signs a claim; custodians release. For migration, hardware refresh, mesh rewrites.
- **Dead man** — the owner emits signed heartbeat beacons. When the newest beacon is older than the plan's staleness window, a designated beneficiary key — a successor organism, a second machine, a trusted party — claims recovery. The mind outlives the body.

Every artifact is signed and self-verifying:

- **Shards** are bound to their ceremony by the owner's ed25519 signature. A forged or corrupted share is detected before recombination, not after.
- **Beacons** are the liveness clock. No trusted time source required — custodians compare timestamps they can verify.
- **Claims** are signed by the authorized key for the plan's mode: the owner for unlock, the beneficiary for dead-man.
- **Recovery certificates** prove a recovery happened, which shards contributed, and the digest of what was recovered — without exposing the secret.

`k - 1` shards yield zero information. Not a partial secret — nothing.

```rust
use nagi::{Escrow, Plan, Identity};

let owner = Identity::generate();
let heir = Identity::generate();
let plan = Plan::dead_man(3, 5, 86_400 * 30, heir.public_key());
let shards = Escrow::seal(&owner, b"vault-master-key", &plan).unwrap();
// distribute shards to custodians — transport is your layer, not the crate's
```

Transport-agnostic by design: nagi produces and consumes signed artifacts. SLICKS mesh, sneakernet, a second laptop — delivery is the organism's problem.

## Artifacts

| Type | Signed by | Purpose |
|---|---|---|
| `Shard` | owner | one custodian's share, ceremony-bound |
| `Beacon` | owner | heartbeat — freshness that blocks dead-man claims |
| `RecoveryClaim` | claimant | signed request a custodian judges |
| `RecoveryCertificate` | recoverer | proof of what was recovered, when, from which shares |

## Status

Extracted from Bad Apple's sovereign memory layer. MIT licensed.
