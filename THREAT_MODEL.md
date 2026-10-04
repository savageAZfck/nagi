# THREAT MODEL — nagi

## Assets

- The escrowed secret (a memory vault master key or equivalent).
- Liveness evidence (beacons) gating dead-man recovery.
- Custodian shares.

## Adversaries

- **Corrupt custodian** holding a share, trying to block or poison recovery.
- **Network adversary** tampering with shards or claims in transit.
- **Impatient beneficiary** claiming before the owner is actually gone.
- **Posthumous attacker** with full physical access to the dead machine
  but not to custodians.
- **Coalition of <k custodians** pooling shares to steal the secret.

## Properties

- `k-1` shares are information-theoretically useless — Shamir, not
  heuristic. A coalition below threshold learns nothing.
- Shards are signature-bound to ceremony + owner + index; tampering is
  detected at custody time and at recovery time.
- Recombination self-verifies against `secret_digest` — a corrupt share
  cannot produce a wrong-but-plausible secret silently.
- Dead-man claims cannot be accelerated without forging the owner's key:
  the claimant must present the newest beacon, and lying older only
  delays release.
- Recovery certificates give the beneficiary (and auditors) a signed
  record of the event for downstream ledgers.

## Non-goals / honest limits

- **k+ malicious custodians can recover the secret.** Choose custodians
  across trust domains (different machines, different rooms) and set k
  accordingly. nagi makes collusion *sufficient* — not impossible.
- **Permanent owner silence is indistinguishable from death.** A dead-man
  plan fires on elapsed time, not on proof of death. Set staleness
  windows with that reality in mind.
- **A custodian can always destroy its share** (denial). Threshold
  redundancy absorbs loss up to n-k; beyond that the secret is gone.
- **No transport security.** Shards are safe alone but a claim replay is
  possible — a released shard is released. Custodians should release
  over authenticated channels and record releases in their own ledgers.
- **Clock skew** between custodian and claimant is handled by the plan
  choosing day-scale staleness; nagi assumes custodian clocks are roughly
  honest.
